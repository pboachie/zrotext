-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant proof-bound sealed effects. No root, grant, or runtime gate is enabled.
ALTER TABLE messages ADD COLUMN sealed_segment_limit smallint
    CHECK (sealed_segment_limit BETWEEN 1 AND 6);
ALTER TABLE messages ADD CONSTRAINT messages_segment_limit_transport
    CHECK (sealed_segment_limit IS NULL OR transport_mode='sealed_candidate02');
ALTER TABLE messages DROP CONSTRAINT messages_sealed_metadata;
ALTER TABLE messages ADD CONSTRAINT messages_sealed_metadata CHECK (
    (transport_mode='synthetic_alpha' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
        sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=0) OR
    (transport_mode='sealed_candidate02' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
        sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=6
     AND sealed_binding_generation>0 AND sealed_manifest_generation>0 AND sealed_manifest_version>0
     AND octet_length(sealed_manifest_digest)=32 AND octet_length(sealed_signer_key_id)=32
     AND (sealed_segment_limit IS NOT NULL OR state IN ('queued','cancelled','expired'))));
CREATE FUNCTION sealed_segment_limit_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.sealed_segment_limit IS DISTINCT FROM OLD.sealed_segment_limit THEN
        RAISE EXCEPTION 'sealed segment limit cannot change' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_segment_limit_before_update BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION sealed_segment_limit_guard();

CREATE TABLE sealed_grant_authorizations (
    attempt_id uuid PRIMARY KEY REFERENCES message_attempts(id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    message_id uuid NOT NULL,
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation>0),
    attempt_generation bigint NOT NULL CHECK (attempt_generation>0),
    connection_epoch bigint NOT NULL CHECK (connection_epoch>0),
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch>0),
    site_id text NOT NULL REFERENCES sites(site_id),
    instance_id text NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 128),
    manifest_generation bigint NOT NULL CHECK (manifest_generation>0),
    manifest_version bigint NOT NULL CHECK (manifest_version>0),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    reader_key_id bytea NOT NULL CHECK (octet_length(reader_key_id)=32),
    envelope_digest bytea NOT NULL CHECK (octet_length(envelope_digest)=32),
    unsigned_digest bytea NOT NULL CHECK (octet_length(unsigned_digest)=32),
    segment_limit smallint NOT NULL CHECK (segment_limit BETWEEN 1 AND 6),
    authority_expires_at_ms bigint NOT NULL CHECK (authority_expires_at_ms>0),
    FOREIGN KEY (account_id,message_id) REFERENCES messages(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,device_id) REFERENCES devices(account_id,id),
    FOREIGN KEY (account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation),
    UNIQUE (account_id,message_id,attempt_generation)
);
CREATE INDEX sealed_grant_authorizations_device ON sealed_grant_authorizations(account_id,device_id);
CREATE INDEX sealed_grant_authorizations_binding ON sealed_grant_authorizations(account_id,line_id,device_id,binding_generation);
CREATE INDEX sealed_grant_authorizations_site ON sealed_grant_authorizations(site_id);

CREATE FUNCTION sealed_grant_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'sealed grant provenance cannot change' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER sealed_grant_before_update BEFORE UPDATE ON sealed_grant_authorizations
    FOR EACH ROW EXECUTE FUNCTION sealed_grant_immutable();

CREATE FUNCTION sealed_message_effect_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.transport_mode='sealed_candidate02' AND NEW.state NOT IN ('queued','cancelled','expired')
        AND NOT EXISTS(SELECT 1 FROM sealed_grant_authorizations g
            WHERE g.account_id=NEW.account_id AND g.message_id=NEW.id AND g.device_id=NEW.device_id
            AND g.line_id=NEW.sealed_line_id AND g.binding_generation=NEW.sealed_binding_generation
            AND g.manifest_generation=NEW.sealed_manifest_generation AND g.manifest_version=NEW.sealed_manifest_version
            AND g.manifest_digest=NEW.sealed_manifest_digest AND g.unsigned_digest=NEW.request_digest
            AND g.segment_limit=NEW.sealed_segment_limit) THEN
        RAISE EXCEPTION 'sealed effect state requires exact grant provenance' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_message_effect_before_write BEFORE INSERT OR UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION sealed_message_effect_state_guard();

-- This predicate rechecks authority already cryptographically verified by the
-- caller under the locked independent root pin. Expiry is capped by every role.
CREATE FUNCTION sealed_grant_current(wanted uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
SELECT EXISTS (
    SELECT 1 FROM sealed_grant_authorizations g
    JOIN sealed_manifest_authorities r ON r.account_id=g.account_id
    JOIN accounts a ON a.id=g.account_id
    JOIN devices d ON (d.account_id,d.id)=(g.account_id,g.device_id)
    JOIN device_keys k ON (k.account_id,k.device_id)=(g.account_id,g.device_id)
    JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(g.account_id,g.device_id)
    JOIN phone_lines l ON (l.account_id,l.id)=(g.account_id,g.line_id)
    JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=
        (g.account_id,g.line_id,g.device_id,g.binding_generation)
    JOIN sites s ON s.site_id=g.site_id
    JOIN deployment_authority p ON p.singleton
    JOIN messages m ON (m.account_id,m.id)=(g.account_id,g.message_id)
    WHERE g.attempt_id=wanted AND a.disabled_at IS NULL AND d.revoked_at IS NULL AND k.revoked_at IS NULL
      AND r.revoked_at IS NULL AND r.generation=g.manifest_generation AND r.version=g.manifest_version
      AND r.semantic_digest=g.manifest_digest
      AND r.last_verified_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND g.authority_expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND m.expires_at>clock_timestamp() AND m.transport_mode='sealed_candidate02'
      AND m.sealed_line_id=g.line_id AND m.sealed_binding_generation=g.binding_generation
      AND m.sealed_manifest_generation=g.manifest_generation AND m.sealed_manifest_version=g.manifest_version
      AND m.sealed_manifest_digest=g.manifest_digest AND m.request_digest=g.unsigned_digest
      AND m.sealed_segment_limit=g.segment_limit AND m.transport_payload IS NOT NULL
      AND EXISTS(SELECT 1 FROM usage_ledger u WHERE u.account_id=g.account_id
          AND u.message_id=g.message_id AND u.metric='outbound_message' AND u.entry_kind='reserve' AND u.units=1)
      AND NOT EXISTS(SELECT 1 FROM usage_ledger u WHERE u.account_id=g.account_id
          AND u.message_id=g.message_id AND u.metric='outbound_message' AND u.entry_kind='refund')
      AND ds.connection_epoch=g.connection_epoch AND ds.deployment_epoch=g.deployment_epoch
      AND ds.site_id=g.site_id AND ds.instance_id=g.instance_id AND ds.lease_until>clock_timestamp()
      AND p.epoch=g.deployment_epoch AND p.dispatch_enabled AND NOT pg_is_in_recovery()
      AND s.enabled AND NOT s.draining
      AND l.state='active' AND l.approved_at IS NOT NULL AND l.current_binding_generation=g.binding_generation
      AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL
      AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM recipient_suppressions q WHERE q.account_id=g.account_id
          AND q.recipient_e164=m.recipient_e164 AND q.active)
      AND NOT EXISTS(SELECT 1 FROM owner_recipient_holds h WHERE h.account_id=g.account_id
          AND h.recipient_e164=m.recipient_e164 AND h.released_at IS NULL)
);
$$;

-- Preserve the original alpha case. Sealed insertions require immutable exact
-- provenance; subsequent historical reconciliation is allowed after revocation.
CREATE OR REPLACE FUNCTION alpha_message_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE wanted uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
        AND device_id=NEW.device_id AND transport_mode='synthetic_alpha' FOR SHARE) THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME='message_attempts' THEN wanted:=NEW.id; ELSE wanted:=NEW.attempt_id; END IF;
    IF TG_OP='UPDATE' AND (
        ROW(NEW.account_id,NEW.message_id,NEW.device_id,NEW.generation,NEW.session_epoch,NEW.deployment_epoch)
        IS DISTINCT FROM
        ROW(OLD.account_id,OLD.message_id,OLD.device_id,OLD.generation,OLD.session_epoch,OLD.deployment_epoch)) THEN
        RAISE EXCEPTION 'sealed attempt identity cannot change' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF TG_TABLE_NAME='message_attempts' THEN
            IF NEW.id<>OLD.id THEN
                RAISE EXCEPTION 'sealed attempt identity cannot change' USING ERRCODE='23514';
            END IF;
        ELSE
            IF ROW(NEW.attempt_id,NEW.grant_expires_at,NEW.recipient_digest) IS DISTINCT FROM
               ROW(OLD.attempt_id,OLD.grant_expires_at,OLD.recipient_digest) THEN
                RAISE EXCEPTION 'sealed fence identity cannot change' USING ERRCODE='23514';
            END IF;
        END IF;
    END IF;
    IF NOT EXISTS(SELECT 1 FROM sealed_grant_authorizations g JOIN messages m
        ON (m.account_id,m.id)=(g.account_id,g.message_id)
        WHERE g.attempt_id=wanted AND g.account_id=NEW.account_id AND g.message_id=NEW.message_id
        AND g.device_id=NEW.device_id AND g.attempt_generation=NEW.generation
        AND g.connection_epoch=NEW.session_epoch AND g.deployment_epoch=NEW.deployment_epoch
        AND m.transport_mode='sealed_candidate02' AND m.sealed_segment_limit=g.segment_limit) THEN
        RAISE EXCEPTION 'sealed effects require exact grant provenance' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' AND NOT sealed_grant_current(wanted) THEN
        RAISE EXCEPTION 'sealed grant authority is stale' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' THEN
        IF TG_TABLE_NAME='message_attempts' THEN
            IF NEW.status<>'granted' THEN
                RAISE EXCEPTION 'sealed attempt starts granted' USING ERRCODE='23514';
            END IF;
        ELSE
            IF NEW.outcome<>'granted' OR NEW.grant_expires_at<=clock_timestamp()
                OR NEW.grant_expires_at>clock_timestamp()+interval '30 seconds'
                OR NOT EXISTS(SELECT 1 FROM sealed_grant_authorizations g JOIN messages m
                    ON (m.account_id,m.id)=(g.account_id,g.message_id)
                    WHERE g.attempt_id=wanted AND NEW.recipient_digest=m.recipient_digest
                    AND NEW.grant_expires_at<=to_timestamp(g.authority_expires_at_ms::double precision/1000)) THEN
                RAISE EXCEPTION 'sealed fence exceeds exact authority' USING ERRCODE='23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION sealed_radio_event_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE authorized smallint;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
        AND transport_mode='sealed_candidate02') THEN RETURN NEW; END IF;
    -- Non-radio queue lifecycle events carry no attempt and remain valid.
    IF NEW.attempt_id IS NULL THEN RETURN NEW; END IF;
    SELECT segment_limit INTO authorized FROM sealed_grant_authorizations
        WHERE attempt_id=NEW.attempt_id AND account_id=NEW.account_id AND message_id=NEW.message_id;
    IF authorized IS NULL OR (NEW.segment_count IS NOT NULL AND NEW.segment_count>authorized) THEN
        RAISE EXCEPTION 'sealed evidence exceeds exact grant' USING ERRCODE='23514';
    END IF;
    IF NEW.evidence_code='durable_intent' AND (NOT sealed_grant_current(NEW.attempt_id)
        OR NOT EXISTS(SELECT 1 FROM dispatch_fences WHERE attempt_id=NEW.attempt_id
            AND outcome='granted' AND grant_expires_at>clock_timestamp())) THEN
        RAISE EXCEPTION 'sealed submit intent has stale authority' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_radio_event_before_insert BEFORE INSERT ON message_events
    FOR EACH ROW EXECUTE FUNCTION sealed_radio_event_guard();
