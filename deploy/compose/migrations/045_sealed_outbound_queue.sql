-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant candidate admission only. No existing dispatcher may execute it.
ALTER TABLE messages
    ADD COLUMN sealed_line_id uuid,
    ADD COLUMN sealed_binding_generation bigint,
    ADD COLUMN sealed_manifest_generation bigint,
    ADD COLUMN sealed_manifest_version bigint,
    ADD COLUMN sealed_manifest_digest bytea,
    ADD COLUMN sealed_signer_key_id bytea;
ALTER TABLE messages DROP CONSTRAINT messages_transport_mode_check;
ALTER TABLE messages DROP CONSTRAINT messages_transport_payload_check;
ALTER TABLE messages ADD CONSTRAINT messages_transport_mode_check
    CHECK (transport_mode IN ('synthetic_alpha','sealed_candidate02'));
ALTER TABLE messages ADD CONSTRAINT messages_transport_payload_check CHECK (
    transport_payload IS NULL OR
    (transport_mode='synthetic_alpha' AND octet_length(transport_payload) BETWEEN 1 AND 32768) OR
    (transport_mode='sealed_candidate02' AND octet_length(transport_payload) BETWEEN 426 AND 34213
     AND substring(transport_payload from 1 for 6)=decode('5a5453450201','hex')));
ALTER TABLE messages ADD CONSTRAINT messages_sealed_metadata CHECK (
    (transport_mode='synthetic_alpha' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
        sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=0) OR
    (transport_mode='sealed_candidate02' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
        sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=6
     AND sealed_binding_generation>0 AND sealed_manifest_generation>0 AND sealed_manifest_version>0
     AND octet_length(sealed_manifest_digest)=32 AND octet_length(sealed_signer_key_id)=32
     AND state IN ('queued','cancelled','expired')));
ALTER TABLE messages ADD CONSTRAINT messages_sealed_binding FOREIGN KEY
    (account_id,sealed_line_id,device_id,sealed_binding_generation)
    REFERENCES device_line_bindings(account_id,line_id,device_id,generation);

CREATE FUNCTION sealed_outbound_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.transport_mode<>OLD.transport_mode THEN
        RAISE EXCEPTION 'message transport cannot change' USING ERRCODE='23514';
    END IF;
    IF OLD.transport_mode='sealed_candidate02' AND (
        ROW(NEW.id,NEW.account_id,NEW.device_id,NEW.request_digest,NEW.recipient_digest,NEW.expires_at,
            NEW.sealed_line_id,NEW.sealed_binding_generation,NEW.sealed_manifest_generation,
            NEW.sealed_manifest_version,NEW.sealed_manifest_digest,NEW.sealed_signer_key_id)
        IS DISTINCT FROM
        ROW(OLD.id,OLD.account_id,OLD.device_id,OLD.request_digest,OLD.recipient_digest,OLD.expires_at,
            OLD.sealed_line_id,OLD.sealed_binding_generation,OLD.sealed_manifest_generation,
            OLD.sealed_manifest_version,OLD.sealed_manifest_digest,OLD.sealed_signer_key_id)
        OR (NEW.transport_payload IS NOT NULL AND NEW.transport_payload IS DISTINCT FROM OLD.transport_payload)
        OR (NEW.recipient_e164 IS NOT NULL AND NEW.recipient_e164 IS DISTINCT FROM OLD.recipient_e164)) THEN
        RAISE EXCEPTION 'sealed message identity cannot change' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_outbound_identity_before_update BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION sealed_outbound_identity_guard();

-- Defense in depth for callers that bypass the alpha claim filter. A later
-- separately reviewed sealed grant implementation must replace this boundary.
CREATE FUNCTION alpha_message_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
                   AND device_id=NEW.device_id AND transport_mode='synthetic_alpha' FOR SHARE) THEN
        RAISE EXCEPTION 'existing effects require alpha transport' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER alpha_attempt_before_write BEFORE INSERT OR UPDATE ON message_attempts
    FOR EACH ROW EXECUTE FUNCTION alpha_message_effect_guard();
CREATE TRIGGER alpha_fence_before_write BEFORE INSERT OR UPDATE ON dispatch_fences
    FOR EACH ROW EXECUTE FUNCTION alpha_message_effect_guard();
