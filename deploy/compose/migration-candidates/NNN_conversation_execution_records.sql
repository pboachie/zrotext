-- SPDX-License-Identifier: AGPL-3.0-only
-- Unnumbered candidate. Requires allocated confirmation records first; never
-- install from application code. Cryptographic admission remains in the server.
-- Legacy NULL cannot authorize execution. The existing proof update guard
-- includes this additive field in its immutable identity comparison.
ALTER TABLE conversation_confirmation_records ADD COLUMN execution_metered boolean;

-- Preserve every metadata predicate from 045. State authority is separately
-- constrained below to the exact permanent execution record and effects.
ALTER TABLE messages DROP CONSTRAINT messages_sealed_metadata;
ALTER TABLE messages ADD CONSTRAINT messages_sealed_metadata CHECK (
 (transport_mode='synthetic_alpha' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
 sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=0) OR
 (transport_mode='sealed_candidate02' AND num_nonnulls(sealed_line_id,sealed_binding_generation,
 sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=6
 AND sealed_binding_generation>0 AND sealed_manifest_generation>0 AND sealed_manifest_version>0
 AND octet_length(sealed_manifest_digest)=32 AND octet_length(sealed_signer_key_id)=32
 AND state IN ('queued','cancelled','expired','claimed','submitting','submitted','unknown','failed','delivered','delivery_unknown')));
CREATE TABLE conversation_execution_records (
 account_id uuid NOT NULL,
 message_id uuid NOT NULL,
 device_id uuid NOT NULL,
 attempt_id uuid NOT NULL UNIQUE CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
 generation bigint NOT NULL CHECK(generation=1),
 phone_session uuid NOT NULL CHECK(phone_session<>'00000000-0000-0000-0000-000000000000'),
 origin_hash bytea NOT NULL CHECK(octet_length(origin_hash)=32),
 site_id text NOT NULL CHECK(length(site_id) BETWEEN 1 AND 255),
 instance_id text NOT NULL CHECK(length(instance_id) BETWEEN 1 AND 255),
 session_epoch bigint NOT NULL CHECK(session_epoch>0),
 deployment_epoch bigint NOT NULL CHECK(deployment_epoch>0),
 reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
 envelope_digest bytea NOT NULL CHECK(octet_length(envelope_digest)=32),
 unsigned_digest bytea NOT NULL CHECK(octet_length(unsigned_digest)=32),
 expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
 segment_count smallint NOT NULL CHECK(segment_count BETWEEN 1 AND 6),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(account_id,message_id),
 FOREIGN KEY(account_id,message_id) REFERENCES conversation_confirmation_records(account_id,message_id),
 FOREIGN KEY(account_id,device_id) REFERENCES devices(account_id,id),
 FOREIGN KEY(attempt_id) REFERENCES message_attempts(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX conversation_execution_inventory ON conversation_execution_records(account_id,created_at,message_id);

-- Decode existing canonical public-manifest integer fields; no signature or
-- root acceptance happens in SQL. The producer uses the existing verifier.
CREATE FUNCTION conversation_execution_u64(bytes bytea, at integer) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE value bigint;
BEGIN
 IF at<0 OR octet_length(bytes)<at+8 THEN RETURN NULL; END IF;
 value:=('x'||encode(substring(bytes FROM at+1 FOR 8),'hex'))::bit(64)::bigint;
 IF value<0 THEN RETURN NULL; END IF;
 RETURN value;
END;
$$;
CREATE FUNCTION conversation_execution_key_live(bytes bytea, role integer, key_id bytea,
 device uuid, line uuid, sampled bigint, deadline bigint) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT EXISTS(SELECT 1 FROM generate_series(0,least(get_byte(bytes,150),64)-1) AS r(i)
 WHERE get_byte(bytes,151+149*i)=role AND get_byte(bytes,299+149*i)=1
 AND (key_id IS NULL OR substring(bytes FROM 153+149*i FOR 32)=key_id)
 AND substring(bytes FROM 250+149*i FOR 16)=uuid_send(device)
 AND substring(bytes FROM 266+149*i FOR 16)=uuid_send(line)
 AND conversation_execution_u64(bytes,283+149*i)<=sampled
 AND conversation_execution_u64(bytes,291+149*i)>=deadline);
$$;

-- Bounded Draft02 outbound reader extraction, not cryptographic admission.
-- The conversation producer requires exactly the device and archive wraps.
CREATE FUNCTION conversation_execution_payload_reader(bytes bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE n integer:=octet_length(bytes); protected_length integer; protected_end integer;
 body_length bigint; body_end integer; peer_length integer;
BEGIN
 IF n<557 OR n>34213 OR substring(bytes FROM 1 FOR 8)<>decode('5a54534502010000','hex')
 THEN RETURN NULL; END IF;
 protected_length:=get_byte(bytes,8)*256+get_byte(bytes,9);
 IF protected_length<157 OR protected_length>170 THEN RETURN NULL; END IF;
 protected_end:=10+protected_length;
 IF protected_end+16>n THEN RETURN NULL; END IF;
 peer_length:=get_byte(bytes,163);
 IF peer_length<3 OR peer_length>16 OR protected_length<>154+peer_length
 THEN RETURN NULL; END IF;
 body_length:=('x'||encode(substring(bytes FROM protected_end+13 FOR 4),'hex'))::bit(32)::bigint;
 IF body_length<17 OR body_length>32784 THEN RETURN NULL; END IF;
 body_end:=protected_end+16+body_length::integer;
 IF body_end>=n THEN RETURN NULL; END IF;
 IF get_byte(bytes,body_end)<>2 OR body_end+1+2*146+64<>n THEN RETURN NULL; END IF;
 IF get_byte(bytes,body_end+1)<>1 OR get_byte(bytes,body_end+147)<>2 THEN RETURN NULL; END IF;
 RETURN substring(bytes FROM body_end+3 FOR 32);
END;
$$;

CREATE FUNCTION conversation_execution_initial_valid(r conversation_execution_records) RETURNS boolean
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE t bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 zero uuid:='00000000-0000-0000-0000-000000000000';
BEGIN
 RETURN r.expires_at_ms>t AND r.expires_at_ms-t<=30000 AND EXISTS(
 SELECT 1 FROM conversation_confirmation_records p
 JOIN messages m ON (m.account_id,m.id)=(p.account_id,p.message_id)
 JOIN conversation_intervals i ON (i.account_id,i.id)=(p.account_id,p.interval_id)
 JOIN sealed_manifest_authorities a ON a.account_id=p.account_id
 JOIN accounts owner_account ON owner_account.id=p.account_id
 JOIN sessions s ON (s.account_id,s.id)=(p.account_id,p.initiating_session_id)
 JOIN users u ON u.id=s.user_id
 JOIN memberships member ON (member.account_id,member.user_id)=(s.account_id,s.user_id)
 JOIN devices d ON (d.account_id,d.id)=(p.account_id,p.device_id)
 JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id)
 JOIN device_sessions phone ON (phone.account_id,phone.device_id)=(d.account_id,d.id)
 JOIN sites site ON site.site_id=phone.site_id
 JOIN deployment_authority deploy ON deploy.singleton=TRUE
 JOIN phone_lines line ON (line.account_id,line.id)=(p.account_id,p.line_id)
 JOIN device_line_bindings binding ON (binding.account_id,binding.line_id,binding.device_id,binding.generation)=
 (p.account_id,p.line_id,p.device_id,p.binding_generation)
 WHERE (p.account_id,p.message_id,p.device_id)=(r.account_id,r.message_id,r.device_id)
 AND m.transport_mode='sealed_candidate02' AND m.state IN ('queued','claimed','submitting')
 AND m.transport_payload IS NOT NULL AND m.expires_at>clock_timestamp()
 AND m.request_digest=r.unsigned_digest AND p.envelope_digest=r.envelope_digest
 AND r.reader_key_id=conversation_execution_payload_reader(m.transport_payload)
 AND p.confirmation IS NOT NULL AND p.signature IS NOT NULL AND p.expires_at_ms>=r.expires_at_ms
 AND (m.sealed_line_id,m.sealed_binding_generation,m.sealed_manifest_generation,m.sealed_manifest_version,
 m.sealed_manifest_digest,m.sealed_signer_key_id)=(p.line_id,p.binding_generation,p.trust_generation,
 p.manifest_version,p.manifest_digest,p.signer_key_id)
 AND i.phase='active' AND i.closed_at IS NULL AND i.statement IS NOT NULL
 AND (i.device_id,i.line_id,i.binding_generation,i.initiating_session_id,i.trust_generation)=
 (p.device_id,p.line_id,p.binding_generation,p.initiating_session_id,p.trust_generation)
 AND owner_account.disabled_at IS NULL AND s.revoked_at IS NULL
 AND floor(extract(epoch FROM s.expires_at)*1000)::bigint>=r.expires_at_ms
 AND member.role='owner' AND member.revoked_at IS NULL AND u.email_verified_at IS NOT NULL
 AND d.revoked_at IS NULL AND k.revoked_at IS NULL
 AND (phone.site_id,phone.instance_id,phone.connection_epoch,phone.deployment_epoch)=
 (r.site_id,r.instance_id,r.session_epoch,r.deployment_epoch)
 AND floor(extract(epoch FROM phone.lease_until)*1000)::bigint>=r.expires_at_ms
 AND site.enabled AND NOT site.draining AND deploy.dispatch_enabled AND deploy.epoch=r.deployment_epoch
 AND line.state='active' AND line.approved_at IS NOT NULL AND line.current_binding_generation=p.binding_generation
 AND binding.state='active' AND binding.purpose='sealed' AND binding.activated_at IS NOT NULL
 AND binding.owner_approval_digest IS NOT NULL AND binding.device_confirmation_digest IS NOT NULL
 AND a.revoked_at IS NULL AND (a.generation,a.version,a.semantic_digest)=
 (p.trust_generation,p.manifest_version,p.manifest_digest) AND a.last_verified_ms<=t
 AND conversation_execution_u64(a.manifest,37)<=t AND conversation_execution_u64(a.manifest,45)>=r.expires_at_ms
 AND conversation_execution_key_live(a.manifest,1,r.reader_key_id,p.device_id,p.line_id,t,r.expires_at_ms)
 AND conversation_execution_key_live(a.manifest,2,p.reader_key_id,zero,zero,t,r.expires_at_ms)
 AND conversation_execution_key_live(a.manifest,5,p.signer_key_id,zero,p.line_id,t,r.expires_at_ms)
 -- Canonical original statement has two bounded text fields before its public
 -- reader/signer IDs. Bind the active phone signer to that original key.
 AND conversation_execution_key_live(a.manifest,4,
 substring(i.statement FROM 216+get_byte(i.statement,149)+get_byte(i.statement,150+get_byte(i.statement,149)) FOR 32),
 p.device_id,p.line_id,t,r.expires_at_ms)
 AND m.recipient_e164 IS NOT NULL AND convert_to(m.recipient_e164,'UTF8')=
 substring(i.statement FROM 151 FOR get_byte(i.statement,149))
 AND NOT EXISTS(SELECT 1 FROM recipient_suppressions WHERE account_id=p.account_id AND recipient_e164=m.recipient_e164 AND active)
 AND NOT EXISTS(SELECT 1 FROM owner_recipient_holds WHERE account_id=p.account_id AND recipient_e164=m.recipient_e164 AND released_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM usage_ledger WHERE account_id=p.account_id AND message_id=p.message_id AND entry_kind='refund')
 AND p.execution_metered IS NOT NULL AND (NOT p.execution_metered OR EXISTS(
 SELECT 1 FROM usage_ledger l JOIN usage_periods period ON
 (period.account_id,period.metric,period.period_start)=(l.account_id,l.metric,l.period_start)
 WHERE l.account_id=p.account_id AND l.message_id=p.message_id AND l.entry_kind='reserve'
 AND l.metric='outbound_message' AND l.units=1 AND period.reserved_units>0))
 AND NOT pg_is_in_recovery());
END;
$$;

CREATE FUNCTION conversation_execution_record_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'execution identity cannot change' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id AND disabled_at IS NULL) THEN
   RAISE EXCEPTION 'execution tombstone requires account erasure' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
 END IF;
 IF NOT conversation_execution_initial_valid(NEW) OR NOT EXISTS(
 SELECT 1 FROM dispatch_jobs j JOIN messages m ON (m.account_id,m.id)=(j.account_id,j.message_id)
 WHERE (j.account_id,j.message_id,j.device_id)=(NEW.account_id,NEW.message_id,NEW.device_id)
 AND j.generation=0 AND NEW.generation=1 AND j.grant_issued_at IS NULL AND j.finished_at IS NULL
 AND (j.lease_until IS NULL OR j.lease_until<clock_timestamp()) AND j.next_attempt_at<=clock_timestamp()
 AND m.state='queued') OR EXISTS(SELECT 1 FROM message_attempts WHERE account_id=NEW.account_id AND message_id=NEW.message_id)
 THEN RAISE EXCEPTION 'execution requires fresh confirmed queued admission' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER conversation_execution_before_write BEFORE INSERT OR UPDATE OR DELETE ON conversation_execution_records
 FOR EACH ROW EXECUTE FUNCTION conversation_execution_record_guard();

-- Extend 071 only for an exact immutable conversation execution. Generic sealed
-- provenance remains unchanged; redacted confirmation identity never becomes generic.
-- Called only when this optional candidate is installed, before locking the
-- message. Keep live identity locks through the final first-intent sample.
CREATE FUNCTION conversation_execution_lock_intent(account uuid, message uuid, device uuid, attempt uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 PERFORM r.attempt_id FROM conversation_execution_records r
 JOIN conversation_confirmation_records p ON (p.account_id,p.message_id)=(r.account_id,r.message_id)
 JOIN conversation_intervals i ON (i.account_id,i.id)=(p.account_id,p.interval_id)
 JOIN sessions origin ON (origin.account_id,origin.id)=(p.account_id,p.initiating_session_id)
 JOIN users u ON u.id=origin.user_id
 JOIN memberships member ON (member.account_id,member.user_id)=(origin.account_id,origin.user_id)
 JOIN device_sessions phone ON (phone.account_id,phone.device_id)=(r.account_id,r.device_id)
 JOIN device_keys k ON (k.account_id,k.device_id)=(r.account_id,r.device_id)
 JOIN sites site ON site.site_id=r.site_id JOIN deployment_authority deploy ON deploy.singleton
 JOIN phone_lines line ON (line.account_id,line.id)=(p.account_id,p.line_id)
 JOIN device_line_bindings binding ON (binding.account_id,binding.line_id,binding.device_id,binding.generation)=
  (p.account_id,p.line_id,p.device_id,p.binding_generation)
 WHERE (r.account_id,r.message_id,r.device_id,r.attempt_id)=($1,$2,$3,$4)
 FOR SHARE OF r,p,i,origin,u,member,phone,k,site,deploy,line,binding;
 RETURN FOUND;
END;
$$;

-- Final submit checks use the same immutable conversation identity and live
-- authority as initial permission; historical callbacks do not invoke it.
CREATE OR REPLACE FUNCTION sealed_grant_current(wanted uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE execution_record conversation_execution_records;
BEGIN
 SELECT * INTO execution_record FROM conversation_execution_records WHERE attempt_id=wanted;
 IF FOUND THEN
  RETURN conversation_execution_initial_valid(execution_record) AND EXISTS(
   SELECT 1 FROM message_attempts a JOIN dispatch_fences f ON f.attempt_id=a.id
   JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(a.account_id,a.message_id)
   WHERE a.id=execution_record.attempt_id AND (a.account_id,a.message_id,a.device_id,a.generation,a.session_epoch,a.deployment_epoch)=
    (execution_record.account_id,execution_record.message_id,execution_record.device_id,execution_record.generation,execution_record.session_epoch,execution_record.deployment_epoch)
   AND (f.account_id,f.message_id,f.device_id,f.generation,f.session_epoch,f.deployment_epoch)=
    (execution_record.account_id,execution_record.message_id,execution_record.device_id,execution_record.generation,execution_record.session_epoch,execution_record.deployment_epoch)
   AND a.status=f.outcome AND f.outcome IN ('granted','submitting')
   AND j.generation=execution_record.generation AND j.finished_at IS NULL AND j.grant_issued_at IS NOT NULL
   AND j.lease_owner='conversation:'||execution_record.phone_session::text
   AND j.lease_until=to_timestamp(execution_record.expires_at_ms::double precision/1000)
   AND f.grant_expires_at=j.lease_until);
 END IF;
 -- Retained confirmation identity cannot fall back after losing its execution.
 IF EXISTS(SELECT 1 FROM message_attempts a JOIN conversation_confirmation_records p
  ON (p.account_id,p.message_id)=(a.account_id,a.message_id) WHERE a.id=wanted) THEN RETURN FALSE; END IF;
 RETURN (
EXISTS (
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
)
 );
END;
$$;

CREATE OR REPLACE FUNCTION sealed_message_effect_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW.transport_mode='sealed_candidate02' AND NEW.state NOT IN ('queued','cancelled','expired')
 AND EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.id) THEN
  IF NOT EXISTS(SELECT 1 FROM conversation_execution_records r
   JOIN conversation_confirmation_records p ON (p.account_id,p.message_id)=(r.account_id,r.message_id)
   WHERE r.account_id=NEW.account_id AND r.message_id=NEW.id AND r.device_id=NEW.device_id
   AND p.device_id=NEW.device_id AND p.line_id=NEW.sealed_line_id
   AND p.binding_generation=NEW.sealed_binding_generation
   AND p.trust_generation=NEW.sealed_manifest_generation AND p.manifest_version=NEW.sealed_manifest_version
   AND p.manifest_digest=NEW.sealed_manifest_digest AND p.signer_key_id=NEW.sealed_signer_key_id
   AND r.unsigned_digest=NEW.request_digest AND r.envelope_digest=p.envelope_digest
   AND r.expires_at_ms<=p.expires_at_ms AND NEW.sealed_segment_limit IS NULL) THEN
   RAISE EXCEPTION 'conversation effect state requires exact execution provenance' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
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

-- The conversation lane retains its exact execution ceiling for historical
-- evidence. Only a fresh intent consults current authority; no callback renews it.
CREATE OR REPLACE FUNCTION sealed_radio_event_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE authorized smallint; r conversation_execution_records;
BEGIN
 IF EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.message_id) AND NEW.attempt_id IS NOT NULL THEN
  SELECT * INTO r FROM conversation_execution_records
   WHERE account_id=NEW.account_id AND message_id=NEW.message_id AND attempt_id=NEW.attempt_id;
  IF NOT FOUND OR (NEW.segment_count IS NOT NULL AND NEW.segment_count>r.segment_count) THEN
   RAISE EXCEPTION 'conversation evidence requires exact execution ceiling' USING ERRCODE='23514';
  END IF;
  IF NEW.evidence_code='durable_intent' AND (NOT conversation_execution_initial_valid(r)
   OR NOT EXISTS(SELECT 1 FROM dispatch_fences WHERE attempt_id=r.attempt_id
    AND account_id=r.account_id AND message_id=r.message_id AND device_id=r.device_id
    AND generation=r.generation AND session_epoch=r.session_epoch AND deployment_epoch=r.deployment_epoch
    AND outcome='granted' AND grant_expires_at=to_timestamp(r.expires_at_ms::double precision/1000)
    AND grant_expires_at>clock_timestamp())) THEN
   RAISE EXCEPTION 'conversation submit intent has stale execution authority' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
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

-- Preserve the original alpha and generic sealed-grant branches exactly.
-- Conversation effects require the immutable, proof-derived execution record.
CREATE OR REPLACE FUNCTION alpha_message_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE r conversation_execution_records; attempt uuid; before_status text; after_status text; wanted uuid;
BEGIN
 IF EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
 AND device_id=NEW.device_id AND transport_mode='synthetic_alpha' FOR SHARE) THEN RETURN NEW; END IF;
 -- Retained confirmation identity, including redacted proof, selects the conversation lane.
 -- Other sealed effects keep every migration 071 provenance and freshness check.
 IF NOT EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.message_id) THEN
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
 END IF;
 IF TG_TABLE_NAME='message_attempts' THEN attempt:=NEW.id; after_status:=NEW.status;
 ELSE attempt:=NEW.attempt_id; after_status:=NEW.outcome; END IF;
 SELECT * INTO r FROM conversation_execution_records WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
 IF NOT FOUND OR (NEW.device_id,attempt,NEW.generation,NEW.session_epoch,NEW.deployment_epoch)<>
 (r.device_id,r.attempt_id,r.generation,r.session_epoch,r.deployment_epoch) THEN
  RAISE EXCEPTION 'effects require exact confirmed execution identity' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='dispatch_fences' THEN
 IF (NEW.recipient_digest IS DISTINCT FROM
 (SELECT recipient_digest FROM messages WHERE account_id=r.account_id AND id=r.message_id)
 OR NEW.grant_expires_at<>to_timestamp(r.expires_at_ms::double precision/1000)) THEN
  RAISE EXCEPTION 'execution fence cannot replace recipient or expiry' USING ERRCODE='23514';
 END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF after_status<>'granted' OR NOT conversation_execution_initial_valid(r) OR NOT EXISTS(
  SELECT 1 FROM dispatch_jobs j JOIN messages m ON (m.account_id,m.id)=(j.account_id,j.message_id)
  WHERE (j.account_id,j.message_id,j.device_id,j.generation)=(r.account_id,r.message_id,r.device_id,r.generation)
  AND j.lease_owner='conversation:'||r.phone_session::text AND j.lease_until=to_timestamp(r.expires_at_ms::double precision/1000)
  AND j.grant_issued_at IS NOT NULL AND j.finished_at IS NULL AND m.state='claimed') THEN
   RAISE EXCEPTION 'execution effects require complete fresh claim' USING ERRCODE='23514';
  END IF;
 ELSE
  IF TG_TABLE_NAME='message_attempts' THEN before_status:=OLD.status;
  ELSE before_status:=OLD.outcome; END IF;
  IF (to_jsonb(NEW)-ARRAY['status','outcome','updated_at'])<>(to_jsonb(OLD)-ARRAY['status','outcome','updated_at'])
  OR (before_status<>'granted' AND after_status='granted')
  OR (before_status NOT IN ('granted','submitting') AND after_status='submitting')
  OR (before_status<>after_status AND NOT (
   (before_status='granted' AND after_status IN ('submitting','unknown','proved_no_submit')) OR
   (before_status='submitting' AND after_status IN ('submitted','failed','unknown','proved_no_submit')) OR
   (before_status='unknown' AND after_status IN ('submitted','failed','proved_no_submit')) OR
   (before_status IN ('submitted','failed') AND after_status='unknown'))) THEN
   RAISE EXCEPTION 'historical execution cannot reopen or replace identity' USING ERRCODE='23514';
  END IF;
  IF before_status='granted' AND after_status='submitting' AND NOT conversation_execution_initial_valid(r) THEN
   RAISE EXCEPTION 'submit intent requires current confirmed authority' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;

CREATE FUNCTION conversation_execution_job_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE r conversation_execution_records;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
 AND transport_mode='sealed_candidate02') THEN RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.message_id) THEN RETURN NEW; END IF;
 SELECT * INTO r FROM conversation_execution_records WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
 IF NOT FOUND THEN
  IF NEW.generation<>OLD.generation OR NEW.grant_issued_at IS NOT NULL OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL THEN
   RAISE EXCEPTION 'sealed claim requires confirmed execution record' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.account_id,NEW.message_id,NEW.device_id,NEW.generation)<>
 ROW(r.account_id,r.message_id,r.device_id,r.generation) OR
 (NEW.lease_owner IS NOT NULL AND NEW.lease_owner<>'conversation:'||r.phone_session::text) OR
 (OLD.lease_owner IS NOT NULL AND NEW.lease_owner IS NULL AND NEW.finished_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM message_attempts WHERE id=r.attempt_id AND status='proved_no_submit')) OR
 (OLD.lease_until IS NOT NULL AND NEW.lease_until IS NULL AND NEW.finished_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM message_attempts WHERE id=r.attempt_id AND status='proved_no_submit')) OR
 (NEW.lease_until IS NOT NULL AND NEW.lease_until<>to_timestamp(r.expires_at_ms::double precision/1000)) OR
 (OLD.grant_issued_at IS NOT NULL AND NEW.grant_issued_at IS DISTINCT FROM OLD.grant_issued_at
 AND NOT(NEW.grant_issued_at IS NULL AND EXISTS(SELECT 1 FROM message_attempts WHERE id=r.attempt_id AND status='proved_no_submit'))) OR
 (OLD.finished_at IS NOT NULL AND NEW.finished_at IS DISTINCT FROM OLD.finished_at) THEN
  RAISE EXCEPTION 'execution claim cannot renew or replace identity' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER conversation_execution_job_before_update BEFORE UPDATE ON dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION conversation_execution_job_guard();

-- An uncertain execution cannot release its device fence through a raw delete.
-- Existing no-radio evidence and account erasure remain the only release paths.
CREATE FUNCTION conversation_execution_effect_delete_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM conversation_execution_records
 WHERE account_id=OLD.account_id AND message_id=OLD.message_id) THEN RETURN OLD; END IF;
 IF NOT EXISTS(SELECT 1 FROM messages WHERE account_id=OLD.account_id AND id=OLD.message_id
 AND transport_mode='sealed_candidate02') THEN RETURN OLD; END IF;
 IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id AND disabled_at IS NULL) THEN RETURN OLD; END IF;
 IF TG_TABLE_NAME='dispatch_fences' THEN
  IF EXISTS(SELECT 1 FROM message_attempts
  WHERE id=OLD.attempt_id AND account_id=OLD.account_id AND message_id=OLD.message_id
  AND status='proved_no_submit') THEN RETURN OLD; END IF;
 END IF;
 RAISE EXCEPTION 'execution effect requires retained fence or account erasure' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER conversation_execution_attempt_before_delete BEFORE DELETE ON message_attempts
 FOR EACH ROW EXECUTE FUNCTION conversation_execution_effect_delete_guard();
CREATE TRIGGER conversation_execution_fence_before_delete BEFORE DELETE ON dispatch_fences
 FOR EACH ROW EXECUTE FUNCTION conversation_execution_effect_delete_guard();

CREATE FUNCTION conversation_execution_message_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW.transport_mode<>'sealed_candidate02' THEN RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.id) THEN RETURN NEW; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state NOT IN ('queued','cancelled','expired') THEN
   RAISE EXCEPTION 'sealed initial state requires queued admission' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.state=OLD.state THEN RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM conversation_execution_records WHERE account_id=NEW.account_id AND message_id=NEW.id) THEN
  IF OLD.state<>'queued' OR NEW.state NOT IN ('cancelled','expired') THEN
   RAISE EXCEPTION 'sealed state requires confirmed execution' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NOT (
  (OLD.state='queued' AND NEW.state IN ('claimed','cancelled','expired')) OR
  (OLD.state='claimed' AND NEW.state IN ('submitting','unknown','queued')) OR
  (OLD.state='submitting' AND NEW.state IN ('submitted','failed','unknown','queued')) OR
  (OLD.state='submitted' AND NEW.state IN ('delivered','delivery_unknown','unknown')) OR
  (OLD.state='delivery_unknown' AND NEW.state IN ('delivered','unknown')) OR
  (OLD.state IN ('delivered','failed') AND NEW.state='unknown') OR
  (OLD.state='unknown' AND NEW.state IN ('submitted','failed','queued'))) THEN
  RAISE EXCEPTION 'execution state cannot reopen or roll back' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER conversation_execution_message_before_write BEFORE INSERT OR UPDATE ON messages
 FOR EACH ROW EXECUTE FUNCTION conversation_execution_message_guard();

CREATE FUNCTION conversation_execution_message_complete_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE r conversation_execution_records; current_state text; needed text;
BEGIN
 IF NEW.transport_mode<>'sealed_candidate02' OR NEW.state=OLD.state THEN RETURN NULL; END IF;
 SELECT * INTO r FROM conversation_execution_records WHERE account_id=NEW.account_id AND message_id=NEW.id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT state INTO current_state FROM messages WHERE account_id=NEW.account_id AND id=NEW.id;
 needed:=CASE current_state WHEN 'claimed' THEN 'granted' WHEN 'queued' THEN 'proved_no_submit'
 WHEN 'cancelled' THEN 'proved_no_submit' WHEN 'expired' THEN 'proved_no_submit'
 WHEN 'delivered' THEN 'submitted' WHEN 'delivery_unknown' THEN 'submitted' ELSE current_state END;
 IF NOT EXISTS(SELECT 1 FROM message_attempts a JOIN dispatch_jobs j ON
 (j.account_id,j.message_id)=(a.account_id,a.message_id)
 WHERE (a.account_id,a.message_id,a.device_id,a.id,a.generation,a.session_epoch,a.deployment_epoch)=
 (r.account_id,r.message_id,r.device_id,r.attempt_id,r.generation,r.session_epoch,r.deployment_epoch)
 AND a.status=needed AND j.generation=r.generation
 AND ((needed='proved_no_submit' AND j.grant_issued_at IS NULL AND NOT EXISTS(SELECT 1 FROM dispatch_fences WHERE attempt_id=a.id))
 OR (needed<>'proved_no_submit' AND j.grant_issued_at IS NOT NULL AND EXISTS(
 SELECT 1 FROM dispatch_fences f WHERE f.attempt_id=a.id AND
 (f.account_id,f.message_id,f.device_id,f.generation,f.session_epoch,f.deployment_epoch)=
 (a.account_id,a.message_id,a.device_id,a.generation,a.session_epoch,a.deployment_epoch)
 AND f.outcome=needed AND f.grant_expires_at=to_timestamp(r.expires_at_ms::double precision/1000))))) THEN
 RAISE EXCEPTION 'execution state requires exact committed attempt and fence' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER conversation_execution_message_complete AFTER UPDATE ON messages
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION conversation_execution_message_complete_guard();

CREATE FUNCTION conversation_execution_complete_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NOT conversation_execution_initial_valid(NEW) OR NOT EXISTS(
 SELECT 1 FROM message_attempts a JOIN dispatch_fences f ON f.attempt_id=a.id
 JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(a.account_id,a.message_id)
 JOIN messages m ON (m.account_id,m.id)=(a.account_id,a.message_id)
 WHERE (a.account_id,a.message_id,a.device_id,a.id,a.generation,a.session_epoch,a.deployment_epoch)=
 (NEW.account_id,NEW.message_id,NEW.device_id,NEW.attempt_id,NEW.generation,NEW.session_epoch,NEW.deployment_epoch)
 AND (f.account_id,f.message_id,f.device_id,f.generation,f.session_epoch,f.deployment_epoch)=
 (a.account_id,a.message_id,a.device_id,a.generation,a.session_epoch,a.deployment_epoch)
 AND a.status='granted' AND f.outcome='granted' AND m.state='claimed'
 AND f.grant_expires_at=to_timestamp(NEW.expires_at_ms::double precision/1000)
 AND j.generation=NEW.generation AND j.lease_owner='conversation:'||NEW.phone_session::text
 AND j.lease_until=f.grant_expires_at AND j.grant_issued_at IS NOT NULL AND j.finished_at IS NULL)
 THEN RAISE EXCEPTION 'execution grant cannot commit partial or stale effects' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER conversation_execution_complete AFTER INSERT ON conversation_execution_records
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION conversation_execution_complete_guard();
