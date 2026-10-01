-- SPDX-License-Identifier: AGPL-3.0-only
-- Durable signed conversation reply confirmations and immutable replay identity.
-- Raw proof content may only be redacted; immutable replay identity remains.
CREATE TABLE conversation_confirmation_records (
 account_id uuid NOT NULL,
 message_id uuid NOT NULL,
 interval_id uuid NOT NULL,
 initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 trust_generation bigint NOT NULL CHECK(trust_generation>0),
 manifest_version bigint NOT NULL CHECK(manifest_version>0),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 signer_key_id bytea NOT NULL CHECK(octet_length(signer_key_id)=32),
 reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
 body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
 expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
 envelope_digest bytea NOT NULL CHECK(octet_length(envelope_digest)=32),
 confirmation_digest bytea NOT NULL CHECK(octet_length(confirmation_digest)=32),
 signature_digest bytea NOT NULL CHECK(octet_length(signature_digest)=32),
 confirmation bytea CHECK(octet_length(confirmation) BETWEEN 297 AND 310),
 signature bytea CHECK(octet_length(signature)=64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(account_id,message_id),
 CHECK((confirmation IS NULL)=(signature IS NULL)),
 FOREIGN KEY(account_id,message_id) REFERENCES messages(account_id,id),
 FOREIGN KEY(account_id,interval_id) REFERENCES conversation_intervals(account_id,id),
 FOREIGN KEY(account_id,initiating_session_id) REFERENCES sessions(account_id,id),
 FOREIGN KEY(account_id,line_id,device_id,binding_generation)
  REFERENCES device_line_bindings(account_id,line_id,device_id,generation)
);
CREATE INDEX conversation_confirmation_inventory ON conversation_confirmation_records(account_id,created_at DESC,message_id DESC);
CREATE INDEX conversation_confirmation_interval ON conversation_confirmation_records(account_id,interval_id);
CREATE INDEX conversation_confirmation_session ON conversation_confirmation_records(account_id,initiating_session_id);
CREATE INDEX conversation_confirmation_line ON conversation_confirmation_records(account_id,line_id,device_id,binding_generation);
CREATE INDEX conversation_confirmation_redaction ON conversation_confirmation_records(expires_at_ms,account_id,message_id) WHERE confirmation IS NOT NULL;
CREATE FUNCTION conversation_confirmation_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['confirmation','signature'])<>(to_jsonb(OLD)-ARRAY['confirmation','signature'])
 OR (ROW(NEW.confirmation,NEW.signature) IS DISTINCT FROM ROW(OLD.confirmation,OLD.signature)
  AND NOT (OLD.confirmation IS NOT NULL AND NEW.confirmation IS NULL AND NEW.signature IS NULL)) THEN
  RAISE EXCEPTION 'confirmed intent identity cannot change' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER conversation_confirmation_before_update BEFORE UPDATE ON conversation_confirmation_records
 FOR EACH ROW EXECUTE FUNCTION conversation_confirmation_guard();
