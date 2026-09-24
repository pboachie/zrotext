-- SPDX-License-Identifier: AGPL-3.0-only
-- Content can be removed without deleting message and inbound replay identities.
ALTER TABLE messages ALTER COLUMN recipient_e164 DROP NOT NULL;
ALTER TABLE messages ALTER COLUMN transport_payload DROP NOT NULL;
ALTER TABLE messages ADD CONSTRAINT messages_content_pair CHECK
    ((recipient_e164 IS NULL) = (transport_payload IS NULL));

ALTER TABLE inbound_events DROP CONSTRAINT inbound_events_check;
ALTER TABLE inbound_events ADD CONSTRAINT inbound_events_content CHECK
    ((content_kind='metadata_only' AND content_ciphertext IS NULL) OR
     (content_kind='opaque_pilot' AND content_ciphertext IS NOT NULL AND
      octet_length(content_ciphertext) BETWEEN 32 AND 8192) OR
     (content_kind='redacted' AND content_ciphertext IS NULL));
ALTER TABLE inbound_events DROP CONSTRAINT inbound_events_content_kind_check;
ALTER TABLE inbound_events ADD CONSTRAINT inbound_events_content_kind_check CHECK
    (content_kind IN ('metadata_only', 'opaque_pilot', 'redacted'));

-- Keep the immutable ID, device sequence, and digest after sealed ciphertext expires.
ALTER TABLE sealed_inbound_events ALTER COLUMN envelope DROP NOT NULL;
ALTER TABLE sealed_inbound_events DROP CONSTRAINT sealed_inbound_events_envelope_check;
ALTER TABLE sealed_inbound_events ADD CONSTRAINT sealed_inbound_events_envelope_check CHECK
    (envelope IS NULL OR (octet_length(envelope) BETWEEN 426 AND 34082 AND
     substring(envelope from 1 for 6) = decode('5a5453450102', 'hex')));
CREATE OR REPLACE FUNCTION sealed_inbound_forbid_update() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.envelope IS NULL OR NEW.envelope IS NOT NULL THEN
        RAISE EXCEPTION 'sealed inbound event is immutable' USING ERRCODE = '23514';
    END IF;
    NEW.envelope := OLD.envelope;
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'sealed inbound event is immutable' USING ERRCODE = '23514';
    END IF;
    NEW.envelope := NULL;
    RETURN NEW;
END;
$$;

CREATE INDEX idempotency_keys_expiry ON idempotency_keys(expires_at);
CREATE INDEX messages_retention_due ON messages(updated_at,id)
    WHERE recipient_e164 IS NOT NULL;
CREATE INDEX message_events_retention_due ON message_events(received_at,id);
CREATE INDEX webhook_deliveries_retention_due ON webhook_deliveries(updated_at,id)
    WHERE status IN ('succeeded','dead');
CREATE INDEX inbound_events_retention_due ON inbound_events(received_at,id)
    WHERE content_ciphertext IS NOT NULL;
CREATE INDEX sealed_inbound_events_retention_due ON sealed_inbound_events(received_at,id)
    WHERE envelope IS NOT NULL;
