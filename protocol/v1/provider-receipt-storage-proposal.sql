-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant proposal, NOT installed by the ordinary migration runner.
-- No production correlation creator or elected-writer permit issuer exists.
-- Future promotion requires trusted atomic submit intent and serial numbering.
CREATE TABLE provider_receipt_attempts (
    account_id uuid NOT NULL REFERENCES accounts(id),
    attempt_id uuid NOT NULL CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    provider text NOT NULL CHECK (provider = 'telnyx_sms_v2'),
    route_fingerprint bytea,
    request_digest bytea,
    provider_message_id uuid,
    state text,
    delivery_failed boolean,
    event_count smallint NOT NULL DEFAULT 0 CHECK (event_count BETWEEN 0 AND 64),
    state_version bigint NOT NULL DEFAULT 0 CHECK (state_version >= event_count),
    accepted_at timestamptz,
    updated_at timestamptz,
    created_epoch bigint CHECK (created_epoch > 0),
    erased_at timestamptz,
    PRIMARY KEY (account_id, attempt_id),
    CHECK ((erased_at IS NULL AND route_fingerprint IS NOT NULL AND request_digest IS NOT NULL
        AND octet_length(route_fingerprint)=32
        AND octet_length(request_digest)=32 AND provider_message_id IS NOT NULL AND state IS NOT NULL
        AND provider_message_id <> '00000000-0000-0000-0000-000000000000'
        AND state IN ('submitting','unknown','submitted','delivery_unconfirmed','delivered','failed')
        AND delivery_failed IS NOT NULL AND accepted_at IS NOT NULL
        AND updated_at IS NOT NULL AND created_epoch IS NOT NULL
        AND (NOT delivery_failed OR state IN ('submitted','delivery_unconfirmed')))
      OR (erased_at IS NOT NULL AND route_fingerprint IS NULL AND request_digest IS NULL
        AND provider_message_id IS NULL AND state IS NULL AND delivery_failed IS NULL
        AND accepted_at IS NULL AND updated_at IS NULL AND created_epoch IS NULL
        AND event_count=0))
);
CREATE UNIQUE INDEX provider_receipt_known_message
    ON provider_receipt_attempts(account_id,provider,route_fingerprint,provider_message_id)
    WHERE erased_at IS NULL;

CREATE TABLE provider_receipt_events (
    account_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    event_id uuid NOT NULL CHECK (event_id <> '00000000-0000-0000-0000-000000000000'),
    semantic_digest bytea NOT NULL CHECK (octet_length(semantic_digest)=32),
    fact text NOT NULL CHECK (fact IN ('carrier_submitted','delivered','delivery_unconfirmed',
        'sending_failed','delivery_failed','unrecognized')),
    state_version bigint NOT NULL CHECK (state_version > 0),
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,attempt_id,event_id),
    UNIQUE(account_id,attempt_id,state_version),
    FOREIGN KEY(account_id,attempt_id) REFERENCES provider_receipt_attempts(account_id,attempt_id)
);

CREATE FUNCTION provider_receipt_attempt_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.erased_at IS NOT NULL THEN
        RAISE EXCEPTION 'provider receipt identity is erased';
    END IF;
    IF (NEW.account_id,NEW.attempt_id,NEW.provider) IS DISTINCT FROM
       (OLD.account_id,OLD.attempt_id,OLD.provider) OR NEW.state_version <= OLD.state_version THEN
        RAISE EXCEPTION 'provider receipt identity or version conflict';
    END IF;
    IF NEW.erased_at IS NULL THEN
        IF (NEW.route_fingerprint,NEW.request_digest,NEW.provider_message_id,NEW.accepted_at,NEW.created_epoch)
            IS DISTINCT FROM (OLD.route_fingerprint,OLD.request_digest,OLD.provider_message_id,OLD.accepted_at,OLD.created_epoch)
          OR NEW.event_count <> OLD.event_count+1
          OR (OLD.state='delivered' AND NEW.state <> 'delivered')
          OR (OLD.state='failed' AND NEW.state <> 'failed')
          OR (OLD.delivery_failed AND NOT NEW.delivery_failed) THEN
            RAISE EXCEPTION 'provider receipt correlation or outcome conflict';
        END IF;
    ELSIF EXISTS (SELECT FROM provider_receipt_events WHERE account_id=OLD.account_id AND attempt_id=OLD.attempt_id) THEN
        RAISE EXCEPTION 'provider receipt erasure must remove events first';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provider_receipt_attempt_immutable BEFORE UPDATE ON provider_receipt_attempts
    FOR EACH ROW EXECUTE FUNCTION provider_receipt_attempt_immutable();

CREATE FUNCTION provider_receipt_event_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE erased timestamptz;
BEGIN
    IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'provider receipt events are immutable'; END IF;
    SELECT erased_at INTO erased FROM provider_receipt_attempts
        WHERE account_id=NEW.account_id AND attempt_id=NEW.attempt_id FOR UPDATE;
    IF NOT FOUND OR erased IS NOT NULL THEN RAISE EXCEPTION 'provider receipt correlation unavailable'; END IF;
    IF (SELECT count(*) FROM provider_receipt_events
        WHERE account_id=NEW.account_id AND attempt_id=NEW.attempt_id) >=64 THEN
        RAISE EXCEPTION 'provider receipt event capacity';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provider_receipt_event_guard BEFORE INSERT OR UPDATE ON provider_receipt_events
    FOR EACH ROW EXECUTE FUNCTION provider_receipt_event_guard();
