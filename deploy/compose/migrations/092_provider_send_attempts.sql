-- SPDX-License-Identifier: AGPL-3.0-only
-- Durable default-off provider submit intent. No sender, route enablement,
-- provider account or receipt caller is created here. Rows store linkage
-- digests only: no body, recipient plaintext, credential or callback bytes.
CREATE TABLE provider_send_attempts (
    account_id uuid NOT NULL REFERENCES accounts(id),
    attempt_id uuid NOT NULL CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    provider text NOT NULL CHECK (provider = 'telnyx_sms_v2'),
    route_fingerprint bytea,
    request_digest bytea,
    recipient_hash bytea,
    action_id uuid,
    action_revision bigint,
    action_binding_digest bytea,
    reservation_id uuid,
    provider_message_id uuid,
    state text,
    lease_id uuid,
    lease_until_ms bigint,
    created_epoch bigint,
    intended_at timestamptz,
    dispatched_at timestamptz,
    resolved_at timestamptz,
    updated_at timestamptz,
    erased_at timestamptz,
    PRIMARY KEY (account_id, attempt_id),
    CHECK ((erased_at IS NULL
            AND route_fingerprint IS NOT NULL AND octet_length(route_fingerprint)=32
            AND request_digest IS NOT NULL AND octet_length(request_digest)=32
            AND recipient_hash IS NOT NULL AND octet_length(recipient_hash)=32
            AND action_id IS NOT NULL AND action_id <> '00000000-0000-0000-0000-000000000000'
            AND action_revision BETWEEN 1 AND 128
            AND action_binding_digest IS NOT NULL AND octet_length(action_binding_digest)=32
            AND reservation_id IS NOT NULL
            AND created_epoch > 0
            AND intended_at IS NOT NULL AND updated_at IS NOT NULL
            AND state IN ('intended','dispatching','accepted','unknown','released')
            AND (lease_id IS NULL) = (lease_until_ms IS NULL)
            AND (state <> 'dispatching' OR lease_id IS NOT NULL)
            AND (state <> 'intended' OR lease_id IS NULL)
            AND ((state = 'intended' AND dispatched_at IS NULL
                  AND resolved_at IS NULL AND provider_message_id IS NULL)
                 OR (state = 'dispatching' AND dispatched_at IS NOT NULL
                     AND resolved_at IS NULL AND provider_message_id IS NULL)
                 OR (state = 'accepted' AND provider_message_id IS NOT NULL
                     AND provider_message_id <> '00000000-0000-0000-0000-000000000000'
                     AND resolved_at IS NOT NULL)
                 OR (state = 'unknown' AND provider_message_id IS NULL
                     AND resolved_at IS NOT NULL)
                 OR (state = 'released' AND provider_message_id IS NULL
                     AND resolved_at IS NOT NULL)))
          OR (erased_at IS NOT NULL
            AND route_fingerprint IS NULL AND request_digest IS NULL
            AND recipient_hash IS NULL
            AND action_id IS NOT NULL AND action_id <> '00000000-0000-0000-0000-000000000000'
            AND action_revision BETWEEN 1 AND 128
            AND action_binding_digest IS NOT NULL AND octet_length(action_binding_digest)=32
            AND reservation_id IS NULL AND provider_message_id IS NULL
            AND state IS NULL AND lease_id IS NULL AND lease_until_ms IS NULL
            AND created_epoch IS NULL AND intended_at IS NULL
            AND dispatched_at IS NULL AND resolved_at IS NULL
            AND updated_at IS NULL)),
    FOREIGN KEY (account_id, reservation_id)
        REFERENCES exposure_reservations(account_id, id)
);
-- Admission idempotency: one durable attempt per exact approved action
-- revision. The fence includes erased rows, so erasure never permits a
-- resend of the same approved commitment.
CREATE UNIQUE INDEX provider_send_attempt_action
    ON provider_send_attempts(account_id, action_id, action_revision);
-- One provider message identity may bind at most one attempt per route.
CREATE UNIQUE INDEX provider_send_attempt_message
    ON provider_send_attempts(account_id, provider, route_fingerprint, provider_message_id)
    WHERE erased_at IS NULL AND provider_message_id IS NOT NULL;
CREATE INDEX provider_send_attempt_dispatch
    ON provider_send_attempts(account_id, state, intended_at)
    WHERE erased_at IS NULL AND state = 'intended';

CREATE FUNCTION provider_send_attempt_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.erased_at IS NOT NULL THEN
        RAISE EXCEPTION 'provider send attempt identity is erased';
    END IF;
    IF (NEW.account_id,NEW.attempt_id,NEW.provider) IS DISTINCT FROM
       (OLD.account_id,OLD.attempt_id,OLD.provider) THEN
        RAISE EXCEPTION 'provider send attempt identity cannot change';
    END IF;
    IF NEW.erased_at IS NOT NULL THEN
        -- A live lease may still release transport; a crashed worker's stale
        -- lease may not block account erasure forever.
        IF OLD.state='dispatching' AND (OLD.lease_until_ms IS NULL
             OR OLD.lease_until_ms >= (extract(epoch FROM clock_timestamp())*1000)::bigint) THEN
            RAISE EXCEPTION 'an in-flight attempt cannot be erased';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.route_fingerprint,NEW.request_digest,NEW.recipient_hash,NEW.action_id,
        NEW.action_revision,NEW.action_binding_digest,NEW.reservation_id,
        NEW.created_epoch,NEW.intended_at) IS DISTINCT FROM
       (OLD.route_fingerprint,OLD.request_digest,OLD.recipient_hash,OLD.action_id,
        OLD.action_revision,OLD.action_binding_digest,OLD.reservation_id,
        OLD.created_epoch,OLD.intended_at) THEN
        RAISE EXCEPTION 'provider send attempt commitment is immutable';
    END IF;
    IF OLD.lease_id IS NOT NULL AND
       (NEW.lease_id,NEW.lease_until_ms) IS DISTINCT FROM (OLD.lease_id,OLD.lease_until_ms) THEN
        RAISE EXCEPTION 'provider send attempt lease cannot be replaced';
    END IF;
    IF OLD.lease_id IS NULL AND NEW.lease_id IS NOT NULL AND
       NOT (OLD.state='intended' AND NEW.state='dispatching'
            AND NEW.dispatched_at IS NOT NULL) THEN
        RAISE EXCEPTION 'a lease requires an intended attempt moving to dispatching';
    END IF;
    IF OLD.provider_message_id IS NOT NULL AND
       NEW.provider_message_id IS DISTINCT FROM OLD.provider_message_id THEN
        RAISE EXCEPTION 'provider message binding is immutable';
    END IF;
    IF OLD.resolved_at IS NOT NULL AND
       NEW.resolved_at IS DISTINCT FROM OLD.resolved_at THEN
        RAISE EXCEPTION 'provider send resolution is immutable';
    END IF;
    IF NOT (
        (OLD.state=NEW.state)
        OR (OLD.state='intended' AND NEW.state IN ('dispatching','released'))
        OR (OLD.state='dispatching' AND NEW.state IN ('accepted','unknown','released'))
        OR (OLD.state='unknown' AND NEW.state='accepted')
    ) THEN
        RAISE EXCEPTION 'provider send attempt cannot resume or resend';
    END IF;
    IF NEW.state='accepted' AND NEW.provider_message_id IS NULL THEN
        RAISE EXCEPTION 'acceptance requires a provider message binding';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provider_send_attempt_immutable BEFORE UPDATE ON provider_send_attempts
    FOR EACH ROW EXECUTE FUNCTION provider_send_attempt_immutable();
