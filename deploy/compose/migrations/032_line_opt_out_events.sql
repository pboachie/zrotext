-- SPDX-License-Identifier: AGPL-3.0-only
-- Internal, signed, line-bound unsolicited STOP/review prerequisite. There is
-- no device-stream frame for this table. It records no SMS body and does not
-- allow an unsolicited START to clear suppression.
CREATE TABLE line_opt_out_events (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation > 0),
    device_sequence bigint NOT NULL CHECK (device_sequence > 0),
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    classification text NOT NULL CHECK (classification IN ('opt_out', 'opt_out_review')),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
    signature_der bytea NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    FOREIGN KEY (account_id, line_id, device_id, binding_generation)
        REFERENCES device_line_bindings(account_id, line_id, device_id, generation),
    UNIQUE (account_id, recipient_e164, id),
    UNIQUE (device_id, device_sequence)
);
CREATE INDEX line_opt_out_events_timeline
    ON line_opt_out_events(account_id, line_id, received_at, id);

-- The same database line guard used by sealed inbound prevents an accidental
-- internal insert after line revocation or rebinding.
CREATE TRIGGER line_opt_out_active_line_before_insert
    BEFORE INSERT ON line_opt_out_events
    FOR EACH ROW EXECUTE FUNCTION sealed_inbound_require_active_line();
CREATE TRIGGER line_opt_out_before_update
    BEFORE UPDATE ON line_opt_out_events
    FOR EACH ROW EXECUTE FUNCTION sealed_inbound_forbid_update();

ALTER TABLE recipient_suppressions
    ALTER COLUMN source_event_id DROP NOT NULL,
    ALTER COLUMN source_attempt_id DROP NOT NULL,
    ADD COLUMN source_unsolicited_event_id uuid;
ALTER TABLE recipient_suppressions
    ADD CONSTRAINT recipient_suppressions_unsolicited_source
    FOREIGN KEY (account_id, recipient_e164, source_unsolicited_event_id)
    REFERENCES line_opt_out_events(account_id, recipient_e164, id);
ALTER TABLE recipient_suppressions DROP CONSTRAINT recipient_suppressions_source_check;
ALTER TABLE recipient_suppressions ADD CONSTRAINT recipient_suppressions_source_check
    CHECK (source IN ('sms_keyword', 'sms_review', 'sms_resume',
                     'sms_unsolicited_keyword', 'sms_unsolicited_review'));
ALTER TABLE recipient_suppressions ADD CONSTRAINT recipient_suppressions_source_shape
    CHECK ((source IN ('sms_keyword', 'sms_review', 'sms_resume')
            AND source_event_id IS NOT NULL AND source_attempt_id IS NOT NULL
            AND source_unsolicited_event_id IS NULL)
        OR (source IN ('sms_unsolicited_keyword', 'sms_unsolicited_review')
            AND source_event_id IS NULL AND source_attempt_id IS NULL
            AND source_unsolicited_event_id IS NOT NULL AND active));

-- A legacy attempt-bound STOP may follow an unsolicited STOP. Keep the
-- attempt-free block as the authoritative source so a later attempt-bound
-- START cannot clear it. The newer signed event remains in inbound_events.
CREATE FUNCTION preserve_unsolicited_suppression() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.active AND OLD.source IN
       ('sms_unsolicited_keyword', 'sms_unsolicited_review')
       AND NEW.source IN ('sms_keyword', 'sms_review', 'sms_resume') THEN
        NEW.active := OLD.active;
        NEW.source_event_id := OLD.source_event_id;
        NEW.source_attempt_id := OLD.source_attempt_id;
        NEW.source_unsolicited_event_id := OLD.source_unsolicited_event_id;
        NEW.source_observed_at := OLD.source_observed_at;
        NEW.source := OLD.source;
        NEW.changed_at := OLD.changed_at;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recipient_suppressions_preserve_unsolicited
    BEFORE UPDATE ON recipient_suppressions
    FOR EACH ROW EXECUTE FUNCTION preserve_unsolicited_suppression();
