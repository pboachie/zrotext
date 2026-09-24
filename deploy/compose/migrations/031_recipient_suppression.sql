-- SPDX-License-Identifier: AGPL-3.0-only
-- Account-scoped suppression from authenticated M1 reply events. The public
-- send route remains absent; this table is enforced by the writer as well.
ALTER TABLE inbound_events DROP CONSTRAINT inbound_events_classification_check;
ALTER TABLE inbound_events ADD CONSTRAINT inbound_events_classification_check
    CHECK (classification IN ('captured_local', 'sim_unverified', 'send_unverified',
        'encryption_unverified', 'opt_out', 'opt_out_review', 'opt_in'));
CREATE TABLE recipient_suppressions (
    account_id uuid NOT NULL REFERENCES accounts(id),
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    active boolean NOT NULL DEFAULT true,
    source_event_id uuid NOT NULL,
    source_attempt_id uuid NOT NULL REFERENCES message_attempts(id),
    source_observed_at timestamptz NOT NULL,
    source text NOT NULL CHECK (source IN ('sms_keyword', 'sms_review', 'sms_resume')),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, recipient_e164),
    FOREIGN KEY (account_id, source_event_id) REFERENCES inbound_events(account_id, id)
);
CREATE INDEX recipient_suppressions_active ON recipient_suppressions(account_id, recipient_e164)
    WHERE active;
