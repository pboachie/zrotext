-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-recorded opt-out holds and durable review decisions.
--
-- recipient_suppressions (031/032) only accepts signed device evidence. A
-- recipient can also withdraw consent off channel, by email or a phone call
-- for example. The owner records that as a separate, account-scoped hold.
-- Admission checks both tables under the same account lock. A hold is released
-- only by verified new consent: a signed START reply from the same recipient
-- observed after the hold was recorded. No owner action lifts a hold or a
-- suppression. No message body or free-text note is stored; every column is
-- an identifier, a timestamp or a bounded code.
CREATE TABLE owner_recipient_holds (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    channel text NOT NULL CHECK (channel IN
        ('email', 'phone_call', 'web_form', 'postal_mail', 'in_person', 'other')),
    reason text NOT NULL CHECK (reason IN
        ('opt_out', 'consent_withdrawn', 'complaint', 'wrong_number')),
    reported_at timestamptz NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at timestamptz,
    release_event_id uuid,
    CHECK (reported_at <= created_at),
    CHECK ((released_at IS NULL) = (release_event_id IS NULL)),
    FOREIGN KEY (account_id, created_by) REFERENCES memberships(account_id, user_id),
    FOREIGN KEY (account_id, release_event_id) REFERENCES inbound_events(account_id, id),
    UNIQUE (account_id, id)
);
CREATE UNIQUE INDEX owner_recipient_holds_one_active
    ON owner_recipient_holds(account_id, recipient_e164) WHERE released_at IS NULL;
CREATE INDEX owner_recipient_holds_listing
    ON owner_recipient_holds(account_id, created_at DESC, id DESC) WHERE released_at IS NULL;

CREATE FUNCTION owner_recipient_hold_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'owner opt-out holds cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.id <> OLD.id OR NEW.account_id <> OLD.account_id
       OR NEW.recipient_e164 <> OLD.recipient_e164 OR NEW.channel <> OLD.channel
       OR NEW.reason <> OLD.reason OR NEW.reported_at <> OLD.reported_at
       OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
       OR OLD.released_at IS NOT NULL THEN
        RAISE EXCEPTION 'owner opt-out hold identity or release cannot change'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.released_at IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM inbound_events e
        JOIN messages m ON m.account_id = e.account_id AND m.id = e.message_id
        WHERE e.account_id = NEW.account_id AND e.id = NEW.release_event_id
          AND e.classification = 'opt_in'
          AND m.recipient_e164 = NEW.recipient_e164
          AND e.observed_at > OLD.created_at
    ) THEN
        RAISE EXCEPTION 'an owner opt-out hold needs a later signed START from the recipient'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER owner_recipient_holds_before_update_or_delete
    BEFORE UPDATE OR DELETE ON owner_recipient_holds
    FOR EACH ROW EXECUTE FUNCTION owner_recipient_hold_guard();

-- One immutable owner decision per review-queue item. The item is the signed
-- event behind an active sms_review or sms_unsolicited_review suppression. A
-- decision never changes the suppression, so a signed STOP stays in force.
CREATE TABLE owner_opt_out_review_decisions (
    account_id uuid NOT NULL REFERENCES accounts(id),
    review_event_id uuid NOT NULL,
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    decision text NOT NULL CHECK (decision IN ('confirmed_opt_out', 'not_opt_out')),
    decided_by uuid NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, review_event_id),
    FOREIGN KEY (account_id, decided_by) REFERENCES memberships(account_id, user_id)
);

CREATE FUNCTION owner_opt_out_review_decision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'owner opt-out review decisions are immutable' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM recipient_suppressions s
        WHERE s.account_id = NEW.account_id AND s.recipient_e164 = NEW.recipient_e164
          AND s.source IN ('sms_review', 'sms_unsolicited_review')
          AND COALESCE(s.source_event_id, s.source_unsolicited_event_id) = NEW.review_event_id
    ) THEN
        RAISE EXCEPTION 'only an SMS withdrawal review item can receive an owner decision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER owner_opt_out_review_decisions_guard
    BEFORE INSERT OR UPDATE OR DELETE ON owner_opt_out_review_decisions
    FOR EACH ROW EXECUTE FUNCTION owner_opt_out_review_decision_guard();

CREATE TABLE owner_opt_out_audit (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    event text NOT NULL CHECK (event IN
        ('hold_created', 'hold_released', 'review_confirmed', 'review_dismissed')),
    actor_user_id uuid,
    actor_session_id uuid REFERENCES sessions(id),
    hold_id uuid,
    review_event_id uuid,
    release_event_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((event = 'hold_released') = (actor_user_id IS NULL)),
    CHECK ((actor_user_id IS NULL) = (actor_session_id IS NULL)),
    CHECK ((event IN ('hold_created', 'hold_released')) = (hold_id IS NOT NULL)),
    CHECK ((event IN ('review_confirmed', 'review_dismissed')) = (review_event_id IS NOT NULL)),
    CHECK ((event = 'hold_released') = (release_event_id IS NOT NULL)),
    FOREIGN KEY (account_id, actor_user_id) REFERENCES memberships(account_id, user_id),
    FOREIGN KEY (account_id, hold_id) REFERENCES owner_recipient_holds(account_id, id),
    FOREIGN KEY (account_id, release_event_id) REFERENCES inbound_events(account_id, id)
);
CREATE INDEX owner_opt_out_audit_timeline ON owner_opt_out_audit(account_id, created_at, id);

CREATE FUNCTION owner_opt_out_audit_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'owner opt-out audit is append-only' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER owner_opt_out_audit_before_update_or_delete
    BEFORE UPDATE OR DELETE ON owner_opt_out_audit
    FOR EACH ROW EXECUTE FUNCTION owner_opt_out_audit_immutable();
