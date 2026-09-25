-- SPDX-License-Identifier: AGPL-3.0-only
-- Close two gaps in the owner opt-out holds from migration 036.
--
-- 1. A signed START releases a hold only when the phone observed it more than
--    five minutes after the hold was recorded. Inbound accepts observed_at up
--    to five minutes in the future (MAX_FUTURE_MS in the server's inbound
--    module), so a START sent before a withdrawal on a phone whose clock runs
--    fast could otherwise release the hold and resume sending to a recipient
--    who withdrew consent. A START inside that window leaves the hold in
--    place; a later START releases it.
-- 2. The 036 guard covered UPDATE and DELETE only. A direct INSERT could
--    create a hold that was already released, or backdate created_at so an
--    older START would release it. New holds now start unreleased at the
--    insert time, and a hold_released audit row must match a released hold.
CREATE OR REPLACE FUNCTION owner_recipient_hold_guard() RETURNS trigger
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
          AND e.observed_at > OLD.created_at + interval '5 minutes'
    ) THEN
        RAISE EXCEPTION 'an owner opt-out hold needs a signed START observed more than five minutes after it'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION owner_recipient_hold_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.released_at IS NOT NULL OR NEW.release_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'a new owner opt-out hold cannot start released' USING ERRCODE = '23514';
    END IF;
    IF NEW.created_at > clock_timestamp()
       OR NEW.created_at < clock_timestamp() - interval '1 minute' THEN
        RAISE EXCEPTION 'an owner opt-out hold is recorded at the insert time' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER owner_recipient_holds_before_insert
    BEFORE INSERT ON owner_recipient_holds
    FOR EACH ROW EXECUTE FUNCTION owner_recipient_hold_insert_guard();

CREATE FUNCTION owner_opt_out_audit_release_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.event = 'hold_released' AND NOT EXISTS (
        SELECT 1 FROM owner_recipient_holds h
        WHERE h.account_id = NEW.account_id AND h.id = NEW.hold_id
          AND h.released_at IS NOT NULL AND h.release_event_id = NEW.release_event_id
    ) THEN
        RAISE EXCEPTION 'a hold_released audit row must match a released hold' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER owner_opt_out_audit_before_insert
    BEFORE INSERT ON owner_opt_out_audit
    FOR EACH ROW EXECUTE FUNCTION owner_opt_out_audit_release_guard();
