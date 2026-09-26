-- SPDX-License-Identifier: AGPL-3.0-only
-- Use the phone's clock at upload to catch a START a fast phone uploads late.
--
-- Migration 038 releases an owner opt-out hold only for a START observed more
-- than five minutes after it, because observed_at is the phone's own clock and
-- inbound accepts it up to five minutes ahead of upload. A phone whose clock
-- runs further ahead and that uploads late can still pass that margin. The
-- phone now also reports its clock when it sends the event (device_sent_at).
-- Against the hub's received_at this estimates the phone's offset at upload.
--
-- The reading can only tighten the rule. The five-minute margin on the raw
-- observation always applies; with a reading, the observation corrected by
-- that offset must also be more than one minute after the hold. The offset is
-- measured at upload, not at observation, so it does not see a clock step in
-- between, and network or queue delay makes the corrected time later than the
-- true one. Neither can loosen the five-minute floor.
--
-- device_sent_at is unsigned metadata, stored only when within a day of the
-- hub clock. The arithmetic uses epoch seconds so the result does not depend
-- on the session time zone.
ALTER TABLE inbound_events ADD COLUMN device_sent_at timestamptz;

CREATE FUNCTION owner_hold_release_allowed(
    observed_at timestamptz, device_sent_at timestamptz,
    received_at timestamptz, hold_created_at timestamptz
) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT extract(epoch FROM observed_at) > extract(epoch FROM hold_created_at) + 300
       AND (device_sent_at IS NULL
            OR extract(epoch FROM observed_at)
               - (extract(epoch FROM device_sent_at) - extract(epoch FROM received_at))
               > extract(epoch FROM hold_created_at) + 60)
$$;

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
          AND owner_hold_release_allowed(e.observed_at, e.device_sent_at, e.received_at, OLD.created_at)
    ) THEN
        RAISE EXCEPTION 'an owner opt-out hold needs a signed START observed more than five minutes after it'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
