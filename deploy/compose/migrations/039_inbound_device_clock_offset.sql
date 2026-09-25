-- SPDX-License-Identifier: AGPL-3.0-only
-- Measure the phone's clock when it uploads an inbound event, and use it to
-- order a signed START against an owner opt-out hold on the hub's clock.
--
-- Migration 038 releases a hold only for a START observed more than five
-- minutes after the hold, because observed_at is the phone's own clock and
-- inbound accepts it up to five minutes ahead of upload. That margin does not
-- cover a phone whose clock runs further ahead and that uploads late. The
-- phone now also reports its clock at upload (device_sent_at). Against the
-- hub's received_at this gives the phone's offset at upload, and the START's
-- observation time on the hub clock is observed_at minus that offset.
-- Network delay makes the phone look further ahead than it is, which moves
-- the corrected time earlier: the safe direction for a consent hold.
--
-- device_sent_at is unsigned metadata stored only when within a day of the
-- hub clock. Events without it keep the five-minute rule.
ALTER TABLE inbound_events ADD COLUMN device_sent_at timestamptz;

CREATE FUNCTION owner_hold_release_allowed(
    observed_at timestamptz, device_sent_at timestamptz,
    received_at timestamptz, hold_created_at timestamptz
) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN device_sent_at IS NULL THEN
            observed_at > hold_created_at + interval '5 minutes'
        ELSE
            observed_at - (device_sent_at - received_at) > hold_created_at + interval '1 minute'
            AND observed_at - (device_sent_at - received_at) <= received_at + interval '1 minute'
    END
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
        RAISE EXCEPTION 'an owner opt-out hold needs a signed START observed after it on the hub clock'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
