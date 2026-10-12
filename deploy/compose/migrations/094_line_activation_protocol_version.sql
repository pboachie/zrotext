-- SPDX-License-Identifier: AGPL-3.0-only
-- Bind each line challenge to its original transcript version. Existing rows
-- and all current issuers remain v1. Version 2 encoding alone does not admit
-- activation: its authenticated runtime and client negotiation are unavailable.
ALTER TABLE line_activation_challenges
    ADD COLUMN protocol_version smallint NOT NULL DEFAULT 1
    CONSTRAINT line_activation_challenges_protocol_version
    CHECK (protocol_version IN (1, 2));

-- Keep the identity/nonce/expiry/consumption guard from 019 unchanged. A second
-- guard makes protocol selection write-once, including before consumption.
CREATE FUNCTION line_activation_challenge_protocol_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.protocol_version IS DISTINCT FROM OLD.protocol_version THEN
        RAISE EXCEPTION 'line activation challenge protocol version cannot change'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER line_activation_challenge_protocol_before_update
    BEFORE UPDATE ON line_activation_challenges
    FOR EACH ROW EXECUTE FUNCTION line_activation_challenge_protocol_guard();
