-- SPDX-License-Identifier: AGPL-3.0-only
-- Protocol implementation admission belongs to the authenticated claimed epoch.
-- It does not certify a subscription observation or an installed line.
ALTER TABLE device_sessions
    ADD COLUMN line_activation_version smallint NOT NULL DEFAULT 1
    CONSTRAINT device_sessions_line_activation_version CHECK (line_activation_version IN (1, 2));

CREATE FUNCTION device_session_line_activation_version_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.line_activation_version IS DISTINCT FROM OLD.line_activation_version
       AND NEW.connection_epoch <= OLD.connection_epoch THEN
        RAISE EXCEPTION 'line protocol admission requires a newly claimed epoch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER device_session_line_activation_version_before_update
    BEFORE UPDATE ON device_sessions
    FOR EACH ROW EXECUTE FUNCTION device_session_line_activation_version_guard();
