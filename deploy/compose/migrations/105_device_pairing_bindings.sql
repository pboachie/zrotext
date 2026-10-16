-- SPDX-License-Identifier: AGPL-3.0-only
-- Public recovery locator, never a bearer credential. The phone must prove
-- possession of the current enrolled key before reading its binding.
ALTER TABLE device_keys ADD COLUMN source_pairing_id uuid UNIQUE;
UPDATE device_keys k SET source_pairing_id=p.id FROM pairing_requests p
WHERE p.device_id=k.device_id AND p.account_id=k.account_id AND p.approved_at IS NOT NULL;
CREATE FUNCTION device_pairing_binding_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.source_pairing_id IS DISTINCT FROM OLD.source_pairing_id THEN
        RAISE EXCEPTION 'device pairing locator is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER device_pairing_binding_before_update BEFORE UPDATE ON device_keys
FOR EACH ROW EXECUTE FUNCTION device_pairing_binding_guard();
