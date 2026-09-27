-- SPDX-License-Identifier: AGPL-3.0-only
-- Role support is a prerequisite only: invitation and observer routes are not
-- enabled by this migration. Existing owner authentication remains owner-only.
ALTER TABLE memberships DROP CONSTRAINT memberships_account_id_key;
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'observer'));
ALTER TABLE memberships ADD COLUMN revoked_at timestamptz;
ALTER TABLE memberships ADD CONSTRAINT memberships_owner_not_revoked
    CHECK (role <> 'owner' OR revoked_at IS NULL);
CREATE UNIQUE INDEX memberships_one_owner ON memberships(account_id) WHERE role = 'owner';

-- A seat cannot be promoted, moved to another account, or silently restored.
-- DELETE remains available for account/user cascades and pending-user pruning.
CREATE FUNCTION membership_identity_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.account_id, NEW.user_id, NEW.role, NEW.created_at)
       IS DISTINCT FROM (OLD.account_id, OLD.user_id, OLD.role, OLD.created_at) THEN
        RAISE EXCEPTION 'membership identity and role are immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'membership revocation is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER memberships_identity_before_update BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION membership_identity_guard();
