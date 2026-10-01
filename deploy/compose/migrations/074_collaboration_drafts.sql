-- SPDX-License-Identifier: AGPL-3.0-only
-- Selected ciphertext-only collaboration projection, independent of agent
-- permissions and the existing owner/observer membership role.
CREATE TABLE collaboration_draft_grants (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK (role='encrypted_drafter'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    FOREIGN KEY (account_id,user_id) REFERENCES memberships(account_id,user_id) ON DELETE CASCADE,
    UNIQUE (account_id,user_id,id)
);
CREATE UNIQUE INDEX collaboration_draft_grants_live
    ON collaboration_draft_grants(account_id,user_id) WHERE revoked_at IS NULL;
CREATE INDEX collaboration_draft_grants_account ON collaboration_draft_grants(account_id,id);

CREATE TABLE collaboration_drafts (
    id uuid NOT NULL,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    ciphertext bytea,
    ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    PRIMARY KEY (account_id,user_id,id),
    FOREIGN KEY (account_id,user_id,grant_id)
        REFERENCES collaboration_draft_grants(account_id,user_id,id) ON DELETE CASCADE,
    CHECK ((ciphertext IS NULL)=(deleted_at IS NOT NULL)),
    CHECK (ciphertext IS NULL OR octet_length(ciphertext) BETWEEN 28 AND 8192)
);
CREATE INDEX collaboration_drafts_grant ON collaboration_drafts(account_id,user_id,grant_id,id);
CREATE INDEX collaboration_drafts_export ON collaboration_drafts(account_id,id);

CREATE FUNCTION collaboration_grant_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.id,NEW.account_id,NEW.user_id,NEW.role,NEW.created_at)
       IS DISTINCT FROM (OLD.id,OLD.account_id,OLD.user_id,OLD.role,OLD.created_at)
       OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'collaboration grant identity and revocation are immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER collaboration_grant_identity_before_update
    BEFORE UPDATE ON collaboration_draft_grants FOR EACH ROW
    EXECUTE FUNCTION collaboration_grant_identity_guard();

CREATE FUNCTION collaboration_draft_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.id,NEW.account_id,NEW.user_id,NEW.grant_id,NEW.ciphertext_digest,NEW.created_at)
       IS DISTINCT FROM (OLD.id,OLD.account_id,OLD.user_id,OLD.grant_id,OLD.ciphertext_digest,OLD.created_at)
       OR (NEW.ciphertext IS NOT NULL AND NEW.ciphertext IS DISTINCT FROM OLD.ciphertext)
       OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
        RAISE EXCEPTION 'collaboration draft identity, bytes and deletion are immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER collaboration_draft_identity_before_update
    BEFORE UPDATE ON collaboration_drafts FOR EACH ROW
    EXECUTE FUNCTION collaboration_draft_identity_guard();
