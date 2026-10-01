-- SPDX-License-Identifier: AGPL-3.0-only
-- Line-scoped connector registration and key lifecycle (#640).
-- Dormant: no route provisions or consumes these rows; the sealed manifest
-- ceremony remains the only trust root and no implicit reader exists.

-- connector_registrations: pending -> active -> revoked identity bound to one
-- manifest role-3 (integration) record; independent approval session required.
CREATE TABLE connector_registrations (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    connector_id uuid NOT NULL,
    display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 80),
    state text NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    key_point bytea NOT NULL CHECK (octet_length(key_point) = 65),
    key_id bytea NOT NULL CHECK (octet_length(key_id) = 32),
    manifest_generation bigint NOT NULL CHECK (manifest_generation > 0),
    manifest_version bigint NOT NULL CHECK (manifest_version > 0),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    proposed_by_user uuid NOT NULL,
    proposed_session uuid NOT NULL,
    proposed_ms bigint NOT NULL CHECK (proposed_ms > 0),
    expires_ms bigint NOT NULL CHECK (expires_ms > 0),
    approved_by_user uuid,
    approved_session uuid,
    approved_ms bigint,
    revoked_ms bigint,
    revoked_by_user uuid,
    revocation_reason text
        CHECK (revocation_reason IS NULL OR octet_length(revocation_reason) BETWEEN 1 AND 200),
    PRIMARY KEY (account_id, connector_id),
    UNIQUE (account_id, key_id),
    CHECK (expires_ms > proposed_ms AND expires_ms - proposed_ms <= 90::bigint*24*3600*1000),
    CHECK (
        (state = 'pending' AND approved_by_user IS NULL AND approved_session IS NULL
            AND approved_ms IS NULL AND revoked_ms IS NULL AND revoked_by_user IS NULL)
        OR (state = 'active' AND approved_by_user IS NOT NULL AND approved_session IS NOT NULL
            AND approved_ms IS NOT NULL AND approved_ms >= proposed_ms
            AND approved_session <> proposed_session
            AND revoked_ms IS NULL AND revoked_by_user IS NULL)
        OR (state = 'revoked' AND revoked_ms IS NOT NULL AND revoked_by_user IS NOT NULL
            AND (approved_session IS NULL OR approved_session <> proposed_session))
    )
);

-- A registration's proposal facts and manifest binding are immutable; only
-- state transitions (pending->active->revoked), one-time approval/revocation
-- stamps and key rotation (key_point/key_id) may change a row.
CREATE FUNCTION connector_registration_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.account_id<>OLD.account_id OR NEW.connector_id<>OLD.connector_id
       OR NEW.display_name<>OLD.display_name
       OR NEW.proposed_by_user<>OLD.proposed_by_user
       OR NEW.proposed_session<>OLD.proposed_session
       OR NEW.proposed_ms<>OLD.proposed_ms OR NEW.expires_ms<>OLD.expires_ms
       OR NEW.manifest_generation<>OLD.manifest_generation
       OR NEW.manifest_version<>OLD.manifest_version
       OR NEW.manifest_digest<>OLD.manifest_digest
       OR (OLD.approved_ms IS NOT NULL AND (NEW.approved_ms,NEW.approved_by_user,NEW.approved_session)
             IS DISTINCT FROM (OLD.approved_ms,OLD.approved_by_user,OLD.approved_session))
       OR (OLD.revoked_ms IS NOT NULL AND (NEW.revoked_ms,NEW.revoked_by_user,NEW.revocation_reason)
             IS DISTINCT FROM (OLD.revoked_ms,OLD.revoked_by_user,OLD.revocation_reason))
       OR (OLD.state='active' AND NEW.state<>'active' AND NEW.state<>'revoked')
       OR (OLD.state='revoked' AND NEW.state<>'revoked')
       OR (OLD.state='pending' AND NEW.state='pending'
             AND (NEW.approved_ms IS NOT NULL OR NEW.revoked_ms IS NOT NULL)) THEN
        RAISE EXCEPTION 'connector registration proposal, binding or history cannot change'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER connector_registration_before_update
    BEFORE UPDATE ON connector_registrations
    FOR EACH ROW EXECUTE FUNCTION connector_registration_guard();

-- Connector public-key history: rotation retires one row and appends the next;
-- a key point is never reused by another connector (or an aliased identity).
CREATE TABLE connector_keys (
    account_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    key_id bytea NOT NULL CHECK (octet_length(key_id) = 32),
    key_point bytea NOT NULL CHECK (octet_length(key_point) = 65),
    valid_from_ms bigint NOT NULL CHECK (valid_from_ms > 0),
    valid_until_ms bigint NOT NULL CHECK (valid_until_ms > valid_from_ms),
    -- Retirement is a marker timestamp; hosts may step the wall clock
    -- backwards, so it is not ordered against valid_from_ms.
    retired_ms bigint CHECK (retired_ms IS NULL OR retired_ms > 0),
    PRIMARY KEY (account_id, connector_id, key_id),
    UNIQUE (account_id, key_point),
    FOREIGN KEY (account_id, connector_id)
        REFERENCES connector_registrations(account_id, connector_id) ON DELETE CASCADE
);

-- Separate read/decrypt and send/sign grants, each line-scoped and bounded.
-- read_directions mirrors the manifest role-3 scope bits (4 outbound read,
-- 8 inbound read, 12 both); conversation_restriction optionally narrows reads
-- to explicit opaque conversation ids.
CREATE TABLE connector_grants (
    account_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('read', 'send')),
    read_directions smallint NOT NULL CHECK (read_directions IN (0, 4, 8, 12)),
    line_id uuid NOT NULL,
    conversation_restriction uuid[] NOT NULL DEFAULT '{}',
    created_by_user uuid NOT NULL,
    created_ms bigint NOT NULL CHECK (created_ms > 0),
    expires_ms bigint NOT NULL
        CHECK (expires_ms > created_ms AND expires_ms - created_ms <= 90::bigint*24*3600*1000),
    revoked_ms bigint,
    revoked_by_user uuid,
    PRIMARY KEY (account_id, connector_id, grant_id),
    FOREIGN KEY (account_id, connector_id)
        REFERENCES connector_registrations(account_id, connector_id) ON DELETE CASCADE,
    CHECK ((kind = 'send' AND read_directions = 0)
        OR (kind = 'read' AND read_directions <> 0))
);

-- Append-only audit trail for grant lifecycle and authorization decisions.
-- Stores identifiers, outcomes and timestamps only: never private key
-- material, never message content, never plaintext. Rows are never rewritten;
-- DELETE stays open so explicit owner erasure and account erasure can remove
-- access records (UPDATE and TRUNCATE remain fenced below).
CREATE TABLE connector_audit_events (
    account_id uuid NOT NULL,
    event_id bigint GENERATED ALWAYS AS IDENTITY,
    connector_id uuid NOT NULL,
    grant_id uuid,
    action text NOT NULL CHECK (action IN (
        'proposed', 'approved', 'rejected', 'rotated', 'revoked',
        'reader_wrap_authorized', 'reader_wrap_denied',
        'send_authorized', 'send_denied',
        'exported', 'erased')),
    actor_user uuid,
    outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied', 'recorded')),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 120),
    recorded_ms bigint NOT NULL CHECK (recorded_ms > 0),
    PRIMARY KEY (account_id, event_id),
    FOREIGN KEY (account_id, connector_id)
        REFERENCES connector_registrations(account_id, connector_id) ON DELETE CASCADE
);
CREATE INDEX connector_audit_events_recent
    ON connector_audit_events(account_id, recorded_ms DESC, event_id DESC);

-- Grant lifecycle must not roll back or rewrite history once recorded.
CREATE FUNCTION connector_grant_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.account_id <> OLD.account_id OR NEW.connector_id <> OLD.connector_id
        OR NEW.grant_id <> OLD.grant_id OR NEW.kind <> OLD.kind
        OR NEW.line_id <> OLD.line_id
        OR NEW.read_directions <> OLD.read_directions
        OR NEW.conversation_restriction <> OLD.conversation_restriction
        OR NEW.created_by_user <> OLD.created_by_user
        OR NEW.created_ms <> OLD.created_ms OR NEW.expires_ms <> OLD.expires_ms
        OR (OLD.revoked_ms IS NOT NULL
            AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
        RAISE EXCEPTION 'connector grant scope or history cannot change'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER connector_grant_before_update
    BEFORE UPDATE ON connector_grants
    FOR EACH ROW EXECUTE FUNCTION connector_grant_guard();

CREATE FUNCTION connector_audit_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'connector audit events are append-only'
        USING ERRCODE = '23514';
END;
$$;
-- UPDATE and TRUNCATE are fenced; DELETE is allowed for explicit access-record
-- erasure and the account-erasure cascade.
CREATE TRIGGER connector_audit_before_update
    BEFORE UPDATE ON connector_audit_events
    FOR EACH ROW EXECUTE FUNCTION connector_audit_immutable();
CREATE TRIGGER connector_audit_before_truncate
    BEFORE TRUNCATE ON connector_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION connector_audit_immutable();
