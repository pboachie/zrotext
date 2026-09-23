-- SPDX-License-Identifier: AGPL-3.0-only
-- M2 identity/storage prerequisite only. There is no sealed-content route,
-- line activation API, or plaintext ingestion path in this migration.
-- A phone line is a stable owner-assigned identity, never an Android
-- subscription ID, SIM slot number, phone number, ICCID, or IMSI.

CREATE TABLE phone_lines (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'revoked')),
    approved_at timestamptz,
    current_binding_generation bigint NOT NULL DEFAULT 0
        CHECK (current_binding_generation >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    CHECK (state <> 'active' OR
        (approved_at IS NOT NULL AND current_binding_generation > 0))
);

-- Rebinding after a SIM move increments generation. Two independent, signed
-- proofs are needed before a future activation path may set state=active:
-- owner approval and device confirmation of its locally selected SIM. Their
-- digests are audit anchors, not evidence that this migration verified them.
CREATE TABLE device_line_bindings (
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'revoked')),
    owner_approval_digest bytea CHECK
        (owner_approval_digest IS NULL OR octet_length(owner_approval_digest) = 32),
    device_confirmation_digest bytea CHECK
        (device_confirmation_digest IS NULL OR octet_length(device_confirmation_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    PRIMARY KEY (account_id, line_id, device_id, generation),
    UNIQUE (account_id, line_id, generation),
    FOREIGN KEY (account_id, line_id) REFERENCES phone_lines(account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id),
    CHECK (state <> 'active' OR
        (owner_approval_digest IS NOT NULL AND device_confirmation_digest IS NOT NULL
         AND activated_at IS NOT NULL))
);
CREATE UNIQUE INDEX device_line_bindings_one_active_device_per_line
    ON device_line_bindings(account_id, line_id) WHERE state='active';

CREATE FUNCTION phone_line_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.account_id <> OLD.account_id OR
       NEW.current_binding_generation < OLD.current_binding_generation OR
       (OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at) OR
       (OLD.state='active' AND NEW.state='pending') OR
       (OLD.state='revoked' AND NEW.state<>'revoked') THEN
        RAISE EXCEPTION 'phone line identity, generation, or revocation cannot roll back'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER phone_line_state_before_update
    BEFORE UPDATE ON phone_lines
    FOR EACH ROW EXECUTE FUNCTION phone_line_state_guard();

CREATE FUNCTION device_line_binding_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.account_id <> OLD.account_id OR NEW.line_id <> OLD.line_id OR
       NEW.device_id <> OLD.device_id OR NEW.generation <> OLD.generation OR
       (OLD.state='revoked' AND NEW.state<>'revoked') OR
       (OLD.state='active' AND NEW.state='pending') OR
       (OLD.owner_approval_digest IS NOT NULL AND
          NEW.owner_approval_digest IS DISTINCT FROM OLD.owner_approval_digest) OR
       (OLD.device_confirmation_digest IS NOT NULL AND
          NEW.device_confirmation_digest IS DISTINCT FROM OLD.device_confirmation_digest) OR
       (OLD.activated_at IS NOT NULL AND
          NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'device line binding identity or revocation cannot roll back'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER device_line_binding_state_before_update
    BEFORE UPDATE ON device_line_bindings
    FOR EACH ROW EXECUTE FUNCTION device_line_binding_state_guard();

-- Keep generation and revocation tombstones even when no event references a
-- binding yet. Deleting then recreating an old generation would bypass the
-- monotonic state guards.
CREATE FUNCTION line_registry_forbid_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'phone line and binding tombstones are immutable'
        USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER phone_line_before_delete
    BEFORE DELETE ON phone_lines
    FOR EACH ROW EXECUTE FUNCTION line_registry_forbid_delete();
CREATE TRIGGER device_line_binding_before_delete
    BEFORE DELETE ON device_line_bindings
    FOR EACH ROW EXECUTE FUNCTION line_registry_forbid_delete();

-- A received SMS has its own event identity. It has no outbound message or
-- attempt FK: M1 inbound_events retains that distinct reply-correlation rule.
-- Only a future, cryptographically verifying sealed ingest may insert here.
CREATE TABLE sealed_inbound_events (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation > 0),
    device_sequence bigint NOT NULL CHECK (device_sequence > 0),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    part_count smallint NOT NULL CHECK (part_count BETWEEN 1 AND 6),
    envelope bytea NOT NULL CHECK (
        octet_length(envelope) BETWEEN 426 AND 34082 AND
        substring(envelope from 1 for 6) = decode('5a5453450102', 'hex')),
    unsigned_digest bytea NOT NULL CHECK (octet_length(unsigned_digest) = 32),
    FOREIGN KEY (account_id, line_id) REFERENCES phone_lines(account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id),
    FOREIGN KEY (account_id, line_id, device_id, binding_generation)
        REFERENCES device_line_bindings(account_id, line_id, device_id, generation),
    UNIQUE (account_id, id),
    UNIQUE (device_id, device_sequence)
);
CREATE INDEX sealed_inbound_events_timeline
    ON sealed_inbound_events(account_id, line_id, received_at, id);

-- Also fail closed for an accidental internal writer that skips the line
-- preflight. Lock both rows so revocation cannot race an insert transaction.
CREATE FUNCTION sealed_inbound_require_active_line() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM phone_lines l
      JOIN device_line_bindings b ON
        (b.account_id,b.line_id)=(l.account_id,l.id)
      JOIN devices d ON (d.account_id,d.id)=(b.account_id,b.device_id)
      JOIN accounts a ON a.id=b.account_id
      WHERE l.account_id=NEW.account_id AND l.id=NEW.line_id
        AND b.device_id=NEW.device_id AND b.generation=NEW.binding_generation
        AND l.state='active' AND l.current_binding_generation=b.generation
        AND b.state='active'
        AND d.revoked_at IS NULL AND a.disabled_at IS NULL
      FOR SHARE OF l,b,d,a;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'sealed inbound line binding is not active'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_inbound_active_line_before_insert
    BEFORE INSERT ON sealed_inbound_events
    FOR EACH ROW EXECUTE FUNCTION sealed_inbound_require_active_line();

-- Future retention may delete an event, but no writer may alter its signed
-- envelope or replay identity after the first insert.
CREATE FUNCTION sealed_inbound_forbid_update() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'sealed inbound event is immutable' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER sealed_inbound_before_update
    BEFORE UPDATE ON sealed_inbound_events
    FOR EACH ROW EXECUTE FUNCTION sealed_inbound_forbid_update();
