-- SPDX-License-Identifier: AGPL-3.0-only
-- Keep an SMS-only owner approval distinct from the future sealed trust root.
-- Existing bindings retain the sealed scope. No live enrollment route is
-- enabled by this migration.

ALTER TABLE device_line_bindings ADD COLUMN purpose text NOT NULL DEFAULT 'sealed'
    CHECK (purpose IN ('sealed', 'sms'));

CREATE FUNCTION line_binding_purpose_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.purpose IS DISTINCT FROM OLD.purpose THEN
        RAISE EXCEPTION 'line binding purpose cannot change'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER device_line_binding_purpose_before_update
    BEFORE UPDATE ON device_line_bindings
    FOR EACH ROW EXECUTE FUNCTION line_binding_purpose_guard();

-- Once a line has reached sealed scope, a later generation cannot silently
-- downgrade it to SMS-only. The line lock serializes this even for an internal
-- writer that bypasses the application transaction.
CREATE FUNCTION line_binding_scope_monotonic_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.purpose='sms' AND NEW.state='active' THEN
        PERFORM 1 FROM phone_lines
          WHERE account_id=NEW.account_id AND id=NEW.line_id FOR UPDATE;
        IF EXISTS (
            SELECT 1 FROM device_line_bindings b
             WHERE b.account_id=NEW.account_id AND b.line_id=NEW.line_id
               AND b.purpose='sealed' AND b.activated_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'sealed line scope cannot downgrade to SMS'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER device_line_binding_scope_before_insert_or_update
    BEFORE INSERT OR UPDATE ON device_line_bindings
    FOR EACH ROW EXECUTE FUNCTION line_binding_scope_monotonic_guard();

-- A key in this table is only an SMS line-approval key. A separate MFA-bound
-- provisioning ceremony must exist before any production use.
CREATE TABLE sms_line_owner_approval_keys (
    account_id uuid NOT NULL REFERENCES accounts(id),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    signing_key_sec1 bytea NOT NULL CHECK (octet_length(signing_key_sec1) = 65),
    installed_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (account_id, fingerprint)
);
CREATE UNIQUE INDEX sms_line_owner_approval_keys_one_active
    ON sms_line_owner_approval_keys(account_id) WHERE revoked_at IS NULL;
CREATE TRIGGER sms_line_owner_key_before_update
    BEFORE UPDATE ON sms_line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION line_owner_key_guard();
CREATE TRIGGER sms_line_owner_key_before_delete
    BEFORE DELETE ON sms_line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION line_owner_key_guard();

-- Even an accidental direct writer must not store a sealed envelope under an
-- SMS-only binding. Replace only the trigger function introduced in 018.
CREATE OR REPLACE FUNCTION sealed_inbound_require_active_line() RETURNS trigger
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
        AND b.state='active' AND b.purpose='sealed'
        AND d.revoked_at IS NULL AND a.disabled_at IS NULL
      FOR SHARE OF l,b,d,a;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'sealed inbound line binding is not active'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- A sealed activation includes a line/device proof strong enough for the
-- SMS-only STOP channel. An SMS-only activation never authorizes sealed data.
CREATE FUNCTION sms_line_opt_out_require_active_line() RETURNS trigger
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
        AND b.state='active' AND b.purpose IN ('sms','sealed')
        AND d.revoked_at IS NULL AND a.disabled_at IS NULL
      FOR SHARE OF l,b,d,a;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SMS line binding is not active'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER line_opt_out_active_line_before_insert ON line_opt_out_events;
CREATE TRIGGER line_opt_out_active_line_before_insert
    BEFORE INSERT ON line_opt_out_events
    FOR EACH ROW EXECUTE FUNCTION sms_line_opt_out_require_active_line();
