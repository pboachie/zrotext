-- SPDX-License-Identifier: AGPL-3.0-only
-- Isolated test schema contract only; not an allocated production migration.
CREATE TABLE hosted_billing_namespaces (
    namespace_id uuid PRIMARY KEY,
    mode text NOT NULL CHECK (mode IN ('test', 'live')),
    provider_account text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    enabled boolean NOT NULL DEFAULT false,
    old_binary_fenced boolean NOT NULL DEFAULT false
);
CREATE FUNCTION hosted_namespace_identity_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_id IS DISTINCT FROM OLD.namespace_id OR
       NEW.mode IS DISTINCT FROM OLD.mode OR
       NEW.provider_account IS DISTINCT FROM OLD.provider_account THEN
        RAISE EXCEPTION 'hosted namespace identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_namespace_identity_immutable
BEFORE UPDATE ON hosted_billing_namespaces
FOR EACH ROW EXECUTE FUNCTION hosted_namespace_identity_immutable();
CREATE TABLE hosted_billing_projections (
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces(namespace_id),
    account_id uuid NOT NULL,
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    dirty_generation bigint NOT NULL CHECK (dirty_generation >= 0),
    processed_generation bigint NOT NULL CHECK (processed_generation >= 0),
    per_read_sequence bigint NOT NULL CHECK (per_read_sequence >= 0),
    payment_hold boolean NOT NULL,
    review_required boolean NOT NULL,
    phase text NOT NULL CHECK (phase IN ('active', 'grace', 'pending', 'restricted', 'terminal')),
    outbound_limit bigint NOT NULL CHECK (outbound_limit >= 0),
    device_limit bigint NOT NULL CHECK (device_limit >= 0),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    valid_until bigint NOT NULL CHECK (valid_until >= 0),
    first_failure_at bigint CHECK (first_failure_at >= 0),
    read_token uuid,
    invoice_id text NOT NULL DEFAULT '',
    price_id text NOT NULL DEFAULT '',
    period_start bigint NOT NULL DEFAULT 0,
    period_end bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace_id, account_id),
    UNIQUE (namespace_id, customer_id),
    UNIQUE (namespace_id, subscription_id),
    CHECK (processed_generation <= dirty_generation),
    CHECK (dirty_generation = per_read_sequence),
    CHECK ((dirty_generation = 0) = (read_token IS NULL)),
    CHECK ((invoice_id='' AND price_id='' AND period_start=0 AND period_end=0) OR
           (invoice_id<>'' AND price_id<>'' AND period_start>=0 AND period_end>period_start)),
    CHECK (phase NOT IN ('active','grace') OR (invoice_id<>'' AND price_id<>'')),
    CHECK (processed_generation > 0 OR
           (phase = 'pending' AND outbound_limit = 0 AND device_limit = 0))
);
CREATE FUNCTION hosted_projection_identity_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_id IS DISTINCT FROM OLD.namespace_id OR
       NEW.account_id IS DISTINCT FROM OLD.account_id OR
       NEW.customer_id IS DISTINCT FROM OLD.customer_id OR
       NEW.subscription_id IS DISTINCT FROM OLD.subscription_id THEN
        RAISE EXCEPTION 'hosted binding identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_projection_identity_immutable
BEFORE UPDATE ON hosted_billing_projections
FOR EACH ROW EXECUTE FUNCTION hosted_projection_identity_immutable();
CREATE FUNCTION hosted_projection_risk_invalidates() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.payment_hold IS DISTINCT FROM OLD.payment_hold OR
       NEW.review_required IS DISTINCT FROM OLD.review_required THEN
        NEW.dirty_generation := OLD.dirty_generation + 1;
        NEW.per_read_sequence := OLD.per_read_sequence + 1;
        NEW.processed_generation := OLD.processed_generation;
        NEW.read_token := gen_random_uuid();
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_projection_risk_invalidates
BEFORE UPDATE ON hosted_billing_projections
FOR EACH ROW EXECUTE FUNCTION hosted_projection_risk_invalidates();
