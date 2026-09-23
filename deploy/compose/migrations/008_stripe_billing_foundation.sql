-- SPDX-License-Identifier: AGPL-3.0-only
-- Test-mode billing inbox and tenant binding. Migration 007 is owned by the
-- inbound webhook branch and must be deployed before this migration.

CREATE TABLE billing_customers (
    account_id uuid PRIMARY KEY REFERENCES accounts(id),
    stripe_customer_id text NOT NULL UNIQUE CHECK (stripe_customer_id ~ '^cus_[A-Za-z0-9]+$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, stripe_customer_id)
);

CREATE TABLE billing_events (
    stripe_event_id text PRIMARY KEY CHECK (stripe_event_id ~ '^evt_[A-Za-z0-9]+$'),
    event_type text NOT NULL,
    object_id text,
    stripe_customer_id text,
    stripe_subscription_id text,
    account_id uuid REFERENCES accounts(id),
    body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
    disposition text NOT NULL CHECK (disposition IN ('queued', 'unbound', 'ignored', 'conflict')),
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_events_unbound ON billing_events(received_at, stripe_customer_id)
    WHERE disposition IN ('unbound', 'conflict');

CREATE TABLE billing_reconciliations (
    stripe_subscription_id text PRIMARY KEY CHECK (stripe_subscription_id ~ '^sub_[A-Za-z0-9]+$'),
    account_id uuid NOT NULL,
    stripe_customer_id text NOT NULL,
    dirty_generation bigint NOT NULL DEFAULT 1 CHECK (dirty_generation > 0),
    processed_generation bigint NOT NULL DEFAULT 0 CHECK (processed_generation >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, stripe_customer_id)
        REFERENCES billing_customers(account_id, stripe_customer_id),
    CHECK (processed_generation <= dirty_generation)
);
CREATE INDEX billing_reconciliations_pending
    ON billing_reconciliations(next_attempt_at, stripe_subscription_id)
    WHERE dirty_generation > processed_generation;

CREATE TABLE billing_subscriptions (
    stripe_subscription_id text PRIMARY KEY,
    account_id uuid NOT NULL,
    stripe_customer_id text NOT NULL,
    stripe_status text NOT NULL,
    stripe_price_id text,
    recognized_price boolean NOT NULL DEFAULT false,
    reconciled_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, stripe_customer_id)
        REFERENCES billing_customers(account_id, stripe_customer_id),
    FOREIGN KEY (stripe_subscription_id)
        REFERENCES billing_reconciliations(stripe_subscription_id)
);
