-- SPDX-License-Identifier: AGPL-3.0-only
-- Durable outbound metering. Policy values are provisioned by trusted billing
-- code or a self-host operator; this migration encodes no product thresholds.

CREATE TABLE usage_quota_policies (
    account_id uuid NOT NULL REFERENCES accounts(id),
    metric text NOT NULL CHECK (metric IN ('outbound_message')),
    limit_units bigint NOT NULL CHECK (limit_units >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, metric)
);

CREATE TABLE usage_periods (
    account_id uuid NOT NULL REFERENCES accounts(id),
    metric text NOT NULL CHECK (metric IN ('outbound_message')),
    period_start date NOT NULL,
    period_end date NOT NULL,
    limit_units bigint NOT NULL CHECK (limit_units >= 0),
    reserved_units bigint NOT NULL DEFAULT 0 CHECK (reserved_units >= 0),
    refunded_units bigint NOT NULL DEFAULT 0 CHECK (refunded_units >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, metric, period_start),
    CHECK (period_start = date_trunc('month', period_start::timestamp)::date),
    CHECK (period_end = (period_start + interval '1 month')::date),
    CHECK (refunded_units <= reserved_units)
);

CREATE TABLE usage_ledger (
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    metric text NOT NULL,
    period_start date NOT NULL,
    entry_kind text NOT NULL CHECK (entry_kind IN ('reserve', 'refund')),
    units smallint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, message_id, entry_kind),
    FOREIGN KEY (account_id, message_id) REFERENCES messages(account_id, id),
    FOREIGN KEY (account_id, metric, period_start)
        REFERENCES usage_periods(account_id, metric, period_start),
    CHECK ((entry_kind = 'reserve' AND units = 1)
        OR (entry_kind = 'refund' AND units = -1))
);
CREATE INDEX usage_ledger_period ON usage_ledger(account_id, metric, period_start, created_at);
