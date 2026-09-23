-- SPDX-License-Identifier: AGPL-3.0-only
-- M0 authority shape. M1 will add tenant-safe message/attempt tables through
-- one locked expand/contract migration runner; Compose init is for new DBs.
CREATE TABLE deployment_authority (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch bigint NOT NULL CHECK (epoch > 0),
    dispatch_enabled boolean NOT NULL DEFAULT false
);
INSERT INTO deployment_authority (singleton, epoch) VALUES (true, 1);

CREATE TABLE sites (
    site_id text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT true,
    draining boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_sessions (
    device_id uuid PRIMARY KEY,
    site_id text NOT NULL REFERENCES sites(site_id),
    instance_id text NOT NULL,
    connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
    lease_until timestamptz NOT NULL,
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch > 0)
);

CREATE TABLE idempotency_keys (
    account_id uuid NOT NULL,
    key text NOT NULL,
    request_digest bytea NOT NULL,
    message_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, key)
);
CREATE UNIQUE INDEX idempotency_message_id ON idempotency_keys (message_id);

CREATE TABLE dispatch_fences (
    message_id uuid PRIMARY KEY,
    device_id uuid NOT NULL,
    attempt_id uuid NOT NULL UNIQUE,
    generation bigint NOT NULL CHECK (generation > 0),
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch > 0),
    grant_expires_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('granted', 'submitting', 'submitted', 'unknown', 'failed'))
);
CREATE UNIQUE INDEX dispatch_fences_active_device ON dispatch_fences (device_id)
    WHERE outcome IN ('granted', 'submitting', 'unknown');
