-- SPDX-License-Identifier: AGPL-3.0-only
-- M1 schema. Apply once under the migration runner's advisory lock, after 002_auth.

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    display_name text NOT NULL,
    preferred_site_id text REFERENCES sites(site_id),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id)
);

ALTER TABLE api_keys ADD CONSTRAINT api_keys_bound_device_owner
    FOREIGN KEY (account_id, bound_device_id) REFERENCES devices (account_id, id);

ALTER TABLE device_sessions ADD COLUMN account_id uuid;
ALTER TABLE device_sessions ADD CONSTRAINT device_sessions_owner
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id);
ALTER TABLE idempotency_keys ADD CONSTRAINT idempotency_owner
    FOREIGN KEY (account_id) REFERENCES accounts (id);

CREATE TABLE messages (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    device_id uuid NOT NULL,
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    recipient_digest bytea NOT NULL CHECK (octet_length(recipient_digest) = 32),
    transport_mode text NOT NULL CHECK (transport_mode = 'synthetic_alpha'),
    transport_payload bytea NOT NULL CHECK (octet_length(transport_payload) BETWEEN 1 AND 32768),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL CHECK (state IN ('accepted', 'queued', 'claimed', 'submitting', 'submitted', 'delivered', 'delivery_unknown', 'unknown', 'failed', 'cancelled', 'expired')),
    state_version bigint NOT NULL DEFAULT 1 CHECK (state_version > 0),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id)
);
CREATE INDEX messages_account_created ON messages (account_id, created_at DESC, id);
CREATE INDEX messages_device_state ON messages (device_id, state, created_at);

ALTER TABLE idempotency_keys ADD CONSTRAINT idempotency_message
    FOREIGN KEY (account_id, message_id) REFERENCES messages (account_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE dispatch_jobs (
    message_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    device_id uuid NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    lease_owner text,
    lease_until timestamptz,
    grant_issued_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, message_id) REFERENCES messages (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id)
);
CREATE INDEX dispatch_jobs_due ON dispatch_jobs (next_attempt_at, message_id)
    WHERE grant_issued_at IS NULL;

CREATE TABLE message_attempts (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch > 0),
    status text NOT NULL CHECK (status IN ('granted', 'submitting', 'submitted', 'unknown', 'failed', 'proved_no_submit')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, message_id) REFERENCES messages (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id),
    UNIQUE (message_id, generation)
);

CREATE TABLE message_events (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    attempt_id uuid,
    evidence_code text NOT NULL,
    event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    resulting_state text NOT NULL,
    segment_index integer,
    segment_count integer,
    FOREIGN KEY (account_id, message_id) REFERENCES messages (account_id, id),
    FOREIGN KEY (attempt_id) REFERENCES message_attempts (id),
    CHECK (segment_index IS NULL OR segment_index >= 0),
    CHECK (segment_count IS NULL OR segment_count BETWEEN 1 AND 6)
);
CREATE INDEX message_events_timeline ON message_events (account_id, message_id, received_at, id);
CREATE UNIQUE INDEX message_events_sent_segment ON message_events (attempt_id, segment_index)
    WHERE evidence_code IN ('sent_callback_ok', 'sent_callback_failed');

ALTER TABLE dispatch_fences ADD COLUMN account_id uuid;
ALTER TABLE dispatch_fences ADD COLUMN recipient_digest bytea;
ALTER TABLE dispatch_fences ADD CONSTRAINT dispatch_fences_message
    FOREIGN KEY (account_id, message_id) REFERENCES messages (account_id, id);
ALTER TABLE dispatch_fences ADD CONSTRAINT dispatch_fences_device
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id);
ALTER TABLE dispatch_fences ADD CONSTRAINT dispatch_fences_attempt
    FOREIGN KEY (attempt_id) REFERENCES message_attempts (id);
