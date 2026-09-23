-- SPDX-License-Identifier: AGPL-3.0-only
-- ZT-008 storage foundation. Migration 006 is reserved by metering.
-- There is deliberately no public inbound route or webhook sender in this slice.

ALTER TABLE message_attempts ADD CONSTRAINT message_attempts_inbound_owner
    UNIQUE (account_id, device_id, message_id, id);

CREATE TABLE inbound_events (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    device_id uuid NOT NULL,
    message_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    device_sequence bigint NOT NULL CHECK (device_sequence > 0),
    classification text NOT NULL CHECK (classification IN
        ('captured_local', 'sim_unverified', 'send_unverified', 'encryption_unverified')),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    part_count smallint NOT NULL CHECK (part_count BETWEEN 1 AND 6),
    content_kind text NOT NULL CHECK (content_kind IN ('metadata_only', 'opaque_pilot')),
    content_ciphertext bytea,
    event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
    signature_der bytea NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id),
    FOREIGN KEY (account_id, message_id) REFERENCES messages(account_id, id),
    FOREIGN KEY (account_id, device_id, message_id, attempt_id)
        REFERENCES message_attempts(account_id, device_id, message_id, id),
    UNIQUE (account_id, id),
    UNIQUE (device_id, device_sequence),
    CHECK ((content_kind = 'metadata_only' AND content_ciphertext IS NULL) OR
           (content_kind = 'opaque_pilot' AND content_ciphertext IS NOT NULL
            AND octet_length(content_ciphertext) BETWEEN 32 AND 8192)),
    CHECK (content_kind = 'metadata_only' OR classification = 'captured_local')
);
CREATE INDEX inbound_events_timeline ON inbound_events(account_id, message_id, received_at, id);

-- A separate operational KEK must encrypt signing secrets before endpoint
-- creation is exposed. URL and secret lifecycle/SSRF policy is not supplied by
-- this basic schema check; the delivery worker remains absent.
CREATE TABLE webhook_endpoints (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    callback_url text NOT NULL CHECK (length(callback_url) BETWEEN 9 AND 2048
        AND callback_url LIKE 'https://%'),
    signing_secret_ciphertext bytea NOT NULL CHECK
        (octet_length(signing_secret_ciphertext) BETWEEN 32 AND 1024),
    signing_secret_key_version integer NOT NULL CHECK (signing_secret_key_version > 0),
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id)
);

CREATE TABLE webhook_deliveries (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    event_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK
        (status IN ('pending', 'leased', 'succeeded', 'dead')),
    attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 7),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, endpoint_id) REFERENCES webhook_endpoints(account_id, id),
    FOREIGN KEY (account_id, event_id) REFERENCES inbound_events(account_id, id),
    UNIQUE (endpoint_id, event_id),
    CHECK ((status = 'leased') = (lease_owner IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries(next_attempt_at, id)
    WHERE status = 'pending';

CREATE TABLE webhook_attempts (
    id uuid PRIMARY KEY,
    delivery_id uuid NOT NULL REFERENCES webhook_deliveries(id),
    attempt_number smallint NOT NULL CHECK (attempt_number BETWEEN 1 AND 7),
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    outcome text CHECK (outcome IN ('ack', 'timeout', 'http_error', 'network_error', 'policy_rejected')),
    http_status smallint CHECK (http_status BETWEEN 100 AND 599),
    UNIQUE (delivery_id, attempt_number),
    CHECK ((completed_at IS NULL) = (outcome IS NULL))
);
