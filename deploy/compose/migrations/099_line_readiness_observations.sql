-- SPDX-License-Identifier: AGPL-3.0-only
-- ADR 0004 step 4 (wiring): the recorded latest per-line readiness
-- observation reported by the phone over the default-off `line_readiness`
-- device-stream frame. One bounded row per line; the row is the phone's
-- reported observation, not authority: activation, consent, suppression,
-- quota and policy fences are applied independently at the accept boundary.
-- No SIM slot, subscription identifier, ICCID, IMSI or phone number is
-- stored here.

CREATE TABLE line_readiness_observations (
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation > 0),
    kind text NOT NULL CHECK (kind IN (
        'inactive', 'binding_not_active', 'continuity_pending',
        'card_changed', 'offline_past_threshold', 'ready')),
    since_observation_ms bigint
        CHECK (since_observation_ms IS NULL OR since_observation_ms >= 0),
    observed_at_ms bigint NOT NULL CHECK (observed_at_ms > 0),
    digest text NOT NULL CHECK (digest ~ '^[A-Za-z0-9_-]{43}$'),
    hub_received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, line_id),
    FOREIGN KEY (account_id, line_id) REFERENCES phone_lines (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, id),
    -- A ready claim must name the age of the freshest observation backing
    -- it, and a missing observation can only ever report offline.
    CONSTRAINT line_readiness_ready_requires_observation_age
        CHECK (kind <> 'ready' OR since_observation_ms IS NOT NULL),
    CONSTRAINT line_readiness_absent_observation_only_offline
        CHECK (since_observation_ms IS NOT NULL
            OR kind = 'offline_past_threshold')
);
