-- SPDX-License-Identifier: AGPL-3.0-only
-- A per-version key commitment prevents two API sites from accepting
-- different webhook KEK bytes under the same version label.
CREATE TABLE webhook_kek_commitments (
    key_version integer PRIMARY KEY CHECK (key_version > 0),
    commitment bytea NOT NULL CHECK (octet_length(commitment) = 32),
    first_seen_at timestamptz NOT NULL DEFAULT now()
);

-- A missing or corrupt KEK is an operator condition, not a delivery attempt.
-- Keep the delivery pending for repair and make repeated failures observable.
ALTER TABLE webhook_deliveries ADD COLUMN key_failure_count integer NOT NULL DEFAULT 0
    CHECK (key_failure_count >= 0);
