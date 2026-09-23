-- SPDX-License-Identifier: AGPL-3.0-only
-- Atomic request budgets shared by every API site. Subjects are HMAC digests
-- under the operational auth pepper; plaintext email and pairing material are
-- never stored here. The worker prunes stale rows in bounded batches.
CREATE TABLE auth_abuse_counters (
    scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 48),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash) = 32),
    window_started_at timestamptz NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope, subject_hash)
);
CREATE INDEX auth_abuse_counters_stale ON auth_abuse_counters(updated_at);
