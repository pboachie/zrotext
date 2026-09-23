-- SPDX-License-Identifier: AGPL-3.0-only
-- One owner-wide factor failure window across login challenges and MFA
-- management. Defaults backfill existing enrollments without locking owners out.
ALTER TABLE owner_mfa
    ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    ADD COLUMN failed_window_started_at timestamptz NOT NULL DEFAULT now();
