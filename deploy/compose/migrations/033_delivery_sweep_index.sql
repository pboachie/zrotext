-- SPDX-License-Identifier: AGPL-3.0-only
-- The delivery recovery worker runs every 15 seconds and walks in-flight
-- messages oldest-first (grant/submit silence and 24-hour delivery timeouts).
-- Without this index each sweep scans every retained message. In-flight rows
-- are a small, self-draining share of the table.
CREATE INDEX messages_in_flight_updated ON messages (updated_at, id)
    WHERE state IN ('claimed', 'submitting', 'submitted');
