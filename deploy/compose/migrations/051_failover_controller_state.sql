-- SPDX-License-Identifier: AGPL-3.0-only
-- Durable journal for the independent-quorum failover controller (second
-- increment of the MULTI-LOCATION.md automatic-failover plan; see
-- crates/failover-quorum). One row: the controller executor writes its
-- restorable state before and after applying promotion decisions, so a
-- restart resumes the interrupted failover at the exact promotion epoch
-- instead of re-deciding or double-bumping. The `state` column is the
-- versioned encoding owned by zrotext-failover-quorum; no other reader
-- exists, and nothing here gates request handling.
CREATE TABLE failover_controller_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    state text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
