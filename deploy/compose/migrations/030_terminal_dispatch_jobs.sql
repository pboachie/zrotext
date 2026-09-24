-- SPDX-License-Identifier: AGPL-3.0-only
-- Preserve dispatch generations for audit/fencing while removing terminal
-- pre-grant jobs from the hot due index.
ALTER TABLE dispatch_jobs ADD COLUMN finished_at timestamptz;

-- Use the recorded state transition time, not the migration time, for history.
UPDATE dispatch_jobs j SET finished_at=m.updated_at,lease_owner=NULL,lease_until=NULL
FROM messages m
WHERE m.id=j.message_id AND m.account_id=j.account_id
  AND m.state IN ('cancelled','expired')
  AND j.grant_issued_at IS NULL AND j.finished_at IS NULL;

DROP INDEX dispatch_jobs_due;
CREATE INDEX dispatch_jobs_due ON dispatch_jobs (next_attempt_at,message_id)
    WHERE grant_issued_at IS NULL AND finished_at IS NULL;

-- Expiry should begin with live queued/claimed messages, rather than walk
-- historical message rows or a dispatch index ordered by next_attempt_at.
CREATE INDEX messages_pending_expiry ON messages (expires_at,id)
    WHERE state IN ('queued','claimed');
