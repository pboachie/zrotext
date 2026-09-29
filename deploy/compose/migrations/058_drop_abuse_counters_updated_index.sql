-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator drops this index with DROP INDEX CONCURRENTLY outside its
-- per-file transaction. Keep this numbered file as the durable, checksummed
-- validation gate; it must not take a write lock on live charges.
-- auth_abuse_counters_stale indexed updated_at, which every abuse-budget
-- upsert rewrites, so each charge was a non-HOT update with two extra index
-- entries. The index served only the bounded prune scan; dropping it lets
-- charges update in place while the prune walks the small live-subject table.
DO $$
BEGIN
    IF to_regclass('public.auth_abuse_counters_stale') IS NOT NULL THEN
        RAISE EXCEPTION 'auth_abuse_counters_stale must be dropped before this migration is recorded';
    END IF;
END;
$$;
