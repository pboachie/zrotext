-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares these changes outside its per-file transaction:
-- CREATE INDEX CONCURRENTLY for the review-queue and review-event indexes and
-- DROP INDEX CONCURRENTLY for the redundant active index. Keep this numbered
-- file as the durable, checksummed validation gate; it must not take a write
-- lock on live suppressions.
-- The owner opt-out review list, its cursor lookup and review decisions all
-- filter on review sources; the new partial indexes serve those pages without
-- reading the account's non-review suppressions. recipient_suppressions_active
-- repeated the primary key's columns and served no query the primary key
-- cannot, while adding a second index write to every suppression upsert.
-- Shape checks read only the catalogs (structural pg_index joins, no
-- pg_get_indexdef: opening the index relation races parallel schema churn).
CREATE FUNCTION optout_review_indexes_ready(expected_schema text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_review_queue'
              AND idx.relkind = 'i' AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'recipient_suppressions'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 3 AND ix.indnatts = 3
              AND ix.indexprs IS NULL
              AND ix.indpred IS NOT NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped)
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'changed_at' AND NOT attisdropped)
              AND ix.indkey[2] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'recipient_e164' AND NOT attisdropped)
              AND ix.indoption[0] = 0 AND (ix.indoption[1] & 1) = 1 AND (ix.indoption[2] & 1) = 1
        )
        AND EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_review_event'
              AND idx.relkind = 'i' AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'recipient_suppressions'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 2 AND ix.indnatts = 2
              -- account_id leading, then the COALESCE expression (indkey 0).
              AND ix.indexprs IS NOT NULL
              AND ix.indpred IS NOT NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped)
              AND ix.indkey[1] = 0
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_active'
        );
$$;

DO $$
BEGIN
    IF NOT optout_review_indexes_ready(current_schema()) THEN
        RAISE EXCEPTION 'opt-out review indexes are absent, invalid, or the redundant active index remains';
    END IF;
END;
$$;
