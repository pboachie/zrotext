-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares these indexes with CREATE INDEX CONCURRENTLY outside
-- its per-file transaction. Keep this numbered file as the durable, checksummed
-- validation gate; it must not build the indexes while holding a write lock.
-- Each index backs one foreign-key check the single-transaction owner account
-- erasure runs for every deleted row (issue #515): without it PostgreSQL scans
-- the referencing table per deleted row, and unindexed checks have been
-- measured to exceed the runtime 10 s statement timeout on large accounts.
CREATE FUNCTION erasure_fk_indexes_ready(expected_schema text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT
        (SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'erasure_fk_webhook_deliveries_event'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'webhook_deliveries'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 2 AND ix.indnatts = 2
              AND ix.indexprs IS NULL
              AND ix.indpred IS NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'event_id' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
              AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
        ))
        AND (SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'erasure_fk_suppressions_attempt'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'recipient_suppressions'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 1 AND ix.indnatts = 1
              AND ix.indexprs IS NULL
              AND ix.indpred IS NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'source_attempt_id' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0
              AND ix.indcollation[0] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
        ))
        AND (SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'erasure_fk_suppressions_event'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'recipient_suppressions'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 2 AND ix.indnatts = 2
              AND ix.indexprs IS NULL
              AND ix.indpred IS NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'source_event_id' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
              AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
        ))
        AND (SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'erasure_fk_holds_release_event'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'owner_recipient_holds'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 2 AND ix.indnatts = 2
              AND ix.indexprs IS NULL
              AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
                  '(release_event_id IS NOT NULL)'
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'release_event_id' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
              AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
        ))
        AND (SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class idx
            JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
            JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
            JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_am am ON am.oid = idx.relam
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'erasure_fk_opt_out_audit_release_event'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'owner_opt_out_audit'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 2 AND ix.indnatts = 2
              AND ix.indexprs IS NULL
              AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
                  '(release_event_id IS NOT NULL)'
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'release_event_id' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
              AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
        ));
$$;

DO $$
BEGIN
    IF NOT erasure_fk_indexes_ready(current_schema()) THEN
        RAISE EXCEPTION 'erasure foreign-key support indexes are absent, invalid, or have the wrong definition';
    END IF;
END;
$$;
