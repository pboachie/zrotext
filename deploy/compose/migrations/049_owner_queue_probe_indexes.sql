-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares these indexes with CREATE INDEX CONCURRENTLY outside
-- its per-file transaction. Keep this numbered file as the durable, checksummed
-- validation gate; it must not build the indexes while holding a write lock.
-- The exact predicates match the owner device-status queue probes so every
-- PostgreSQL release can prove the state filter from the index predicate
-- instead of filtering the device's full history at read time.
CREATE FUNCTION owner_queue_probe_indexes_ready(expected_schema text) RETURNS boolean
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
              AND idx.relname = 'messages_owner_pending_state'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'messages'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 3 AND ix.indnatts = 3
              AND ix.indexprs IS NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
              )
              AND ix.indkey[2] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0 AND ix.indoption[2] = 0
              AND ix.indcollation[0] = 0
              AND ix.indcollation[1] = (
                  SELECT attcollation FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
              )
              AND ix.indcollation[2] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'text'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[2] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
                  '(state = ANY (ARRAY[''accepted''::text, ''queued''::text, ''claimed''::text]))'
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
              AND idx.relname = 'messages_owner_in_flight_state'
              AND idx.relkind = 'i'
              AND idx.relpersistence = 'p'
              AND tbl_ns.nspname = expected_schema
              AND tbl.relname = 'messages'
              AND am.amname = 'btree'
              AND ix.indisvalid AND ix.indisready AND ix.indislive
              AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
              AND ix.indnkeyatts = 3 AND ix.indnatts = 3
              AND ix.indexprs IS NULL
              AND ix.indkey[0] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
              )
              AND ix.indkey[1] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
              )
              AND ix.indkey[2] = (
                  SELECT attnum FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
              )
              AND ix.indoption[0] = 0 AND ix.indoption[1] = 0 AND ix.indoption[2] = 0
              AND ix.indcollation[0] = 0
              AND ix.indcollation[1] = (
                  SELECT attcollation FROM pg_catalog.pg_attribute
                  WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
              )
              AND ix.indcollation[2] = 0
              AND ix.indclass[0] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'uuid'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[1] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'text'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND ix.indclass[2] = (
                  SELECT opc.oid FROM pg_catalog.pg_opclass opc
                  WHERE opc.opcmethod = am.oid
                    AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
                    AND opc.opcdefault
              )
              AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
                  '(state = ANY (ARRAY[''submitting''::text, ''submitted''::text]))'
        ));
$$;

DO $$
BEGIN
    IF NOT owner_queue_probe_indexes_ready(current_schema()) THEN
        RAISE EXCEPTION 'owner queue probe indexes are absent, invalid, or have the wrong definition';
    END IF;
END;
$$;
