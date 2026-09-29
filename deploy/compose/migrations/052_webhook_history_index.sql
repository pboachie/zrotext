-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares this index with CREATE INDEX CONCURRENTLY outside its
-- per-file transaction. Keep this numbered file as the durable, checksummed
-- validation gate; it must not build the index while holding a write lock.
-- Owner webhook history pages by (created_at,id) DESC within one endpoint;
-- leading with endpoint_id makes each page a bounded backward scan instead
-- of reading and sorting the endpoint's whole retention history.
CREATE FUNCTION webhook_history_index_ready(expected_schema text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class idx
        JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
        JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
        JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
        JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
        JOIN pg_catalog.pg_am am ON am.oid = idx.relam
        WHERE ns.nspname = expected_schema
          AND idx.relname = 'webhook_deliveries_history'
          AND idx.relkind = 'i'
          AND idx.relpersistence = 'p'
          AND tbl_ns.nspname = expected_schema
          AND tbl.relname = 'webhook_deliveries'
          AND am.amname = 'btree'
          AND ix.indisvalid AND ix.indisready AND ix.indislive
          AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
          AND ix.indnkeyatts = 3 AND ix.indnatts = 3
          AND ix.indexprs IS NULL
          AND ix.indkey[0] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'endpoint_id' AND NOT attisdropped
          )
          AND ix.indkey[1] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
          )
          AND ix.indkey[2] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'id' AND NOT attisdropped
          )
          AND ix.indoption[0] = 0 AND ix.indoption[1] = 3 AND ix.indoption[2] = 3
          AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0 AND ix.indcollation[2] = 0
          AND ix.indclass[0] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indclass[1] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indclass[2] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indpred IS NULL
    );
$$;

DO $$
BEGIN
    IF NOT webhook_history_index_ready(current_schema()) THEN
        RAISE EXCEPTION 'webhook_deliveries_history is absent, invalid, or has the wrong definition';
    END IF;
END;
$$;
