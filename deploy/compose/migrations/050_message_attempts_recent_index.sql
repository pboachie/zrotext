-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares this index with CREATE INDEX CONCURRENTLY outside its
-- per-file transaction. Keep this numbered file as the durable, checksummed
-- validation gate; it must not build the index while holding a write lock.
-- The dispatch pre-check asks whether a device has any attempt from the last
-- minute. Leading with (account_id, device_id) and then created_at makes that
-- a bounded range scan instead of a walk over the device's whole history.
CREATE FUNCTION message_attempts_recent_index_ready(expected_schema text) RETURNS boolean
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
          AND idx.relname = 'message_attempts_device_created'
          AND idx.relkind = 'i'
          AND idx.relpersistence = 'p'
          AND tbl_ns.nspname = expected_schema
          AND tbl.relname = 'message_attempts'
          AND am.amname = 'btree'
          AND ix.indisvalid AND ix.indisready AND ix.indislive
          AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
          AND ix.indnkeyatts = 3 AND ix.indnatts = 3
          AND ix.indexprs IS NULL
          AND ix.indkey[0] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
          )
          AND ix.indkey[1] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
          )
          AND ix.indkey[2] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
          )
          AND ix.indoption[0] = 0 AND ix.indoption[1] = 0 AND ix.indoption[2] = 0
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
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indclass[2] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indpred IS NULL
    );
$$;

DO $$
BEGIN
    IF NOT message_attempts_recent_index_ready(current_schema()) THEN
        RAISE EXCEPTION 'message_attempts_device_created is absent, invalid, or has the wrong definition';
    END IF;
END;
$$;
