-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares this index with CREATE INDEX CONCURRENTLY outside
-- its per-file transaction. Keep this numbered file as the durable,
-- checksummed validation gate; it must not build the index while holding a
-- write lock. The index backs the inbound_events (account_id, device_id,
-- message_id, attempt_id) -> message_attempts foreign-key check that the
-- single-transaction owner account erasure runs for every deleted attempt
-- (issues #515 and #601): until now the check was served only by the
-- (account_id, message_id) prefix of inbound_events_timeline, and #601
-- measured it at 7.4 s of an 8.5 s erasure when one message carried many
-- attempts.
CREATE FUNCTION inbound_events_attempt_fk_index_ready(expected_schema text) RETURNS boolean
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
          AND idx.relname = 'erasure_fk_inbound_events_attempt'
          AND idx.relkind = 'i'
          AND idx.relpersistence = 'p'
          AND tbl_ns.nspname = expected_schema
          AND tbl.relname = 'inbound_events'
          AND am.amname = 'btree'
          AND ix.indisvalid AND ix.indisready AND ix.indislive
          AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
          AND ix.indnkeyatts = 4 AND ix.indnatts = 4
          AND ix.indexprs IS NULL
          AND ix.indpred IS NULL
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
              WHERE attrelid = tbl.oid AND attname = 'message_id' AND NOT attisdropped
          )
          AND ix.indkey[3] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'attempt_id' AND NOT attisdropped
          )
          AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
          AND ix.indoption[2] = 0 AND ix.indoption[3] = 0
          AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
          AND ix.indcollation[2] = 0 AND ix.indcollation[3] = 0
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
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indclass[3] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
    );
$$;

DO $$
BEGIN
    IF NOT inbound_events_attempt_fk_index_ready(current_schema()) THEN
        RAISE EXCEPTION 'the inbound_events attempt foreign-key support index is absent, invalid, or has the wrong definition';
    END IF;
END;
$$;
