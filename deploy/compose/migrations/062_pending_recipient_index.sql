-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares this index with CREATE INDEX CONCURRENTLY outside
-- its per-file transaction. Keep this numbered file as the durable,
-- checksummed validation gate; it must not build the index while holding a
-- write lock.
-- messages_pending_recipient backs cancel_pending_recipient (issue #654,
-- formerly #501): every owner STOP cancels the pending sends of one
-- recipient, and until now that lookup scanned the account's pending queue
-- because the only pending index (messages_admission_pending, migration 052)
-- is device-keyed. The NOT NULL column of the predicate keeps this index
-- exclusive to recipient-keyed lookups: an account-only pending count can
-- never prove the index predicate and stays on messages_admission_pending.
-- The retention candidate walk is already served by the
-- messages_retention_due index of migration 026.
CREATE FUNCTION pending_recipient_index_ready(expected_schema text)
RETURNS boolean
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
          AND idx.relname = 'messages_pending_recipient'
          AND idx.relkind = 'i'
          AND idx.relpersistence = 'p'
          AND tbl_ns.nspname = expected_schema
          AND tbl.relname = 'messages'
          AND am.amname = 'btree'
          AND ix.indisvalid AND ix.indisready AND ix.indislive
          AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
          AND ix.indnkeyatts = 2 AND ix.indnatts = 2
          AND ix.indexprs IS NULL
          AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
              '((state = ANY (ARRAY[''queued''::text, ''claimed''::text])) AND (recipient_e164 IS NOT NULL))'
          AND ix.indkey[0] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'recipient_e164' AND NOT attisdropped
          )
          AND ix.indkey[1] = (
              SELECT attnum FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
          )
          AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
          AND ix.indcollation[0] = (
              SELECT attcollation FROM pg_catalog.pg_attribute
              WHERE attrelid = tbl.oid AND attname = 'recipient_e164' AND NOT attisdropped
          )
          AND ix.indcollation[1] = 0
          AND ix.indclass[0] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'text'::pg_catalog.regtype
                AND opc.opcdefault
          )
          AND ix.indclass[1] = (
              SELECT opc.oid FROM pg_catalog.pg_opclass opc
              WHERE opc.opcmethod = am.oid
                AND opc.opcintype = 'uuid'::pg_catalog.regtype
                AND opc.opcdefault
          )
    );
$$;

DO $$
BEGIN
    IF NOT pending_recipient_index_ready(current_schema()) THEN
        RAISE EXCEPTION 'the pending-recipient index is absent, invalid, or has the wrong definition';
    END IF;
END;
$$;
