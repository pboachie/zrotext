-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares messages_summary_queue CONCURRENTLY before this file.
-- Backfill/capture must commit together: a failed deadline leaves no partial
-- summary available. Large retained histories require a reviewed maintenance
-- plan; this migration never silently skips their first-submission evidence.
SET LOCAL lock_timeout = '1s';
SET LOCAL statement_timeout = '10s';

CREATE TABLE message_submission_receipts (
    message_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    device_id uuid NOT NULL,
    first_submitted_at timestamptz NOT NULL,
    FOREIGN KEY (account_id,message_id) REFERENCES messages(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,device_id) REFERENCES devices(account_id,id) ON DELETE CASCADE
);
CREATE INDEX message_submission_receipts_account_day
    ON message_submission_receipts(account_id,first_submitted_at,message_id);
CREATE INDEX message_submission_receipts_device_day
    ON message_submission_receipts(account_id,device_id,first_submitted_at,message_id);

CREATE FUNCTION capture_message_submission_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.evidence_code = 'sent_callback_ok' AND NEW.resulting_state = 'submitted' THEN
        EXECUTE format(
            'INSERT INTO %I.message_submission_receipts(message_id,account_id,device_id,first_submitted_at)
             SELECT m.id,m.account_id,m.device_id,$3 FROM %I.messages m
             WHERE m.id=$1 AND m.account_id=$2 ON CONFLICT(message_id) DO NOTHING',
            TG_TABLE_SCHEMA,TG_TABLE_SCHEMA)
            USING NEW.message_id,NEW.account_id,NEW.received_at;
    END IF;
    RETURN NEW;
END;
$$;

-- This bounded lock closes the install/backfill race with callback inserts.
-- Both the trigger and complete retained-evidence backfill roll back together.
LOCK TABLE message_events IN SHARE ROW EXCLUSIVE MODE;
CREATE TRIGGER message_summary_capture_submission
    AFTER INSERT ON message_events FOR EACH ROW
    EXECUTE FUNCTION capture_message_submission_receipt();
INSERT INTO message_submission_receipts(message_id,account_id,device_id,first_submitted_at)
    SELECT m.id,m.account_id,m.device_id,min(e.received_at)
    FROM messages m JOIN message_events e ON (e.account_id,e.message_id)=(m.account_id,m.id)
    WHERE e.evidence_code='sent_callback_ok' AND e.resulting_state='submitted'
    GROUP BY m.id,m.account_id,m.device_id;

CREATE FUNCTION message_summary_metadata_ready(expected_schema text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    WITH expected(name,table_name,columns,predicate) AS (VALUES
        ('messages_device_state','messages',ARRAY['device_id','state','created_at'],NULL),
        ('messages_summary_queue','messages',ARRAY['account_id','state','created_at'],
         '(state = ANY (ARRAY[''accepted''::text, ''queued''::text, ''claimed''::text, ''submitting''::text, ''submitted''::text]))'),
        ('message_submission_receipts_account_day','message_submission_receipts',
         ARRAY['account_id','first_submitted_at','message_id'],NULL),
        ('message_submission_receipts_device_day','message_submission_receipts',
         ARRAY['account_id','device_id','first_submitted_at','message_id'],NULL)
    ), indexes AS (
        SELECT coalesce(idx.relkind='i' AND idx.relpersistence='p'
            AND tbl.relkind='r' AND tbl_ns.nspname=expected_schema AND tbl.relname=expected.table_name
            AND am.amname='btree' AND ix.indisvalid AND ix.indisready AND ix.indislive
            AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
            AND ix.indnkeyatts=array_length(expected.columns,1) AND ix.indnatts=ix.indnkeyatts
            AND ix.indexprs IS NULL
            AND pg_get_expr(ix.indpred,ix.indrelid) IS NOT DISTINCT FROM expected.predicate
            AND ARRAY(SELECT a.attname::text FROM unnest(ix.indkey) WITH ORDINALITY key(attnum,ord)
                JOIN pg_attribute a ON a.attrelid=tbl.oid AND a.attnum=key.attnum AND NOT a.attisdropped
                ORDER BY key.ord)=expected.columns
            AND NOT EXISTS (
                SELECT 1 FROM unnest(ix.indkey::smallint[],ix.indclass::oid[],ix.indcollation::oid[],ix.indoption::smallint[])
                    key(attnum,opclass,collation_oid,options)
                LEFT JOIN pg_attribute a ON a.attrelid=tbl.oid AND a.attnum=key.attnum AND NOT a.attisdropped
                LEFT JOIN pg_opclass opc ON opc.oid=key.opclass
                WHERE a.attnum IS NULL OR key.options<>0 OR key.collation_oid<>a.attcollation
                    OR NOT opc.opcdefault OR opc.opcmethod<>am.oid OR opc.opcintype<>a.atttypid
            ),FALSE) AS ready
        FROM expected
        LEFT JOIN pg_namespace ns ON ns.nspname=expected_schema
        LEFT JOIN pg_class idx ON idx.relnamespace=ns.oid AND idx.relname=expected.name
        LEFT JOIN pg_index ix ON ix.indexrelid=idx.oid
        LEFT JOIN pg_class tbl ON tbl.oid=ix.indrelid
        LEFT JOIN pg_namespace tbl_ns ON tbl_ns.oid=tbl.relnamespace
        LEFT JOIN pg_am am ON am.oid=idx.relam
    )
    SELECT (SELECT count(*)=4 AND bool_and(ready) FROM indexes) AND EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class table_class ON table_class.oid=t.tgrelid
        JOIN pg_namespace table_ns ON table_ns.oid=table_class.relnamespace
        JOIN pg_proc p ON p.oid=t.tgfoid
        JOIN pg_namespace function_ns ON function_ns.oid=p.pronamespace
        WHERE table_ns.nspname=expected_schema AND table_class.relname='message_events'
            AND t.tgname='message_summary_capture_submission' AND t.tgtype=5
            AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
            AND function_ns.nspname=expected_schema AND p.proname='capture_message_submission_receipt'
            AND p.pronargs=0 AND p.prorettype='trigger'::regtype AND NOT p.prosecdef
    );
$$;

DO $$
BEGIN
    IF NOT message_summary_metadata_ready(current_schema()) THEN
        RAISE EXCEPTION 'message summary metadata is absent, invalid, or has the wrong definition';
    END IF;
END;
$$;
