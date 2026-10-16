-- SPDX-License-Identifier: AGPL-3.0-only
-- Run as runtime in the disposable smoke database. All writes roll back.
BEGIN;
DO $$
DECLARE
    statement text;
    anchor_account uuid;
    review_relation text;
    review_column record;
    review_routine record;
BEGIN
    IF to_regprocedure('public.parent_account_mirror_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.parent_account_mirror_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime can directly execute the ownership mirror helper';
    END IF;
    FOREACH review_relation IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_broker_sessions','review_bootstrap_attempts','review_workspaces'] LOOP
        IF to_regclass(format('public.%I',review_relation)) IS NULL THEN CONTINUE; END IF;
        IF NOT has_table_privilege(current_user,format('public.%I',review_relation),'SELECT')
          OR has_table_privilege(current_user,format('public.%I',review_relation),'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
            RAISE EXCEPTION 'review persistence runtime privileges are not select-only';
        END IF;
        FOR review_column IN SELECT attname FROM pg_attribute
          WHERE attrelid=to_regclass(format('public.%I',review_relation)) AND attnum>0 AND NOT attisdropped LOOP
            IF has_column_privilege(current_user,format('public.%I',review_relation),review_column.attname,'INSERT,UPDATE,REFERENCES') THEN
                RAISE EXCEPTION 'review persistence column write privileges remain';
            END IF;
        END LOOP;
    END LOOP;
    FOR review_routine IN SELECT p.oid FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
      AND p.proname LIKE 'review_workspace_%' LOOP
        IF has_function_privilege(current_user,review_routine.oid,'EXECUTE') THEN
            RAISE EXCEPTION 'runtime can execute owner-only review persistence helper';
        END IF;
    END LOOP;
    IF current_user <> 'zrotext_runtime' OR EXISTS (
        SELECT FROM pg_roles WHERE rolname = current_user AND
        (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'unexpected runtime identity or privileges';
    END IF;
    INSERT INTO sites(site_id) VALUES ('runtime-role-smoke');
    UPDATE sites SET draining = true WHERE site_id = 'runtime-role-smoke';
    IF NOT EXISTS (SELECT FROM sites WHERE site_id = 'runtime-role-smoke' AND draining) THEN
        RAISE EXCEPTION 'runtime CRUD failed';
    END IF;
    DELETE FROM sites WHERE site_id = 'runtime-role-smoke';
    IF NOT auth_abuse_consume('runtime-role-smoke', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 2, 60, 1, 60) THEN
        RAISE EXCEPTION 'runtime function execution failed';
    END IF;
    FOREACH statement IN ARRAY ARRAY[
        'CREATE TABLE public.runtime_forbidden(id integer)',
        'CREATE TEMP TABLE runtime_forbidden(id integer)',
        'CREATE SCHEMA runtime_forbidden',
        'CREATE ROLE runtime_forbidden',
        'ALTER TABLE public.sites ADD COLUMN runtime_forbidden integer',
        'TRUNCATE public.sites CASCADE',
        'DELETE FROM public.schema_migrations',
        'SET ROLE zrotext',
        'SELECT pg_read_file(''/etc/passwd'')',
        'COPY (SELECT 1) TO PROGRAM ''true'''
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'runtime unexpectedly allowed: %', statement;
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END LOOP;
    IF to_regclass('public.payload_profile_account_anchors') IS NOT NULL THEN
        IF has_table_privilege(current_user,'public.payload_profile_account_anchors','INSERT')
          OR has_table_privilege(current_user,'public.payload_profile_account_anchors','DELETE')
          OR has_table_privilege(current_user,'public.payload_profile_account_anchors','TRUNCATE')
          OR has_column_privilege(current_user,'public.payload_profile_account_anchors','state','UPDATE')
          OR has_column_privilege(current_user,'public.payload_profile_account_anchors','selection_epoch','UPDATE')
          OR NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','account_id','UPDATE') THEN
            RAISE EXCEPTION 'runtime anchor privileges are not narrow';
        END IF;
        anchor_account := gen_random_uuid();
        INSERT INTO public.accounts(id) VALUES(anchor_account);
        PERFORM account_id FROM public.payload_profile_account_anchors
          WHERE account_id=anchor_account AND state='live' AND selection_epoch=0
          FOR SHARE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'runtime account creation did not create a live anchor';
        END IF;
        FOREACH statement IN ARRAY ARRAY[
            'UPDATE public.payload_profile_account_anchors SET selection_epoch=1',
            'UPDATE public.payload_profile_account_anchors SET state=''deleted''',
            'DELETE FROM public.payload_profile_account_anchors',
            'INSERT INTO public.payload_profile_account_anchors(account_id) SELECT id FROM public.accounts',
            'TRUNCATE public.payload_profile_account_anchors',
            'SELECT public.payload_profile_anchor_row_guard()',
            'SELECT public.payload_profile_anchor_account_created()',
            'SELECT public.payload_profile_anchor_account_changing()',
            'SELECT public.payload_profile_anchor_account_deleted()'
        ] LOOP
            BEGIN
                EXECUTE statement;
                RAISE EXCEPTION 'runtime unexpectedly allowed anchor operation';
            EXCEPTION WHEN insufficient_privilege THEN
                NULL;
            END;
        END LOOP;
        DELETE FROM public.accounts WHERE id=anchor_account;
        IF NOT EXISTS (SELECT FROM public.payload_profile_account_anchors
          WHERE account_id=anchor_account AND state='deleted' AND selection_epoch=1) THEN
            RAISE EXCEPTION 'runtime account deletion did not retain its tombstone';
        END IF;
    END IF;
END $$;
ROLLBACK;
