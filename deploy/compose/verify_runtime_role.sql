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
    review_allowed oid[] := ARRAY[]::oid[];
    writer_expected record;
BEGIN
    IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
        -- Pin compiled migration108 bodies before invoking a readiness helper.
        -- A substituted helper returning true cannot validate its own body.
        FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','ba20a6a52c8e77012dc41546475ab19f0d1743bd4675a3184108b78abdfb4b45','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()','f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()','960230c7506e3777f855c8637235a0f413c37e877c4f41b55d58ccf4914d3dd0','bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()','b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4','boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()','8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a','boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()','57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('auth_abuse_consume(text, bytea, bytea, integer, integer, integer, integer)','cdac204cd61b30c1c4a7e9513264467da8cd81ebb1b72332a065ad8ab380d6a1','boolean','plpgsql','v',false,false,ARRAY['search_path=pg_catalog'])
        ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,configuration) LOOP
            IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
              JOIN pg_class c ON c.oid='public.accounts'::regclass
              WHERE p.oid=to_regprocedure(writer_expected.signature)
                AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
                AND format_type(p.prorettype,NULL)=writer_expected.result_type
                AND l.lanname=writer_expected.language_name AND p.provolatile::text=writer_expected.volatility
                AND p.proisstrict=writer_expected.is_strict AND p.prosecdef=writer_expected.is_definer
                AND p.proconfig=writer_expected.configuration AND p.proowner=c.relowner
                AND NOT p.proretset AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0) THEN
                RAISE EXCEPTION 'mandatory writer helper body or configuration is inconsistent';
            END IF;
        END LOOP;
        IF public.payload_profile_writer_ready() IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'mandatory writer graph or runtime authority is inconsistent';
        END IF;
    END IF;
    IF to_regprocedure('public.user_membership_freshness_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.user_membership_freshness_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime can directly execute the user membership freshness helper';
    END IF;
    IF to_regprocedure('public.parent_account_mirror_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.parent_account_mirror_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime can directly execute the ownership mirror helper';
    END IF;
    FOREACH review_relation IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_broker_sessions','review_bootstrap_attempts','review_workspaces',
        'review_access_preparations','review_access_sessions','review_access_authentications',
        'review_access_root_reauth','review_access_locators'] LOOP
        IF to_regclass(format('public.%I',review_relation)) IS NULL THEN CONTINUE; END IF;
        IF NOT has_table_privilege(current_user,format('public.%I',review_relation),'SELECT')
          OR has_table_privilege(current_user,format('public.%I',review_relation),'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
            RAISE EXCEPTION 'review persistence runtime privileges are not select-only';
        END IF;
        IF EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
            WHERE c.oid=to_regclass(format('public.%I',review_relation)) AND a.grantee=0)
          OR EXISTS(SELECT FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a
            WHERE c.attrelid=to_regclass(format('public.%I',review_relation)) AND a.grantee=0) THEN
            RAISE EXCEPTION 'public review relation or column privileges remain';
        END IF;
        FOR review_column IN SELECT attname FROM pg_attribute
          WHERE attrelid=to_regclass(format('public.%I',review_relation)) AND attnum>0 AND NOT attisdropped LOOP
            IF has_column_privilege(current_user,format('public.%I',review_relation),review_column.attname,'INSERT,UPDATE,REFERENCES') THEN
                RAISE EXCEPTION 'review persistence column write privileges remain';
            END IF;
        END LOOP;
    END LOOP;
    IF to_regclass('public.review_access_preparations') IS NOT NULL THEN
        SELECT array_agg(to_regprocedure(signature)::oid) INTO review_allowed
          FROM unnest(ARRAY[
            'public.review_access_prune()',
            'public.review_access_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)',
            'public.review_access_browser(uuid,bytea,text,bytea,bytea,bigint,bytea,bigint,bigint,boolean)',
            'public.review_access_guard_lock(uuid,bytea,text,bytea,bytea,bigint,bytea)',
            'public.review_access_prepare(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,bigint,bigint,bigint,bytea)',
            'public.review_access_transition(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,text)',
            'public.review_access_login(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,uuid,uuid,bigint,text,uuid,uuid,bytea,bytea,uuid,uuid,uuid,bytea,bytea,bytea,bigint)',
            'public.review_access_broker_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_settlement(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,text,uuid,uuid,bigint,bytea,bytea,bytea)',
            'public.review_access_root_commit(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,uuid,uuid,bigint,bytea,jsonb,uuid,uuid,bigint,text,bigint)'
        ]) AS expected(signature);
        IF array_position(review_allowed,NULL::oid) IS NOT NULL THEN
            RAISE EXCEPTION 'review access wrapper missing';
        END IF;
    END IF;
    FOR review_routine IN SELECT p.oid,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
      AND p.proname LIKE 'review_access_%' LOOP
        IF EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            WHERE p.oid=review_routine.oid AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN
            RAISE EXCEPTION 'public review helper execution remains';
        END IF;
        IF has_function_privilege(current_user,review_routine.oid,'EXECUTE') IS DISTINCT FROM
            (review_routine.oid=ANY(review_allowed)) THEN
            RAISE EXCEPTION 'runtime review wrapper privileges are not narrow';
        END IF;
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
    IF to_regclass('public.hosted_runtime_secrets') IS NOT NULL THEN
        IF has_any_column_privilege(current_user,'public.hosted_runtime_secrets','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_any_column_privilege(current_user,'public.hosted_runtime_sessions','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_any_column_privilege(current_user,'public.hosted_billing_resolutions','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_table_privilege(current_user,'public.hosted_runtime_secrets','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_runtime_sessions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_billing_resolutions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_billing_namespaces','INSERT,DELETE,TRUNCATE,TRIGGER')
           OR has_function_privilege(current_user,'public.hosted_resolve_review(uuid,bigint,text,text)','EXECUTE') THEN
            RAISE EXCEPTION 'hosted authority privileges are not isolated';
        END IF;
    END IF;
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
DO $$
BEGIN
    IF to_regprocedure('public.registration_browser_intent_binding_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.registration_browser_intent_binding_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime registration trigger privilege is not narrow';
    END IF;
END $$;
ROLLBACK;
