-- SPDX-License-Identifier: AGPL-3.0-only
-- Dedicated Compose database only. Run as its migration owner after migrations.
-- psql reads the secret from the environment; never interpolate shell SQL.
\getenv runtime_password RUNTIME_DATABASE_PASSWORD
\getenv bootstrap_password PGPASSWORD
SELECT :'runtime_password' ~ '^[0-9a-fA-F]{64}$'
    AND :'runtime_password' <> :'bootstrap_password' AS valid_password \gset
\if :valid_password
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'RUNTIME_DATABASE_PASSWORD must be independent of the admin password and contain exactly 64 hexadecimal characters';
  END $$;
\endif
BEGIN;
SELECT pg_advisory_xact_lock(72839726391844);
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zrotext_runtime') THEN
        CREATE ROLE zrotext_runtime;
    END IF;
    -- Refuse a pre-existing role with inherited privileges or object ownership.
    -- Operators must resolve those explicitly rather than silently retain DDL.
    IF EXISTS (SELECT FROM pg_auth_members
               WHERE member = 'zrotext_runtime'::regrole)
       OR EXISTS (SELECT FROM pg_shdepend
                  WHERE refclassid = 'pg_authid'::regclass
                    AND refobjid = 'zrotext_runtime'::regrole AND deptype = 'o') THEN
        RAISE EXCEPTION 'runtime role has unexpected memberships or ownership';
    END IF;
    -- Only ACLs that this provisioner resets are allowed on a reused role.
    -- In particular, reject explicit pg_catalog function privileges and grants
    -- in other schemas/databases instead of leaving a server-file/DDL bypass.
    IF EXISTS (
        SELECT FROM pg_shdepend d
        WHERE d.refclassid = 'pg_authid'::regclass
          AND d.refobjid = 'zrotext_runtime'::regrole AND d.deptype = 'a'
          AND NOT (
            (d.dbid = 0 AND d.classid = 'pg_database'::regclass
             AND d.objid = (SELECT oid FROM pg_database WHERE datname = current_database()))
            OR (d.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND (
                (d.classid = 'pg_namespace'::regclass AND d.objid = 'public'::regnamespace)
                OR (d.classid = 'pg_class'::regclass AND EXISTS (
                    SELECT FROM pg_class c WHERE c.oid = d.objid AND c.relnamespace = 'public'::regnamespace))
                OR (d.classid = 'pg_proc'::regclass AND EXISTS (
                    SELECT FROM pg_proc p WHERE p.oid = d.objid AND p.pronamespace = 'public'::regnamespace))
                OR (d.classid = 'pg_default_acl'::regclass AND EXISTS (
                    SELECT FROM pg_default_acl a WHERE a.oid = d.objid
                    AND a.defaclrole = current_user::regrole
                    AND a.defaclnamespace IN (0, 'public'::regnamespace)
                    AND a.defaclobjtype IN ('r', 'S', 'f')))
            ))
          )
    ) OR EXISTS (
        SELECT FROM pg_db_role_setting WHERE setrole = 'zrotext_runtime'::regrole
          AND setdatabase NOT IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
    ) THEN
        RAISE EXCEPTION 'runtime role has unexpected grants or database settings';
    END IF;
END $$;
ALTER ROLE zrotext_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE zrotext_runtime RESET ALL;
SELECT format('ALTER ROLE zrotext_runtime IN DATABASE %I RESET ALL', current_database()) \gexec
ALTER ROLE zrotext_runtime SET search_path = pg_catalog, public;
SELECT format('ALTER ROLE zrotext_runtime PASSWORD %L', :'runtime_password') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC, zrotext_runtime', current_database()) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO zrotext_runtime', current_database()) \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC, zrotext_runtime;
GRANT USAGE ON SCHEMA public TO zrotext_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, zrotext_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zrotext_runtime;
REVOKE ALL ON TABLE public.schema_migrations FROM zrotext_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, zrotext_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO zrotext_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, zrotext_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO zrotext_runtime;
-- These defaults apply to future objects created by this same migration owner.
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO zrotext_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO zrotext_runtime;
-- Lifecycle-only anchor authority is narrower than the ordinary DML defaults.
-- Reset column ACLs too: relation REVOKE does not remove old column grants.
DO $$
BEGIN
    IF to_regclass('public.payload_profile_account_anchors') IS NOT NULL THEN
        REVOKE ALL ON TABLE public.payload_profile_account_anchors FROM PUBLIC,zrotext_runtime;
        REVOKE ALL (account_id,state,selection_epoch) ON TABLE public.payload_profile_account_anchors FROM PUBLIC,zrotext_runtime;
        GRANT SELECT ON TABLE public.payload_profile_account_anchors TO zrotext_runtime;
        GRANT UPDATE(account_id) ON TABLE public.payload_profile_account_anchors TO zrotext_runtime;
        GRANT EXECUTE ON FUNCTION public.payload_profile_account_fence_key(uuid) TO zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_anchor_row_guard() FROM PUBLIC,zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_anchor_account_created() FROM PUBLIC,zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_anchor_account_changing() FROM PUBLIC,zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_anchor_account_deleted() FROM PUBLIC,zrotext_runtime;
    END IF;
END $$;
DO $$
BEGIN
    IF to_regprocedure('public.parent_account_mirror_guard()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION public.parent_account_mirror_guard() FROM PUBLIC,zrotext_runtime;
    END IF;
    IF to_regprocedure('public.user_membership_freshness_guard()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION public.user_membership_freshness_guard() FROM PUBLIC,zrotext_runtime;
    END IF;
END $$;
-- Review persistence remains SELECT only. Only explicit authenticated access
-- wrappers are callable; original owner/test factories and internal helpers
-- remain unavailable even after broad/default grants and provisioner reruns.
DO $$
DECLARE relation_name text;
        columns_sql text;
        routine record;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_broker_sessions','review_bootstrap_attempts','review_workspaces'] LOOP
        -- 104 relations use the same relation AND column reset below.
        IF to_regclass(format('public.%I',relation_name)) IS NULL THEN CONTINUE; END IF;
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
          FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name))
            AND attnum>0 AND NOT attisdropped;
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zrotext_runtime',relation_name);
        EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
        EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
    END LOOP;
    FOR routine IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
      WHERE p.pronamespace='public'::regnamespace AND
        (p.proname LIKE 'review_workspace_%' OR p.proname LIKE 'review_access_%') LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zrotext_runtime',routine.signature);
    END LOOP;
END $$;
DO $$
DECLARE relation_name text; columns_sql text; signature text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['review_access_preparations','review_access_sessions',
        'review_access_authentications','review_access_root_reauth','review_access_locators'] LOOP
        IF to_regclass(format('public.%I',relation_name)) IS NULL THEN CONTINUE; END IF;
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
          WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zrotext_runtime',relation_name);
        EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
        EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
    END LOOP;
    IF to_regclass('public.review_access_preparations') IS NOT NULL THEN
        FOREACH signature IN ARRAY ARRAY[
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
        ] LOOP
            IF to_regprocedure(signature) IS NULL THEN RAISE EXCEPTION 'review access wrapper missing'; END IF;
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',signature);
        END LOOP;
    END IF;
END $$;
-- Isolated hosted runtime has its own proof and operator-only review boundary.
-- Reset relation, column and default-derived helper grants on every rerun.
DO $$
DECLARE relation_name text; columns_sql text; routine record;
BEGIN
    IF to_regclass('public.hosted_runtime_secrets') IS NOT NULL THEN
        FOREACH relation_name IN ARRAY ARRAY['hosted_runtime_secrets','hosted_runtime_sessions','hosted_billing_resolutions','hosted_billing_namespaces','hosted_billing_history'] LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
              WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zrotext_runtime',relation_name);
            EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
        END LOOP;
        GRANT SELECT,UPDATE(review_required) ON TABLE public.hosted_billing_namespaces TO zrotext_runtime;
        GRANT SELECT,INSERT ON TABLE public.hosted_billing_history TO zrotext_runtime;
        FOR routine IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
          WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_%'
            AND (p.prosecdef OR p.proname='hosted_resolve_review') LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zrotext_runtime',routine.signature);
        END LOOP;
        GRANT EXECUTE ON FUNCTION public.hosted_runtime_role_safe(),public.hosted_runtime_challenge(uuid,bigint),
          public.hosted_runtime_bind(uuid,bigint,bytea),public.hosted_runtime_verified(uuid,bigint) TO zrotext_runtime;
    END IF;
END $$;
-- The registration trigger runs only in its table's trigger context. Broad
-- function defaults must not regrant direct execution during reprovisioning.
DO $$
BEGIN
    IF to_regprocedure('public.registration_browser_intent_binding_guard()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION public.registration_browser_intent_binding_guard() FROM PUBLIC,zrotext_runtime;
    END IF;
END $$;
-- Mandatory writer helpers are trigger-only; the finite schema baseline and
-- global row versions remain read-only after broad/default grants or reruns.
DO $$
DECLARE relation_name text; columns_sql text;
BEGIN
    IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
        FOREACH relation_name IN ARRAY ARRAY['payload_profile_writer_catalog','payload_profile_writer_global_fences'] LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
              WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zrotext_runtime',relation_name);
            EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
            EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
        END LOOP;
        REVOKE ALL ON FUNCTION public.payload_profile_writer_guard(),public.payload_profile_writer_global_guard(),public.payload_profile_writer_catalog_guard() FROM PUBLIC,zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_writer_json(json),public.payload_profile_writer_graph(),public.payload_profile_writer_version(),public.payload_profile_writer_ready() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.payload_profile_writer_json(json),public.payload_profile_writer_graph(),public.payload_profile_writer_version(),public.payload_profile_writer_ready() TO zrotext_runtime;
    END IF;
END $$;
-- Accepted original proofs have one narrow fresh-capture entry point. Broad
-- defaults and reprovisioning must never grant direct row/column mutation.
DO $$
DECLARE columns_sql text;
BEGIN
    IF to_regclass('public.payload_profile_v2_activation_receipts') IS NOT NULL THEN
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
          WHERE attrelid='public.payload_profile_v2_activation_receipts'::regclass AND attnum>0 AND NOT attisdropped;
        REVOKE ALL ON TABLE public.payload_profile_v2_activation_receipts FROM PUBLIC,zrotext_runtime;
        EXECUTE format('REVOKE ALL (%s) ON TABLE public.payload_profile_v2_activation_receipts FROM PUBLIC,zrotext_runtime',columns_sql);
        GRANT SELECT ON TABLE public.payload_profile_v2_activation_receipts TO zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_v2_receipt_guard(),public.payload_profile_v2_receipt_complete() FROM PUBLIC,zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready() TO zrotext_runtime;
    END IF;
END $$;
-- Election rows and epoch helpers are never broad runtime DML.
DO $migration$
DECLARE routine record; relation_name text; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'payload_profile_election'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND (starts_with(proname::text,'payload_profile_election_') OR proname IN('payload_profile_epoch_valid','payload_profile_writer_policy'))) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=110 THEN
   RAISE EXCEPTION 'recorded capability 110 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 109 THEN
    RAISE EXCEPTION 'earlier writer installation for 110 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('payload_profile_election_challenges','payload_profile_elections') AND relkind='r')<>2
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'payload_profile_election') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['payload_profile_election_accept','payload_profile_election_complete','payload_profile_election_device_proof','payload_profile_election_frame','payload_profile_election_number','payload_profile_election_old_binding','payload_profile_election_quiescent','payload_profile_election_reader','payload_profile_election_ready','payload_profile_election_reserve','payload_profile_election_rows_guard','payload_profile_election_scope','payload_profile_election_uuid','payload_profile_epoch_valid','payload_profile_writer_policy']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 110 installation'; END IF;
 FOREACH relation_name IN ARRAY ARRAY['payload_profile_election_challenges','payload_profile_elections'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
  AND(p.proname LIKE 'payload_profile_election_%' OR p.proname IN('payload_profile_epoch_valid','payload_profile_writer_policy')) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_election_reserve','payload_profile_election_device_proof','payload_profile_election_accept','payload_profile_election_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

-- Same-phone physical receipts are narrow writes, never message permission.
DO $migration$
DECLARE routine record; relation_name text; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'payload_profile_selection_'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'payload_profile_selection_')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=111 THEN
   RAISE EXCEPTION 'recorded capability 111 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 110 THEN
    RAISE EXCEPTION 'earlier writer installation for 111 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('payload_profile_selection_challenges','payload_profile_selection_receipts') AND relkind='r')<>2
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'payload_profile_selection_') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['payload_profile_selection_approve','payload_profile_selection_complete','payload_profile_selection_device_proof','payload_profile_selection_install','payload_profile_selection_observation','payload_profile_selection_owner','payload_profile_selection_ready','payload_profile_selection_reserve','payload_profile_selection_rows_guard','payload_profile_selection_same_scope','payload_profile_selection_scope']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 111 installation'; END IF;
 FOREACH relation_name IN ARRAY ARRAY['payload_profile_selection_challenges','payload_profile_selection_receipts'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_selection_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_selection_reserve','payload_profile_selection_device_proof','payload_profile_selection_approve','payload_profile_selection_install','payload_profile_selection_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

-- Same-root03 successor rows are immutable and narrow-write only.
DO $migration$
DECLARE routine record; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'payload_profile_manifest_'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'payload_profile_manifest_')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=112 THEN
   RAISE EXCEPTION 'recorded capability 112 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 111 THEN
    RAISE EXCEPTION 'earlier writer installation for 112 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('payload_profile_manifest_successors') AND relkind='r')<>1
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'payload_profile_manifest_') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['payload_profile_manifest_ancestry','payload_profile_manifest_base','payload_profile_manifest_complete','payload_profile_manifest_context','payload_profile_manifest_install','payload_profile_manifest_keys','payload_profile_manifest_ready','payload_profile_manifest_retention','payload_profile_manifest_rows_guard','payload_profile_manifest_scope','payload_profile_manifest_step']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 112 installation'; END IF;
 REVOKE ALL ON TABLE public.payload_profile_manifest_successors FROM PUBLIC;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.payload_profile_manifest_successors'::regclass AND attnum>0 AND NOT attisdropped;
  REVOKE ALL ON TABLE public.payload_profile_manifest_successors FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.payload_profile_manifest_successors FROM PUBLIC,zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.payload_profile_manifest_successors TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_manifest_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_manifest_install','payload_profile_manifest_retention','payload_profile_manifest_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;
-- Additive installed conversation03 consent, narrow writes only.
DO $migration$
DECLARE routine record; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'conversation_profile03_intervals'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'conversation_profile03_interval_')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=113 THEN
   RAISE EXCEPTION 'recorded capability 113 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 112 THEN
    RAISE EXCEPTION 'earlier writer installation for 113 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('conversation_profile03_intervals') AND relkind='r')<>1
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'conversation_profile03_intervals') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['conversation_profile03_interval_approve','conversation_profile03_interval_complete','conversation_profile03_interval_device_actor','conversation_profile03_interval_device_stop','conversation_profile03_interval_install','conversation_profile03_interval_lock','conversation_profile03_interval_parse','conversation_profile03_interval_ready','conversation_profile03_interval_request','conversation_profile03_interval_reserve','conversation_profile03_interval_rows_guard','conversation_profile03_interval_scope','conversation_profile03_interval_stop']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 113 installation'; END IF;
 REVOKE ALL ON TABLE public.conversation_profile03_intervals FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_profile03_intervals'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_intervals FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_profile03_intervals FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_intervals FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_profile03_intervals TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_profile03_interval_reserve','conversation_profile03_interval_request','conversation_profile03_interval_approve','conversation_profile03_interval_install','conversation_profile03_interval_stop','conversation_profile03_interval_device_stop','conversation_profile03_interval_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;
-- Original reviewed03 admission, closed sidecar capture only.
DO $migration$
DECLARE routine record; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'conversation_reviewed_sends03'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'conversation_reviewed_send03_')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=114 THEN
   RAISE EXCEPTION 'recorded capability 114 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 113 THEN
    RAISE EXCEPTION 'earlier writer installation for 114 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('conversation_reviewed_sends03') AND relkind='r')<>1
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'conversation_reviewed_sends03') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['conversation_reviewed_send03_admit','conversation_reviewed_send03_complete','conversation_reviewed_send03_envelope','conversation_reviewed_send03_erasure_fence','conversation_reviewed_send03_message_redact','conversation_reviewed_send03_parse','conversation_reviewed_send03_ready','conversation_reviewed_send03_rows_guard','conversation_reviewed_send03_scope','conversation_reviewed_send03_writer']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 114 installation'; END IF;
 REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_reviewed_sends03'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_reviewed_sends03 TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_reviewed_send03_admit','conversation_reviewed_send03_ready','conversation_reviewed_send03_v2_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;
-- Distinct one-use03 grant, all other effect transitions stay closed.
DO $migration$
DECLARE routine record; columns_sql text;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'conversation_profile03_grants'))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'conversation_profile03_grant_')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=115 THEN
   RAISE EXCEPTION 'recorded capability 115 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 114 THEN
    RAISE EXCEPTION 'earlier writer installation for 115 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('conversation_profile03_grants') AND relkind='r')<>1
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND starts_with(relname::text,'conversation_profile03_grants') AND relkind NOT IN('r','i'))
  OR NOT ARRAY['conversation_profile03_grant_billing','conversation_profile03_grant_complete','conversation_profile03_grant_issue','conversation_profile03_grant_issued','conversation_profile03_grant_lock','conversation_profile03_grant_mode','conversation_profile03_grant_ready','conversation_profile03_grant_rows_guard','conversation_profile03_grant_same_scope','conversation_profile03_grant_scope','conversation_profile03_grant_usage_writer','conversation_profile03_grant_writer']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 115 installation'; END IF;
 REVOKE ALL ON TABLE public.conversation_profile03_grants FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_profile03_grants'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_grants FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_profile03_grants FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_grants FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_profile03_grants TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_grant_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_profile03_grant_issue','conversation_profile03_grant_lock','conversation_profile03_grant_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;
-- Native backend inputs are computed by defaults, never runtime-writable.
DO $migration$
DECLARE relation_name text; columns_sql text; routine record;
        recorded_version bigint;writer_rows bigint;
BEGIN
 -- Only a completely absent earlier capability may skip this reset.
 IF NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace AND (starts_with(relname::text,'hosted_runtime_entries') OR starts_with(relname::text,'hosted_runtime_requests')))
  AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN('hosted_runtime_native_start','hosted_runtime_native_schema_valid','hosted_runtime_identity_ready','hosted_runtime_scope','hosted_runtime_expiry','hosted_runtime_request_apply','hosted_runtime_request_remove','hosted_runtime_enter')) THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=116 THEN
   RAISE EXCEPTION 'recorded capability 116 is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 115 THEN
    RAISE EXCEPTION 'earlier writer installation for 116 is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
      AND relname IN('hosted_runtime_entries','hosted_runtime_requests') AND relkind='r')<>2
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
      AND (starts_with(relname::text,'hosted_runtime_entries') OR starts_with(relname::text,'hosted_runtime_requests')) AND relkind NOT IN('r','i'))
  OR NOT ARRAY['hosted_runtime_native_start','hosted_runtime_native_schema_valid','hosted_runtime_identity_ready','hosted_runtime_scope','hosted_runtime_expiry','hosted_runtime_request_apply','hosted_runtime_request_remove','hosted_runtime_enter']::text[] <@ ARRAY(SELECT proname::text FROM pg_proc
      WHERE pronamespace='public'::regnamespace) THEN
  RAISE EXCEPTION 'partial capability 116 installation'; END IF;
 FOREACH relation_name IN ARRAY ARRAY['hosted_runtime_entries','hosted_runtime_requests'] LOOP
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
   WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC',columns_sql,relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM zrotext_runtime',columns_sql,relation_name);
  END IF;
 END LOOP;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  GRANT INSERT(operation,namespace_id,policy_revision,proof),SELECT(result) ON public.hosted_runtime_requests TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

-- First-origin ledgers are readable history, never direct writable authority.
DO $migration$
DECLARE relation_name text;columns_sql text;routine record;
        protection_objects bigint;protection_relations bigint;protection_helpers bigint;recorded_version bigint;writer_rows bigint;
BEGIN
 -- Earlier supported installations have none of this capability. Refuse any
 -- partial graph or recorded new installation instead of silently granting
 -- ordinary DML after its protection objects have disappeared.
 SELECT count(*),count(*) FILTER(WHERE relkind='r') INTO protection_objects,protection_relations FROM pg_class
  WHERE relnamespace='public'::regnamespace AND starts_with(relname::text,'device_protection_');
 SELECT count(*) INTO protection_helpers FROM pg_proc
  WHERE pronamespace='public'::regnamespace AND starts_with(proname::text,'device_protection_');
 IF protection_objects=0 AND protection_helpers=0 THEN
  SELECT max(version) INTO recorded_version FROM public.schema_migrations;
  IF coalesce(recorded_version,0)>=118 THEN
   RAISE EXCEPTION 'recorded device protection installation is absent'; END IF;
  IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
   SELECT count(*),max(migration_version) INTO writer_rows,recorded_version
    FROM public.payload_profile_writer_catalog WHERE singleton;
   IF coalesce(recorded_version,0)>=118 THEN
    RAISE EXCEPTION 'recorded device protection graph is absent'; END IF;
   IF writer_rows<>1 OR recorded_version IS NULL OR recorded_version NOT BETWEEN 108 AND 117 THEN
    RAISE EXCEPTION 'earlier writer installation is unavailable'; END IF;
  END IF;
  RETURN;
 END IF;
 IF protection_relations<>5 OR protection_helpers<>11
  OR EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace
   AND starts_with(relname::text,'device_protection_') AND relkind NOT IN('r','i')) THEN
  RAISE EXCEPTION 'partial device protection installation'; END IF;
 FOREACH relation_name IN ARRAY ARRAY['device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
   WHERE attrelid=format('public.%I',relation_name)::regclass AND attnum>0 AND NOT attisdropped;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC',columns_sql,relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('device_protection_lock','device_protection_open','device_protection_attempt','device_protection_accept','device_protection_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;
COMMIT;
