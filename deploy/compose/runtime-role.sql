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
-- Review-realm persistence is unmounted: runtime SELECT only, no factory call.
DO $$
DECLARE relation_name text;
        columns_sql text;
        routine record;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_broker_sessions','review_bootstrap_attempts','review_workspaces'] LOOP
        IF to_regclass(format('public.%I',relation_name)) IS NULL THEN CONTINUE; END IF;
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
          FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name))
            AND attnum>0 AND NOT attisdropped;
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zrotext_runtime',relation_name);
        EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
        EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
    END LOOP;
    FOR routine IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
      WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'review_workspace_%' LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zrotext_runtime',routine.signature);
    END LOOP;
END $$;
COMMIT;
