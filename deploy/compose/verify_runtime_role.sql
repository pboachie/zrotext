-- SPDX-License-Identifier: AGPL-3.0-only
-- Run as runtime in the disposable smoke database. All writes roll back.
BEGIN;
DO $$
DECLARE
    statement text;
BEGIN
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
END $$;
ROLLBACK;
