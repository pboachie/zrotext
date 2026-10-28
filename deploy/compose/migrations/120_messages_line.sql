-- SPDX-License-Identifier: AGPL-3.0-only
-- ADR 0004 submit path: the immutable line identity a submission resolved to
-- at admission. The label is mutable presentation; this column stores only
-- the account-scoped line identity, never a SIM slot, subscription
-- identifier, ICCID, IMSI or phone number. NULL keeps the pre-line routing
-- behavior for requests that do not address a line by label.

ALTER TABLE messages ADD COLUMN line_id uuid;

ALTER TABLE messages
    ADD CONSTRAINT messages_owner_line
    FOREIGN KEY (account_id, line_id) REFERENCES phone_lines (account_id, id);

CREATE INDEX messages_account_line ON messages (account_id, line_id)
    WHERE line_id IS NOT NULL;

-- Writer-graph ceremony for the new installation version: the schema
-- version helpers and the hosted identity gates name the current
-- migration count, and the writer catalog records this version with the
-- unchanged canonical graph bytes. The ceremony applies wherever the
-- compiled108+ writer graph is installed; every ordinary installation
-- and the migration runner always have it. Curated in-schema test
-- fixtures that deliberately stop before the writer era keep their
-- partial schema instead.
DO $ceremony$
BEGIN
    IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=120 AND min(version)=1 AND max(version)=120 FROM public.schema_migrations
$function$;
$ddl$;
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=120 AND graph_sha256=public.payload_profile_writer_graph()
  AND (SELECT count(*)=12 AND bool_and(revision>=0) FROM public.payload_profile_writer_global_fences)
  AND NOT EXISTS(SELECT FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND t.tgisinternal AND t.tgenabled<>'O')
  AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND a.grantee=0)
  AND NOT EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0)
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_writer_%' AND a.grantee=0 AND a.privilege_type='EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
  AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=current_user::regrole)
  AND NOT has_schema_privilege(current_user,'public','CREATE')
  AND NOT has_database_privilege(current_user,current_database(),'CREATE,TEMP')
  AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND has_table_privilege(current_user,c.oid,'TRUNCATE,REFERENCES,TRIGGER'))
  AND NOT has_table_privilege(current_user,'public.payload_profile_account_anchors','INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','state','UPDATE')
  AND NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','selection_epoch','UPDATE')
  AND has_column_privilege(current_user,'public.payload_profile_account_anchors','account_id','UPDATE')
  AND NOT has_table_privilege(current_user,'public.payload_profile_writer_catalog','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_table_privilege(current_user,'public.payload_profile_writer_global_fences','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_writer_catalog','INSERT,UPDATE,REFERENCES')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_writer_global_fences','INSERT,UPDATE,REFERENCES')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_guard()','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_global_guard()','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_catalog_guard()','EXECUTE')
  FROM public.payload_profile_writer_catalog WHERE singleton),false)
$function$;
$ddl$;
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.hosted_runtime_native_schema_valid() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT public.hosted_runtime_role_safe() AND public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=120 AND graph_sha256=public.payload_profile_writer_graph()
 FROM public.payload_profile_writer_catalog WHERE singleton),false) AND NOT EXISTS(SELECT FROM pg_roles WHERE oid=(SESSION_USER::regrole)::oid AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SESSION_USER::regrole)::oid)
 AND NOT has_database_privilege((SESSION_USER::regrole)::oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass) AND a.grantee<>c.relowner)
 AND NOT EXISTS(SELECT FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass)
   AND x.grantee<>c.relowner AND(c.relname<>'hosted_runtime_requests' OR x.grantee<>(SESSION_USER::regrole)::oid))
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass)
  AND(has_table_privilege((SESSION_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege((SESSION_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT has_table_privilege((SESSION_USER::regrole)::oid,'public.hosted_runtime_requests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege((SESSION_USER::regrole)::oid,'public.hosted_runtime_requests','UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.hosted_runtime_requests'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND(has_column_privilege((SESSION_USER::regrole)::oid,a.attrelid,a.attname,'INSERT') IS DISTINCT FROM(a.attname IN('operation','namespace_id','policy_revision','proof'))
   OR has_column_privilege((SESSION_USER::regrole)::oid,a.attrelid,a.attname,'SELECT') IS DISTINCT FROM(a.attname='result')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
  AND has_function_privilege((SESSION_USER::regrole)::oid,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
   AND(a.grantee<>p.proowner AND(a.grantee<>(SESSION_USER::regrole)::oid OR p.proname NOT IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope'))))
$function$;
$ddl$;
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.hosted_runtime_identity_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready() AND public.payload_profile_writer_version()
 AND NOT EXISTS(SELECT FROM pg_roles WHERE oid=(CURRENT_USER::regrole)::oid AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(CURRENT_USER::regrole)::oid)
 AND NOT has_database_privilege((CURRENT_USER::regrole)::oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass) AND a.grantee<>c.relowner)
 AND NOT EXISTS(SELECT FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass)
   AND x.grantee<>c.relowner AND(c.relname<>'hosted_runtime_requests' OR x.grantee<>(CURRENT_USER::regrole)::oid))
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass)
  AND(has_table_privilege((CURRENT_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege((CURRENT_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT has_table_privilege((CURRENT_USER::regrole)::oid,'public.hosted_runtime_requests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege((CURRENT_USER::regrole)::oid,'public.hosted_runtime_requests','UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.hosted_runtime_requests'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND(has_column_privilege((CURRENT_USER::regrole)::oid,a.attrelid,a.attname,'INSERT') IS DISTINCT FROM(a.attname IN('operation','namespace_id','policy_revision','proof'))
   OR has_column_privilege((CURRENT_USER::regrole)::oid,a.attrelid,a.attname,'SELECT') IS DISTINCT FROM(a.attname='result')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
  AND has_function_privilege((CURRENT_USER::regrole)::oid,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
   AND(a.grantee<>p.proowner AND(a.grantee<>(CURRENT_USER::regrole)::oid OR p.proname NOT IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope'))))
$function$;
$ddl$;
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.hosted_runtime_scope() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE fence bigint;
BEGIN
 IF (public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=120 AND graph_sha256=public.payload_profile_writer_graph()
 FROM public.payload_profile_writer_catalog WHERE singleton),false) AND(SELECT count(*)=12 AND bool_and(revision>=0) FROM public.payload_profile_writer_global_fences)) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'hosted namespace scope schema unavailable' USING ERRCODE='23514'; END IF;
 -- This is an actual transaction-held absence/selection fence, not identity.
 -- Namespace transitions already take EXCLUSIVE and version this SAME tuple.
 fence:=('x'||substr(encode(sha256(convert_to('ZTSE/writer/global/v1:hosted_configuration','UTF8')),'hex'),1,16))::bit(64)::bigint;
 IF NOT pg_try_advisory_xact_lock_shared(fence) THEN
  RAISE EXCEPTION 'hosted namespace scope busy' USING ERRCODE='55P03'; END IF;
 PERFORM operation_class FROM public.payload_profile_writer_global_fences
  WHERE operation_class='hosted_configuration' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'hosted namespace scope missing' USING ERRCODE='23514'; END IF;
END;
$function$;
$ddl$;
        EXECUTE $ddl$
CREATE OR REPLACE FUNCTION public.device_protection_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready()
 AND coalesce((SELECT migration_version=120 AND graph_sha256=public.payload_profile_writer_graph()
  FROM public.payload_profile_writer_catalog WHERE singleton),false)
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname IN
  ('device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements')
  AND(NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%'
  AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN
   ('device_protection_lock','device_protection_open','device_protection_attempt','device_protection_accept','device_protection_ready')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%' AND a.grantee=0)
$function$;
$ddl$;
        DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
        ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
        DELETE FROM public.payload_profile_writer_catalog;
        ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=120);
        CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
         FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
        INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,120,public.payload_profile_writer_graph());
    END IF;
END $ceremony$;
