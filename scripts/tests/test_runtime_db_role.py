#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise role provisioning in a new disposable local PostgreSQL container."""

import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest

COMPOSE = Path(__file__).resolve().parents[2] / "deploy" / "compose"
sys.path.insert(0, str(COMPOSE))
from fresh_install_smoke import ensure_local_docker  # noqa: E402


OWNER_LABEL = "org.zrotext.runtime-role-test"


def remove_owned_container(name, owner):
    """Resolve an exact name, then verify ownership and remove only its immutable ID."""
    listed = subprocess.run(
        ["docker", "container", "ls", "--all", "--no-trunc", "--filter",
         "name=^/" + name + "$", "--format", "{{.ID}}"],
        check=True, capture_output=True, text=True, timeout=60)
    identity = listed.stdout.strip()
    if not identity:
        return  # A successful listing proves no matching container exists.
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise RuntimeError("unexpected disposable container identity")
    inspected = subprocess.run(
        ["docker", "container", "inspect", "--format", "{{json .Config.Labels}}", identity],
        check=True, capture_output=True, text=True, timeout=60)
    if len(inspected.stdout) > 4096:
        raise RuntimeError("unexpected disposable container ownership")
    try:
        labels = json.loads(inspected.stdout)
    except (ValueError, TypeError):
        raise RuntimeError("invalid disposable container ownership") from None
    if not isinstance(labels, dict) or labels.get(OWNER_LABEL) != owner:
        raise RuntimeError("disposable container ownership mismatch")
    subprocess.run(["docker", "rm", "-f", "-v", identity], check=True,
                   capture_output=True, timeout=60)


class RuntimeRoleFixture:
    migration_limit = None

    @classmethod
    def setUpClass(cls):
        ensure_local_docker()
        cls.container = "zt-role-test-" + secrets.token_hex(8)
        owner = secrets.token_hex(32)
        cls.addClassCleanup(remove_owned_container, cls.container, owner)
        cls.env = dict(os.environ, POSTGRES_PASSWORD=secrets.token_hex(32),
                       RUNTIME_DATABASE_PASSWORD=secrets.token_hex(32))
        subprocess.run(["docker", "run", "--detach", "--name", cls.container,
                        "--label", OWNER_LABEL + "=" + owner,
                        "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_USER=zrotext",
                        "-e", "POSTGRES_DB=zrotext",
                        "docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"],
                       env=cls.env, check=True, capture_output=True, timeout=60)
        for _ in range(60):
            ready = subprocess.run(["docker", "exec", cls.container, "pg_isready",
                                    "-h", "127.0.0.1", "-U", "zrotext"],
                                   capture_output=True, timeout=10)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("disposable database startup timed out")
        cls.sql("CREATE TABLE schema_migrations(version integer);")
        for migration in sorted((COMPOSE / "migrations").glob("*.sql")):
            if cls.migration_limit is not None and int(migration.name[:3]) > cls.migration_limit:
                continue
            if migration.name == "034_delivery_sweep_index.sql":
                # The migrator prepares this index in autocommit mode before
                # applying the numbered validation file in a transaction.
                cls.sql("CREATE INDEX CONCURRENTLY messages_in_flight_updated "
                        "ON public.messages(updated_at,id) "
                        "WHERE state IN ('claimed','submitting','submitted');")
            if migration.name == "040_radio_evidence_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY message_events_attempt_evidence "
                        "ON public.message_events(attempt_id,evidence_code)")
            if migration.name == "049_owner_queue_probe_indexes.sql":
                cls.sql("CREATE INDEX CONCURRENTLY messages_owner_pending_state "
                        "ON public.messages(device_id,state,created_at) "
                        "WHERE state IN ('accepted','queued','claimed');")
                cls.sql("CREATE INDEX CONCURRENTLY messages_owner_in_flight_state "
                        "ON public.messages(device_id,state,created_at) "
                        "WHERE state IN ('submitting','submitted');")
            if migration.name == "070_message_summary_metadata.sql":
                cls.sql("CREATE INDEX CONCURRENTLY messages_summary_queue "
                        "ON public.messages(account_id,state,created_at) "
                        "WHERE state IN ('accepted','queued','claimed','submitting','submitted');")
            if migration.name == "057_webhook_history_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY webhook_deliveries_history "
                        "ON public.webhook_deliveries(endpoint_id,created_at DESC,id DESC);")
            if migration.name == "060_optout_review_indexes.sql":
                cls.sql("CREATE INDEX CONCURRENTLY recipient_suppressions_review_queue "
                        "ON public.recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) "
                        "WHERE active AND source IN ('sms_review','sms_unsolicited_review');")
                cls.sql("CREATE INDEX CONCURRENTLY recipient_suppressions_review_event "
                        "ON public.recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) "
                        "WHERE source IN ('sms_review','sms_unsolicited_review');")
                cls.sql("DROP INDEX CONCURRENTLY IF EXISTS "
                        "public.recipient_suppressions_active;")
            if migration.name == "066_conversation_interval_session_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_conversation_interval_session "
                        "ON public.conversation_intervals(account_id,initiating_session_id);")
            if migration.name == "062_pending_recipient_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY messages_pending_recipient "
                        "ON public.messages(recipient_e164,account_id) "
                        "WHERE state IN ('queued','claimed') "
                        "AND recipient_e164 IS NOT NULL;")
            if migration.name == "061_inbound_events_attempt_fk_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_inbound_events_attempt "
                        "ON public.inbound_events(account_id,device_id,message_id,attempt_id);")
            if migration.name == "058_drop_abuse_counters_updated_index.sql":
                cls.sql("DROP INDEX CONCURRENTLY IF EXISTS "
                        "public.auth_abuse_counters_stale;")
            if migration.name == "059_erasure_fk_indexes.sql":
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_webhook_deliveries_event "
                        "ON public.webhook_deliveries(account_id,event_id);")
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_suppressions_attempt "
                        "ON public.recipient_suppressions(source_attempt_id);")
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_suppressions_event "
                        "ON public.recipient_suppressions(account_id,source_event_id);")
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_holds_release_event "
                        "ON public.owner_recipient_holds(account_id,release_event_id) "
                        "WHERE release_event_id IS NOT NULL;")
                cls.sql("CREATE INDEX CONCURRENTLY erasure_fk_opt_out_audit_release_event "
                        "ON public.owner_opt_out_audit(account_id,release_event_id) "
                        "WHERE release_event_id IS NOT NULL;")
            if migration.name == "050_message_attempts_recent_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY message_attempts_device_created "
                        "ON public.message_attempts(account_id,device_id,created_at);")
            if migration.name == "052_admission_pending_index.sql":
                cls.sql("CREATE INDEX CONCURRENTLY messages_admission_pending "
                        "ON public.messages(account_id,device_id) "
                        "WHERE state IN ('queued','claimed');")
            cls.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")

    @classmethod
    def sql(cls, sql, *, runtime=False, password=None, success=True):
        env = dict(cls.env)
        if password is not None:
            env["RUNTIME_DATABASE_PASSWORD"] = password
        env["PGPASSWORD"] = env["RUNTIME_DATABASE_PASSWORD"] if runtime else env["POSTGRES_PASSWORD"]
        result = subprocess.run(
            ["docker", "exec", "-i", "-e", "PGPASSWORD", "-e", "RUNTIME_DATABASE_PASSWORD",
             cls.container, "psql", "-X", "-q", "-h", "127.0.0.1",
             "-U", "zrotext_runtime" if runtime else "zrotext", "-d", "zrotext",
             "-v", "ON_ERROR_STOP=1", "-f", "-"], env=env, input=sql, text=True,
            capture_output=True, timeout=30)
        if (result.returncode == 0) != success:
            # Do not include SQL/output: provisioning commands contain credentials.
            raise AssertionError("unexpected database command result")
        for secret in (env["POSTGRES_PASSWORD"], env["RUNTIME_DATABASE_PASSWORD"]):
            if secret in result.stdout + result.stderr:
                raise AssertionError("database command exposed a credential")
        return result

    def provision(self, **kwargs):
        return self.sql((COMPOSE / "runtime-role.sql").read_text(encoding="utf-8"), **kwargs)

class RuntimeRoleTest(RuntimeRoleFixture, unittest.TestCase):
    def test_registration_trigger_permission_is_repaired_after_reprovisioning(self):
        self.provision()
        self.sql("GRANT EXECUTE ON FUNCTION public.registration_browser_intent_binding_guard() "
                 "TO PUBLIC,zrotext_runtime;")
        self.provision()
        self.sql("DO $$ BEGIN IF has_function_privilege(current_user,"
                 "'public.registration_browser_intent_binding_guard()','EXECUTE') THEN "
                 "RAISE EXCEPTION 'registration trigger execute grant retained'; END IF; END $$;",
                 runtime=True)
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)

    def test_provision_upgrade_and_defenses(self):
        # Existing schema/volume migration path, then repeat without resetting DB.
        self.provision()
        self.provision()
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        # New objects from the same migration owner inherit runtime privileges.
        self.sql("CREATE TABLE future_fixture(id bigint GENERATED ALWAYS AS IDENTITY, value text);"
                 "CREATE FUNCTION future_function() RETURNS integer LANGUAGE sql AS 'SELECT 1';")
        self.sql("INSERT INTO future_fixture(value) VALUES ('synthetic');"
                 "UPDATE future_fixture SET value = 'updated'; SELECT * FROM future_fixture;"
                 "DELETE FROM future_fixture; SELECT future_function();", runtime=True)
        self.provision()
        self.sql("DROP TABLE future_fixture; DROP FUNCTION future_function();")
        # Quote/backslash/shell metacharacters never become SQL or appear in output.
        for password in ("'\\; SELECT pg_sleep(30); --", '$(false)"`bad', "a" * 63, self.env["POSTGRES_PASSWORD"]):
            self.provision(password=password, success=False)
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        # Pre-existing role grants/ownership must fail, not silently retain power.
        self.sql("GRANT pg_read_server_files TO zrotext_runtime;")
        self.provision(success=False)
        self.sql("REVOKE pg_read_server_files FROM zrotext_runtime;"
                 "CREATE TABLE unsafe_owned_fixture(id integer);"
                 "ALTER TABLE unsafe_owned_fixture OWNER TO zrotext_runtime;")
        self.provision(success=False)
        self.sql("ALTER TABLE unsafe_owned_fixture OWNER TO zrotext; DROP TABLE unsafe_owned_fixture;")
        for grant, revoke in (
            ("CREATE SCHEMA extra; GRANT CREATE ON SCHEMA extra TO zrotext_runtime;",
             "REVOKE CREATE ON SCHEMA extra FROM zrotext_runtime; DROP SCHEMA extra;"),
            ("GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO zrotext_runtime;",
             "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM zrotext_runtime;"),
            ("ALTER DATABASE zrotext OWNER TO zrotext_runtime;",
             "ALTER DATABASE zrotext OWNER TO zrotext;"),
            ("ALTER SCHEMA public OWNER TO zrotext_runtime;",
             "ALTER SCHEMA public OWNER TO zrotext;"),
        ):
            self.sql(grant)
            self.provision(success=False)
            self.sql(revoke)
        self.sql("ALTER ROLE zrotext_runtime IN DATABASE zrotext SET search_path = extra;"
                 "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT TRUNCATE ON TABLES TO zrotext_runtime;")
        self.provision()
        self.sql("CREATE TABLE future_fixture(id integer);")
        self.sql("TRUNCATE future_fixture;", runtime=True, success=False)
        self.sql("DROP TABLE future_fixture;")
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)


class RuntimeRoleAnchorUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 99

    def test_existing_defaults_and_provisioner_reruns_preserve_anchor_authority(self):
        self.provision()
        self.sql("INSERT INTO public.accounts(id) VALUES ('01010101-0101-0101-0101-010101010101');")
        migration = COMPOSE / "migrations" / "100_payload_profile_account_anchors.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        # The migration must override pre-existing DML/EXECUTE defaults itself.
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        self.provision()
        self.provision()
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        # Relation REVOKE alone leaves column ACLs intact. Deliberately pollute
        # both PUBLIC and direct role grants, then require the whole provisioner
        # to close them again without changing the immutable anchor identity.
        self.sql("GRANT UPDATE(state,selection_epoch) ON public.payload_profile_account_anchors TO PUBLIC,zrotext_runtime;"
                 "GRANT EXECUTE ON FUNCTION public.payload_profile_anchor_account_created() TO PUBLIC,zrotext_runtime;")
        self.provision()
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        self.sql("DELETE FROM public.accounts WHERE id='01010101-0101-0101-0101-010101010101';", runtime=True)
        self.sql("DO $$ BEGIN IF NOT EXISTS (SELECT FROM public.payload_profile_account_anchors "
                 "WHERE account_id='01010101-0101-0101-0101-010101010101' AND state='deleted' AND selection_epoch=1) "
                 "THEN RAISE EXCEPTION 'upgraded identity tombstone missing'; END IF; END $$;", runtime=True)
        self.sql("INSERT INTO public.accounts(id) VALUES ('01010101-0101-0101-0101-010101010101');",
                 runtime=True, success=False)


class RuntimeRoleMembershipUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 102

    def test_membership_guard_upgrade_and_helper_grant_pollution_repair(self):
        self.provision()
        account = "10000000-0000-4000-8000-000000000001"
        user = "10000000-0000-4000-8000-000000000002"
        self.sql(f"INSERT INTO users(id,email,password_hash) VALUES('{user}','owner@review.invalid','!');"
                 f"INSERT INTO accounts(id) VALUES('{account}');"
                 f"INSERT INTO memberships(account_id,user_id,role) VALUES('{account}','{user}','owner');",
                 runtime=True)
        migration = COMPOSE / "migrations" / "103_user_membership_freshness.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        verify = (COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8")
        self.sql(verify, runtime=True)
        self.sql(f"UPDATE users SET password_hash='changed' WHERE id='{user}';", runtime=True)
        self.sql("SELECT public.user_membership_freshness_guard();", runtime=True, success=False)
        self.sql("ALTER TABLE public.users DISABLE TRIGGER user_membership_freshness_before_user_change;",
                 runtime=True, success=False)
        self.sql("TRUNCATE public.users CASCADE;", runtime=True, success=False)
        self.sql("GRANT EXECUTE ON FUNCTION public.user_membership_freshness_guard() TO PUBLIC,zrotext_runtime;")
        self.sql(verify, runtime=True, success=False)
        self.provision()
        self.provision()
        self.sql(verify, runtime=True)
        self.sql("SELECT public.user_membership_freshness_guard();", runtime=True, success=False)
        self.sql(f"BEGIN; DELETE FROM memberships WHERE account_id='{account}';"
                 f"DELETE FROM users WHERE id='{user}'; DELETE FROM accounts WHERE id='{account}'; COMMIT;",
                 runtime=True)
        result = self.sql(f"SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id='{account}';",
                          runtime=True)
        self.assertIn("deleted", result.stdout)
        self.assertRegex(result.stdout, r"deleted\s*\|\s*1")


class RuntimeRoleReviewWorkspaceUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 101

    def test_review_schema_overrides_broad_defaults_and_polluted_column_helper_grants(self):
        self.provision()
        migration = COMPOSE / "migrations" / "102_review_workspace_persistence.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        verify = (COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8")
        self.sql(verify, runtime=True)
        relations = ("review_realm_installation", "review_brokers",
                     "review_broker_sessions", "review_bootstrap_attempts", "review_workspaces")
        for relation in relations:
            for sql in (f"INSERT INTO public.{relation} DEFAULT VALUES;",
                        f"DELETE FROM public.{relation};",
                        f"TRUNCATE public.{relation};"):
                self.sql(sql, runtime=True, success=False)
        # Old column ACLs survive relation REVOKE. Pollute every actual column
        # for both PUBLIC and the role, and every exact new helper signature.
        self.sql("""DO $$ DECLARE r record; columns_sql text; BEGIN
          FOR r IN SELECT c.oid,c.relname FROM pg_class c WHERE c.relnamespace='public'::regnamespace
            AND c.relname IN ('review_realm_installation','review_brokers','review_broker_sessions',
                             'review_bootstrap_attempts','review_workspaces') LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
              FROM pg_attribute WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped;
            EXECUTE format('GRANT INSERT (%s),UPDATE (%s),REFERENCES (%s) ON TABLE public.%I TO PUBLIC,zrotext_runtime',
                           columns_sql,columns_sql,columns_sql,r.relname);
            EXECUTE format('GRANT ALL ON TABLE public.%I TO PUBLIC,zrotext_runtime',r.relname);
          END LOOP;
          FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
            WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'review_workspace_%' LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC,zrotext_runtime',r.signature);
          END LOOP;
        END $$;""")
        self.sql(verify, runtime=True, success=False)
        self.provision()
        self.provision()
        self.sql(verify, runtime=True)
        self.sql("SELECT public.review_workspace_before_delete();", runtime=True, success=False)
        self.sql("SELECT public.review_workspace_reserve(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);",
                 runtime=True, success=False)
        self.sql("SELECT public.review_workspace_provision(NULL,NULL,NULL,NULL,NULL,NULL,NULL);",
                 runtime=True, success=False)


class RuntimeRoleReviewAccessUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 103

    def test_access_upgrade_and_full_default_column_helper_pollution_repair(self):
        self.provision()
        self.sql("CREATE FUNCTION public.review_access_prune(integer) RETURNS bigint LANGUAGE sql AS 'SELECT $1::bigint'; "
                 "GRANT EXECUTE ON FUNCTION public.review_access_prune(integer) TO PUBLIC,zrotext_runtime;")
        migration = COMPOSE / "migrations" / "104_review_root_access.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        verify = (COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8")
        self.sql(verify, runtime=True)
        self.sql("SELECT public.review_access_prune(1);", runtime=True, success=False)
        self.sql("""DO $$ DECLARE r record; columns_sql text; BEGIN
          FOR r IN SELECT c.oid,c.relname FROM pg_class c WHERE c.relnamespace='public'::regnamespace
            AND c.relname LIKE 'review_%' AND c.relkind='r' LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
              FROM pg_attribute WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped;
            EXECUTE format('GRANT SELECT (%s),INSERT (%s),UPDATE (%s),REFERENCES (%s) ON TABLE public.%I TO PUBLIC,zrotext_runtime',
                           columns_sql,columns_sql,columns_sql,columns_sql,r.relname);
            EXECUTE format('GRANT ALL ON TABLE public.%I TO PUBLIC,zrotext_runtime',r.relname);
          END LOOP;
          FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
            WHERE p.pronamespace='public'::regnamespace
              AND (p.proname LIKE 'review_workspace_%' OR p.proname LIKE 'review_access_%') LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC,zrotext_runtime',r.signature);
          END LOOP;
        END $$;
        ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO PUBLIC,zrotext_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC,zrotext_runtime;
        ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC,zrotext_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO PUBLIC,zrotext_runtime;
        """)
        self.sql(verify, runtime=True, success=False)
        self.provision()
        self.provision()
        self.sql(verify, runtime=True)
        self.sql("SELECT public.review_access_prune(1);", runtime=True, success=False)
        for relation in ("review_access_preparations", "review_access_sessions",
                         "review_access_authentications", "review_access_root_reauth", "review_access_locators"):
            self.sql(f"INSERT INTO public.{relation} DEFAULT VALUES;", runtime=True, success=False)
            self.sql(f"DELETE FROM public.{relation};", runtime=True, success=False)
        self.sql("SELECT public.review_access_account_lock(NULL,NULL,true);", runtime=True, success=False)
        self.sql("SELECT public.review_workspace_provision(NULL,NULL,NULL,NULL,NULL,NULL,NULL);", runtime=True, success=False)


class RuntimeRoleReviewAccessRelocationTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 103

    def test_existing_stock_role_never_gains_relocated_review_privileges(self):
        self.provision()  # Actual stock role exists before either installation.
        dependencies = ["002_auth.sql", "013_owner_mfa.sql",
                        "100_payload_profile_account_anchors.sql",
                        "102_review_workspace_persistence.sql",
                        "104_review_root_access.sql"]
        for schema in ("review_relocated", "Review'Quoted"):
            with self.subTest(schema=schema):
                quoted = '"' + schema.replace('"', '""') + '"'
                self.sql(f"CREATE SCHEMA {quoted};")
                for filename in dependencies:
                    self.sql(f"SET search_path TO {quoted}; BEGIN;\n"
                             + (COMPOSE / "migrations" / filename).read_text(encoding="utf-8")
                             + "\nCOMMIT;")
                literal = "'" + schema.replace("'", "''") + "'"
                self.sql("""DO $$ DECLARE namespace_oid oid; r record; c record; BEGIN
                  SELECT oid INTO STRICT namespace_oid FROM pg_namespace WHERE nspname=""" + literal + """;
                  FOR r IN SELECT oid FROM pg_class WHERE relnamespace=namespace_oid AND relname LIKE 'review_%' LOOP
                    IF has_table_privilege('zrotext_runtime',r.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
                      RAISE EXCEPTION 'stock runtime gained relocated review relation access'; END IF;
                    FOR c IN SELECT attname FROM pg_attribute WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped LOOP
                      IF has_column_privilege('zrotext_runtime',r.oid,c.attname,'SELECT,INSERT,UPDATE,REFERENCES') THEN
                        RAISE EXCEPTION 'stock runtime gained relocated review column access'; END IF;
                    END LOOP;
                  END LOOP;
                  IF (SELECT count(*) FROM pg_class WHERE relnamespace=namespace_oid AND relname LIKE 'review_%' AND relkind='r')<>10 THEN
                    RAISE EXCEPTION 'expected actual review relations'; END IF;
                  FOR r IN SELECT oid FROM pg_proc WHERE pronamespace=namespace_oid AND proname LIKE 'review_%' LOOP
                    IF has_function_privilege('zrotext_runtime',r.oid,'EXECUTE') THEN
                      RAISE EXCEPTION 'stock runtime gained relocated review helper execution'; END IF;
                  END LOOP;
                END $$;""")
                self.sql(f"DROP SCHEMA {quoted} CASCADE;")
        # An unrelated supported installation remains usable and independently
        # qualifies the actual stock-role provisioner rather than an exemption.
        self.provision()
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)


class RuntimeRoleParentMirrorUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 100

    def test_existing_defaults_and_reruns_keep_parent_mirror_helpers_private(self):
        self.provision()
        self.sql("INSERT INTO accounts(id) VALUES(md5('mirror-account')::uuid);"
                 "INSERT INTO users(id,email,password_hash) VALUES(md5('mirror-user')::uuid,'mirror@example.test','synthetic-unusable-hash');"
                 "INSERT INTO memberships(account_id,user_id,role) VALUES(md5('mirror-account')::uuid,md5('mirror-user')::uuid,'owner');"
                 "INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) VALUES(md5('mirror-verification')::uuid,md5('mirror-account')::uuid,md5('mirror-user')::uuid,decode(repeat('11',32),'hex'),now()+interval '1 hour');"
                 "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) VALUES(md5('mirror-reset')::uuid,md5('mirror-account')::uuid,md5('mirror-user')::uuid,decode(repeat('11',32),'hex'),now()+interval '1 hour');"
                 "INSERT INTO verification_mail_outbox(verification_id) VALUES(md5('mirror-verification')::uuid);"
                 "INSERT INTO password_reset_mail_outbox(reset_id) VALUES(md5('mirror-reset')::uuid);", runtime=True)
        migration = COMPOSE / "migrations" / "101_parent_account_mirrors.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        self.sql("SELECT public.parent_account_mirror_guard();", runtime=True, success=False)
        self.sql("DO $$ BEGIN IF (SELECT count(*) FROM verification_mail_outbox WHERE account_id=md5('mirror-account')::uuid)<>1 "
                 "OR (SELECT count(*) FROM password_reset_mail_outbox WHERE account_id=md5('mirror-account')::uuid)<>1 "
                 "THEN RAISE EXCEPTION 'existing mail ownership was not backfilled'; END IF; END $$;", runtime=True)
        self.sql("UPDATE verification_mail_outbox SET attempt_count=1; UPDATE password_reset_mail_outbox SET attempt_count=1;", runtime=True)
        self.sql("UPDATE verification_mail_outbox SET account_id=md5('mirror-foreign')::uuid;", runtime=True, success=False)
        self.sql("GRANT EXECUTE ON FUNCTION public.parent_account_mirror_guard() TO PUBLIC,zrotext_runtime;")
        self.provision()
        self.provision()
        self.sql((COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8"), runtime=True)
        self.sql("SELECT public.parent_account_mirror_guard();", runtime=True, success=False)
        self.sql("DELETE FROM email_verifications; DELETE FROM password_resets;", runtime=True)
        self.sql("DO $$ BEGIN IF EXISTS(SELECT FROM verification_mail_outbox) OR EXISTS(SELECT FROM password_reset_mail_outbox) "
                 "THEN RAISE EXCEPTION 'mail parent cascade changed'; END IF; END $$;", runtime=True)


class RuntimeRoleHostedUpgradeTest(RuntimeRoleFixture, unittest.TestCase):
    migration_limit = 105

    def test_hosted_upgrade_and_provisioner_reruns_repair_private_relation_column_and_helper_grants(self):
        self.provision()
        migration = COMPOSE / "migrations" / "106_hosted_runtime.sql"
        self.sql("BEGIN;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        verify = (COMPOSE / "verify_runtime_role.sql").read_text(encoding="utf-8")
        self.sql(verify, runtime=True)
        self.sql("""DO $$ DECLARE r record; columns_sql text; BEGIN
          FOR r IN SELECT c.oid,c.relname FROM pg_class c WHERE c.relnamespace='public'::regnamespace
            AND c.relname IN ('hosted_runtime_secrets','hosted_runtime_sessions','hosted_billing_resolutions','hosted_billing_namespaces','hosted_billing_history') LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
              FROM pg_attribute WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped;
            EXECUTE format('GRANT SELECT (%s),INSERT (%s),UPDATE (%s),REFERENCES (%s) ON TABLE public.%I TO PUBLIC,zrotext_runtime',
                           columns_sql,columns_sql,columns_sql,columns_sql,r.relname);
            EXECUTE format('GRANT ALL ON TABLE public.%I TO PUBLIC,zrotext_runtime',r.relname);
          END LOOP;
          FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
            WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_%' LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC,zrotext_runtime',r.signature);
          END LOOP;
        END $$;
        CREATE FUNCTION public.hosted_runtime_bind(integer) RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT $1';
        GRANT EXECUTE ON FUNCTION public.hosted_runtime_bind(integer) TO PUBLIC,zrotext_runtime;
        """)
        self.sql(verify, runtime=True, success=False)
        self.provision()
        self.provision()
        self.sql(verify, runtime=True)
        self.sql("SELECT public.hosted_runtime_bind(1)", runtime=True, success=False)
        for relation in ('hosted_runtime_secrets', 'hosted_runtime_sessions', 'hosted_billing_resolutions'):
            self.sql(f"SELECT * FROM public.{relation}", runtime=True, success=False)
            self.sql(f"DELETE FROM public.{relation}", runtime=True, success=False)
        self.sql("SELECT public.hosted_resolve_review(NULL,NULL,NULL,NULL)",runtime=True,success=False)


if __name__ == "__main__":
    unittest.main()
