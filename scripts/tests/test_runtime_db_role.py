#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise role provisioning in a new disposable local PostgreSQL container."""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest

COMPOSE = Path(__file__).resolve().parents[2] / "deploy" / "compose"
sys.path.insert(0, str(COMPOSE))
from fresh_install_smoke import ensure_local_docker  # noqa: E402


class RuntimeRoleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_local_docker()
        cls.container = "zt-role-test-" + secrets.token_hex(8)
        cls.env = dict(os.environ, POSTGRES_PASSWORD=secrets.token_hex(32),
                       RUNTIME_DATABASE_PASSWORD=secrets.token_hex(32))
        subprocess.run(["docker", "run", "--detach", "--name", cls.container,
                        "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_USER=zrotext",
                        "-e", "POSTGRES_DB=zrotext", "postgres:18.6-bookworm"],
                       env=cls.env, check=True, capture_output=True, timeout=60)
        cls.addClassCleanup(lambda: subprocess.run(
            ["docker", "rm", "-f", "-v", cls.container], check=True,
            capture_output=True, timeout=60))
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
            if migration.name == "072_message_summary_metadata.sql":
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


if __name__ == "__main__":
    unittest.main()
