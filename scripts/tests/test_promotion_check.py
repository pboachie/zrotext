"""Writer-promotion checker: verdicts, fencing checks and output hygiene."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy" / "compose"))
import promotion_check as pc  # noqa: E402

CAUGHT_UP_STANDBY = {
    "in_recovery": True,
    "receiver_status": "streaming",
    "receiver_message_age_seconds": 0.4,
    "replay_lag_bytes": 0,
    # An idle old writer makes the last replayed commit look old.
    "replay_lag_seconds": 900.0,
}

PROMOTED_WRITER = {
    "in_recovery": False,
    "authority": {"epoch": 2, "dispatch_enabled": False},
    "sites": [
        {"site_id": "site-a", "enabled": True, "draining": True},
        {"site_id": "site-b", "enabled": True, "draining": False},
    ],
    "sessions": [
        {"site_id": "site-b", "deployment_epoch": 2, "live": True, "count": 3},
        {"site_id": "site-a", "deployment_epoch": 1, "live": False, "count": 2},
    ],
}

WRITER_ARGS = [
    "writer", "--service", "zt-new-writer", "--expected-epoch", "2",
    "--fenced-site", "site-a", "--active-site", "site-b",
]


def run(argv, observed, fetch=None):
    queries = []

    def runner(sql):
        queries.append(sql)
        return json.loads(json.dumps(observed))

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err):
        code = pc.main(
            argv, runner=runner, fetch=fetch or (lambda url: (200, '{"status":"ready"}')),
            stdout=out,
        )
    report = json.loads(out.getvalue()) if out.getvalue() else None
    return code, report, queries, err.getvalue()


def failed(report):
    return {(c["name"], c.get("site_id") or c.get("target")) for c in report["checks"] if not c["ok"]}


class StandbyPhaseTest(unittest.TestCase):
    def test_caught_up_streaming_standby_is_go_even_when_idle(self):
        code, report, queries, _ = run(["standby", "--service", "zt-standby"], CAUGHT_UP_STANDBY)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "go")
        self.assertEqual(queries, [pc.STANDBY_SQL])

    def test_lagging_or_disconnected_standby_is_no_go(self):
        lagging = dict(CAUGHT_UP_STANDBY, replay_lag_bytes=8192, replay_lag_seconds=75.0)
        code, report, _, _ = run(["standby", "--service", "zt-standby"], lagging)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("replay_caught_up", None)})

        stale = dict(CAUGHT_UP_STANDBY, receiver_status=None, receiver_message_age_seconds=None)
        _, report, _, _ = run(["standby", "--service", "zt-standby"], stale)
        self.assertEqual(
            failed(report), {("wal_receiver_streaming", None), ("wal_receiver_recent", None)}
        )

    def test_a_primary_is_not_a_standby(self):
        primary = {
            "in_recovery": False, "receiver_status": None,
            "receiver_message_age_seconds": None, "replay_lag_bytes": None,
            "replay_lag_seconds": None,
        }
        code, report, _, _ = run(["standby", "--service", "zt-standby"], primary)
        self.assertEqual(code, 1)
        self.assertIn(("standby_in_recovery", None), failed(report))
        self.assertIn(("replay_caught_up", None), failed(report))

    def test_stopped_writer_needs_full_replay_but_no_receiver(self):
        disconnected = dict(
            CAUGHT_UP_STANDBY, receiver_status=None, receiver_message_age_seconds=None
        )
        args = ["standby", "--service", "zt-standby", "--writer-stopped"]
        code, report, _, _ = run(args, disconnected)
        self.assertEqual(code, 0)
        self.assertEqual(
            {c["name"] for c in report["checks"]}, {"standby_in_recovery", "replay_caught_up"}
        )
        self.assertTrue(any("cannot prove" in w for w in report["warnings"]))
        # Recent but unreplayed WAL passes the running-writer rule, not this one.
        recent = dict(CAUGHT_UP_STANDBY, replay_lag_bytes=512, replay_lag_seconds=1.0)
        self.assertEqual(run(["standby", "--service", "zt-standby"], recent)[0], 0)
        unreplayed = dict(disconnected, replay_lag_bytes=512, replay_lag_seconds=1.0)
        code, report, _, _ = run(args, unreplayed)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("replay_caught_up", None)})

    def test_lag_limit_is_configurable(self):
        lagging = dict(CAUGHT_UP_STANDBY, replay_lag_bytes=10, replay_lag_seconds=75.0)
        code, _, _, _ = run(
            ["standby", "--service", "zt-standby", "--max-lag-seconds", "120"], lagging
        )
        self.assertEqual(code, 0)


class WriterPhaseTest(unittest.TestCase):
    def test_promoted_fenced_writer_is_go(self):
        code, report, queries, _ = run(
            WRITER_ARGS + ["--readyz", "https://b.example.test/readyz"], PROMOTED_WRITER
        )
        self.assertEqual(code, 0, report)
        self.assertEqual(report["verdict"], "go")
        self.assertEqual(queries, [pc.WRITER_SQL])
        self.assertEqual(report["warnings"], [])

    def test_each_fence_failure_is_no_go(self):
        cases = {
            "writer_not_in_recovery": dict(PROMOTED_WRITER, in_recovery=True),
            "deployment_epoch": dict(
                PROMOTED_WRITER, authority={"epoch": 1, "dispatch_enabled": False}
            ),
            "dispatch_state": dict(
                PROMOTED_WRITER, authority={"epoch": 2, "dispatch_enabled": True}
            ),
            "site_fenced": dict(
                PROMOTED_WRITER,
                sites=[
                    {"site_id": "site-a", "enabled": True, "draining": False},
                    {"site_id": "site-b", "enabled": True, "draining": False},
                ],
            ),
            "site_active": dict(
                PROMOTED_WRITER,
                sites=[
                    {"site_id": "site-a", "enabled": False, "draining": False},
                    {"site_id": "site-b", "enabled": True, "draining": True},
                ],
            ),
        }
        for expected, observed in cases.items():
            with self.subTest(expected):
                code, report, _, _ = run(WRITER_ARGS, observed)
                self.assertEqual(code, 1)
                self.assertEqual({name for name, _ in failed(report)}, {expected})

    def test_missing_authority_and_unknown_sites_fail(self):
        observed = dict(PROMOTED_WRITER, authority=None, sites=[])
        code, report, _, _ = run(WRITER_ARGS, observed)
        self.assertEqual(code, 1)
        self.assertEqual(
            failed(report),
            {
                ("deployment_authority_present", None),
                ("deployment_epoch", None),
                ("dispatch_state", None),
                ("site_fenced", "site-a"),
                ("site_active", "site-b"),
            },
        )

    def test_dispatch_expectation_can_be_relaxed_for_planned_promotion(self):
        observed = dict(PROMOTED_WRITER, authority={"epoch": 2, "dispatch_enabled": True})
        self.assertEqual(run(WRITER_ARGS + ["--dispatch", "enabled"], observed)[0], 0)
        code, report, _, _ = run(WRITER_ARGS + ["--dispatch", "any"], observed)
        self.assertEqual(code, 0)
        self.assertNotIn("dispatch_state", {c["name"] for c in report["checks"]})

    def test_live_stale_sessions_are_warned_about(self):
        observed = dict(
            PROMOTED_WRITER,
            sessions=[{"site_id": "site-a", "deployment_epoch": 1, "live": True, "count": 4}],
        )
        code, report, _, _ = run(WRITER_ARGS, observed)
        self.assertEqual(code, 0)
        self.assertEqual(len(report["warnings"]), 2)
        self.assertIn("older deployment epoch 1", report["warnings"][0])
        self.assertIn("fenced site site-a", report["warnings"][1])

    def test_readyz_results_do_not_echo_urls(self):
        responses = {
            "https://new.example.test/readyz": (503, '{"status":"unavailable"}'),
            "https://old.example.test/readyz": (200, '{"status":"ready"}'),
        }
        code, report, _, _ = run(
            WRITER_ARGS
            + ["--readyz", "https://new.example.test/readyz",
               "--readyz-unready", "https://old.example.test/readyz"],
            PROMOTED_WRITER,
            fetch=lambda url: responses[url],
        )
        self.assertEqual(code, 1)
        self.assertEqual(
            failed(report), {("readyz_ready", "ready #1"), ("readyz_not_ready", "unready #1")}
        )
        self.assertNotIn("example.test", json.dumps(report))

    def test_unreachable_old_site_counts_as_not_ready(self):
        code, _, _, _ = run(
            WRITER_ARGS + ["--readyz-unready", "https://old.example.test/readyz"],
            PROMOTED_WRITER,
            fetch=lambda url: (None, ""),
        )
        self.assertEqual(code, 0)


class ArgumentAndConnectionTest(unittest.TestCase):
    def test_connection_strings_and_bad_inputs_are_refused(self):
        for argv in (
            ["standby", "--service", "host=db.example.test password=x"],
            ["standby", "--service", "postgresql://u@db.example.test/zt"],
            WRITER_ARGS[:-2] + ["--active-site", "site-a"],
            WRITER_ARGS + ["--readyz", "file:///etc/passwd"],
            ["writer", "--service", "zt", "--expected-epoch", "0"],
        ):
            with self.subTest(argv):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code = pc.main(argv, stdout=io.StringIO())
                self.assertEqual(code, 2)
                self.assertNotIn("password=x", err.getvalue())

    def test_service_runner_passes_only_the_service_name_and_sql_on_stdin(self):
        completed = subprocess.CompletedProcess([], 0, stdout='{"in_recovery": false}\n', stderr="")
        with mock.patch.object(pc.subprocess, "run", return_value=completed) as run_mock:
            self.assertEqual(pc.service_runner("zt-new-writer")(pc.WRITER_SQL), {"in_recovery": False})
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:3], ["psql", "-d", "service=zt-new-writer"])
        self.assertIn("ON_ERROR_STOP=1", command)
        self.assertEqual(run_mock.call_args.kwargs["input"], pc.WRITER_SQL)

    def test_database_errors_are_not_echoed(self):
        failure = subprocess.CompletedProcess(
            [], 2, stdout="", stderr='connection to server at "db.example.test" failed'
        )
        with mock.patch.object(pc.subprocess, "run", return_value=failure):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = pc.main(
                    ["standby", "--service", "zt-standby"], stdout=io.StringIO()
                )
        self.assertEqual(code, 2)
        self.assertIn("query failed (exit 2)", err.getvalue())
        self.assertNotIn("example.test", err.getvalue())

    def test_compose_runner_queries_the_db_service(self):
        completed = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
        with mock.patch.object(pc.subprocess, "run", return_value=completed) as run_mock:
            pc.compose_runner(Path(".env"))(pc.STANDBY_SQL)
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:2], ["docker", "compose"])
        self.assertIn("exec", command)
        self.assertEqual(command[command.index("exec") + 1 : command.index("exec") + 3], ["-T", "db"])
        self.assertEqual(run_mock.call_args.kwargs["input"], pc.STANDBY_SQL)

    def test_queries_are_read_only(self):
        for sql in (pc.STANDBY_SQL, pc.WRITER_SQL):
            upper = sql.upper()
            for verb in ("INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "DROP", "TRUNCATE"):
                self.assertNotIn(verb, upper)


if __name__ == "__main__":
    unittest.main()
