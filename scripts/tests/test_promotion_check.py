"""Writer-promotion checker: verdicts, fencing checks and output hygiene."""

import contextlib
import http.server
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
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
    "replay_lsn": "0/3000060",
    "sender_gap_bytes": 0,
    "sender_report_age_seconds": 0.4,
}

# Reproduces the audited false GO: everything received is replayed, but the
# sender reported WAL far beyond it and the last replayed commit is old.
BEHIND_SENDER = dict(
    CAUGHT_UP_STANDBY, sender_gap_bytes=69 * 1024 * 1024, replay_lag_seconds=900.0
)

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
    STANDBY = ["standby", "--service", "zt-standby"]
    STOPPED = ["standby", "--service", "zt-standby", "--writer-stopped"]

    def test_caught_up_streaming_standby_is_go_even_when_idle(self):
        code, report, queries, _ = run(self.STANDBY, CAUGHT_UP_STANDBY)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "go")
        self.assertEqual(queries, [pc.STANDBY_SQL])

    def test_unreceived_wal_is_no_go_even_when_received_wal_is_replayed(self):
        code, report, _, _ = run(self.STANDBY, BEHIND_SENDER)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("sender_caught_up", None)})
        # A busy writer whose commits replay within the limit is still go.
        busy = dict(BEHIND_SENDER, replay_lag_seconds=4.0)
        self.assertEqual(run(self.STANDBY, busy)[0], 0)

    def test_zero_gap_from_a_stale_sender_report_is_no_go(self):
        stale = dict(CAUGHT_UP_STANDBY, sender_report_age_seconds=300.0)
        code, report, _, _ = run(self.STANDBY, stale)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("sender_caught_up", None)})

    def test_unknown_sender_gap_is_no_go(self):
        unknown = dict(CAUGHT_UP_STANDBY, sender_gap_bytes=None, replay_lag_seconds=1.0)
        code, report, _, _ = run(self.STANDBY, unknown)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("sender_caught_up", None)})
        check = next(c for c in report["checks"] if c["name"] == "sender_caught_up")
        self.assertIn("hint", check)

    def test_lagging_or_disconnected_standby_is_no_go(self):
        lagging = dict(
            CAUGHT_UP_STANDBY,
            replay_lag_bytes=8192,
            replay_lag_seconds=75.0,
            sender_gap_bytes=8192,
        )
        code, report, _, _ = run(self.STANDBY, lagging)
        self.assertEqual(code, 1)
        self.assertEqual(
            failed(report), {("received_replayed", None), ("sender_caught_up", None)}
        )

        stale = dict(CAUGHT_UP_STANDBY, receiver_status=None, receiver_message_age_seconds=None)
        _, report, _, _ = run(self.STANDBY, stale)
        self.assertEqual(
            failed(report), {("wal_receiver_streaming", None), ("wal_receiver_recent", None)}
        )

    def test_a_primary_is_not_a_standby(self):
        primary = {
            "in_recovery": False, "receiver_status": None,
            "receiver_message_age_seconds": None, "replay_lag_bytes": None,
            "replay_lag_seconds": None, "replay_lsn": None,
            "sender_gap_bytes": None, "sender_report_age_seconds": None,
        }
        code, report, _, _ = run(self.STANDBY, primary)
        self.assertEqual(code, 1)
        self.assertIn(("standby_in_recovery", None), failed(report))
        self.assertIn(("received_replayed", None), failed(report))
        self.assertIn(("sender_caught_up", None), failed(report))

    def test_stopped_writer_needs_full_replay_but_no_receiver(self):
        disconnected = dict(
            CAUGHT_UP_STANDBY, receiver_status=None, receiver_message_age_seconds=None
        )
        code, report, _, _ = run(self.STOPPED, disconnected)
        self.assertEqual(code, 0)
        self.assertEqual(
            {c["name"] for c in report["checks"]},
            {"standby_in_recovery", "received_replayed", "sender_caught_up"},
        )
        self.assertTrue(any("cannot prove" in w for w in report["warnings"]))
        # Recent but unreplayed WAL passes the running-writer rule, not this one.
        recent = dict(CAUGHT_UP_STANDBY, replay_lag_bytes=512, replay_lag_seconds=1.0)
        self.assertEqual(run(self.STANDBY, recent)[0], 0)
        unreplayed = dict(disconnected, replay_lag_bytes=512, replay_lag_seconds=1.0)
        code, report, _, _ = run(self.STOPPED, unreplayed)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("received_replayed", None)})

    def test_stopped_writer_with_unreceived_wal_is_no_go(self):
        code, report, _, _ = run(self.STOPPED, dict(BEHIND_SENDER, replay_lag_seconds=1.0))
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("sender_caught_up", None)})

    def test_stopped_writer_with_unknown_sender_needs_min_replay_lsn(self):
        gone = dict(
            CAUGHT_UP_STANDBY,
            receiver_status=None,
            receiver_message_age_seconds=None,
            sender_gap_bytes=None,
            sender_report_age_seconds=None,
            replay_lsn="1/A0",
        )
        code, report, _, _ = run(self.STOPPED, gone)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("sender_caught_up", None)})
        self.assertEqual(run(self.STOPPED + ["--min-replay-lsn", "1/A0"], gone)[0], 0)
        self.assertEqual(run(self.STOPPED + ["--min-replay-lsn", "0/FFFFFFFF"], gone)[0], 0)
        code, report, _, _ = run(self.STOPPED + ["--min-replay-lsn", "1/A1"], gone)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("min_replay_lsn", None)})

    def test_min_replay_lsn_applies_while_the_writer_runs_too(self):
        code, report, _, _ = run(self.STANDBY + ["--min-replay-lsn", "0/3000061"], CAUGHT_UP_STANDBY)
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("min_replay_lsn", None)})
        code, _, _, err = run(self.STANDBY + ["--min-replay-lsn", "3000061"], CAUGHT_UP_STANDBY)
        self.assertEqual(code, 2)
        self.assertIn("--min-replay-lsn", err)

    def test_lag_limit_is_configurable(self):
        lagging = dict(BEHIND_SENDER, replay_lag_bytes=10, replay_lag_seconds=75.0)
        self.assertEqual(run(self.STANDBY, lagging)[0], 1)
        code, _, _, _ = run(self.STANDBY + ["--max-lag-seconds", "120"], lagging)
        self.assertEqual(code, 0)

    def test_lsn_parsing(self):
        self.assertEqual(pc.parse_lsn("0/0"), 0)
        self.assertEqual(pc.parse_lsn("1/A0"), (1 << 32) + 0xA0)
        for bad in ("", "1", "1/", "G/0", "123456789/0", None):
            with self.assertRaises(ValueError):
                pc.parse_lsn(bad)


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

    def test_readyz_200_without_ready_body_is_not_ready(self):
        code, report, _, _ = run(
            WRITER_ARGS + ["--readyz", "https://new.example.test/readyz"],
            PROMOTED_WRITER,
            fetch=lambda url: (200, '{"status":"unavailable"}'),
        )
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("readyz_ready", "ready #1")})

    def test_unreachable_old_site_counts_as_not_ready(self):
        code, _, _, _ = run(
            WRITER_ARGS + ["--readyz-unready", "https://old.example.test/readyz"],
            PROMOTED_WRITER,
            fetch=lambda url: (None, ""),
        )
        self.assertEqual(code, 0)


class ArgumentAndConnectionTest(unittest.TestCase):
    def test_connection_strings_and_bad_inputs_are_refused(self):
        cases = (
            (["standby", "--service", "host=db.example.test password=x"], "libpq service name"),
            (["standby", "--service", "postgresql://u@db.example.test/zt"], "libpq service name"),
            (WRITER_ARGS[:-2] + ["--active-site", "site-a"], "both fenced and active"),
            (WRITER_ARGS + ["--readyz", "file:///etc/passwd"], "http:// or https://"),
            (["writer", "--service", "zt", "--expected-epoch", "0"], "--expected-epoch"),
        )
        for argv, message in cases:
            with self.subTest(argv):
                err = io.StringIO()
                # Nothing may be executed: a refused input never reaches psql.
                with mock.patch.object(pc.subprocess, "run") as run_mock, \
                        contextlib.redirect_stderr(err):
                    code = pc.main(argv, stdout=io.StringIO())
                run_mock.assert_not_called()
                self.assertEqual(code, 2)
                self.assertIn(message, err.getvalue())
                self.assertNotIn("password=x", err.getvalue())

    def test_service_runner_passes_only_the_service_name_and_sql_on_stdin(self):
        completed = subprocess.CompletedProcess([], 0, stdout='{"in_recovery": false}\n', stderr="")
        with mock.patch.object(pc.subprocess, "run", return_value=completed) as run_mock:
            self.assertEqual(pc.service_runner("zt-new-writer")(pc.WRITER_SQL), {"in_recovery": False})
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:3], ["psql", "-d", "service=zt-new-writer"])
        self.assertIn("ON_ERROR_STOP=1", command)
        self.assertEqual(
            run_mock.call_args.kwargs["input"], pc.READ_ONLY_SESSION + pc.WRITER_SQL
        )

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
        self.assertEqual(
            run_mock.call_args.kwargs["input"], pc.READ_ONLY_SESSION + pc.STANDBY_SQL
        )

    def test_queries_are_read_only(self):
        self.assertEqual(pc.READ_ONLY_SESSION, "SET default_transaction_read_only = on;\n")
        for sql in (pc.STANDBY_SQL, pc.WRITER_SQL):
            upper = sql.upper()
            for verb in ("INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "DROP", "TRUNCATE"):
                self.assertNotIn(verb, upper)


class _ReadyzHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/readyz")
            self.end_headers()
            return
        body = b'{"status":"ready"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ReadyzFetchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("localhost", 0), _ReadyzHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://localhost:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_ready_endpoint_is_fetched(self):
        self.assertEqual(pc.fetch_readyz(self.base + "/readyz"), (200, '{"status":"ready"}'))

    def test_redirects_are_reported_not_followed(self):
        status, _ = pc.fetch_readyz(self.base + "/redirect")
        self.assertEqual(status, 302)
        code, report, _, _ = run(
            WRITER_ARGS + ["--readyz", self.base + "/redirect"],
            PROMOTED_WRITER,
            fetch=pc.fetch_readyz,
        )
        self.assertEqual(code, 1)
        self.assertEqual(failed(report), {("readyz_ready", "ready #1")})


if __name__ == "__main__":
    unittest.main()
