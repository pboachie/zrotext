"""Liveness-run report: marker parsing, totals, checks and privacy."""

import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liveness_report as lr  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RUST_MARKERS = ROOT / "crates/server/src/device_socket/stream_diagnostic.rs"


def beat(stamp, epoch, gap_ms, handling_ms=2):
    prefix = f"app-1  | {stamp} " if stamp else "app-1  | "
    return (
        f"{prefix}ZTDeviceStream heartbeat_ack connection_epoch={epoch} "
        f"since_prior_accepted_ms={gap_ms} handling_ms={handling_ms}\n"
    )


def close(stamp, epoch, reason, since_ms, totals=None):
    prefix = f"app-1  | {stamp} " if stamp else "app-1  | "
    line = (
        f"{prefix}ZTDeviceStream close_reason={reason} connection_epoch={epoch} "
        f"since_heartbeat_ms={since_ms}"
    )
    if totals is not None:
        heartbeats, max_gap_ms, connected_ms = totals
        line += f" heartbeats={heartbeats} max_gap_ms={max_gap_ms} connected_ms={connected_ms}"
    return line + "\n"


def run(lines, *args):
    out = io.StringIO()
    code = lr.main(list(args), stdin=io.StringIO("".join(lines)), stdout=out)
    return code, (json.loads(out.getvalue()) if out.getvalue() else None)


TWO_CONNECTIONS = [
    "app-1  | 2026-01-01T00:00:00.000000000Z INFO server listening\n",
    beat("2026-01-01T00:00:30.000000000Z", 4, 30000),
    beat("2026-01-01T00:01:00.000000000Z", 4, 30000),
    beat("2026-01-01T00:01:30.500000000Z", 4, 30500),
    # Per-heartbeat markers stopped at the cap; the close totals still count
    # the suppressed tail.
    close("2026-01-01T02:30:40.000000000Z", 4, "heartbeat_deadline", 45100, (300, 31000, 9040000)),
    beat("2026-01-01T02:31:30.000000000Z", 5, 30000),
    beat("2026-01-01T02:32:00.000000000Z", 5, 30000),
    close("2026-01-01T02:32:10.000000000Z", 5, "site_drain", 10000, (2, 30000, 70000)),
]


class LivenessReportTest(unittest.TestCase):
    def test_summarizes_connections_totals_and_reconnect_downtime(self):
        code, report = run(TWO_CONNECTIONS)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["reconnects"], 1)
        self.assertEqual(report["heartbeats"], 302)
        self.assertEqual(report["observed_connected_ms"], 9_110_000)
        self.assertTrue(report["observed_connected_ms_exact"])
        self.assertEqual(report["close_reasons"], {"heartbeat_deadline": 1, "site_drain": 1})
        self.assertEqual(report["gap_ms"]["max"], 31000)
        self.assertEqual(report["gap_ms"]["sampled"], 5)
        self.assertEqual(report["gap_ms"]["p50_sampled"], 30000)
        # Connection 5 started 30 s before its first ack at 02:31:30, i.e.
        # 20 s after connection 4 closed at 02:30:40.
        self.assertEqual(
            report["reconnect_downtime"], {"count": 1, "max_ms": 20000, "total_ms": 20000}
        )
        self.assertEqual(report["span_ms"], 9_130_000)
        self.assertEqual(
            [row["heartbeats"] for row in report["connections"]], [300, 2]
        )
        self.assertEqual(report["warnings"], [])

    def test_gap_hidden_after_the_marker_cap_fails_the_run(self):
        lines = [
            beat(None, 9, 30000),
            close(None, 9, "heartbeat_deadline", 46000, (400, 44000, 12_000_000)),
        ]
        code, report = run(lines, "--max-gap-seconds", "40")
        self.assertEqual(code, 1)
        self.assertEqual(report["verdict"], "fail")
        gap_check = next(c for c in report["checks"] if c["name"] == "max_gap")
        self.assertEqual(gap_check["value_ms"], 44000)
        self.assertFalse(gap_check["ok"])
        self.assertIsNone(report["reconnect_downtime"])

    def test_never_echoes_log_content_and_counts_malformed_markers(self):
        secret = "sk_live_" + "Z" * 24
        lines = [
            f"app-1  | request body {secret}\n",
            f"app-1  | ZTDeviceStream heartbeat_ack connection_epoch=1 note={secret}\n",
            beat(None, 1, 30000),
            close(None, 1, "superseded", 5, (1, 30000, 35000)),
        ]
        out = io.StringIO()
        code = lr.main([], stdin=io.StringIO("".join(lines)), stdout=out)
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn("request body", out.getvalue())
        report = json.loads(out.getvalue())
        self.assertEqual(report["unparsed_markers"], 1)
        check = next(c for c in report["checks"] if c["name"] == "well_formed_markers")
        self.assertFalse(check["ok"])

    def test_older_close_markers_without_totals_are_estimated(self):
        lines = [
            beat(None, 2, 30000),
            beat(None, 2, 30000),
            close(None, 2, "other_stream_exit", 12000),
        ]
        code, report = run(lines)
        self.assertEqual(code, 0)
        self.assertEqual(report["observed_connected_ms"], 60000)
        self.assertFalse(report["observed_connected_ms_exact"])
        self.assertTrue(any("estimates" in warning for warning in report["warnings"]))

    def test_open_connection_at_end_of_log_is_reported(self):
        code, report = run([beat(None, 3, 30000)])
        self.assertEqual(code, 0)
        self.assertIsNone(report["connections"][0]["close_reason"])
        self.assertTrue(any("no close marker" in warning for warning in report["warnings"]))

    def test_min_observed_and_max_reconnect_checks(self):
        code, report = run(
            TWO_CONNECTIONS, "--min-observed-seconds", "86400", "--max-reconnects", "0"
        )
        self.assertEqual(code, 1)
        failed = {c["name"] for c in report["checks"] if not c["ok"]}
        self.assertEqual(failed, {"min_observed", "max_reconnects"})
        code, report = run(
            TWO_CONNECTIONS, "--min-observed-seconds", "9000", "--max-reconnects", "1"
        )
        self.assertEqual(code, 0)

    def test_overlapping_connections_warn_about_mixed_devices(self):
        lines = [
            beat(None, 1, 30000),
            beat(None, 8, 30000),
            close(None, 1, "superseded", 1, (1, 30000, 31000)),
            close(None, 8, "superseded", 1, (1, 30000, 31000)),
        ]
        _, report = run(lines)
        self.assertTrue(any("overlapped" in warning for warning in report["warnings"]))

    def test_no_markers_is_a_usage_failure(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            code = lr.main([], stdin=io.StringIO("server started\n"), stdout=out)
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("ZT_DEVICE_STREAM_DIAGNOSTIC=1", err.getvalue())

    def test_reads_log_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text("".join(TWO_CONNECTIONS), encoding="utf-8")
            out = io.StringIO()
            self.assertEqual(lr.main([str(path)], stdout=out), 0)
            self.assertEqual(json.loads(out.getvalue())["reconnects"], 1)

    def test_labels_are_restricted_to_coarse_context(self):
        code, report = run(
            TWO_CONNECTIONS,
            "--label",
            "device_model=Example Phone 7",
            "--label",
            "network=wifi to lte",
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            report["labels"], {"device_model": "Example Phone 7", "network": "wifi to lte"}
        )
        for bad in ("imei=1", "network=", "device_model=abc12345", "screen=a;b"):
            with self.assertRaises(lr.LabelError):
                lr.parse_labels([bad])

    def test_timestamps_accept_offsets_and_ignore_zone_less_stamps(self):
        self.assertEqual(
            lr.parse_timestamp("x 2026-01-01T01:00:00+01:00 "),
            lr.parse_timestamp("x 2026-01-01T00:00:00Z "),
        )
        self.assertIsNone(lr.parse_timestamp("x 2026-01-01T00:00:00 "))
        self.assertIsNone(lr.parse_timestamp("x 2026-01-01T00:00:00Z and more "))

    def test_parser_accepts_the_markers_the_server_tests_pin(self):
        source = RUST_MARKERS.read_text(encoding="utf-8")
        flattened = re.sub(r"\\\r?\n\s*", "", source)
        pinned = re.findall(r'"(ZTDeviceStream [^"{}]*)"', flattened)
        closes = [m for m in pinned if "close_reason=" in m]
        beats = [m for m in pinned if "heartbeat_ack" in m]
        self.assertTrue(closes and beats)
        for marker in closes:
            self.assertIsNotNone(lr.CLOSE_RE.fullmatch(marker), marker)
            self.assertIn("connected_ms=", marker)
        for marker in beats:
            self.assertIsNotNone(lr.HEARTBEAT_RE.fullmatch(marker), marker)


if __name__ == "__main__":
    unittest.main()
