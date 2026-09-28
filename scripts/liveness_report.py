#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize a device-stream liveness run from content-free server markers.

The server prints ``ZTDeviceStream`` markers only when started with
``ZT_DEVICE_STREAM_DIAGNOSTIC=1``. This tool reads server logs, recognizes
exactly the documented marker grammar, and prints an aggregate JSON report
with pass/fail checks. It never echoes a log line: anything other than a
well-formed marker is ignored, and malformed markers are only counted.

Run it against logs from one enrolled device at a time; markers carry no
device ID by design, so a log with several devices mixes their connections.
See docs/ANDROID-TESTING.md#long-liveness-runs.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
import json
import math
import re
import sys
from typing import Iterable, TextIO

# Mirrors HEARTBEAT_DEADLINE in crates/server/src/device_socket/mod.rs: a
# longer gap closes the connection.
DEFAULT_MAX_GAP_SECONDS = 45
MARKER = "ZTDeviceStream"
_NUM = r"(\d{1,15})"
HEARTBEAT_RE = re.compile(
    rf"{MARKER} heartbeat_ack connection_epoch={_NUM} "
    rf"since_prior_accepted_ms={_NUM} handling_ms={_NUM}\s*$"
)
# The totals suffix is absent in markers from servers before it was added.
CLOSE_RE = re.compile(
    rf"{MARKER} close_reason=([a-z_]{{1,64}}) connection_epoch={_NUM} "
    rf"since_heartbeat_ms={_NUM}"
    rf"(?: heartbeats={_NUM} max_gap_ms={_NUM} connected_ms={_NUM})?\s*$"
)
# Optional timestamp immediately before the marker, as printed by
# `docker compose logs --timestamps` or `journalctl -o short-iso-precise`.
TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\s+$"
)
LABEL_KEYS = (
    "android_version",
    "app_version",
    "carrier_class",
    "device_model",
    "network",
    "power",
    "screen",
)
LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,39}$")
# Long digit runs look like phone numbers, serials or IMEIs; refuse them.
LABEL_DIGIT_RUN_RE = re.compile(r"\d{5,}")


@dataclass
class Connection:
    epoch: int
    first_seen_line: int
    start_ts: float | None = None
    end_ts: float | None = None
    close_reason: str | None = None
    sampled_gaps_ms: list[int] = field(default_factory=list)
    max_handling_ms: int = 0
    total_heartbeats: int | None = None
    total_max_gap_ms: int | None = None
    connected_ms: int | None = None

    @property
    def heartbeats(self) -> int:
        sampled = len(self.sampled_gaps_ms)
        return max(sampled, self.total_heartbeats or 0)

    @property
    def max_gap_ms(self) -> int:
        return max([*self.sampled_gaps_ms, self.total_max_gap_ms or 0])

    @property
    def connected_ms_value(self) -> tuple[int, bool]:
        """Connected time and whether it is exact (from the close totals)."""
        if self.connected_ms is not None:
            return self.connected_ms, True
        if self.start_ts is not None and self.end_ts is not None:
            return int(round((self.end_ts - self.start_ts) * 1000)), False
        return sum(self.sampled_gaps_ms), False


class LabelError(ValueError):
    pass


def parse_labels(pairs: Iterable[str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or key not in LABEL_KEYS:
            raise LabelError(
                f"label must be KEY=VALUE with KEY one of {', '.join(LABEL_KEYS)}"
            )
        if not LABEL_VALUE_RE.fullmatch(value) or LABEL_DIGIT_RUN_RE.search(value):
            raise LabelError(
                f"label {key} must be 1-40 letters, digits, spaces or ._+- "
                "with no run of five or more digits"
            )
        labels[key] = value
    return labels


def parse_timestamp(prefix: str) -> float | None:
    """Timestamp ending right before the marker; zone-less stamps are ignored."""
    match = TIMESTAMP_RE.search(prefix[-64:])
    if match is None:
        return None
    base, fraction, zone = match.groups()
    text = base.replace(" ", "T") + (fraction or "")[:7]
    if zone:
        text += "+00:00" if zone == "Z" else zone
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.timestamp()


@dataclass
class Scan:
    connections: list[Connection] = field(default_factory=list)
    unparsed_markers: int = 0
    max_open: int = 0
    timestamps_seen: int = 0
    markers_seen: int = 0


def scan(lines: Iterable[str]) -> Scan:
    result = Scan()
    open_by_epoch: dict[int, Connection] = {}

    def opened(epoch: int, line_no: int) -> Connection:
        connection = open_by_epoch.get(epoch)
        if connection is None:
            connection = Connection(epoch=epoch, first_seen_line=line_no)
            open_by_epoch[epoch] = connection
            result.connections.append(connection)
            result.max_open = max(result.max_open, len(open_by_epoch))
        return connection

    for line_no, raw in enumerate(lines, start=1):
        marker_at = raw.find(MARKER)
        if marker_at < 0:
            continue
        result.markers_seen += 1
        tail = raw[marker_at:].rstrip("\r\n")
        stamp = parse_timestamp(raw[:marker_at])
        if stamp is not None:
            result.timestamps_seen += 1
        if match := HEARTBEAT_RE.fullmatch(tail):
            epoch, gap_ms, handling_ms = (int(value) for value in match.groups())
            connection = opened(epoch, line_no)
            if stamp is not None and connection.start_ts is None:
                # The stream's heartbeat clock starts when the session opens,
                # so the first gap reaches back to the connection start.
                connection.start_ts = stamp - gap_ms / 1000
            connection.sampled_gaps_ms.append(gap_ms)
            connection.max_handling_ms = max(connection.max_handling_ms, handling_ms)
            if stamp is not None:
                connection.end_ts = stamp
            continue
        if match := CLOSE_RE.fullmatch(tail):
            reason = match.group(1)
            epoch = int(match.group(2))
            connection = opened(epoch, line_no)
            connection.close_reason = reason
            if match.group(4) is not None:
                connection.total_heartbeats = int(match.group(4))
                connection.total_max_gap_ms = int(match.group(5))
                connection.connected_ms = int(match.group(6))
            if stamp is not None:
                connection.end_ts = stamp
                if connection.start_ts is None and connection.connected_ms is not None:
                    connection.start_ts = stamp - connection.connected_ms / 1000
            del open_by_epoch[epoch]
            continue
        result.unparsed_markers += 1
    return result


def percentile(values: list[int], fraction: float) -> int | None:
    """Nearest-rank percentile."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def build_report(
    result: Scan,
    *,
    max_gap_seconds: float,
    min_observed_seconds: float | None,
    max_reconnects: int | None,
    labels: dict[str, str],
) -> dict:
    connections = result.connections
    gaps = [gap for c in connections for gap in c.sampled_gaps_ms]
    close_reasons = Counter(c.close_reason for c in connections if c.close_reason)
    observed_ms = 0
    exact = True
    rows = []
    for connection in connections:
        connected_ms, is_exact = connection.connected_ms_value
        observed_ms += connected_ms
        exact = exact and is_exact
        rows.append(
            {
                "close_reason": connection.close_reason,
                "connected_ms": connected_ms,
                "connected_ms_exact": is_exact,
                "connection_epoch": connection.epoch,
                "heartbeats": connection.heartbeats,
                "max_gap_ms": connection.max_gap_ms,
                "sampled_heartbeats": len(connection.sampled_gaps_ms),
            }
        )
    downtime = None
    span_ms = None
    timed = [c for c in connections if c.start_ts is not None and c.end_ts is not None]
    if connections and len(timed) == len(connections):
        ordered = sorted(timed, key=lambda c: c.start_ts)
        gaps_between = [
            max(0, int(round((later.start_ts - earlier.end_ts) * 1000)))
            for earlier, later in zip(ordered, ordered[1:])
        ]
        downtime = {
            "count": len(gaps_between),
            "max_ms": max(gaps_between) if gaps_between else 0,
            "total_ms": sum(gaps_between),
        }
        span_ms = int(round((max(c.end_ts for c in ordered) - ordered[0].start_ts) * 1000))

    max_gap_ms = max((c.max_gap_ms for c in connections), default=0)
    reconnects = max(0, len(connections) - 1)
    checks = [
        {
            "name": "max_gap",
            "ok": max_gap_ms <= max_gap_seconds * 1000,
            "limit_ms": int(max_gap_seconds * 1000),
            "value_ms": max_gap_ms,
        },
        {
            "name": "well_formed_markers",
            "ok": result.unparsed_markers == 0,
            "value": result.unparsed_markers,
        },
    ]
    if min_observed_seconds is not None:
        checks.append(
            {
                "name": "min_observed",
                "ok": observed_ms >= min_observed_seconds * 1000,
                "limit_ms": int(min_observed_seconds * 1000),
                "value_ms": observed_ms,
            }
        )
    if max_reconnects is not None:
        checks.append(
            {
                "name": "max_reconnects",
                "ok": reconnects <= max_reconnects,
                "limit": max_reconnects,
                "value": reconnects,
            }
        )
    warnings = []
    if result.max_open > 1:
        warnings.append(
            "connections overlapped: the log may contain several devices or a "
            "server restart without close markers"
        )
    if any(c.close_reason is None for c in connections):
        warnings.append("some connections have no close marker (still open or log truncated)")
    if not exact:
        warnings.append(
            "some connected times are estimates: close totals were missing "
            "(open connection or an older server)"
        )
    if 0 < result.timestamps_seen < result.markers_seen:
        warnings.append("only some markers had timestamps; reconnect downtime was not computed")

    return {
        "checks": checks,
        "close_reasons": dict(sorted(close_reasons.items())),
        "connections": rows,
        "gap_ms": {
            "max": max_gap_ms,
            "p50_sampled": percentile(gaps, 0.50),
            "p95_sampled": percentile(gaps, 0.95),
            "p99_sampled": percentile(gaps, 0.99),
            "sampled": len(gaps),
        },
        "heartbeats": sum(c.heartbeats for c in connections),
        "labels": labels,
        "max_handling_ms_sampled": max((c.max_handling_ms for c in connections), default=0),
        "observed_connected_ms": observed_ms,
        "observed_connected_ms_exact": exact,
        "reconnect_downtime": downtime,
        "reconnects": reconnects,
        "report": "zrotext-liveness-run/v1",
        "span_ms": span_ms,
        "unparsed_markers": result.unparsed_markers,
        "verdict": "pass" if all(check["ok"] for check in checks) else "fail",
        "warnings": warnings,
    }


def _read(paths: list[str], stdin: TextIO) -> Iterable[str]:
    if not paths:
        yield from stdin
        return
    for path in paths:
        if path == "-":
            yield from stdin
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            yield from handle


def main(argv: list[str] | None = None, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("logs", nargs="*", help="server log files; '-' or none reads stdin")
    parser.add_argument(
        "--max-gap-seconds",
        type=float,
        default=DEFAULT_MAX_GAP_SECONDS,
        help="fail if any accepted heartbeat gap exceeds this (default: %(default)s)",
    )
    parser.add_argument(
        "--min-observed-seconds",
        type=float,
        help="fail unless the connections together stayed up at least this long",
    )
    parser.add_argument(
        "--max-reconnects", type=int, help="fail if the run reconnected more often"
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=f"coarse run context; KEY is one of {', '.join(LABEL_KEYS)}",
    )
    args = parser.parse_args(argv)
    try:
        labels = parse_labels(args.label)
    except LabelError as error:
        parser.error(str(error))
    if args.max_gap_seconds <= 0:
        parser.error("--max-gap-seconds must be positive")
    try:
        result = scan(_read(args.logs, stdin))
    except OSError as error:
        print(f"liveness_report: cannot read log: {error.strerror}", file=sys.stderr)
        return 2
    if not result.connections:
        print(
            "liveness_report: no ZTDeviceStream markers found; start the server "
            "with ZT_DEVICE_STREAM_DIAGNOSTIC=1",
            file=sys.stderr,
        )
        return 2
    report = build_report(
        result,
        max_gap_seconds=args.max_gap_seconds,
        min_observed_seconds=args.min_observed_seconds,
        max_reconnects=args.max_reconnects,
        labels=labels,
    )
    json.dump(report, stdout, indent=2, sort_keys=True)
    stdout.write("\n")
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
