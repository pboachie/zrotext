#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only go/no-go checks for manual writer promotion.

Two phases follow docs/WRITER-PROMOTION.md:

* ``standby`` runs before promotion against the standby you intend to promote.
* ``writer`` runs after promotion and the deployment-epoch bump against the
  new writer, and optionally probes each site's ``/readyz``.

The tool only runs SELECT statements, in a session set to
``default_transaction_read_only``. It connects through a libpq service
name (``pg_service.conf`` plus ``.pgpass``) or through the Compose ``db``
container, so no connection string, password or hostname is passed on the
command line or printed. Database errors are reported without their text,
because libpq messages can name hosts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, TextIO
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yaml"
SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
SITE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,62}\Z")
# The design's replication lag alarm (docs/MULTI-LOCATION.md).
DEFAULT_MAX_LAG_SECONDS = 60.0
READYZ_TIMEOUT_SECONDS = 5.0
PSQL_FLAGS = ["-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-f", "-"]

STANDBY_SQL = """
SELECT json_build_object(
  'in_recovery', pg_is_in_recovery(),
  'receiver_status', (SELECT status FROM pg_stat_wal_receiver LIMIT 1),
  'receiver_message_age_seconds', (
    SELECT EXTRACT(EPOCH FROM now() - last_msg_receipt_time)::float8
    FROM pg_stat_wal_receiver LIMIT 1),
  'replay_lag_bytes', CASE WHEN pg_is_in_recovery() THEN
    pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::float8 END,
  'replay_lag_seconds', CASE WHEN pg_is_in_recovery() THEN
    EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())::float8 END,
  'replay_lsn', pg_last_wal_replay_lsn()::text,
  'sender_gap_bytes', (
    SELECT pg_wal_lsn_diff(latest_end_lsn, pg_last_wal_replay_lsn())::float8
    FROM pg_stat_wal_receiver WHERE latest_end_lsn IS NOT NULL LIMIT 1),
  'sender_report_age_seconds', (
    SELECT EXTRACT(EPOCH FROM now() - latest_end_time)::float8
    FROM pg_stat_wal_receiver WHERE latest_end_time IS NOT NULL LIMIT 1)
);
"""
# Sent before every query, so even a mistaken statement cannot write.
READ_ONLY_SESSION = "SET default_transaction_read_only = on;\n"
LSN = re.compile(r"([0-9A-Fa-f]{1,8})/([0-9A-Fa-f]{1,8})\Z")

WRITER_SQL = """
SELECT json_build_object(
  'in_recovery', pg_is_in_recovery(),
  'authority', (SELECT json_build_object('epoch', epoch,
      'dispatch_enabled', dispatch_enabled)
    FROM deployment_authority WHERE singleton),
  'sites', COALESCE((SELECT json_agg(json_build_object('site_id', site_id,
      'enabled', enabled, 'draining', draining) ORDER BY site_id)
    FROM sites), '[]'::json),
  'sessions', COALESCE((SELECT json_agg(json_build_object('site_id', site_id,
      'deployment_epoch', deployment_epoch, 'live', live, 'count', n)
      ORDER BY site_id, deployment_epoch, live)
    FROM (SELECT site_id, deployment_epoch, lease_until > now() AS live,
            count(*) AS n
          FROM device_sessions GROUP BY 1, 2, 3) grouped), '[]'::json)
);
"""


class CheckError(Exception):
    """The checks could not run; the message is safe to print."""


Runner = Callable[[str], dict]
Fetcher = Callable[[str], tuple[int | None, str]]


def service_runner(service: str) -> Runner:
    if not SERVICE_NAME.fullmatch(service):
        raise CheckError("--service must be a libpq service name, not a connection string")
    return lambda sql: _run_psql(["psql", "-d", f"service={service}", *PSQL_FLAGS], sql)


def compose_runner(env_file: Path, compose_file: Path = COMPOSE) -> Runner:
    command = [
        "docker", "compose", "--env-file", str(env_file), "-f", str(compose_file),
        "exec", "-T", "db", "sh", "-ec",
        'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" '
        '-d "$POSTGRES_DB" "$@"',
        "psql", *PSQL_FLAGS,
    ]
    return lambda sql: _run_psql(command, sql)


def _run_psql(command: list[str], sql: str) -> dict:
    try:
        result = subprocess.run(
            command,
            input=READ_ONLY_SESSION + sql,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"could not run {command[0]}") from error
    if result.returncode:
        # stderr can contain host names or connection details; do not print it.
        raise CheckError(f"query failed (exit {result.returncode})")
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError as error:
        raise CheckError("query returned unexpected output") from error


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect is reported as its 3xx status, never followed."""

    def redirect_request(self, *args, **kwargs):
        return None


_READYZ_OPENER = urllib.request.build_opener(_RefuseRedirects)


def parse_lsn(text: str) -> int:
    match = LSN.fullmatch(text or "")
    if match is None:
        raise ValueError("not a PostgreSQL LSN")
    return (int(match.group(1), 16) << 32) | int(match.group(2), 16)


def fetch_readyz(url: str) -> tuple[int | None, str]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with _READYZ_OPENER.open(request, timeout=READYZ_TIMEOUT_SECONDS) as response:
            return response.status, response.read(256).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(256).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


def check(name: str, ok: bool, **detail) -> dict:
    return {"name": name, "ok": bool(ok), **detail}


def standby_checks(
    observed: dict,
    max_lag_seconds: float,
    writer_stopped: bool = False,
    min_replay_lsn: str | None = None,
) -> tuple[list[dict], list[str]]:
    checks = [check("standby_in_recovery", observed.get("in_recovery") is True)]
    status = observed.get("receiver_status")
    age = observed.get("receiver_message_age_seconds")
    if not writer_stopped:
        # Before the old writer is stopped, the standby must still be receiving.
        checks.append(
            check(
                "wal_receiver_streaming",
                status == "streaming",
                value=status,
                **({} if status is not None else {"hint": "needs pg_monitor or a running receiver"}),
            )
        )
        checks.append(
            check(
                "wal_receiver_recent",
                age is not None and age <= max_lag_seconds,
                limit_seconds=max_lag_seconds,
                value_seconds=age,
            )
        )
    lag_bytes = observed.get("replay_lag_bytes")
    lag_seconds = observed.get("replay_lag_seconds")
    seconds_ok = lag_seconds is not None and lag_seconds <= max_lag_seconds
    # Received minus replayed. It cannot see WAL the writer produced that
    # has not arrived yet; sender_caught_up covers that.
    if writer_stopped:
        received_ok = lag_bytes == 0
    else:
        received_ok = lag_bytes is not None and (lag_bytes == 0 or seconds_ok)
    checks.append(
        check(
            "received_replayed",
            received_ok,
            limit_seconds=None if writer_stopped else max_lag_seconds,
            value_bytes=lag_bytes,
            value_seconds=lag_seconds,
        )
    )
    # The sender's WAL end as last reported to this standby, minus replay.
    gap = observed.get("sender_gap_bytes")
    report_age = observed.get("sender_report_age_seconds")
    hint = {}
    if writer_stopped:
        if gap is not None:
            # A receiver that is still present keeps the sender's last report
            # until wal_receiver_timeout drops it. If the old writer crashed
            # behind a network partition, that report is stale: the writer kept
            # committing WAL that never shipped, so a zero gap proves nothing.
            # Trust the report only while it is fresh, or when the operator's
            # recorded final LSN bounds what was lost.
            report_fresh = (
                report_age is not None and report_age <= max_lag_seconds
            )
            sender_ok = gap <= 0 and (report_fresh or min_replay_lsn is not None)
            if gap <= 0 and not sender_ok:
                hint = {"hint": "sender report is stale; pass --min-replay-lsn"}
        else:
            # The receiver exits with the writer; only the operator's recorded
            # final LSN can bound what was lost.
            sender_ok = min_replay_lsn is not None
            if not sender_ok:
                hint = {"hint": "sender position unknown; pass --min-replay-lsn"}
    else:
        # A zero gap proves nothing unless the sender reported recently; an
        # idle writer is caught up only then. Otherwise the replayed commit
        # must be recent. An unknown gap is never caught up.
        idle_caught_up = (
            gap is not None
            and gap <= 0
            and report_age is not None
            and report_age <= max_lag_seconds
        )
        sender_ok = gap is not None and (idle_caught_up or seconds_ok)
        if gap is None:
            hint = {"hint": "sender position unknown; needs pg_monitor or a running receiver"}
    checks.append(
        check(
            "sender_caught_up",
            sender_ok,
            limit_seconds=max_lag_seconds,
            value_bytes=gap,
            value_report_age_seconds=report_age,
            **hint,
        )
    )
    if min_replay_lsn is not None:
        try:
            replayed = parse_lsn(observed.get("replay_lsn"))
        except ValueError:
            replayed = None
        checks.append(
            check(
                "min_replay_lsn",
                replayed is not None and replayed >= parse_lsn(min_replay_lsn),
                expected_at_least=min_replay_lsn,
                value=observed.get("replay_lsn"),
            )
        )
    warnings = [
        "with asynchronous replication, WAL the old writer never shipped is lost "
        "on promotion; only --min-replay-lsn with the writer's final LSN bounds it"
    ]
    if writer_stopped:
        warnings.append(
            "receiver streaming checks skipped because the old writer is "
            "declared stopped; this tool cannot prove that it is"
        )
    return checks, warnings


def writer_checks(
    observed: dict,
    *,
    expected_epoch: int,
    dispatch: str,
    fenced_sites: list[str],
    active_sites: list[str],
) -> tuple[list[dict], list[str]]:
    checks = [check("writer_not_in_recovery", observed.get("in_recovery") is False)]
    authority = observed.get("authority")
    checks.append(check("deployment_authority_present", isinstance(authority, dict)))
    authority = authority if isinstance(authority, dict) else {}
    epoch = authority.get("epoch")
    checks.append(
        check("deployment_epoch", epoch == expected_epoch, expected=expected_epoch, value=epoch)
    )
    if dispatch != "any":
        enabled = authority.get("dispatch_enabled")
        checks.append(
            check(
                "dispatch_state",
                enabled is (dispatch == "enabled"),
                expected=dispatch,
                value=None if enabled is None else ("enabled" if enabled else "paused"),
            )
        )
    sites = {row["site_id"]: row for row in observed.get("sites") or []}
    for site in fenced_sites:
        row = sites.get(site)
        checks.append(
            check(
                "site_fenced",
                row is not None and (row["draining"] or not row["enabled"]),
                site_id=site,
                value=_site_state(row),
            )
        )
    for site in active_sites:
        row = sites.get(site)
        checks.append(
            check(
                "site_active",
                row is not None and row["enabled"] and not row["draining"],
                site_id=site,
                value=_site_state(row),
            )
        )
    warnings = []
    fenced = {site for site, row in sites.items() if row["draining"] or not row["enabled"]}
    for row in observed.get("sessions") or []:
        if not row.get("live"):
            continue
        if isinstance(epoch, int) and row["deployment_epoch"] < epoch:
            warnings.append(
                f"{row['count']} live device session(s) on site {row['site_id']} carry "
                f"older deployment epoch {row['deployment_epoch']}; they cannot receive "
                "grants and should reconnect or expire"
            )
        if row["site_id"] in fenced:
            warnings.append(
                f"{row['count']} live device session(s) remain on fenced site {row['site_id']}"
            )
    return checks, warnings


def _site_state(row: dict | None) -> str:
    if row is None:
        return "missing"
    if not row["enabled"]:
        return "disabled"
    return "draining" if row["draining"] else "active"


def readyz_checks(ready: list[str], unready: list[str], fetch: Fetcher) -> list[dict]:
    checks = []
    # URLs are not echoed: reports get pasted into tickets and chats.
    for index, url in enumerate(ready, start=1):
        status, body = fetch(url)
        checks.append(
            check(
                "readyz_ready",
                status == 200 and '"ready"' in body,
                target=f"ready #{index}",
                value=status,
            )
        )
    for index, url in enumerate(unready, start=1):
        status, _ = fetch(url)
        checks.append(
            check("readyz_not_ready", status != 200, target=f"unready #{index}", value=status)
        )
    return checks


def _site_list(values: list[str], flag: str) -> list[str]:
    for value in values:
        if not SITE_ID.fullmatch(value):
            raise CheckError(f"{flag} values must be site IDs")
    return values


def _url_list(values: list[str]) -> list[str]:
    for value in values:
        if not re.match(r"https?://", value):
            raise CheckError("readyz URLs must start with http:// or https://")
    return values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="phase", required=True)
    for name, help_text in (
        ("standby", "before promotion: is this standby safe to promote?"),
        ("writer", "after promotion and the epoch bump: is the new writer fenced correctly?"),
    ):
        phase = sub.add_parser(name, help=help_text)
        target = phase.add_mutually_exclusive_group(required=True)
        target.add_argument("--service", help="libpq service name from pg_service.conf")
        target.add_argument(
            "--compose-env",
            type=Path,
            help="private Compose .env file; query the local Compose db service (rehearsal)",
        )
        if name == "standby":
            phase.add_argument(
                "--max-lag-seconds", type=float, default=DEFAULT_MAX_LAG_SECONDS,
                help="replay and receiver lag limit (default: %(default)s)",
            )
            phase.add_argument(
                "--writer-stopped", action="store_true",
                help="the old writer is already fenced and stopped: skip receiver "
                "streaming checks, require every received WAL byte to be replayed, "
                "and trust the receiver's sender report only while it is fresh",
            )
            phase.add_argument(
                "--min-replay-lsn", metavar="LSN",
                help="the old writer's final LSN (pg_current_wal_lsn() recorded just "
                "before stopping it); replay must have reached it",
            )
        else:
            phase.add_argument("--expected-epoch", type=int, required=True)
            phase.add_argument(
                "--dispatch", choices=("paused", "enabled", "any"), default="paused",
                help="expected deployment_authority.dispatch_enabled (default: %(default)s)",
            )
            phase.add_argument("--fenced-site", action="append", default=[], metavar="SITE_ID")
            phase.add_argument("--active-site", action="append", default=[], metavar="SITE_ID")
            phase.add_argument(
                "--readyz", action="append", default=[], metavar="URL",
                help="a /readyz URL that must return 200 ready",
            )
            phase.add_argument(
                "--readyz-unready", action="append", default=[], metavar="URL",
                help="a /readyz URL that must not return 200 (for example the old site)",
            )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    runner: Runner | None = None,
    fetch: Fetcher = fetch_readyz,
    stdout: TextIO = sys.stdout,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        if runner is None:
            runner = (
                service_runner(args.service)
                if args.service
                else compose_runner(args.compose_env)
            )
        if args.phase == "standby":
            if args.max_lag_seconds <= 0:
                raise CheckError("--max-lag-seconds must be positive")
            if args.min_replay_lsn is not None and not LSN.fullmatch(args.min_replay_lsn):
                raise CheckError("--min-replay-lsn must be an LSN such as 0/3000060")
            observed = runner(STANDBY_SQL)
            checks, warnings = standby_checks(
                observed, args.max_lag_seconds, args.writer_stopped, args.min_replay_lsn
            )
        else:
            if args.expected_epoch <= 0:
                raise CheckError("--expected-epoch must be positive")
            fenced = _site_list(args.fenced_site, "--fenced-site")
            active = _site_list(args.active_site, "--active-site")
            if set(fenced) & set(active):
                raise CheckError("a site cannot be both fenced and active")
            ready, unready = _url_list(args.readyz), _url_list(args.readyz_unready)
            observed = runner(WRITER_SQL)
            checks, warnings = writer_checks(
                observed,
                expected_epoch=args.expected_epoch,
                dispatch=args.dispatch,
                fenced_sites=fenced,
                active_sites=active,
            )
            checks += readyz_checks(ready, unready, fetch)
    except CheckError as error:
        print(f"promotion_check: {error}", file=sys.stderr)
        return 2
    report = {
        "checks": checks,
        "observed": observed,
        "phase": args.phase,
        "report": "zrotext-promotion-check/v1",
        "verdict": "go" if all(item["ok"] for item in checks) else "no-go",
        "warnings": warnings,
    }
    json.dump(report, stdout, indent=2, sort_keys=True)
    stdout.write("\n")
    return 0 if report["verdict"] == "go" else 1


if __name__ == "__main__":
    sys.exit(main())
