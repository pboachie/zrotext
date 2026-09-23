#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Rehearse a logical Compose restore in a new, disposable project.

The archive is short lived and local. No application container is started in
the restore project, so a restored queue cannot dispatch during this drill.
"""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yaml"
MIGRATIONS = HERE / "migrations"
PROJECT_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
MIGRATION_NAME = re.compile(r"(\d{3})_[a-z0-9_]+\.sql\Z")


class DrillError(Exception):
    pass


def run(command, *, stage, stdin=None, stdout=subprocess.PIPE, timeout=3600):
    try:
        result = subprocess.run(
            command, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DrillError(f"{stage} could not run") from exc
    if result.returncode:
        # Command stderr can contain connection strings or database content.
        raise DrillError(f"{stage} failed (exit {result.returncode})")
    return result.stdout


def compose(project, env_file, *args):
    return [
        "docker", "compose", "--project-name", project,
        "--env-file", str(env_file), "-f", str(COMPOSE), *args,
    ]


def db_exec(project, env_file, *args):
    return compose(project, env_file, "exec", "-T", "db", "sh", "-ec", *args)


SUMMARY_SQL = """
SELECT json_build_object(
  'ledger', COALESCE((
    SELECT json_agg(json_build_array(version, filename,
      encode(checksum_sha256, 'hex'), kind) ORDER BY version)
    FROM schema_migrations), '[]'::json),
  'tenants', COALESCE((
    SELECT json_agg(json_build_array(a.id::text,
      (SELECT count(*) FROM messages m WHERE m.account_id = a.id)) ORDER BY a.id)
    FROM accounts a), '[]'::json),
  'messages', (SELECT count(*) FROM messages),
  'device_identities', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, device_count,
      revoked_count, identity_digest) ORDER BY account_id)
    FROM (
      SELECT d.account_id, count(*) AS device_count,
        count(*) FILTER (WHERE d.revoked_at IS NOT NULL) AS revoked_count,
        md5(string_agg(d.id::text || ':' ||
          COALESCE(encode(k.fingerprint, 'hex'), '') || ':' ||
          (d.revoked_at IS NOT NULL)::text || ':' ||
          (k.revoked_at IS NOT NULL)::text, ',' ORDER BY d.id)) AS identity_digest
      FROM devices d LEFT JOIN device_keys k
        ON (k.account_id, k.device_id) = (d.account_id, d.id)
      GROUP BY d.account_id
    ) identities), '[]'::json),
  'message_states', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, state, count)
      ORDER BY account_id, state)
    FROM (SELECT account_id, state, count(*) AS count
      FROM messages GROUP BY account_id, state) states), '[]'::json),
  'attempt_states', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, status, count)
      ORDER BY account_id, status)
    FROM (SELECT account_id, status, count(*) AS count
      FROM message_attempts GROUP BY account_id, status) attempts), '[]'::json),
  'dispatch_jobs', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, count, ungranted)
      ORDER BY account_id)
    FROM (SELECT account_id, count(*) AS count,
      count(*) FILTER (WHERE grant_issued_at IS NULL) AS ungranted
      FROM dispatch_jobs GROUP BY account_id) jobs), '[]'::json),
  'usage_periods', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, metric,
      period_start::text, limit_units, reserved_units, refunded_units)
      ORDER BY account_id, metric, period_start)
    FROM usage_periods), '[]'::json),
  'usage_ledger', COALESCE((
    SELECT json_agg(json_build_array(account_id::text, metric,
      period_start::text, entry_kind, count, units)
      ORDER BY account_id, metric, period_start, entry_kind)
    FROM (SELECT account_id, metric, period_start, entry_kind,
      count(*) AS count, sum(units) AS units
      FROM usage_ledger
      GROUP BY account_id, metric, period_start, entry_kind) entries), '[]'::json)
)::text;
"""


def summary(project, env_file):
    raw = run(
        db_exec(project, env_file,
                'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -A -t -q '
                '-v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"',
                "psql", SUMMARY_SQL),
        stage="database summary", timeout=30,
    )
    try:
        value = json.loads(raw.decode("utf-8").strip())
        list_fields = ("ledger", "tenants", "device_identities", "message_states",
                       "attempt_states", "dispatch_jobs", "usage_periods", "usage_ledger")
        if (any(not isinstance(value[field], list) for field in list_fields)
                or not isinstance(value["messages"], int)):
            raise ValueError("unexpected summary shape")
        if sum(row[1] for row in value["tenants"]) != value["messages"]:
            raise ValueError("tenant count sum differs from messages total")
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise DrillError("database summary is invalid") from exc
    return value


def verify_ledger(ledger):
    files = sorted(MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
    if not files or len(files) != len(ledger):
        raise DrillError("migration ledger differs from local migration files")
    for expected_version, (path, row) in enumerate(zip(files, ledger), 1):
        match = MIGRATION_NAME.fullmatch(path.name)
        if not match or int(match.group(1)) != expected_version:
            raise DrillError("local migrations are not consecutive")
        expected = [expected_version, path.name,
                    hashlib.sha256(path.read_bytes()).hexdigest()]
        if (not isinstance(row, list) or len(row) != 4
                or row[:3] != expected
                or row[3] not in ("applied", "legacy_baseline")):
            raise DrillError("migration ledger checksum or order differs from local files")
    return len(files)


def protected_tempdir():
    directory = Path(tempfile.mkdtemp(prefix="zrotext-restore-"))
    try:
        if os.name == "nt":
            identity = run(["whoami", "/user", "/fo", "csv", "/nh"],
                           stage="Windows identity", timeout=10)
            sid = next(csv.reader(identity.decode("utf-8-sig").splitlines()))[1]
            if not re.fullmatch(r"S-1(?:-\d+)+", sid):
                raise DrillError("Windows identity is invalid")
            run(["icacls", str(directory), "/inheritance:r", "/grant:r",
                 f"*{sid}:(OI)(CI)F"], stage="private directory ACL", timeout=10)
        else:
            os.chmod(directory, 0o700)
    except Exception:
        shutil.rmtree(directory)
        raise
    return directory


def target_is_new(project):
    volume = f"{project}_pgdata"
    network = f"{project}_private"
    try:
        volume_check = subprocess.run(["docker", "volume", "inspect", volume],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      timeout=10, check=False)
        network_check = subprocess.run(["docker", "network", "inspect", network],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=10, check=False)
        containers = run(["docker", "ps", "-aq", "--filter",
                          f"label=com.docker.compose.project={project}"],
                         stage="restore target preflight", timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DrillError("restore target preflight could not run") from exc
    if volume_check.returncode == 0 or network_check.returncode == 0 or containers.strip():
        raise DrillError("restore target already exists")


def stop_on_signal(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-project", required=True,
                        help="existing Compose project to read; no source writes")
    parser.add_argument("--env-file", required=True, type=Path,
                        help="private Compose environment file")
    args = parser.parse_args()
    if not PROJECT_NAME.fullmatch(args.source_project):
        raise DrillError("invalid source project name")
    env_file = args.env_file.resolve(strict=True)
    if not env_file.is_file():
        raise DrillError("environment file is not a regular file")
    target = "zt-restore-" + uuid.uuid4().hex[:16]
    target_is_new(target)
    directory = protected_tempdir()
    archive = directory / "snapshot.dump"
    started = False
    completed = False
    cleanup_error = None
    try:
        before = summary(args.source_project, env_file)
        migration_count = verify_ledger(before["ledger"])
        with archive.open("xb") as output:
            if os.name != "nt":
                os.chmod(archive, 0o600)
            run(db_exec(args.source_project, env_file,
                        'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump '
                        '--format=custom --no-owner --no-acl --lock-wait-timeout=5s '
                        '-U "$POSTGRES_USER" -d "$POSTGRES_DB"'),
                stage="logical backup", stdout=output)
        after = summary(args.source_project, env_file)
        if before != after:
            raise DrillError("source changed during backup; quiesce writers and retry")
        started = True
        run(compose(target, env_file, "up", "-d", "--wait", "db"),
            stage="disposable database startup", timeout=180)
        with archive.open("rb") as source:
            run(db_exec(target, env_file,
                        'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_restore '
                        '--exit-on-error --single-transaction --no-owner --no-acl '
                        '-U "$POSTGRES_USER" -d "$POSTGRES_DB"'),
                stage="disposable restore", stdin=source)
        restored = summary(target, env_file)
        verify_ledger(restored["ledger"])
        if before != restored:
            raise DrillError("restored migration ledger or tenant/message counts differ")
        completed = True
    finally:
        if started:
            try:
                run(compose(target, env_file, "down", "--volumes", "--remove-orphans"),
                    stage="disposable target cleanup", timeout=180)
            except DrillError as exc:
                cleanup_error = exc
        try:
            shutil.rmtree(directory)
        except OSError as exc:
            cleanup_error = DrillError("private temporary archive cleanup failed")
        if cleanup_error:
            raise DrillError(f"{cleanup_error}; inspect disposable project {target}")
    if completed:
        print(f"restore rehearsal passed: {migration_count} migrations, "
              f"{len(before['tenants'])} tenants, {before['messages']} messages; "
              "disposable target removed")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, stop_on_signal)
    signal.signal(signal.SIGTERM, stop_on_signal)
    try:
        main()
    except (DrillError, FileNotFoundError, KeyboardInterrupt) as error:
        print(f"restore rehearsal failed: {error}", file=sys.stderr)
        sys.exit(1)
