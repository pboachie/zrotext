# Compose schema migrations

The `migrate` service applies `migrations/001_*.sql`, `002_*.sql`, and later
consecutive numbered SQL files before the API starts. It holds a PostgreSQL
advisory lock, records a SHA-256 checksum for each version, and commits each
file with its ledger row in one transaction. A failed migration stops Compose
startup with a nonzero exit. Never edit an applied file; add the next number.

For a **new database**, use the normal documented `docker compose up -d --build`
command. The old `docker-entrypoint-initdb.d` mount is no longer used.

For a **pre-runner M0 Compose volume**, first stop API containers and keep
dispatch disabled. Back up the volume. Then run once:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml up -d db
docker compose --env-file .env -f deploy/compose/compose.yaml build migrate
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm migrate --baseline-m0
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --build
```

The baseline command verifies that all five M0 tables have the expected
columns and a primary key, required named unique indexes exist, and dispatch
is off. This structural check does not compare every constraint definition;
review any older database with known manual schema changes before baselining.
It records 001 without replaying it, then applies the remaining numbered files.
It refuses missing or extra M0 columns and missing primary keys or required
indexes. Investigate any failure before retrying; do not modify
`schema_migrations` by hand.

The Compose connection is private-network PostgreSQL without transport TLS.
This is a self-host example, not a production migration procedure. The
deployment plan must add a protected TLS connection and backup/restore proof
before an internet-facing launch.

## Disposable logical restore rehearsal

With an existing Compose database and its private `.env` file, quiesce all
writers first and run from the repository root:

```sh
python3 deploy/compose/restore_rehearsal.py --source-project zrotext --env-file .env
```

On Windows, use `python` if `python3` is not installed. The script reads the
named source project and does not write to it. It makes a PostgreSQL custom
format logical dump in a private temporary directory (mode `0700` and archive
mode `0600` on POSIX; inherited ACLs removed and the current user granted
access on Windows). The archive contains the complete database, including any
message content, so run this only on a trusted local machine with protected
temporary storage. It is deleted after the drill; deletion is not a secure
erase of storage blocks. This script is a rehearsal, not a durable or off-site
backup policy.

The restore target is a randomly named, fresh Compose project. Only its `db`
service starts: no API, dispatcher, mail sender, or webhook worker starts from
the restored snapshot. The script refuses an existing target volume or
container. It compares source summaries before and after the dump, restores
into the new database, and requires an exact match for the numbered migration
ledger (including checksums and local SQL files), per-tenant message counts,
tenant set, total messages, device identity digests, message and attempt state
counts, dispatch job counts, and usage period/ledger totals. The identity
digest is a change detector, not an authentication check. Only aggregate
counts appear in success output; message bodies, recipients, tenant IDs, and
credentials do not. A mismatch exits nonzero. The script removes only its
generated target project and volume and its temporary archive, including on a
failed check. If Docker cleanup fails, it prints the generated target project
name for manual inspection.

The pre/post comparison detects ordinary concurrent writes but cannot prove a
quiescent snapshot if rows change and counts return to the same values. Keep
writers stopped for this drill. This local test does not establish off-site
recovery, encrypted archival, a measured RPO/RTO, or safe production
re-enablement of dispatch after a real restore; those remain deployment gates.
