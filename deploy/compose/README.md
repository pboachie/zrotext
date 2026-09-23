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

The application image also includes `zrotext-webhook-kek-rewrap` for a staged
operational webhook encryption-key change. Follow the
[KEK rotation procedure](../../docs/WEBHOOK-KEK-ROTATION.md); the local self-host
example does not configure webhook delivery or supply the required private
keys.
