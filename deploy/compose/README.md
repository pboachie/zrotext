# Compose schema migrations

Run `python deploy/compose/fresh_install_smoke.py` from the repository root to
check a disposable fresh installation and logical restore. The script generates
its own local credentials and Compose project, chooses an available loopback
port, and removes its containers and database volume afterward. It does not
read the repository `.env` or enable message dispatch. After checking an empty
install, it stops the API, inserts two synthetic tenants with device identities,
message payloads and states, an attempt and event, an ungranted dispatch job,
an idempotency key, and usage records. The restore rehearsal verifies those
exact records in both the source and the database-only restore target.

For moving an existing deployment to a newer version of the source, follow the
[upgrade guide](UPGRADE.md); it covers pre-flight recording, the migration
sequence, and rollback.

For a release image, use a checkout of its exact annotated source tag. Run
`python3 scripts/release_source_metadata.py` there to obtain the web digest,
device-stream schema digest and final migration number. Pass those values with
the immutable image digest and expected public source identity:

```sh
docker pull ghcr.io/pboachie/zrotext@sha256:<digest>
docker tag ghcr.io/pboachie/zrotext@sha256:<digest> zrotext-release-smoke:local
python3 deploy/compose/fresh_install_smoke.py \
  --image-ref ghcr.io/pboachie/zrotext@sha256:<digest> \
  --source-commit <full-commit-sha> --source-tag v0.1.0-rc.1 \
  --web-static-sha256 <web-digest> \
  --device-stream-schema-sha256 <schema-digest> \
  --migration-last <final-migration-number>
```

This mode checks that the staged local alias has the requested repository digest
and source labels, then verifies that both the migrator and API containers ran
that same image and that `/about/version` reports its source metadata before
checking migrations,
health, readiness, dispatch isolation, and a seeded logical restore. The release-image
workflow runs it before attesting or writing a promotion receipt. A failed
smoke may leave the uniquely tagged image in GHCR, but no reviewed receipt is
produced. The script does not verify a registry attestation or authorize
production promotion; follow the release verification steps in
[RELEASING.md](../../docs/RELEASING.md).

Set `APP_PORT` in `.env` if port 8080 is occupied for the normal local setup;
the documented health endpoints then use that port.

The `app` and `app_b` services forward the documented server settings in
`.env.example`, including synthetic-alpha, inbound-pilot, webhook, and Stripe
TEST settings. Uncomment an optional setting in `.env` only when configuring
that feature; unset keys are omitted from the container. Compose uses
`POSTGRES_PASSWORD` for `db`, `RUNTIME_DATABASE_PASSWORD` to build the API
database URL, and `APP_PORT` for the host-side port. `DATABASE_URL` goes to the
migrator; `MIGRATIONS_DIR` in `.env.example` is for a local binary. Compose
always sets `DISPATCH_ENABLED=false` for both API services, regardless of the
value in `.env`.

## Owner registration

Compose passes `REGISTRATION_MODE`, allowlists, and the optional enrollment
key to both API services. The default is `closed` even if SMTP is configured.
For the first owner, leave it closed, apply migrations and runtime-role
provisioning, stop every API instance, then use the packaged `zrotext-admin`
binary through the private `app` service. It reads a password only from a
non-echoing stdin pipe, creates one verified owner when `accounts` is empty,
and sends no mail. The executable command and later invited-owner HTTPS
registration/verification procedure are in
[Self-hosting](../../docs/SELF-HOSTING.md#owner-registration). Allowlist mode
requires an independent private master key. `zrotext-admin issue-invite`
derives an address-bound token from it; `open` is intentionally public.
Instances without SMTP recover a forgotten owner password with
`zrotext-admin reset-password`; see
[Self-hosting](../../docs/SELF-HOSTING.md#owner-password-recovery).

The `migrate` service applies `migrations/001_*.sql`, `002_*.sql`, and later
consecutive numbered SQL files before the API starts. Migration files are trusted
operator source code, not sandboxed input. The runner rejects explicit transaction
control under both PostgreSQL ordinary-string escaping modes; use explicit
`E'...'` escapes or dollar quoting when ordinary backslash strings are ambiguous.
It holds a PostgreSQL
advisory lock, records a SHA-256 checksum for each version, and commits each
file with its ledger row in one transaction. A failed migration stops Compose
startup with a nonzero exit. Never edit an applied file; add the next number.

Migration 034 is a narrow online-index exception. After the runner validates the
existing ledger, it prepares `messages_in_flight_updated` with
`CREATE INDEX CONCURRENTLY` in autocommit mode while holding the migration
advisory lock. The numbered 034 SQL file then validates the exact index shape
and readiness and records its checksum in the normal transaction. This also runs
automatically on fresh databases. If an interrupted build leaves an invalid
index with the expected shape, rerunning `migrate` drops that invalid index
concurrently and retries. An index with the same name and a different definition
stops migration without being replaced. Once 034 is recorded, later migrator
runs and dispatch-enabled API readiness fail if the index becomes absent,
invalid, or different.

A concurrent build permits message writes but may wait for older transactions;
monitor `pg_stat_progress_create_index` and allow migration to finish before
starting API workers. If application rollback is needed, the valid index can
remain; keep the migration package containing this 034 file so a rolled-back
API does not rerun an older migrator with a mismatched checksum. Removing the
index later requires a separately planned
`DROP INDEX CONCURRENTLY` outside a transaction, after workers that depend on
it are stopped. Do not repair the migration ledger by hand.

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

The local Compose database is named `db` and stays on its private Docker network;
this example does not enable PostgreSQL transport TLS. Remote database URLs for
the API, migrator, and key rewrap tool must use `sslmode=require`. The application
verifies the server certificate and URL hostname using system trust roots, or a
private CA PEM bundle supplied as `DATABASE_TLS_CA_PEM_B64`. Provide that variable
to each relevant container when using a private CA. A URL with `sslmode=prefer` or `disable` for
any host other than loopback, a Unix socket, or Compose `db` fails unless
`DATABASE_ALLOW_PLAINTEXT=true` is explicitly set; that override logs a warning
and permits unencrypted database traffic. See the
[self-hosting guide](../../docs/SELF-HOSTING.md#postgresql-transport-tls).

The application image also includes `zrotext-webhook-kek-rewrap` for a staged
operational webhook encryption-key change. Follow the
[KEK rotation procedure](../../docs/WEBHOOK-KEK-ROTATION.md); the local self-host
example does not configure webhook delivery or supply the required private
keys.

The image also contains the local TEST billing review command
`/usr/local/bin/zrotext-billing-risk-review`. After migration 024, run it as a
one-off process on the private Compose network with the runtime database URL;
`list [--after evt_ID]` needs no provider key. For `resolve`, supply a TEST-only
`STRIPE_BILLING_RECONCILIATION_KEY` through a temporary protected environment,
not a Compose file, command argument or image layer. See the
[billing review procedure](../../docs/STRIPE-TEST-BILLING.md)
for the decision and audit rules. The Compose example does not enable billing.

## Database role separation

The Compose API services use `zrotext_runtime`, with a separate
`RUNTIME_DATABASE_PASSWORD`. Generate this as 32 random bytes encoded as exactly
64 hexadecimal characters, for example with `openssl rand -hex 32`. It must
differ from `POSTGRES_PASSWORD`. Compose constructs the runtime URL itself;
`DATABASE_URL` is used only by `migrate` and must refer to the Compose `zrotext`
database and its `zrotext` migration owner, using `POSTGRES_PASSWORD`.
Do not put the migration credential in an API's environment.

After migrations, `db-runtime` provisions the login before either API starts.
This runs against the current database, not an init directory that would be
skipped for existing volumes. It grants data CRUD, sequence use, and application
function execution, but no migration ledger access, object ownership, schema
creation, temporary tables, truncation, role administration, or server file
access. It also removes public grants in this dedicated application database.
Future tables, sequences, and functions created by the same migration owner
inherit runtime grants. Review new functions for privilege requirements; do not
add `SECURITY DEFINER` functions without a separate security review. A migration
using another object owner needs an explicit grant review.

For an **existing Compose volume**, back up first and stop both API services.
Keep the existing admin password and URL, and add the independent runtime secret
to the private `.env`. Do not delete or reinitialize the volume. For this upgrade
and later migration or runtime-password changes, run from the repository root
(the full procedure, including pre-flight recording and post-upgrade checks, is
in the [upgrade guide](UPGRADE.md)):

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml stop app app_b
docker compose --env-file .env -f deploy/compose/compose.yaml up -d db
docker compose --env-file .env -f deploy/compose/compose.yaml build migrate app
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm migrate
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm --no-deps db-runtime
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --force-recreate app
```

Require each command to succeed before proceeding. For the two-hub profile,
also build and recreate `app_b` with `--profile two-hub`. Explicit provisioning
avoids relying on Compose to rerun an unchanged, previously completed one-shot
container. Password changes require restarting every API connection pool.
Provisioning is transactional and repeatable; it refuses a pre-existing runtime
role that owns objects, has role memberships, or holds unexpected grants or
database settings outside the provisioned scope. Investigate and explicitly
reassign ownership/revoke unsafe grants as an administrator before retrying.
This assumes an administrator-controlled PostgreSQL cluster; custom public
grants or privileged extensions elsewhere require their own review.

Backups made with `--no-owner --no-acl` intentionally omit these grants. After a
real restore, run migrations and `db-runtime` before starting any API. The restore
rehearsal remains database-only and never enables a restored API. The fresh
install smoke additionally checks runtime CRUD and application functions and
rejects DDL, ledger writes, admin role switching, and server file/program access.
Run `python scripts/tests/test_runtime_db_role.py` to exercise repeat provisioning,
future migration grants, unsafe existing roles, and invalid/reused secrets in a
new disposable local PostgreSQL container.

This reduces database privileges of a compromised API; it does not isolate
tenants within the shared runtime role or prevent access to application rows.
The migration owner remains an administrative credential for this template;
restrict it to operator-controlled migration/provisioning jobs. Database hosts,
backups, secret stores, and production TLS still need deployment controls.

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
re-enablement of dispatch after a real restore.

The fresh-install smoke uses `--expect-synthetic-fixture` when it invokes this
drill. That flag checks the checked-in synthetic fixture on both sides of the
restore and is intended for disposable projects only. Leave it off when
rehearsing a real self-host database.

## Production hardening checklist

Work through this before exposing a deployment beyond local tests. Every item
names a mechanism this repository ships, or says plainly when the control is
operator guidance it does not automate. A ticked box is an operator statement
about one deployment; nothing here is enforced by the repository.

### Edge and TLS exposure

- [ ] Run the `edge` profile (or an equivalent TLS proxy); the API service
  itself stays published on host loopback (`127.0.0.1:${APP_PORT:-8080}`) and
  the edge holds the only public ports.
- [ ] Set `EDGE_DOMAIN` to a real DNS name and `AUTH_ORIGIN` to the exact
  public HTTPS origin; account mutations reject any other `Origin`
  ([Self-hosting](../../docs/SELF-HOSTING.md#public-https-and-device-wss)).
- [ ] Serve the device stream under a publicly trusted certificate; Android
  does not trust user-installed CAs by default. Keep the `caddy_data` volume so
  certificate state survives restarts.
- [ ] Rehearse the edge with `python deploy/compose/edge_smoke.py` (HTTPS
  sign-in, secure cookies, exact-Origin handling, WSS upgrade) before pointing
  production traffic at it.
- [ ] Add per-source connection limits in front of `/v1/device-stream`. The
  in-process budgets (32 authenticated sockets and 32 handshakes per process)
  are not keyed by client address and the bundled Caddyfile adds no limiting;
  this control is upstream guidance the repository does not ship.

### Database roles and network isolation

- [ ] Keep the `db` service on the private Compose network; it publishes no
  host ports, and only the API services and the edge join the frontend
  network.
- [ ] Keep `RUNTIME_DATABASE_PASSWORD` an independent 64-hex-character secret
  distinct from `POSTGRES_PASSWORD`, and rerun `db-runtime` explicitly on every
  upgrade (see [Database role separation](#database-role-separation)).
- [ ] After any real restore, run `migrate` and `db-runtime` before starting an
  API; `--no-owner --no-acl` backups omit the runtime grants.
- [ ] Use `sslmode=require` (and `DATABASE_TLS_CA_PEM_B64` for a private CA) in
  every database URL that leaves the local Compose network. The local `db` does
  not enable PostgreSQL transport TLS; it stays on the private network. Treat
  `DATABASE_ALLOW_PLAINTEXT=true` as a warned exception, never a default.
- [ ] Accept the stated limits honestly: the runtime role narrows a compromised
  API but does not isolate tenants within the shared schema, and the migration
  owner stays an administrative credential restricted to operator jobs.

### Secrets

- [ ] Keep every secret in the private `.env` or an operator secret store;
  `.env` is git-ignored, and no credential belongs in a Compose file, a command
  argument, an image layer, or the repository.
- [ ] Generate `AUTH_TOKEN_PEPPER_B64` and `ENROLLMENT_TOKEN_PEPPER_B64`
  independently and keep them stable across restarts and restores; sessions and
  recovery-code verification depend on them.
- [ ] After enrolling invited owners, remove the allowlists and the enrollment
  master key and return `REGISTRATION_MODE` to `closed` (see
  [Owner registration](#owner-registration)).
- [ ] Supply SMTP credentials (`SMTP_USERNAME`/`SMTP_PASSWORD`; port 465 is
  implicit TLS and other ports use STARTTLS, `SMTP_SECURE=false` is rejected)
  only through the private environment.
- [ ] If the TEST billing review command is used, supply its reconciliation key
  through a protected temporary environment only, never a Compose file, a
  command argument, or an image layer (see the billing review paragraph above).
- [ ] Give every site the same webhook KEK pair and rotate only through the
  staged two-site procedure with `zrotext-webhook-kek-rewrap --check/--apply`
  ([KEK rotation](../../docs/WEBHOOK-KEK-ROTATION.md)). The repository ships
  the procedure; the rotation cadence and its scheduling are operator policy it
  does not automate.
- [ ] Plan an MFA key change as a separate migration, never an ad hoc
  replacement of `MFA_ENCRYPTION_KEY_B64`
  ([MFA operations](../../docs/MFA-OPERATIONS.md)).

### Backups and restore rehearsal

- [ ] Take real backups with your own `pg_dump` policy before every upgrade and
  on a defined cadence. There is no checked-in production backup script; the
  drill below verifies you could restore, it does not produce a backup.
- [ ] Rehearse a restore before every upgrade, as the
  [upgrade pre-flight](UPGRADE.md) requires: quiesce writers, then
  `python3 deploy/compose/restore_rehearsal.py --source-project zrotext --env-file .env`.
  Rerun it against the upgraded database before it accumulates new data.
- [ ] Record the pre-upgrade identity (image digest or source commit, highest
  migration number, `/about/version`) and compare it with the post-upgrade
  record; rollback means restoring the backup, because downgrades are
  unsupported.
- [ ] Rehearse the target version with `fresh_install_smoke.py` from that
  version's checkout; for a release image, pass the immutable digest and
  receipt metadata and verify the receipt per
  [Releases](../../docs/RELEASING.md).
- [ ] Protect every archive (it contains message content), keep it off the
  machine, and plan encrypted archival, off-site recovery, and a measured
  RPO/RTO yourself. The drill establishes none of these, and archive deletion
  is not a secure erase. Backup cadence and retention are operator policy.

### Monitoring and alerting

- [ ] Probe `/healthz` (process liveness) and `/readyz` (adds database
  readiness; returns 503 while draining). These two, plus `/about/version`,
  are the only operational endpoints today; the per-surface `/readyz/api` and
  `/readyz/hub` checks in
  [Multi-location](../../docs/MULTI-LOCATION.md#health-endpoints-and-failure-behavior)
  are design, not shipped routes.
- [ ] While webhook delivery is enabled, watch the `webhook_queue
  pending=... oldest_pending_age_seconds=... in_flight=...` line in container
  logs (about once a minute) alongside the owner-visible pause state.
- [ ] During migration 034, monitor `pg_stat_progress_create_index` and let
  the migration finish before starting API workers.
- [ ] Provide your own alerting. The stack has no metrics endpoint, dashboard,
  or notifier; wiring the endpoints and log lines above into monitoring is
  operator work the repository does not automate.

### Dependency and image updates

- [ ] Track the repository's update signals: CI builds the server image and
  fails on critical fixable Trivy findings, keeping the report as an artifact
  ([ci.yml](../../.github/workflows/ci.yml)); Dependabot opens weekly update
  PRs for Cargo, Gradle, Actions, and Docker pins; and PR dependency review
  fails on high severity.
- [ ] Scan your own image on your own cadence. The CI scan covers the
  repository's build on pull requests and `main`, not a running deployment.
- [ ] Deploy release images only by immutable digest from a reviewed
  `image-receipt.json`, verified with `scripts/verify_release_image.py`
  ([Releases](../../docs/RELEASING.md)); never a mutable registry tag.
- [ ] Rebuild and redeploy deliberately. This stack builds from a pinned
  source checkout, so updates are the [upgrade procedure](UPGRADE.md), not an
  automated channel; pinned versions and provenance are described in
  [Dependencies](../../docs/DEPENDENCIES.md).

### Account security

- [ ] Create the first owner with `zrotext-admin create-owner` while
  registration stays closed and the APIs are stopped; never leave
  `REGISTRATION_MODE=open` on an instance you intend to keep private.
- [ ] Enroll owner MFA per [MFA operations](../../docs/MFA-OPERATIONS.md): an
  independent 32-byte `MFA_ENCRYPTION_KEY_B64`, the same value on every
  account-serving site and across restores, older binaries drained before
  `MFA_ENROLLMENT_ENABLED=true`, and recovery codes saved during enrollment.
- [ ] If the MFA key becomes unavailable, use `MFA_RECOVERY_ONLY=true`
  deliberately and restore the key afterwards; the mode is a fallback, not a
  substitute for key custody.
- [ ] Know the session behavior: owner sessions last a fixed 14 days, the
  session cookie is `__Host-` Secure/HttpOnly/SameSite=Lax, and sign-out or a
  password reset revokes sessions and owner-issued API keys. The lifetime is
  fixed in code; there is no configurable idle timeout or session-listing
  page, so treat shared workstations accordingly.
- [ ] Reset a forgotten owner password without SMTP through
  `zrotext-admin reset-password` and reissue integration keys afterwards
  ([Self-hosting](../../docs/SELF-HOSTING.md#owner-password-recovery)).

### Retention defaults

- [ ] Choose the six `ZT_*_RETENTION_DAYS` values deliberately (defaults:
  idempotency 7, message content 30, events 90, webhook history 30, inbound 30,
  sealed inbound 30; integers 1-3650; an invalid value blocks startup) and
  deploy the same values to every hub. Cutoffs are eligibility ages, not
  deletion deadlines, and a longer value cannot restore redacted content.
- [ ] Plan lifecycle controls beyond the worker: backups, WAL, replicas, and
  PostgreSQL dead tuples keep data past these cutoffs and need their own
  policy; the repository does not automate that.
- [ ] Expect what retention does not do: opt-out rows and review audit records
  are never pruned, and the worker is not an account-erasure API
  ([Self-hosting](../../docs/SELF-HOSTING.md#data-retention)).
