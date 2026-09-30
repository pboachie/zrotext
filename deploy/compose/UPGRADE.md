# Upgrading a self-hosted Compose deployment

This guide moves an existing deployment built from this repository's Compose
stack to a newer version of the source. It covers the mechanics that exist
today: stopping API services, applying numbered SQL migrations with the
migration role, re-provisioning the runtime database role, restarting, and
checking health. Read it together with the [Compose guide](README.md) and
[Self-hosting](../../docs/SELF-HOSTING.md).

Select a reviewed source commit or a published version tag using
[Releases and version tags](../../docs/RELEASING.md). An installation made
before the first release is a *source snapshot*: do not infer its migration
level or compatibility from a release name. Identify the version you are
running and the version you are moving to by three things, and record all
three before and after every upgrade:

1. the image digest or source commit the API was built from,
2. the highest applied migration number, and
3. the output of `/about/version` (populated on release images; see below).

## Pre-flight: record state and verify backups

Run every command from the repository root of the checkout that matches the
version you are deploying, with your private `.env` file present.

Record the running API's reported identity (uses `APP_PORT`, default 8080):

```sh
curl http://127.0.0.1:8080/about/version
```

On an image built locally with `docker compose build`, the optional fields
(`bundle_version`, `source_commit`, `web_static_sha256`,
`device_stream_schema_sha256`, `migration_last`) are `null` because the build
arguments are only stamped by the release-image workflow. In that case record
the checkout commit instead:

```sh
git rev-parse HEAD
git status --porcelain   # should be empty; deploy from a clean checkout
```

Record the image the running containers use:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml images
```

Record the database migration level. The ledger lives in `schema_migrations`
in the `zrotext` database; query it through the `db` service with the
migration owner account (`POSTGRES_USER`), the same access path the restore
rehearsal uses:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml exec -T db \
  sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" -c "SELECT version, filename, kind, applied_at \
  FROM schema_migrations ORDER BY version;"'
```

The highest `version` row is your migration level. The runtime role used by
the API cannot read this table; that is expected.

Verify your backup path before touching anything:

- Rehearse the restore procedure on the current database with the checked-in
  drill, exactly as documented in the
  [restore rehearsal section](README.md#disposable-logical-restore-rehearsal):

  ```sh
  python3 deploy/compose/restore_rehearsal.py --source-project zrotext --env-file .env
  ```

  On Windows, use `python` if `python3` is not installed. The rehearsal is a
  disposable drill, not a backup policy; it verifies you could restore, it does
  not produce a durable backup.
- Before the upgrade itself, take a real backup with your own `pg_dump`
  policy (the Compose guide says "back up first" for existing volumes and the
  restore rehearsal's caveats apply to any archive: it contains message
  content, so protect it accordingly). There is no checked-in production
  backup script; backups are an operator responsibility.
- Optionally rehearse a complete fresh install of the version you are moving
  to with `python3 deploy/compose/fresh_install_smoke.py` from that version's
  checkout. It creates and removes its own disposable Compose project and never
  reads your `.env`.

Finally, check the release notes or changelog of the version you are deploying
for maintenance windows. Two past examples show the shape of these: migration
029 required webhook delivery to be stopped on every old node before migrating,
and the inbound pilot required draining pre-retention-change workers (both
described in [Self-hosting](../../docs/SELF-HOSTING.md)).

## Upgrade sequence

The Compose file already orders the stack correctly: `migrate` runs to
completion before `db-runtime` provisions the runtime role, and both complete
before `app` (and `app_b`) start — `app` depends on `db` being healthy and
`db-runtime` having completed successfully, and `db-runtime` depends on
`migrate` having completed successfully. `migrate` and `db-runtime` are one-shot
services (`restart: "no"`) that Compose does not reliably rerun when their
definitions are unchanged, so the documented upgrade runs them explicitly
instead of relying on `up -d --build` alone.

Today the stack builds its image from the local checkout (`build:` with the
repository root as context), so "pulling the pinned image" means pinning the
source: fetch, check out the exact commit you reviewed, and build from it.
From the repository root of the new version's checkout:

```sh
git fetch origin main
git rev-parse HEAD        # record the target commit
```

Then, with your private `.env` unchanged except for intentional setting
changes, run each step and require it to succeed before the next:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml stop app app_b
docker compose --env-file .env -f deploy/compose/compose.yaml up -d db
docker compose --env-file .env -f deploy/compose/compose.yaml build migrate app
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm migrate
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm --no-deps db-runtime
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --force-recreate app
```

This is the existing-volume sequence from the
[database role separation section](README.md#database-role-separation) of the
Compose guide. Step by step:

1. `stop app app_b` quiesces all API writers (the exact form documented in
   the Compose guide; when you use the second hub, Self-hosting shows the
   equivalent `--profile two-hub stop app_b` form).
2. `up -d db` starts PostgreSQL alone (or reuses the running one).
3. `build migrate app` builds the new image from the pinned checkout. Build
   `app_b` as well when you use the two-hub profile.
4. `run --rm migrate` starts a one-shot migrator container. It reads the SQL
   files bundled into the image at `/opt/zrotext/migrations` — not your
   working copy — so the migrations applied are exactly the ones shipped with
   the image you built. A nonzero exit here stops the procedure: the database
   is unchanged (each file commits with its ledger row in one transaction).
5. `run --rm --no-deps db-runtime` re-provisions the restricted runtime login.
   It is transactional and repeatable; see the Compose guide for what it does
   and what it refuses.
6. `up -d --force-recreate app` starts the new API. For two hubs, also
   recreate `app_b` with `--profile two-hub`. Compose always starts
   `DISPATCH_ENABLED=false` for both API services in this stack.

The migrator and the API never share credentials: `migrate` uses `DATABASE_URL`
(the `zrotext` migration owner with `POSTGRES_PASSWORD`), the API uses the URL
Compose builds from the separate `RUNTIME_DATABASE_PASSWORD`. Do not put the
migration credential in an API environment.

## What the migrator does, and what to expect

- Migrations are numbered SQL files in `deploy/compose/migrations/`, append-only
  and consecutive from `001_foundation.sql`. The current highest migration in
  this repository is **060** (`060_optout_review_indexes.sql`). Never
  edit a file that is already applied; a change is always a new file with the
  next number.
- The runner takes a fixed PostgreSQL advisory lock for the whole run, creates
  and reads the `schema_migrations` ledger (version, filename, SHA-256
  checksum, kind `applied` or `legacy_baseline`), verifies every applied file
  still matches its recorded checksum, and applies each pending file together
  with its ledger row in a single transaction. A failed file leaves the ledger
  and schema unchanged for that file and exits nonzero, which stops the
  upgrade before any API starts.
- Editing an applied migration file makes the next run fail with
  "applied migration NNN differs from its file; restore the original file and
  add a new migration". Do not repair `schema_migrations` by hand.
- Migrations 034, 040, 049, 050, 052, 057, 059 and 060 are documented exceptions: they build their indexes with
  `CREATE INDEX CONCURRENTLY` before recording the numbered file; see the
  [Compose guide](README.md) for the interrupted-build and rollback rules that
  apply to them. Migration 059 builds five foreign-key support indexes for
  owner account erasure the same way: a matching invalid index left by an
  interrupted build is dropped and rebuilt, and an index of the same name with
  a different definition stops the migration without being replaced.
  Migration 060 builds the opt-out review queue and event lookup indexes the
  same way and drops the redundant `recipient_suppressions_active` index
  online once both are valid.
- Migration 054 drops the `device_auth_challenges` table. Device socket
  challenges are now stateless, but an older binary still writes that table,
  so once 054 is applied every device handshake served by an older API
  instance fails. Stop all older API instances before migrating and do not
  run mixed versions. Going back to an older version after 054 means
  restoring the pre-upgrade backup.
- Migration 058 is the matching exception for a removal: the migrator drops
  `auth_abuse_counters_stale` with `DROP INDEX CONCURRENTLY IF EXISTS` before
  recording the numbered file, and every later run refuses to proceed if that
  index is re-created. See the [Compose guide](README.md).
- `TEST_MIGRATIONS` is not an operator setting. It is the name of private test
  constants in the Rust test suites (for example in
  `crates/delivery-store/src/tests.rs`) that embed the migration SQL so
  PostgreSQL-backed tests can build disposable schemas. There is no
  environment variable of that name; nothing in an upgrade sets it.

**If the database is ahead of the files you are deploying** — the ledger
contains a version with no matching numbered file, which happens when the
checkout or image you built is older than the database — the migrator refuses
to run with "schema_migrations contains an unknown or out-of-order version".
The remedy is to deploy the correct source: fetch the exact commit (or image
digest) whose `deploy/compose/migrations/` contains those numbered files and
rerun `run --rm migrate` from it. Do not delete ledger rows to force the older
version through. The reverse gap (files ahead of the ledger) is the normal
case and is exactly what the upgrade applies.

## Post-upgrade checks

Check the health endpoints from the host (adjust `APP_PORT`, and use your
HTTPS domain when running the edge profile):

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/about/version
```

`/healthz` reports process liveness, `/readyz` additionally reports database
readiness and returns `503` while draining. `/about/version` reports the build
metadata described above. Then check the pages that exist today, signing in as
an owner: `/owner/devices` (the dashboard), `/owner/account` (account, MFA,
API keys), `/owner/sms-lines` (when the SMS line features are enabled), and
`/source` (the source-link page required for modified deployments). The
billing dashboard at `/billing` exists only when Stripe TEST billing is
enabled. Devices reconnect to `/v1/device-stream` on their own schedule;
there is no separate device-fleet status page today.

Confirm the ledger advanced to the expected level by rerunning the pre-flight
ledger query and comparing it with the migration files in the new checkout.
Optionally rerun the restore rehearsal against the upgraded database before
it accumulates new data.

### Rollback

Downgrades are unsupported. There are no down migrations, the ledger is
append-only, and an older API may not understand rows written by the newer
version. The rollback path is the backup you took before upgrading: restore
it per your own procedure, then start the previously recorded image/checkout
against the restored database. Two rules from the Compose guide apply to any
restore:

- Backups made with `--no-owner --no-acl` omit the runtime-role grants. After
  a real restore, run `run --rm migrate` and `run --rm --no-deps db-runtime`
  before starting any API.
- Keep the migration package containing the 034 file available to a
  rolled-back API so an older migrator is not run with a mismatched checksum
  (see the 034 rules in the [Compose guide](README.md)).

Expect to lose data written between the backup and the rollback, and note
that retention deletions and content redaction performed by the newer version
cannot be undone by restoring unless your backup predates them.

## Behavior changes operators must expect

These changes are active in current source and apply when upgrading an older
snapshot; they are listed here so an upgrade is not surprised by them.

- **Database transport policy.** A `DATABASE_URL` for a non-local PostgreSQL
  host (including one literally named `db`) must use `sslmode=require`,
  `verify-ca`, or `verify-full`, or the process refuses to start until the
  explicit, warned `DATABASE_ALLOW_PLAINTEXT=true` opt-in is set. The local
  Compose development stack already sets it. Accepted modes and CA
  configuration are described in the [Compose guide](README.md) and
  [self-hosting documentation](../../docs/SELF-HOSTING.md).
- **Owner session lifetime.** Owner sessions expire after 72 hours without
  use; signed-in owners are logged out rather than retained indefinitely.
  API keys are unaffected and record their last use.
- **API-key issuance and lifetime.** Creating an API key requires the
  owner's current password (and an MFA code when enabled). New keys expire
  after 365 days by default; an explicit, discouraged opt-in issues a
  non-expiring key, and keys created before this change keep working.
  Signing out other sessions does not revoke API keys unless the request
  explicitly opts in.
- **Authentication ordering and error shape.** Owner and API requests are
  authenticated from their headers before their bodies are read. Missing or
  invalid credentials get `401` (or `403` for a bad Origin or CSRF header)
  even when the body is also malformed; that combination used to get `400`.
  A malformed JSON body from an authenticated caller gets the API error
  envelope with HTTP 400. Each account may have at most four authenticated
  body requests in flight per API process, and a fifth concurrent one gets
  `429`.
- **Admission limits.** HTTP admission uses route-class permit pools
  (provider callbacks, device WebSocket upgrades, anonymous
  authentication/enrollment, and general routes) plus a separate pool for
  health, readiness and version probes. Saturation in one class no longer
  rejects the others; a full pool answers `503` with `Retry-After: 1`. A
  request body not received within ten seconds of admission, or a handler
  that passes its 30-second deadline, gets a bare `408`.
- **Registration invites.** Invite tokens expire after a bounded lifetime
  (seven days by default). Outstanding tokens issued by an older snapshot
  stop being accepted; issue new ones through the admin CLI.
- **Email verification.** Verifying an email address now requires the
  registrant's password, and password-reset emails are budgeted per verified
  owner per day.
- **Trusted browsers and reset networks.** After a completed sign-in the
  server sets a signed `__Host-zrotext_trusted_browser` cookie. A password
  reset request from that browser, or from a network listed in the optional
  `RESET_TRUSTED_CIDRS`, spends a separate daily budget that a stranger who
  knows only the address cannot exhaust. `X-Forwarded-For` is honored only
  from peers inside `TRUSTED_PROXY_CIDRS`. Both settings are empty by
  default, and the reset lanes then work as before. A password change, a
  reset, revoking other sessions, an MFA change or erasure invalidates the
  cookie (migration 055 adds the per-owner trust epoch this uses). See the
  [self-hosting documentation](../../docs/SELF-HOSTING.md).
- **Device socket challenges.** The pre-proof device challenge is a
  stateless HMAC value, valid for 60 seconds with 10 seconds of clock-skew
  tolerance between instances. Keep API instance clocks synchronized. See
  the migration 054 note above for why mixed versions must not run.
- **Owner account erasure.** `POST /v1/owner/erasure` is available to owners
  again, with a password proof and, when MFA is enabled, a second-factor
  code. It is local and bounded: it deletes only this server's rows and does
  not cancel Stripe subscriptions or customers, touch external systems, or
  rewrite backups. Apply migration 059 so large accounts erase within the
  statement timeout.
- **Default-off features.** Sealed v1 message admission
  (`SEALED_ADMISSION_ENABLED`), usage-limit plans (`USAGE_LIMITS_ENABLED`
  with `USAGE_LIMIT_PLANS`) and independent-quorum failover
  (`FAILOVER_QUORUM_ENABLED`) are all off unless set. Enabling usage limits
  without a plan catalog, or setting a catalog without enabling them, stops
  startup. Enabling failover requires `FAILOVER_QUORUM_STORE_DIR` to be an
  absolute path without `.` or `..` components.

## Moving to a tagged release or candidate

The release process is defined in
[Releases and version tags](../../docs/RELEASING.md). A source release and a
verified server image are separate artifacts. A tag alone does not publish an
image, and a release candidate does not establish general sending, supported
hardware, or a hosted deployment.

For the first release, apply the same backup, stop, migrate, runtime-role and
restart sequence above to the exact source commit selected by its tag. Use
the target checkout's migrator to apply every missing migration; do not copy
SQL files individually or assume a pre-release snapshot already has the
release's schema. Read all intervening migration and compatibility notes.
Keep dispatch and experimental feature gates at their reviewed settings;
upgrading the software does not authorize enabling them.

If the release offers a verified server image, the procedure stays the same
and the image source changes:

- Publishing a GitHub Release starts the server image build. Only a successful
  workflow produces an `image-receipt.json` eligible for independent review.
  The image digest is recorded in that receipt. Promote and
  deploy only the immutable digest reference (`ghcr.io/pboachie/zrotext@sha256:...`)
  from a reviewed receipt, never a mutable registry tag.
- Verify the image before deploying it with
  `python3 scripts/verify_release_image.py --tag <tag> < image-receipt.json`
  as documented in [Releases and version tags](../../docs/RELEASING.md).
- The upgrade sequence then pins the target by tag and digest: pull the digest,
  run `deploy/compose/fresh_install_smoke.py --image-ref <digest-reference>`
  with the receipt's source metadata to rehearse it, and replace the
  `build:`-based services with the pinned `image:` reference in your private
  override. The migrator inside that image carries the matching numbered
  migrations at `/opt/zrotext/migrations`.
- Release images populate `/about/version`, so the pre- and post-upgrade
  records gain the tag, full source commit, web and schema digests, and
  `migration_last` without a local `git rev-parse`.
- Read the selected [GitHub Release](https://github.com/pboachie/zrotext/releases)
  for its upgrade steps, compatibility notes, and verified artifact links.
  If image verification is incomplete, use only the source artifacts described
  by that release; do not infer an approved image from a registry tag or a
  successful upload.
