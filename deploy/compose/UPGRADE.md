# Upgrading a self-hosted Compose deployment

This guide moves an existing deployment built from this repository's Compose
stack to a newer version of the source. It covers the mechanics that exist
today: stopping API services, applying numbered SQL migrations with the
migration role, re-provisioning the runtime database role, restarting, and
checking health. Read it together with the [Compose guide](README.md) and
[Self-hosting](../../docs/SELF-HOSTING.md).

**No tagged releases exist yet.** Until the first `vMAJOR.MINOR.PATCH` tag is
published (see [Releases and version tags](../../docs/RELEASING.md)), an
upgrade is a move between two deployed *source snapshots*, not between named
releases. Identify the version you are running and the version you are moving
to by three things, and record all three before and after every upgrade:

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
  this repository is **039** (`039_inbound_device_clock_offset.sql`). Never
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
- Migration 034 is a documented exception: it builds its index with
  `CREATE INDEX CONCURRENTLY` before recording the numbered file; see the
  [Compose guide](README.md) for the interrupted-build and rollback rules that
  apply to it.
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

## When the first tagged release exists

The release process is defined in
[Releases and version tags](../../docs/RELEASING.md). Once a tag exists, this
guide's procedure stays the same and only the image source changes:

- Each tag publishes a server image to `ghcr.io/pboachie/zrotext`, with its
  digest recorded in the workflow's reviewed `image-receipt.json`. Promote and
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
- Each GitHub Release then carries its own upgrade steps and compatibility
  notes; this page will link them release by release instead of describing
  snapshot-to-snapshot moves.
