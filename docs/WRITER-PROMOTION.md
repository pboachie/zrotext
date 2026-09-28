# Rehearsing manual writer promotion

ZROtext is designed for two locations with **one PostgreSQL writer** at any
time. Moving the writer (promotion) is a manual, fenced operation by design;
[Two-location operation](MULTI-LOCATION.md#automatic-failover-needs-an-independent-decision)
explains why automatic failover is deliberately not implemented yet. This page
is an operator runbook: first a rehearsal you can run on one host with the
Compose `two-hub` profile, then the procedure for promoting between two real
sites.

What this rehearsal exercises: the site, deployment-epoch and device-session
fences that make a promotion safe, and the refusal behavior when they trip.
What it does not exercise: an actual PostgreSQL standby promotion — the
Compose stack has exactly one `db` service and no replication, and Compose
pins `DISPATCH_ENABLED=false` for both API services. Two containers on one
host do not model separate-location resilience
([MULTI-LOCATION](MULTI-LOCATION.md)).

## The fences, as they exist in the code

All of the following are enforced by queries that run against the writer; the
runbook cites them so you know what each check proves.

- **Writer fence.** `/readyz` and device-session validation both include
  `NOT pg_is_in_recovery()`: a process connected to a PostgreSQL standby is
  never write-ready and can never validate a device session, whatever its
  other configuration (`crates/server/src/main.rs`, `ready`; and the session
  validation query in `crates/server/src/device_socket/mod.rs`).
- **Deployment-epoch fence.** The `deployment_authority` table (migration
  `001_foundation.sql`) holds one row with an `epoch`. `/readyz` requires the
  database epoch to equal the process's configured `DEPLOYMENT_EPOCH`, device
  sessions store their `deployment_epoch`, and send grants are only issued
  while `deployment_authority.epoch` matches (`SELECT dispatch_enabled FROM
  deployment_authority WHERE singleton=TRUE AND epoch=$1`). A process running
  yesterday's epoch refuses traffic even if it can still reach the database.
- **Site fence.** The `sites` table (`site_id`, `enabled`, `draining`) is
  checked on every device-session validation and by `/readyz`: a site marked
  `draining` or not `enabled` stops being write-ready without a restart. A
  process whose site row is fenced also refuses to start (`configured site is
  disabled or draining`).

`/readyz` is unauthenticated, so its database checks (writer, epoch, site,
message index, billing authorization) run as one probe at a time per process,
and concurrent callers share its result. The result is reused for one second
after the probe finishes. A probe that cannot finish within five seconds counts
as not ready. The authority query (writer, epoch, site) runs first, so a slow
probe can report an observation made almost five seconds earlier, and the cache
can serve it for one more second. A database-side fence change can therefore
take up to about six seconds, plus your probe interval, to show on `/readyz`.
This delay affects only load-balancer routing: device-session validation and
grant issuance still check the fences live on every operation. The in-process
draining flag and billing provider authorization flags are read on every
request.
- **Device-session fence.** Each new authenticated device connection
  upserts `device_sessions` with `connection_epoch = connection_epoch + 1`
  and takes over the lease; validation matches the exact `site_id`,
  `instance_id`, `connection_epoch` and an unexpired `lease_until`. When a
  device moves hubs, the previous hub's cached session stops being able to
  request or renew grants immediately. `dispatch_fences` additionally allows
  only one active fence per device
  (unique partial index in `001_foundation.sql`).

Note for readers of the design page: `MULTI-LOCATION.md` describes future
split readiness endpoints (`/readyz/api`, `/readyz/hub`). The endpoint that
exists today is the single `/readyz`, and that is what this runbook uses.

## Part A — rehearsal on one host (Compose `two-hub` profile)

The `two-hub` profile runs a second API instance, `app_b`, against the same
writer: `app` is site `local-a`/`api-1` on `127.0.0.1:${APP_PORT:-8080}`,
`app_b` is site `local-b`/`api-2` on `127.0.0.1:8081`. Both read
`DEPLOYMENT_EPOCH` from your `.env` (default `1`). From the repository root:

```sh
docker compose --env-file .env --profile two-hub -f deploy/compose/compose.yaml up -d --build
```

Have the `db`-service query pattern from the
[upgrade guide](../deploy/compose/UPGRADE.md) ready; it is used throughout:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml exec -T db \
  sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q -v ON_ERROR_STOP=1 \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "<SQL>"'
```

### A1. Pre-flight: prove single-writer and fence state

```sh
curl -s http://127.0.0.1:8080/readyz ; echo
curl -s http://127.0.0.1:8081/readyz ; echo
```

Both must return `{"status":"ready"}` with HTTP 200 (use `curl -s -o /dev/null
-w '%{http_code}\n' ...` to see the status code). If either returns
`503 {"status":"unavailable"}`, stop: one of the fences is already tripped.

Then inspect the authority, the registered sites, and the recovery state:

```sql
SELECT pg_is_in_recovery();          -- must be false on the writer
SELECT epoch, dispatch_enabled FROM deployment_authority WHERE singleton;
SELECT site_id, enabled, draining FROM sites ORDER BY site_id;
SELECT device_id, site_id, instance_id, connection_epoch, lease_until,
       deployment_epoch
FROM device_sessions ORDER BY device_id;
```

Expect both `local-a` and `local-b` registered (each API instance inserts its
own `SITE_ID` at startup), the epoch equal to the `DEPLOYMENT_EPOCH` in your
`.env`, and `pg_is_in_recovery()` false. With no devices enrolled the session
table is empty; that is fine for this rehearsal — the session fence is
exercised by the simulator and regression test cited at the end.

### A2. Move hub authority from site A to site B

This is the rehearsal of "traffic and devices follow the surviving site":

```sh
docker compose --env-file .env --profile two-hub -f deploy/compose/compose.yaml stop app
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # still 200
```

`stop` sends SIGTERM, which sets the in-process draining flag; `/readyz`
answers `503 unavailable` while draining and then the process exits. Site B
keeps serving on 8081 because it reaches the same writer and its site row is
unfenced. Check the owner pages on B (`http://127.0.0.1:8081/owner/devices`).

A real device connected to A would reconnect through the stable hostname; on
reconnection to B the session upsert bumps `connection_epoch`, and A — if it
ever came back with stale state — could no longer validate that session.

### A3. Demonstrate the site fence (live, reversible)

The `sites.draining` column is read by a running process, so it fences that
process without touching it. Fence B, watch it refuse (allow a few seconds for
the readiness cache; see the staleness bound above), then unfence:

```sql
UPDATE sites SET draining = TRUE WHERE site_id = 'local-b';
```

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # 503
```

```sql
UPDATE sites SET draining = FALSE WHERE site_id = 'local-b';
```

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # 200
```

Also note the startup form: with `draining = TRUE` (or `enabled = FALSE`), a
stopped process of that site refuses to start at all. This is the operator
lever for keeping a site out of service during a promotion even if its
process or host reboots. In a real promotion you would fence the *old
writer's* site this way before touching the database, and leave it fenced
until the site is deliberately re-commissioned.

### A4. Demonstrate the deployment-epoch fence

Bump the authority epoch, exactly as you would on a new writer after
promotion so that every process with the old configuration refuses:

```sql
UPDATE deployment_authority SET epoch = epoch + 1 WHERE singleton = TRUE;
```

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # 503
```

B is process-healthy and can reach the database, but its configured
`DEPLOYMENT_EPOCH` no longer matches the authority row, so it is not
write-ready and cannot issue grants. Restore service by moving the
configuration onto the new epoch: set `DEPLOYMENT_EPOCH=2` in your private
`.env`, then recreate **both** API services with the two-hub profile:

```sh
docker compose --env-file .env --profile two-hub -f deploy/compose/compose.yaml up -d --force-recreate app app_b
```

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # 200
```

Check the result with the read-only [promotion checker](#automated-go-no-go-checks),
which runs the same writer queries through the Compose `db` service:

```sh
python3 deploy/compose/promotion_check.py writer --compose-env .env \
  --expected-epoch 2 --active-site local-a --active-site local-b \
  --readyz http://127.0.0.1:8080/readyz --readyz http://127.0.0.1:8081/readyz
```

It prints `"verdict": "go"` and exits 0. Run it once before you recreate the
services and the two `--readyz` checks fail, which is the refusal this step
demonstrates.

The epoch gate is the reason a promotion is safe against stale processes:
until every hub is restarted with the new `DEPLOYMENT_EPOCH`, none of the old
ones can serve or grant, so there is no window where two configurations both
believe they are current.

**Rehearsal rollback.** Set the authority epoch back (`UPDATE
deployment_authority SET epoch = 1 WHERE singleton = TRUE;`), restore
`DEPLOYMENT_EPOCH=1` in `.env`, recreate both services, and confirm both
`/readyz` endpoints return 200. In a rehearsal with no devices this is clean;
in a real promotion, sessions and fences written under the new epoch carry it
forward, which is one reason real failback is a planned operation rather than
a flip (see [MULTI-LOCATION](MULTI-LOCATION.md#automatic-failover-needs-an-independent-decision)).

## Part B — promoting between two real sites

This is the procedure the rehearsal trains you for, following
[MULTI-LOCATION](MULTI-LOCATION.md). It assumes your own two-site PostgreSQL
setup with asynchronous streaming replication, a standby you monitor, and
private operational knowledge of hostnames — none of which live in this
public repository.

1. **Prove the standby is caught up.** Check received/replayed WAL lag and
   slot growth on the standby with your replication monitoring. The design
   target is a 60-second lag alarm; lag is an operational target, not a bound
   on loss. If the standby is far behind, stop and reconcile expectations
   first: asynchronous promotion can lose recently acknowledged idempotency,
   quota, revocation, grant and callback records. Record the checker's
   verdict: `promotion_check.py standby --service <standby>` must say `go`.
2. **Fence and stop the old writer.** Fence its site in `sites` (as in A3),
   then stop PostgreSQL on the old writer with your operating procedure and
   make sure it cannot be restarted automatically (systemd mask, cluster
   policy, or equivalent). The design is explicit: promotion is only allowed
   after proving the old writer is stopped/fenced. If you cannot fence it,
   stay unavailable rather than risk two writers. Immediately before stopping
   it, record its final position with `SELECT pg_current_wal_lsn();` in your
   private operations record. Then run
   `promotion_check.py standby --service <standby> --writer-stopped
   --min-replay-lsn <recorded LSN>`. With the old writer gone, the WAL
   receiver stops and the standby no longer knows how far the writer got.
   The recorded LSN is the only real bound on what an asynchronous promotion
   loses, so the check requires replay to have reached it, and returns
   `no-go` when the sender position is unknown and no LSN is given. It cannot
   prove the old writer is stopped; that remains your fencing procedure. If
   the old writer was lost before you could record its LSN, the check can
   show only that everything the standby received was replayed; treat the
   promotion as unplanned and follow step 6.
3. **Promote the standby** with your PostgreSQL distribution's documented
   promotion procedure (see the
   [standby documentation](https://www.postgresql.org/docs/current/warm-standby.html)
   referenced by MULTI-LOCATION; for a manual setup this is `pg_ctl -D
   <data directory> promote`). After promotion `SELECT pg_is_in_recovery();`
   returns false on the new writer.
4. **Bump the deployment epoch on the new writer** (`UPDATE
   deployment_authority SET epoch = epoch + 1 WHERE singleton = TRUE;`) and
   update every site's configuration to the new writer: writer DSN with
   `sslmode=require`, a certificate matching the new writer's DNS name, and
   `DATABASE_TLS_CA_PEM_B64` if it uses a private CA
   ([Self-hosting: PostgreSQL transport TLS](SELF-HOSTING.md#postgresql-transport-tls)).
   Set the new `DEPLOYMENT_EPOCH` everywhere.
5. **Restart every API instance** at both sites with the new configuration.
   Processes that did not receive the new epoch refuse traffic (A4 is the
   rehearsal of exactly this refusal). Devices reconnect through the stable
   hostname; each reconnection takes over the session with a new
   `connection_epoch` at whatever site they land on.
6. **Keep dispatch paused and reconcile before resuming.** After an
   *unplanned* promotion, keep outbound dispatch paused until the uncertain
   acceptance window, ledgers and device journals are reconciled; unknown
   prior sends stay unknown — never treat a missing row as permission to
   resend, and pause the affected account or device if safety cannot be
   established ([MULTI-LOCATION: replication and safety](MULTI-LOCATION.md#replication-rpo-and-safety-choices)).
   For a *planned* promotion with a quiesced old writer, the uncertain
   window is the replication lag you measured in step 1.
7. **Post-checks.** `/readyz` returns 200 on both sites; `pg_is_in_recovery()`
   is false on the new writer only; `sites` shows the old writer's site still
   fenced; spot-check `device_sessions` to see sessions re-established on
   surviving hubs with fresh epochs. `promotion_check.py writer --service
   <new writer> --expected-epoch <N> --fenced-site <old site> --active-site
   <surviving site> --readyz <URL> ...` checks all of these at once; add
   `--readyz-unready` for the fenced site's endpoint if it is still reachable,
   and `--dispatch enabled` only after reconciliation has resumed dispatch.
8. **Failback is planned, not automatic.** The former primary rejoins only as
   a reseeded or rewound replica after timeline and data checks, and traffic
   returns with hysteresis (for example 3 failed / 5 successful checks and at
   least 5 minutes stable — the design's starting point, tuned per
   deployment). Never disable fencing to regain availability.

## Automated go/no-go checks

`deploy/compose/promotion_check.py` turns the checks above into a JSON report
with a `go` or `no-go` verdict. It only runs `SELECT` statements, in a session
that first sets `default_transaction_read_only = on`, and exits `0` for `go`,
`1` for `no-go`, and `2` when it could not run.

It connects in one of two ways, so no connection string, password or hostname
appears on its command line, in its output or in this repository:

- `--service NAME` uses a libpq service from your private `pg_service.conf`,
  with the password in `.pgpass`. Use a dedicated read-only role, not the
  application or owner role: `SELECT` on `sites`, `deployment_authority` and
  `device_sessions`, membership in `pg_monitor` for the `standby` phase's
  `pg_stat_wal_receiver` columns, and nothing else. Without `pg_monitor` the
  sender position reads as unknown and the `standby` phase is `no-go`.
- `--compose-env .env` queries the local Compose `db` service, for the Part A
  rehearsal.

Database errors are reported only as an exit status, because libpq messages
can name hosts. `/readyz` targets appear in the report as `ready #1`,
`unready #1` and so on, not as URLs. A redirect is reported as its `3xx`
status and never followed.

Two WAL gaps are measured on the standby. **Received minus replayed** shows
only WAL that has already arrived. The **sender gap** is the writer's WAL end,
as last reported to the standby's receiver
(`pg_stat_wal_receiver.latest_end_lsn`), minus the replay position. It also
shows WAL the writer produced that has not arrived yet, so a standby limited
by bandwidth cannot look caught up just because it has replayed everything it
received.

| Phase | When | Checks |
|---|---|---|
| `standby` | Step 1, old writer still running | In recovery. WAL receiver `streaming` and heard from within `--max-lag-seconds` (default 60). Received WAL replayed, or the last replayed commit within the limit. Sender gap known, and either zero with a sender report within the limit (an idle writer) or the last replayed commit within the limit. An unknown sender gap is `no-go`. |
| `standby --writer-stopped` | Step 2, before promoting | In recovery; every received WAL byte replayed. If the receiver still reports a sender gap, it must be zero; if not, `--min-replay-lsn` is required. Receiver checks are skipped. |
| `standby --min-replay-lsn LSN` | Either standby step | Additionally, replay has reached `LSN`. |
| `writer` | Step 7 | Not in recovery; `deployment_authority.epoch` equals `--expected-epoch`; dispatch matches `--dispatch` (default `paused`); each `--fenced-site` is draining or disabled; each `--active-site` is enabled and not draining; each `--readyz` returns 200 `ready`; each `--readyz-unready` does not return 200. |

The `writer` phase also warns about live device sessions that carry an older
deployment epoch or sit on a fenced site. Those sessions cannot receive
grants, so they are not failures, but they should reconnect or expire.

Without `--min-replay-lsn`, a `go` covers only WAL the writer reported to the
standby. With asynchronous replication, writes the old writer never shipped
or reported are lost on promotion, which is why step 6 keeps dispatch paused.

## Related automated coverage

- `cargo run --locked -p zrotext-device-sim` — deterministic two-hub fault
  matrix (dropped ACKs, writer loss with paused dispatch, stale hub sessions,
  lease expiry/reconnect) asserting one shared writer and no blind regrant.
- The PostgreSQL-backed server regression
  `device_socket::tests::lost_intent_ack_across_hubs_needs_no_radio_proof_before_regrant`
  exercises a device moving from hub A to hub B with a retained fence; run it
  with `ZT_AUTH_TEST_DATABASE_URL` pointed at a disposable database.

Neither covers PostgreSQL promotion itself; that is why the Part A rehearsal
and the Part B procedure above exist.
