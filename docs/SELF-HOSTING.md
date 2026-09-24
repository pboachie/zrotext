# Self-hosting ZROtext

The repository includes a local Docker Compose stack for development and evaluation. It starts PostgreSQL, runs migrations, and serves the Rust API. SMS dispatch is disabled by default; bringing up the stack does not connect a phone or send a message.

## Local setup

Install Docker and Docker Compose, copy [`.env.example`](../.env.example) to `.env`, and replace the example PostgreSQL password in both `POSTGRES_PASSWORD` and `DATABASE_URL` with the same local value. From the repository root:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --build
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

The [Compose guide](../deploy/compose/README.md) covers migrations, volumes, shutdown, and the optional second local API instance. Local health checks establish process and database availability, not SMS delivery.

For a disposable fresh-install check, run `python deploy/compose/fresh_install_smoke.py` from the repository root (`python3` on systems where that is the Python command). It creates a separate Compose project with a generated local database password and an available loopback port, checks migrations and both health endpoints, runs the logical restore rehearsal, and removes its containers, volume, and temporary credentials. It never uses your `.env` or sends SMS.

The smoke stops its API before inserting synthetic tenants, devices, queued and failed messages, an attempt, an idempotency key, and usage records. It verifies those records in a new database-only restore project. Run the same script with the immutable image digest, source commit, and release tag as described in the [Compose guide](../deploy/compose/README.md) to rehearse the published server image.

## Running your own deployment

Use separate secrets and a private database network, terminate HTTPS and WSS at a trusted edge, keep migrations serialized, and retain recoverable database backups. The server, Android gateway, and device protocol are evolving; test the exact release and phone model you intend to run. The [architecture](ARCHITECTURE.md) describes the database and device ownership model, while [MULTI-LOCATION.md](MULTI-LOCATION.md) describes how a second site can join without creating an independent writer.

Production packaging and upgrade instructions will expand as release artifacts become available. For now, use this stack as a development environment and check the repository's releases for supported versions.

### Database privileges

Use separate migration and runtime credentials before public deployment. The
runtime role should have only required application data, sequence and function
access, no superuser, role/database creation or schema DDL privileges, and a
connection limit sized for the number of hubs.

[PR #105](https://github.com/pboachie/zrotext/pull/105) supplies Compose runtime
role provisioning with separate `RUNTIME_DATABASE_PASSWORD` credentials. Follow
the [Compose guide](../deploy/compose/README.md#database-role-separation) for
provisioning, existing-volume validation and restore order when using that
change. Versions without that provisioning require equivalent operator-managed
role separation; do not give the API the migration owner's credentials.

Validate startup, backup/restore and upgrade operations with the restricted
role. Runtime connection budgets below do not establish least-privilege database
permissions, and role separation does not isolate tenants within shared
application tables.

### Runtime database and device capacity

Each server process reserves separate PostgreSQL connection budgets: 16 ordinary
requests, 16 device sessions, and 4 background jobs. A device fleet cannot consume
the request/job reserves. Requests wait at most two seconds for admission;
device/job admission fails immediately when its reserve is full. Count every hub
and other database client when sizing PostgreSQL: two hubs can use 72 runtime
connections in total. These conservative limits are fixed in `runtime_db.rs`;
adding replicas requires a database capacity review. Migration and operator CLI
connections are separate and must be included in the deployment budget.

Connection establishment is limited to three seconds. Runtime sessions enforce a
10-second statement timeout, three-second lock timeout, and 15-second idle
transaction timeout. The connection driver retains its capacity permit even when
an HTTP request is cancelled, until its database socket actually closes. Slow
queries fail closed and transactions roll back; investigate capacity/timeout
errors before increasing limits. These limits do not replace the HTTP admission
gate or a reverse proxy connection/request limit.

A process holds at most 32 authenticated device WebSockets, of which at most 16
can hold database sessions. Sockets that have not yet proven an enrolled device
key use a separate budget of 32 handshakes per process and never occupy an
authenticated slot. Each handshake must send its hello and its proof within 10
seconds each and must finish authenticating within 15 seconds of the upgrade
request, or it is closed and its handshake slot is released. When either budget
is full, the upgrade is refused with HTTP 503. These in-process budgets are not
keyed by client address; put a reverse proxy per-address connection limit in
front of `/v1/device-stream` so one source cannot keep the handshake budget
full. Each socket permits a burst of 256 received frames and refills
64 frame credits per second. Text, ping, pong and duplicate replay frames all
count. An exhausted socket closes; devices can reconnect and replay unacknowledged
evidence using existing deduplication. Device implementations should pace backlog
replay and use reconnect backoff. These are resource limits, not per-account abuse
or billing quotas.

## Data retention

The API starts a retention worker at startup. Every 15
seconds, each hub processes at most 100 rows per table, using `SKIP LOCKED` so
concurrent hubs can divide the work. The first run occurs at startup. Backlogs
are reduced over successive ticks; the configured age is an eligibility cutoff,
not a hard deletion deadline. Values below are calendar days and must be integers
from 1 through 3650. An invalid value prevents server startup.

| Setting | Default | Action and cutoff |
|---|---:|---|
| `ZT_IDEMPOTENCY_RETENTION_DAYS` | 7 | New keys expire after this many days; expired keys are ignored for replay and removed. Changing the setting does not rewrite existing expiry timestamps. |
| `ZT_MESSAGE_CONTENT_RETENTION_DAYS` | 30 | Null the E.164 recipient and synthetic payload on delivered, failed, cancelled, or expired messages after this many days since their last state update. |
| `ZT_MESSAGE_EVENTS_RETENTION_DAYS` | 90 | Delete message event rows after this many days since receipt when their message is eligible for terminal retention. |
| `ZT_WEBHOOK_HISTORY_RETENTION_DAYS` | 30 | Delete succeeded/dead deliveries and their attempts and manual replay requests after this many days since the delivery's last update. |
| `ZT_INBOUND_CONTENT_RETENTION_DAYS` | 30 | Redact M1 opaque pilot ciphertext after this many days since receipt, once every related webhook delivery has been removed. |
| `ZT_SEALED_INBOUND_CONTENT_RETENTION_DAYS` | 30 | Null sealed inbound envelopes after this many days since receipt. |

The message, event, webhook, and M1 inbound actions require an eligible terminal
outbound message and no unresolved dispatch fence (`granted`, `submitting`, or
`unknown`). Completed `submitted` and `failed` fence records do not block
retention. `unknown`, `delivery_unknown`, other nonterminal states, and messages
with unresolved fences retain their data until resolved. Pending
and leased webhook deliveries also remain until terminal. The M1 and sealed
inbound event rows keep their IDs, device sequence fences, and digests after
content redaction, so replay cannot recreate a purged body. Message IDs, state,
attempts, digests, and usage records remain; this worker is not an account-erasure
API. Backups, WAL, replicas, and PostgreSQL dead tuples need their own lifecycle
policy. A database row update or deletion does not immediately erase old pages.

After content redaction, late radio receipts are rejected as stale even when
their event ID used to exist in the audit timeline. Device clients must
quarantine that terminal rejection rather than reconnecting with the same
frame. The [stale-event protocol fix](https://github.com/pboachie/zrotext/issues/147)
is a rollout dependency for this retention worker. Inbound source admission
uses the attempt's durable `submitted` status after sent-callback audit events
have been pruned; new inbound events still have a seven-day upload-age limit.

When changing these settings across multiple hubs, deploy the same values to
every hub. A shorter value can make data eligible immediately, while a longer
value cannot restore content already redacted or history already deleted.

## Source for modified deployments

The server's HTML pages link to `/source`. Published release images point this link to the exact upstream commit used for the build. If you modify ZROtext and let people use your server over a network, set `SOURCE_URL` to a downloadable copy of the full corresponding source for **your running version**, including your changes and applicable build instructions. A link to the unmodified upstream repository is insufficient for a modified deployment. See [AGPL-3.0 section 13](https://www.gnu.org/licenses/agpl-3.0.en.html). Review the license for your situation.

## Inbound pilot rolling upgrade

Before enabling the inbound pilot, drain every server process built before the
`inbound_daily` counter retention change. Older background workers prune unknown
counter scopes after two minutes and can erase the pilot's 24-hour budget while
newer processes are accepting inbound events. Keep `INBOUND_PILOT_ENABLED=false`
through the mixed-version rollout, verify the old workers have stopped, then
enable the pilot in a separate step. The application check alone cannot enforce
this ordering against an older process sharing the database.
