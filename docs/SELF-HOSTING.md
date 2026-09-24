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

A process accepts at most 32 device WebSockets, of which at most 16 can hold
database sessions. Each socket permits a burst of 256 received frames and refills
64 frame credits per second. Text, ping, pong and duplicate replay frames all
count. An exhausted socket closes; devices can reconnect and replay unacknowledged
evidence using existing deduplication. Device implementations should pace backlog
replay and use reconnect backoff. These are resource limits, not per-account abuse
or billing quotas.

## Source for modified deployments

The server's HTML pages link to `/source`. Published release images point this link to the exact upstream commit used for the build. If you modify ZROtext and let people use your server over a network, set `SOURCE_URL` to a downloadable copy of the full corresponding source for **your running version**, including your changes and applicable build instructions. A link to the unmodified upstream repository is insufficient for a modified deployment. See [AGPL-3.0 section 13](https://www.gnu.org/licenses/agpl-3.0.en.html). Review the license for your situation.
