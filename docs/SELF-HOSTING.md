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

### Owner registration

`REGISTRATION_MODE` defaults to `closed`, even when SMTP is configured. A
closed instance does not create accounts or queue verification mail from
`POST /v1/auth/register`. It still lets existing owners verify pending codes,
log in, and use their accounts. The register endpoint returns the same generic
`202 Accepted` for a blocked address as for an accepted request; the response
does not prove that mail was queued.

**First owner:** after applying migrations and provisioning the runtime
database role, keep `REGISTRATION_MODE=closed` and stop every API service. Run
the operator CLI inside the private Compose network, with the password read
from a non-echoing prompt and piped on stdin (never in argv or a URL):

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml stop app
docker compose --env-file .env -f deploy/compose/compose.yaml \
  --profile two-hub stop app_b
docker compose --env-file .env -f deploy/compose/compose.yaml build app
set +x
read -rsp 'New owner passphrase> ' ZT_OWNER_PASSWORD; printf '\n'
printf '%s' "$ZT_OWNER_PASSWORD" | docker compose --env-file .env \
  -f deploy/compose/compose.yaml run --rm --no-deps -T \
  --entrypoint /usr/local/bin/zrotext-admin app \
  create-owner --email owner@example.test
unset ZT_OWNER_PASSWORD
docker compose --env-file .env -f deploy/compose/compose.yaml up -d app
```

Replace the example address with one you control. The CLI connects to the
already migrated private database through the runtime role. It creates **one
verified owner** only if `accounts` is empty, and sends no verification mail.
Configure `AUTH_ORIGIN`, `AUTH_TOKEN_PEPPER_B64`, and
`ENROLLMENT_TOKEN_PEPPER_B64` before starting the API. The account can sign in
at `/owner/devices.html` once it is running.
Further invocations refuse to create another owner; inspect an existing
database before attempting bootstrap again. For two hubs, restart `app_b`
with `--profile two-hub` after the CLI succeeds. Keep the operator CLI and
database URL inside the private operator environment.

For later invited owners, allowlist mode requires a **separate** 32-byte random
base64 `REGISTRATION_ENROLLMENT_KEY_B64` (for example, generated privately with
`openssl rand -base64 32`). Keep this master key in private operator settings.
The CLI derives a distinct invite token for each normalized email address;
the raw master key is never sent in the HTTP request. After setting
`REGISTRATION_MODE=allowlist` and the intended address/domain, issue one token
for that exact address:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm \
  --no-deps -T --entrypoint /usr/local/bin/zrotext-admin app \
  issue-invite --email invited@example.test
```

The command prints an address-bound token. Share it only with that registrant
through a private channel; they send it in the
`x-zrotext-registration-token` header. It cannot authorize a different
address, even one on the same allowed domain. A missing or invalid token
returns generic `202 Accepted` without a database lookup, password hash,
account, or mail. Missing or malformed tokens return before email parsing.
The token remains usable for its one address until registration closes or the
master key rotates; close registration or rotate the key after enrollment.

In allowlist mode, `REGISTRATION_ALLOWED_EMAILS` and
`REGISTRATION_ALLOWED_DOMAINS` are comma-separated. Address and domain matching
is case-insensitive; a domain permits **every** address at that exact domain,
so prefer individual addresses for a private instance. Subdomains are not
implicitly included. At least one entry and the enrollment key are required.
When account routes are enabled, invalid entries, an unknown mode, or
allowlists/key supplied in `closed` or `open` mode stop server startup.
`REGISTRATION_MODE=open` deliberately accepts registrations from anyone who
can reach the route and verify an email address. Keep the normal
registration abuse budget and mail-provider limits in place for open mode.

There is no registration form in the current owner UI. For a later invited
owner, configure SMTP and account routes, restart every API instance with the
same allowlist and master key, then send these two HTTPS requests to the exact
configured `AUTH_ORIGIN` (replace the example host and placeholders):

```http
POST /v1/auth/register HTTP/1.1
Host: app.example.test
Origin: https://app.example.test
Content-Type: application/json
x-zrotext-registration-token: <address-bound-invite-token>

{"email":"invited@example.test","password":"<new-owner-password>"}
```

After the code arrives in that mailbox:

```http
POST /v1/auth/verify-email HTTP/1.1
Host: app.example.test
Origin: https://app.example.test
Content-Type: application/json

{"token":"<emailed-verification-code>"}
```

Use a client that takes the password, invite and code from protected input;
keep them out of URLs, shell arguments and request logs. Reject redirects to
another origin. The local CLI above is the executable first-owner path.

`register` returns `202` even when admission is denied. A successful
`verify-email` returns `204`. If no mail arrives, check the private policy and
SMTP worker rather than repeating registrations blindly. After verification,
remove the allowlists and enrollment key, set `REGISTRATION_MODE=closed`, and
restart every API instance. Closing registration does not revoke owner sessions.

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
