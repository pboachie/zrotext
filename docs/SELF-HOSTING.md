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

Use separate secrets and a private database network, terminate HTTPS and WSS at a trusted edge, keep migrations serialized, and retain recoverable database backups. The server, Android gateway, and device protocol are evolving; test the exact release and phone model you intend to run. The [architecture](ARCHITECTURE.md) describes the database and device ownership model, while [MULTI-LOCATION.md](MULTI-LOCATION.md) describes how a second site can join without creating an independent writer; the [promotion runbook](WRITER-PROMOTION.md) covers the fenced manual move of the writer.

### Public HTTPS and device WSS

The optional Compose `edge` profile runs Caddy in front of the API. Point a DNS
name at the host and allow inbound TCP 80 and 443 for certificate issuance and
HTTPS. In your private `.env`, set `EDGE_DOMAIN` to that name and set
`AUTH_ORIGIN=https://<that exact name>` (no trailing slash). Generate independent
random `AUTH_TOKEN_PEPPER_B64` and `ENROLLMENT_TOKEN_PEPPER_B64` values as
described in `.env.example`, keep them stable across restarts and restores, and
configure verification SMTP before registering an owner. Then run:

```sh
docker compose --env-file .env --profile edge -f deploy/compose/compose.yaml up -d --build
curl https://<your-domain>/healthz
curl https://<your-domain>/readyz
```

`AUTH_ORIGIN` must equal the browser's exact public HTTPS origin, including a
port when using a nonstandard public HTTPS port. Account mutations reject any
other `Origin`. The API remains bound to host loopback on `APP_PORT`; Caddy
forwards `Host` and WebSocket upgrades to `app:8080`. The Android gateway uses
`wss://<your-domain>/v1/device-stream` and needs a certificate issued by a CA
the phone already trusts. A local Caddy certificate or a user-installed CA is
only suitable for local tests; ordinary Android apps do not trust user-added CAs
by default. Keep the `caddy_data` volume so certificate state survives restarts.
The edge permits long-lived streams for up to 24 hours and delays forced closure
for five minutes during a Caddy reload; gateway reconnection still remains
necessary. Apply per-source connection limits upstream before exposing the
device stream broadly, as described under runtime capacity below.

For an existing nginx TLS edge, proxy ordinary requests and
`/v1/device-stream` to `http://127.0.0.1:8080`. Preserve the original `Host` and
`Origin` headers; for the device path use HTTP/1.1, forward `Upgrade` and
`Connection: upgrade`, and set read and send timeouts above the 30-second
heartbeat (for example, 90 seconds). A minimal device location is:

```nginx
location /v1/device-stream {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 90s;
    proxy_send_timeout 90s;
}
```

The nginx server also needs its trusted `ssl_certificate` and
`ssl_certificate_key`, a normal `location /` proxy to the same API, and the same
canonical public origin in `AUTH_ORIGIN`. To test the Compose edge without a
public domain or a phone, install Python's `cryptography` package with Argon2id
support, then run `python deploy/compose/edge_smoke.py`. It creates
a disposable loopback-only stack, trusts only its temporary Caddy local CA,
creates a synthetic verified owner with a freshly generated passphrase in its
own database, checks HTTPS sign-in,
secure session cookies and exact-Origin handling, then performs a WSS upgrade
and removes the test containers and volumes. It does not send mail or SMS.

Production packaging instructions will expand as release artifacts become
available. For now, use this stack as a development environment, check the
repository's releases for supported versions, and follow the
[Compose upgrade guide](../deploy/compose/UPGRADE.md) when moving an existing
deployment to a newer source snapshot or release image.

### PostgreSQL transport TLS

For a database outside the local Compose network, use a DNS name in each
`DATABASE_URL` that matches the server certificate and append `sslmode=require`.
The API, migrator, and `zrotext-webhook-kek-rewrap` then require TLS and verify
both the certificate chain and hostname. By default they trust the host's
system root store. Set `DATABASE_TLS_CA_PEM_B64` to the base64 encoding of a
private PEM CA bundle instead; pass it to every relevant container. Restart
processes after changing CA trust. For example:

```sh
DATABASE_URL='postgres://zrotext_runtime:<secret>@writer.example.com:5432/zrotext?sslmode=require'
DATABASE_TLS_CA_PEM_B64='<base64-encoded-PEM-CA-bundle>'
```

Accepted `sslmode` values are `require`, `prefer`, and `disable`. In a
`postgres://` or `postgresql://` URL, libpq's `verify-full` and `verify-ca` are
also accepted and behave exactly like `require`: every TLS connection verifies
the certificate chain and hostname, so `verify-ca` is stricter here than in
libpq and a certificate must match the URL host. Key=value connection strings
accept only the first three. libpq file options such as `sslrootcert` are not
read; use `DATABASE_TLS_CA_PEM_B64`. The server checks `DATABASE_URL` at startup
and exits with a message naming the problem (without the URL or credentials) if
its `sslmode`, syntax, plaintext policy, or CA trust cannot be used.

Do not put a real credential in the repository. A connection with
`sslmode=prefer` or `disable` can carry credentials and metadata without TLS.
Such modes are allowed without an opt-in only for `localhost`, a loopback IP
address, or a Unix socket. To use them with any other host, an operator must set
`DATABASE_ALLOW_PLAINTEXT=true`; the process warns on startup. A private IP
address or a service name alone does not bypass the TLS requirement: a name such
as `db` is ordinary DNS and can resolve to another node in Kubernetes, Swarm,
Nomad, or a multi-host Compose network. The bundled Compose `db` has no TLS, so
the Compose file sets `DATABASE_ALLOW_PLAINTEXT` to `true` unless `.env`
overrides it, and its processes log the plaintext warning. The CA bundle is public trust
material, but verify its source before encoding it. The same settings apply to
migration and webhook key rewrap jobs, not just the server. Test CA trust and
hostname verification before directing production traffic to a new writer.

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
at `/owner/devices` once it is running.
Further invocations refuse to create another owner; inspect an existing
database before attempting bootstrap again. For two hubs, restart `app_b`
with `--profile two-hub` after the CLI succeeds. Keep the operator CLI and
database URL inside the private operator environment.

For later invited owners, allowlist mode requires a **separate** 32-byte random
base64 `REGISTRATION_ENROLLMENT_KEY_B64` (for example, generated privately with
`openssl rand -base64 32`). Keep this master key in private operator settings.
The CLI derives a distinct invite token for each normalized email address;
the raw master key is never sent in the HTTP request. Every token carries a
signed expiry that is checked against the server clock: seven days after
issuance by default, or sooner with `--lifetime-hours` (1 to 168). The
server also refuses any correctly signed token whose expiry is more than
seven days away, so the bound holds even if the master key is misused to
mint a longer-lived token. After setting
`REGISTRATION_MODE=allowlist` and the intended address/domain, issue
one token for that exact address:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml run --rm \
  --no-deps -T --entrypoint /usr/local/bin/zrotext-admin app \
  issue-invite --email invited@example.test
```

The command prints an address-bound token. Share it only with that registrant
through a private channel; they send it in the
`x-zrotext-registration-token` header. It cannot authorize a different
address, even one on the same allowed domain. A missing, invalid, or expired
token returns generic `202 Accepted` without a database lookup, password
hash, account, or mail. Missing or malformed tokens return before email
parsing. The token stops admitting its one address at its signed expiry;
close registration or rotate the master key after enrollment to end access
sooner still. Invite tokens issued before this expiry format carried no
timestamp and stop working when every API instance runs the newer server;
re-issue any invite that is still outstanding.

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

For a later invited owner, configure SMTP and account routes, then restart
every API instance with the same allowlist and master key. The registrant opens
`/owner/account` on the exact configured HTTPS `AUTH_ORIGIN`, enters their
email, a new password and the address-bound invite token, then enters the
emailed code in the verification form on that page. The page also offers a
resend form. It sends JSON with the token in a request header; no credentials
or codes go in URLs. A successful request still returns generic `202`, so the
page cannot tell a denied invitation from an accepted one.

For a headless setup, send these two HTTPS requests to that same origin
(replace the example host and placeholders):

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

After signing in at `/owner/devices`, open `/owner/account` to enroll, confirm
or disable an authenticator. Enrollment requires `MFA_ENROLLMENT_ENABLED=true`
and the shared MFA encryption key on every API instance. The page shows the
manual secret and one-time recovery codes only during setup and clears them
when the page is left. Save the recovery codes before leaving.

`register` returns `202` even when admission is denied. A successful
`verify-email` returns `204`. If no mail arrives, check the private policy and
SMTP worker rather than repeating registrations blindly. After verification,
remove the allowlists and enrollment key, set `REGISTRATION_MODE=closed`, and
restart every API instance. Closing registration does not revoke owner sessions.

### Owner sessions and API keys

Owner sessions last at most 14 days and end after 72 hours without use; sign in
again after either. The API key list on `/owner/devices` shows when each key
was last used, recorded at most once per 15 minutes per key. Revoke keys that
show no recent use. Keys created without a lifetime never expire, so prefer a
lifetime for new keys. See
[SECURITY-DESIGN.md](SECURITY-DESIGN.md#owner-session-and-api-key-lifetime).

### Owner password recovery

With SMTP configured, a signed-out owner can request a one-hour, one-use reset
code from `/owner/devices` and paste it into the reset form there. Without
SMTP, an operator with private database access resets the password locally.
The API services may keep running; the command takes the same owner-row lock
as sign-in and email reset. Read the new password from a non-echoing prompt
and pipe it on stdin (never in argv or a URL):

```sh
set +x
read -rsp 'New owner passphrase> ' ZT_OWNER_PASSWORD; printf '
'
printf '%s' "$ZT_OWNER_PASSWORD" | docker compose --env-file .env   -f deploy/compose/compose.yaml run --rm --no-deps -T   --entrypoint /usr/local/bin/zrotext-admin app   reset-password --email owner@example.test
unset ZT_OWNER_PASSWORD
```

It succeeds only for a verified owner of an active account. Like an emailed
reset, it revokes every session, every API key issued by that owner, pending
MFA sign-in challenges and outstanding reset codes, and leaves MFA enrollment
unchanged; sign in with the new password and an authenticator or recovery code
if MFA is enabled, then reissue integration keys. A reset notification is
queued and is delivered if SMTP is configured later. Password recovery restores
authentication only; it does not unlock sealed message history.

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
requests, 16 device database operations, and 4 background jobs. A device fleet
cannot consume the request/job reserves. Requests and device operations wait at
most two seconds for pool admission; background jobs fail immediately when their
reserve is full. Device sockets release their database clients between handshake
steps and after each database operation, before waiting for or writing frames.
The separate stream limits remain 32 authenticated sessions and 32 handshakes
per process; idle phones and pending proofs do not reserve database clients.
Heartbeats cannot multiply database work: each session renews its lease at most
once every 15 seconds (four renewals a minute) and answers faster heartbeats
from memory, plus one session check every 10 seconds, so heartbeats and those
checks together cost a socket at most 10 device database operations a minute.
A session that sends more than 60 heartbeats in a minute is closed with policy
code 1008.
Database saturation can still close a stream with retry-later code 1013, so
these socket limits are admission ceilings, not a throughput guarantee. Count every hub
and other database client when sizing PostgreSQL: two hubs can use 72 runtime
connections in total. These conservative limits are fixed in `runtime_db.rs`;
adding replicas requires a database capacity review. Migration and operator CLI
connections are separate and must be included in the deployment budget.

When `WEBHOOK_DELIVERY_ENABLED=true`, `WEBHOOK_DISPATCH_CONCURRENCY` controls
parallel sender lanes per process (default 2, allowed 1–3). The cap leaves at
least one of the four background database slots for other jobs. Claims rotate
between accounts and endpoints with due work across all hubs; only one leased
attempt per endpoint can exist. Private process logs emit `webhook_queue` with
pending count, oldest pending age in seconds, and in-flight count about once a
minute. Monitor these alongside the owner-visible pause state.

The delivery recovery worker runs every 15 seconds. It expires pre-grant
messages past their expiry and refunds their quota, marks silent granted or
submitting attempts `unknown`, and closes submitted messages with no delivery
receipt after 24 hours. Each sweep handles 100 rows per transaction and repeats
while batches come back full, for at most 10 batches per sweep per tick. It
stops early when the process begins draining. About once a minute, and on every
tick that reaches the batch bound, private process logs emit
`delivery_recovery` with the number of expired pending messages, the oldest
expiry age in seconds, silent attempts, and overdue delivery receipts waiting
(each count capped at 10,000), plus whether the tick reached its bound. The line
contains no IDs, phone numbers, or content. A count that stays high or keeps
growing means recovery is falling behind.

Some requests are rejected before they take a request connection. The alpha
message routes reject a missing or malformed `Authorization: Bearer` header, and
owner routes reject a request with no session cookie. A request that carries a
well-formed but invalid bearer or session cookie still needs the database to
reject it. `/readyz` runs at most one readiness probe at a time per process,
reuses its result for one second after the probe finishes, and shares that
result across concurrent callers. A probe that times out can leave its
connection busy for up to two more seconds while the pool resets it.

Migration 029 (`029_webhook_dispatch_fairness.sql`; its error text still says "027") requires a webhook maintenance window. Stop webhook delivery on
**every** old dispatch node (`WEBHOOK_DELIVERY_ENABLED=false`) before migrating.
The migration takes an exclusive delivery-table lock, records expired leases as
timed-out attempts using the normal retry schedule, and fails with a clear error
if any unexpired lease remains. A failure rolls back the whole migration,
including that recovery. Wait for the remaining leases to expire, then retry;
recovery is committed only when the migration succeeds.
Keep old senders stopped until the new code is
running. The unique index then protects the one-in-flight rule even if an old
worker is accidentally restarted; duplicate claims fail and retry instead of
creating overlapping sends.

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
API. Restricted-pilot `recipient_suppressions` rows keep their E.164 recipient,
whether active or cleared by START, so an opt-out outlives message content
redaction; the worker never prunes them. Owner off-channel holds, review decisions
and their append-only audit (`owner_recipient_holds`, `owner_opt_out_review_decisions`,
`owner_opt_out_audit`) are kept the same way; they hold codes and IDs, never notes or SMS content. Backups, WAL, replicas, and PostgreSQL dead tuples need their own lifecycle
policy. A database row update or deletion does not immediately erase old pages.

The owner takeout (`GET /v1/owner/export`) still lists a message after its
content has been redacted: `recipient_e164`, `transport_payload` and
`payload_encoding` are `null` and `content_scrubbed` is `true`, while the
message ID, state, timestamps and any remaining events are exported as usual.
A message that still carries content reports `content_scrubbed: false` and a
`payload_encoding` of `utf8` for a `synthetic_alpha` text body, or `base64`
for a `sealed_candidate02` envelope or any body that is not valid UTF-8.

Message events are deleted only after their parent message content has been
redacted. If the event window is shorter than the content window, or an old
unknown message becomes terminal recently, the content cutoff is the effective
earliest event-deletion time. This preserves exact radio-event replay until the
store starts rejecting all late receipts for that redacted message.

After content redaction, late radio receipts are rejected as stale even when
their event ID used to exist in the audit timeline. Device clients must
quarantine that terminal rejection rather than reconnecting with the same
frame. The [stale-event protocol fix](https://github.com/pboachie/zrotext/issues/147)
is a rollout dependency for this retention worker. An M1 inbound event whose
source message content has been redacted is rejected as an unknown source, so
no reply content or suppression is recorded for it; an exact replay of an
event stored before redaction is still acknowledged. New inbound events have a
seven-day upload-age limit and the phone's reply window is 24 hours, so a
content window of 8 days or less can reject a delayed STOP upload. The phone's
local block still applies.

When changing these settings across multiple hubs, deploy the same values to
every hub. A shorter value can make data eligible immediately, while a longer
value cannot restore content already redacted or history already deleted.

A separate maintenance task runs every 60 seconds and removes expired auth
abuse counters, MFA login challenges, device authentication challenges, pairing
requests, unverified pending owners, and password resets. Each task repeats
while its batch comes back full, for at most 10 batches per pass. When a task or
its database connection fails, the process log shows one
`maintenance prune unavailable (task=NAME)` line per failure streak, where
`NAME` is `connect`, `abuse_limits`, `mfa_challenges`, `enrollment`,
`pending_owners`, or `password_resets`. The line has no SQL error text or row
data, and a later success re-arms it. Investigate the failure before these
tables grow.

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
