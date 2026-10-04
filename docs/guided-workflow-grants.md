# Guided narrow workflow setup candidate

The simulator remains the default: `python scripts/guided_workflow_setup.py`
runs the existing synthetic journey. It creates no credential, pairs no phone,
and changes no client configuration. This source candidate does not complete
the whole #618/#614 setup journey or enable production sending.

Explicit `connect` installs a metadata/status-only workflow connector for an
already independently registered connector, exact context, contact and consent
purpose. The new sealed line setup is a separate prerequisite; this command
cannot register a reader, compare a root or approve a phone. Content, proposal,
schedule and send permissions are excluded. The server independently enforces
scope, current owner, purpose, manifest, expiry and permission checks.

## Review and authentication

Build the locked TypeScript SDK and review `sdk/mcp/secret-broker.mjs` and its
imports before computing its SHA-256. A digest checks replacement of the selected
entrypoint, not publisher identity or the entire import graph. No download or
package installer is run. Supported client formats are `mcp-json` and
`claude-desktop`; application-specific client acceptance remains unverified.

Run `connect` with explicit `--client`, `--config`, `--broker`, `--sha256`,
`--origin` and `--scope` arguments. The scope document contains only
`connector_id`, `context_id`, `contact_id`, `purpose` and `expires_at_ms`.
Use a reviewed HTTPS origin. Review the scope file and pinned launcher locally.
The command prints their review digests and the existing configuration digest,
and requires typed confirmation before
owner authentication or mutation. Password and the login MFA factor are entered
through hidden prompts; issuing a grant requires a separate fresh MFA factor.
The owner session/cookies/CSRF stay in the setup process and are never supplied
to the agent. A successful newly issued grant retains its remote creator session:
the server deliberately requires that session to remain live. Local cookies are
discarded and the HTTP connection is closed. Logging out that creator, revoking
it, or its expiry invalidates the grant. Failed setup and newly authenticated
resume/disconnect sessions attempt logout; an unavailable logout cannot prove
remote session revocation. A nonsecret receipt records creator account, user and
session IDs for deliberate cleanup. Python strings and OS copies cannot be securely
zeroized.

Launch from the deliberately selected private configuration directory. Config,
scope and recovery files must be absolute paths within that directory or the
home `.config` directory. Brokers must be within the installed repository or
the dedicated home `.config/zrotext/workflow-artifacts` subtree. Merely placing
a broker under an arbitrary setup working directory does not authorize it;
unsupported broker roots refuse before authentication or issuance. Preflight also
checks the selected root's canonical identity and supported ownership/permission
guards before requesting owner credentials or consuming MFA.
A filesystem-volume root cannot serve as the launch capability.
Normalized and canonical containment checks reject sibling escapes, aliases,
reparse points and hardlinked leaves. Parent and target identity are rechecked
after asynchronous owner/custody operations and before replacement or deletion.
Custom directories remain supported by deliberately launching there; the tool
does not infer a trusted root from a supplied file's parent. POSIX configuration
anchors must be user-owned and not group/world writable. Windows requires a
trusted directory ACL. These checks are not a sandbox and cannot prevent a
privileged actor or a writer with access to a trusted ancestor from racing every
filesystem operation. CLI status/error output contains no credential or creator
IDs; those nonsecret recovery identities stay in the local receipt/config.

The reviewed generated launcher records the closed `installed` or `home-config`
selector as its `--artifact-root` capability. The selector chooses one of the
independent fixed roots; it cannot supply an arbitrary filesystem path. This
allows a pinned custom broker within the dedicated home subtree
to start when the desktop application uses a different working directory. The
capability is launcher-only; connect, resume, review and disconnect still run from
the selected configuration directory. Artifact roots may be readable by others
but must be owned by the current user and not group/world writable on POSIX;
system-owned installations are not supported by this customer-owned checkout path.
Canonical directory/ancestor
checks and a root identity recheck precede startup; the broker must remain a regular,
single-link descendant with the reviewed digest. The trusted launcher/config
is an operator capability, not model-controlled authority or an OS sandbox.

## Credential custody and launcher

Windows uses current-user generic Windows Credential Manager through its native
API. POSIX requires an installed, unlocked desktop Secret Service and
`secret-tool`; a headless/missing backend refuses, with no plaintext fallback.
Recovery deletion confirms absence of matching Secret Service entries; locked,
remaining or unavailable entries refuse custody cleanup. Ordinary unit tests mock
vault access. The installed verification fixture owns unique synthetic entries
in actual OS custody and removes only its own recorded names. The Windows ABI mock checks
best-effort wiping of the returned native copy before release; this does not
verify the real OS store or erase Python strings, pipes or OS-owned copies. Other users and privileged
processes, desktop session compromise and same-user access remain OS trust
boundaries. This is not hardware custody or process isolation.

Only a random nonsecret vault reference, grant ID, scope fingerprint, origin and
reviewed launcher path/digest are placed in MCP configuration. Existing servers
and unrelated configuration are preserved using the existing atomic installer.
The private Python launcher retrieves only the narrow credential and sends it
through its child stdin bootstrap. The broker consumes that frame before
processing model JSON-RPC and reuses the shared workflow client/session. No
credential is put in arguments, environment, public configuration or stdout.
The process remains customer-trusted; debug tools can inspect memory or pipes.

An exact rerun resumes the installed entry without creating another grant.
Changed scope, launcher or origin refuses rather than silently widening or
renewing it. Resume is configuration recovery, not a claim of current grant
authority: every tool call rechecks the actual service. Expired/revoked grants
must be explicitly disconnected and newly reviewed; no automatic retry or
renewal occurs. An exclusive, flushed intent receipt is written before issuance. Lost issuance
responses and custody/config failures retain that receipt and block another
issuance, even if no grant ID was received. The receipt contains identifiers and
fingerprints, never passwords, cookies or narrow credentials. POSIX also flushes the parent directory before issuance and refuses issuance
if that flush fails. Windows does not provide a directory persistence guarantee
through this implementation. File flushing is not a guarantee against filesystem damage or power-loss loss of directory
metadata; the customer must protect the configuration directory and receipt.
No automatic retry follows an ambiguous effect.

Use `preview` with the installed nonsecret grant/reference and original launch
arguments to obtain the disconnect review digest. `disconnect` authenticates
the owner and requires that digest through `--review-digest`. It confirms remote
grant revocation before removing the entry and deleting vault custody. If
revocation is unavailable, configuration and custody remain. Failed installation
attempts revoke the new grant; uncertain cleanup returns only its nonsecret
grant/reference for deliberate recovery and never claims success.

For an incomplete setup without an installed entry, run `recovery-preview` with
`--config` to review the recorded creator and receipt digest. Then run `recover`
with the same configuration and `--review-digest`. A fresh owner login must match
the recorded origin, account and user. The authenticated, CSRF-protected exact-session
DELETE revokes only that user's session; it does not sign out other users or
bulk-revoke sessions. A confirmed idempotent response is required before deleting
custody and the intent receipt. An unknown response preserves the receipt, so a
later explicitly reviewed recovery can confirm revocation. Disconnect first if
the entry was installed. Confirmed disconnect also revokes its recorded creator
and clears the receipt; it never silently reconnects or renews.

## Verification limits

Tests exercise actual stdio broker subprocess framing and redaction, synthetic
owner login/MFA/closed grant requests, native Windows API structure, mocked
Secret Service invocation, config preservation/rerun, rollback and revocation
ordering. The composed real-router HTTPS/PostgreSQL fixture exercises the guided
CLI, private bootstrap, creator-session retention and explicit recovery using
synthetic credentials and an in-memory vault by default. The dedicated installed
verification mode additionally requires actual OS custody and the official MCP
client; a missing dependency or refused launcher fails the scenario. These tests do not prove live deployment setup, Android
pairing, current reader enrollment, physical-device operation or carrier delivery.
The doctor still reports unknown/unavailable device and release prerequisites;
this metadata connector cannot turn those prerequisites into authority.

## Verify the installed connection

Install the optional client into the same Python environment used to create the
reviewed launcher. The command never downloads or installs dependencies itself:

```sh
python -m pip install -r sdk/mcp/verify-requirements.txt
python scripts/guided_workflow_setup.py verify \
  --client mcp-json --config /absolute/private/client.json \
  --scope /absolute/private/reviewed-scope.json \
  --broker /absolute/trusted/sdk/mcp/secret-broker.mjs \
  --sha256 REVIEWED_SHA256 --origin https://gateway.example
```

Use the original reviewed scope, origin and broker digest. `verify` requires an
unchanged owned entry and scope fingerprint; it refuses an absent, altered or
widened installation. It neither authenticates an owner nor issues, renews,
revokes or replaces a grant. Configuration, the intent receipt and vault entries
are read only. Other configured servers are never launched.

The official [MCP Python client](https://py.sdk.modelcontextprotocol.io/client/)
launches that exact Python stdio command. The existing launcher retrieves its
existing narrow credential from OS custody and privately bootstraps the actual
Node broker. The verifier negotiates the existing handshake protocol, discovers
tools, requests authenticated readiness, then reads context metadata for the
same reviewed context. The later metadata request independently rechecks current
authority. A prior successful readiness result cannot override a later refusal.
It never calls content, proposals, scheduling, send or cancellation tools.
On POSIX, the host forwards only the existing `DBUS_SESSION_BUS_ADDRESS` and
`XDG_RUNTIME_DIR` custody hints beyond the official client's default environment.
The existing Python launcher still strips these and all credential/TLS overrides
from its Node child environment.

Exit zero means `status: verified` and `authenticatedMetadata: observed` for that
exchange. The redacted report names observed Python, Node, SDK and protocol
versions. It contains no identifiers, metadata bodies, credential references or
source digests. A failure exits two and contains only an allowlisted diagnosis;
unknown connection, TLS, custody or malformed-response failures cannot become a
success. Revoked/expired authority requires explicit owner review; there is no
automatic reconnect or owner-credential fallback. Recheck custody, the reviewed
artifact and service access separately when the report is `connection_unknown`.

The optional SDK is pinned to `mcp==2.3.0` with exact resolved dependency versions.
Its [legacy handshake](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/src/mcp/client/client.py)
supports the broker's `2025-11-25` and `2025-06-18` protocols; client response
caching is disabled. The connection operation has a thirty-second deadline including
the bounded Node version probe. Overall return additionally includes the official
SDK's bounded shutdown grace; it is not an exactly thirty-second wall-clock promise.
Windows Job Object creation and assignment are best effort in this SDK; children spawned before
assignment or when assignment fails are outside its tree guarantee. On POSIX,
gracefully exited servers may leave descendants alive. The existing Python launcher
kills and waits for its direct Node child on teardown. Raw SDK logs and child stderr
are suppressed because validation errors may include input fragments.

The dedicated `Guided connector verification / installed-connector` job selects
`ZT_GUIDED_VERIFY_TEST=1` before running the existing guided HTTPS/PostgreSQL test.
It mandates actual SDK initialization, tool discovery, readiness and metadata
through the installed launcher, and repeats verification after creator revocation.
It checks unchanged configuration, intent and narrow custody. Linux CI owns an
isolated Secret Service session; Windows local acceptance uses unique synthetic
Credential Manager entries. Its test-only PATH shim accepts only the version
probe or exact reviewed broker and injects the loopback fixture CA before executing
the real Node binary; production TLS and launcher environment
filtering remain unchanged. The default PostgreSQL test exercises its original
in-memory scenario and does not claim installed verification ran.

The installed path has also been exercised on Windows with Python 3.12.9,
Node 22.16.0 and official MCP client 2.3.0 against the synthetic HTTPS/PostgreSQL
fixture. The fixture blocks metadata after authorized readiness to check the
deadline, bounded return including shutdown grace, and exit of its recorded
launcher and Node processes; it also checks a revoked grant returns unverified.

This verifies the Python/Node MCP host path, as described by the official
[host integration guide](https://py.sdk.modelcontextprotocol.io/get-started/real-host/).
It does not establish a tested Claude Desktop application version, original
encrypted-content access, Android pairing, or a new-user send/reply journey.
Those remain separate acceptance gates under #614 and #759.
