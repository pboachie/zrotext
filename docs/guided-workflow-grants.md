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
home `.config` directory; the pinned broker may also be within the installed
repository. A filesystem-volume root cannot serve as the launch capability.
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

## Credential custody and launcher

Windows uses current-user generic Windows Credential Manager through its native
API. POSIX requires an installed, unlocked desktop Secret Service and
`secret-tool`; a headless/missing backend refuses, with no plaintext fallback.
Recovery deletion confirms absence of matching Secret Service entries; locked,
remaining or unavailable entries refuse custody cleanup. Synthetic tests do not
access either real vault. The Windows ABI mock checks
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
synthetic credentials and an in-memory vault. These tests do not prove a real vault write, live deployment setup, Android
pairing, current reader enrollment, physical-device operation or carrier delivery.
The doctor still reports unknown/unavailable device and release prerequisites;
this metadata connector cannot turn those prerequisites into authority.
