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
Use a reviewed HTTPS origin. The command previews the selected launcher,
scope and existing configuration digest and requires typed confirmation before
owner authentication or mutation. Password and the login MFA factor are entered
through hidden prompts; issuing a grant requires a separate fresh MFA factor.
The owner session/cookies/CSRF stay in the setup process and are never supplied
to the agent. Logout is attempted before exit; an unavailable logout cannot
prove remote session revocation. Python strings and OS copies cannot be securely
zeroized.

## Credential custody and launcher

Windows uses current-user generic Windows Credential Manager through its native
API. POSIX requires an installed, unlocked desktop Secret Service and
`secret-tool`; a headless/missing backend refuses, with no plaintext fallback.
Synthetic tests do not access either real vault. Other users and privileged
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
renewal occurs. Lost issuance responses remain unknown and require owner review.

Use `preview` with the installed nonsecret grant/reference and original launch
arguments to obtain the disconnect review digest. `disconnect` authenticates
the owner and requires that digest through `--review-digest`. It confirms remote
grant revocation before removing the entry and deleting vault custody. If
revocation is unavailable, configuration and custody remain. Failed installation
attempts revoke the new grant; uncertain cleanup returns only its nonsecret
grant/reference for deliberate recovery and never claims success.

## Verification limits

Tests exercise actual stdio broker subprocess framing and redaction, synthetic
owner login/MFA/closed grant requests, native Windows API structure, mocked
Secret Service invocation, config preservation/rerun, rollback and revocation
ordering. They do not prove a real vault write, live deployment setup, Android
pairing, current reader enrollment, physical-device operation or carrier delivery.
The doctor still reports unknown/unavailable device and release prerequisites;
this metadata connector cannot turn those prerequisites into authority.
