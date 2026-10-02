# Customer-controlled workflow recipe integration

This candidate integrates existing shared workflow tools. It does not enable
production sending, approve an action, enroll a reader, select a model provider
or replace the existing radio executor. Imported recipes start disabled.

## Owner credential setup

When `WORKFLOW_TOOLS_ENABLED` is explicitly enabled, the authenticated owner
surface additionally mounts these routes under `/v1/auth`:

| Method and path | Authority and result |
| --- | --- |
| `POST /workflow-grants` | Current owner session, exact HTTPS Origin/CSRF, current password and MFA; creates a narrow credential using the existing shared grant service. Returns `201` with `grant_id` and the one-time `token`. |
| `DELETE /workflow-grants/{grant_id}` | Current owner session and Origin/CSRF; revokes only that account's grant. Returns `204`; unknown or foreign grants are refused. |

Creation has a closed body: `current_password`, `code`, `connector_id`,
`context_id`, `contact_id`, `purpose`, `permissions`, `expires_at_ms`, and
optional `signer_key_id` and `content_envelope_base64url`. Purpose is one of
`transactional`, `operational`, `marketing`. Permissions use the existing seven
independent operation names; empty/duplicate/unknown permissions are refused.
Approval and takeover are not integration permissions. A signer key ID is the
canonical unpadded base64url encoding of exactly 32 bytes. Selected content is
an independently client-encrypted, bounded canonical base64url envelope.
The 50 KiB request bound accommodates the existing context envelope limit.

The real grant service checks the current signed manifest, connector/reader,
signer when required, owner-confirmed interval, contact/purpose, generations,
expiry and independent MFA. Naming these identities is not proof. Creation
cannot widen an existing grant: it issues a new credential and grant. No new
manifest key or content equivalence is inferred from the request. Revocation
requires no password/MFA ceremony that could prevent withdrawal. All responses
are `no-store`; token/password/factor values must remain outside workflow
exports, model arguments, URLs and logs.

## Local recipe interface

`sdk/recipes/workflow-runtime.mjs` holds one owner-selected immutable action
descriptor and a dedicated `WorkflowToolClient`. Its source preview uses the
actual HTTPS metadata operation and compares the returned version/digest.
Task completion and owner proposal persist an exact proposal. Status reads
current durable metadata. Preparation calls the real send tool with the exact
copy-owned action key and optional actual occurrence; caller mutation during
digest calculation cannot select another action. Waiting owner binding/window and
Prepared remain distinct. Prepared is not carrier submission or delivery.

One import installs an inactive manual n8n recipe. The credential reference in
that export is for a separate customer-local adapter credential, never an owner
session or the hub workflow credential. The trusted installation controller
calls `setup`, reviews the returned exact scope/permission hints, runs a
read-only preview against a controlled test recipient/context, and separately
enables the local recipe. Readiness hints are not effect permits: every remote
operation still authenticates and checks current authority. Local activation
does not change any server or release gate.

Local disable invalidates pending activation and work before transport, including
digest calculation and reply consumption. A later activation cannot revive that
work. It does not retract a request already submitted. A reply reserved before
withdrawal remains unknown and is not automatically replayed.

The unstarted local bridge has `GET /recipe` for setup and `POST /recipe` with
exact `operation` and `params`. Operations are `preview`, `task_completion`,
`owner_proposal`, `status`, `prepare`, `verified_reply`. The first four have
exact `request_id` params; preparation has `request_id`, exact four-field `key`
and optional `occurrence_id`; reply routing has `event_id` and `request_id`.
Caller recipient, scope, approval, verification and credential fields are
refused. There is no activation, owner grant, model or raw-text endpoint.
The bridge requires a separate 32-byte local credential, refuses browser Origin
and cookies, bounds bodies/concurrency, and returns only metadata and redacted
error codes. Bind it to loopback or supply reviewed customer TLS/network controls.

## Verified replies and uncertainty

Raw webhook bytes enter the existing `ReplyEventAdapter`: authenticated HMAC,
closed event shape, current independent source-attempt/grant lookup and selected
reader policy precede routing. No `verified=true` field is accepted. Its durable
SQLite consumer/action ledger owns replay, STOP, expiry, turn caps and takeover;
the recipe does not create another event queue or checkpoint ledger. A permitted
reply can only propose the installation's exact action for owner review. STOP
and unavailable/ambiguous content produce metadata review, not a model call,
plaintext fallback, approval or automatic send. An interrupted reservation stays
unknown and cannot automatically execute again after restart.

The current authenticated source/grant lookup and selected reader are customer
integration seams, not mounted event-authority or reader-enrollment services.
Missing independent integrations remain unavailable. A synthetic callback or
shared-service readiness response does not prove source-attempt provenance.

Remote refusal, opt-out, takeover, expiry and budget admission remain the shared
service's responsibility. Calls use one attempt. Unknown network/provider
acceptance stops without retry or replacement identity; inspect current status
using a distinct read request. Explicit exact effect replay remains governed by
the shared service. No provider call, real SMS or physical gateway acceptance is
established by recipe fixture tests.
