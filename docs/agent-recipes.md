# Importable agent recipe previews

## Authenticated workflow recipe candidate

The separate [runtime adapter](../sdk/recipes/workflow-runtime.mjs) uses the actual
HTTPS `WorkflowToolClient` for selected-context metadata, exact proposals, action
status and owner-bound preparation. The older simulator below remains a synthetic
preview. Neither a proposal nor `Prepared` means a message was delivered.

Build the TypeScript SDK first, then import `WorkflowRecipe` and
`createWorkflowRecipeServer` in a customer-controlled startup module. Configure
the service origin, a narrowly scoped workflow credential and one immutable
owner-selected descriptor from the customer secret/configuration store. Do not
put credentials or recipient material in exported workflows. `setup()` checks
actual readiness and selected scope; `preview(requestId)` reads metadata only.
Installation starts disabled. Only the trusted local controller can call
`enable()`; callable input cannot activate the recipe or change its recipient.
Keep the local bridge bound to loopback, or supply customer-controlled TLS and
network isolation. Its separate local credential is not the service credential.

When the existing default-off workflow service is explicitly configured, an
authenticated owner can request a narrow grant through
`POST /v1/auth/workflow-grants`, using the existing session, CSRF, current password
and MFA protections. The credential is returned once with `Cache-Control:
no-store`; store it privately. Revoke through
`DELETE /v1/auth/workflow-grants/{grant_id}`. Permission widening requires a new
grant. This setup does not approve an action or create its message binding.
See the [closed setup and recipe contract](../protocol/v1/workflow-recipe-contract.md).

Import [the runtime workflow](../sdk/recipes/n8n-workflow-runtime.json) only into a
fresh disposable n8n instance. It is disabled and starts with a manual read-only
preview with a credential-store reference. Edit the **Select closed recipe
operation** node's JSON to choose an operation from the
[callable schema](../sdk/recipes/callable-workflow-runtime.json), keeping its
exact `operation` and `params` shape. Task completion and owner proposal accept
only a stable `request_id`; both create proposals for independent owner review.
Use a new read identity for status. Verified reply routing accepts the existing
adapter's `event_id` and stable action `request_id`; it cannot mark a reply as
verified, approve a proposal or select a recipient. The HTTP node forwards this
closed request to the local bridge, which rejects extra authority fields.
Keep effect identities stable after uncertainty and inspect status before any
further action. The
[callable descriptor](../sdk/recipes/callable-workflow-runtime.json) also exposes
closed task-completion, owner-proposal, status, exact preparation and verified
reply operations through the same local adapter. Review and configure these
operations before activation; no connector compatibility beyond actual tested
versions is implied.

Reply ingestion reuses the signed-raw-byte `ReplyEventAdapter` and its durable
identity/consumption ledger. The customer must independently configure its
current-source authority and selected-reader implementation. These seams are
not mounted grant/source lookup services in this candidate. Without them, reply
routing is unavailable. A caller's `verified` or `approved` boolean is never
accepted. STOP metadata produces no proposal; other eligible replies can propose
the fixed action, but cannot approve it or send. Interrupted effects remain
unknown and are not automatically retried. No model provider is configured.

The original sealed profile-02 reply reader is a separate #617 dependency. This
recipe currently accepts the existing `ReplyEventAdapter`; its simulator reader
does not prove original-event provenance or profile-02 source/reader enrollment.
This manual JSON configuration also does not complete the nontechnical guided
grant/recipient setup tracked in #618. Both dependencies remain open.

These customer-controlled examples are **synthetic previews; production activation
is unavailable**. They cover task completion, an owner-reviewed proposal and
verified reply routing. Production authority and reply services remain #615 and
#617. Reply text cannot approve an action. Existing sending and release gates stay
closed.

## Software and setup

The callable example requires Node.js 22 and the existing TypeScript SDK
dependencies. The workflow was imported and executed with n8n 2.41.4 and its
Node.js 24 runtime. No second connector is claimed compatible.

From `sdk/typescript`:

```sh
npm ci --ignore-scripts
npm run build
node examples/recipe-simulator.mjs setup
node examples/recipe-simulator.mjs preview journey
node examples/recipe-simulator.mjs serve
```

`setup` displays the controlled fixture owner recipient, selected local reader,
expiry, turn cap, budget and narrow grant request: metadata, draft, selected owner
reply reading and owner self-notification. It records that authenticated owner
action is required; it cannot create production grants or enable sending. The
preview uses existing public test vectors, never an owner token or real recipient.

Import [the workflow](../sdk/recipes/n8n-owner-preview.json) into a **fresh disposable
n8n instance**. Its fixed fixture ID is only for that instance: CLI import into an
existing instance could replace a workflow with the same ID. One import creates
an unpublished, disabled recipe. Keep it unpublished and use its manual trigger.
The HTTP node contacts the customer-controlled fixture adapter on localhost,
never the hub API. Run n8n and the adapter in the same local environment. For an
isolated container, mount the repository read-only and run the adapter with the
container's Node runtime before executing the workflow.

The [provider-neutral callable descriptor](../sdk/recipes/callable-owner-preview.json)
has a closed schema: pass its operation and optional scenario to the same `preview`
command. It accepts no credentials, arbitrary text or recipient. Both entry points
use the shared SDK recipe service and checkpoint store.

## Reader and authority

The selected customer adapter verifies the public fixture signature and decrypts
with the public fixture archive key through the existing SDK reader. These test
keys are not production enrollment, manifest trust or an approved Android provider.
Decrypted content remains inside that local reader. Outputs and checkpoints carry
metadata only; model-provider access is `none`. The workflow has no credentials,
automatic trigger or model node; execution persistence is disabled.

The bounded local checkpoint stores event/action identities and digests in the
system temporary directory. An exclusive file lock covers consumption and action
identity; replacement follows a synced pending file. Restart preserves duplicate
consumption and unknown submission decisions. Busy, malformed or interrupted
checkpoints fail closed. This fixture has no external effects and supplies no
production pre-effect outbox, multi-host authority or filesystem crash-recovery
guarantee.

## Adverse previews and teardown

With a fresh disposable checkpoint, run `preview task_completion unknown`:
repeating the identity retains the unknown result. Other scenarios are
`missing_grant`, `stop`, `takeover`, `revoked` and `offline`. STOP, revocation and
takeover remain latched; normal previews cannot undo them. Expiry, turns and budgets
bound further work. Ambiguous replies require owner review; missing content never
becomes plaintext fallback. A verified STOP survives an exhausted reply turn cap.

Stop the adapter, discard only its synthetic temporary checkpoint, and delete the
fixture workflow or discard its disposable n8n instance. An interrupted lock or
pending file requires inspecting and discarding that disposable preview; automatic
recovery must not erase an unknown result. Never use a production checkpoint.

Ordinary SDK CI discovers `test/agent-recipe.test.mjs`: restart/replay, signature,
reader selection, foreign scope, owner-review boundary, unavailable content, STOP,
expiry, budgets, takeover, revocation, concurrent ownership, interrupted writes,
malformed checkpoints, credential rejection, disabled exports and actual local
HTTP are covered. n8n import/export/execute is an additional compatibility check.
No physical device, carrier, external account, production grants or live AI call
is claimed.

## Reproduce runtime workflow compatibility

The SDK test suite checks the disabled export and default preview in ordinary CI.
To also import, export and execute it in a separately installed n8n **2.41.4**, use
Node.js **24** and set `ZT_N8N_CLI` to that installation's `bin/n8n` file. If its
Node executable differs from the SDK runtime, set `ZT_N8N_NODE` to that executable.
From `sdk/typescript`, after building the SDK:

```sh
node --test test/n8n-workflow.test.mjs
```

The opt-in check creates a new disposable n8n instance and a random local
credential. It actually imports and exports the disabled workflow for each
operation, executes the manual trigger, and verifies preview, completion/proposal,
status, waiting for independent owner binding, signed fixture replies, duplicate
replay across an adapter restart, offline request expiry, metadata STOP, missing
grants and teardown. It uses the same certificate-validated HTTPS policy simulator
as the SDK runtime tests. It makes no external provider call. Its current source
and reader callbacks are synthetic; these checks establish connector compatibility
and local routing boundaries, not real gateway or carrier acceptance. The fixture
deletes its temporary credential, SQLite ledger and n8n instance when it exits.
Fresh n8n database initialization may take several minutes.
