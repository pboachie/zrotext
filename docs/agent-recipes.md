# Importable agent recipe previews

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
