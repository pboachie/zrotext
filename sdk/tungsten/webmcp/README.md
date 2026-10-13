# Experimental scoped WebMCP application adapter

`index.mjs` exports `registerWorkflowTools` and `WebMcpRegistrationError`.
Importing it never reads browser globals, loads credentials, contacts a server or
registers tools. Build `sdk/typescript` first; the adapter reuses its existing
browser-safe workflow schemas and request/response validators.

This is an additive application adapter for the Tungsten-generated WebMCP
catalog. It does not invoke that catalog's raw HTTP client. Applications must
explicitly supply all of:

- The generated WebMCP `manifest` with `catalogVersion: 1` and `api: "zrotext"`.
- An explicit nonempty `allowlist` of generated workflow aliases. Only the eight
  reviewed `workflow_tools_contact_*`, `workflow_tools_context_*` and
  `workflow_tools_action_*` operations are recognized. Owner, sealed, macro,
  readiness and raw legacy tool names are refused.
- A trusted `transport` with synchronous `isAuthorized()` and asynchronous
  `call(method, params, {signal})`. It must enforce the existing workflow grant,
  current authority and response-binding checks of `WorkflowToolClient` through
  an application-owned authenticated transport. A local boolean is not a server
  permission grant. Keep service credentials in the application's trusted
  transport boundary; never include them in page code, model arguments or tools.
- A required permission-lifetime `AbortSignal`. Abort it immediately on sign-out,
  scope change or revocation. The application also calls `close()` on page/route
  teardown. Revocation is enforced independently by the server for every call.
- An explicit registry `{kind: "document", registerTool(tool, {signal})}` with
  the current document-style asynchronous registration contract. It must remove
  that owned tool when the signal aborts and reject aborted registrations. Bind
  native methods to their actual receiver when building this wrapper.

```js
import { registerWorkflowTools } from './index.mjs';

// All four values come from the trusted application, after its own scope checks.
const registration = await registerWorkflowTools({
  manifest: generatedCatalog,
  registry: supportedDocumentRegistry,
  transport: authorizedWorkflowTransport,
  signal: permissionLifetime.signal,
  allowlist: ['workflow_tools_contact_read', 'workflow_tools_action_status'],
});

// At sign-out, permission revocation or route teardown:
permissionLifetime.abort();
registration.close(); // idempotent; affects only this registration
```

The adapter does not auto-detect browsers or support the legacy synchronous
`navigator.modelContext` API. Missing registry support or authorization refuses
before registering. The current contract is taken from the pinned Tungsten
WebMCP runtime; actual browser implementations remain experimental. The tests
use an injected registry: they do **not** demonstrate native browser support,
installed agent interoperability, a real credential session or SMS delivery.

Generated descriptions and schemas cannot expand authority: the adapter uses
the guarded vocabulary and original exact argument schemas. Mutation tools must
be explicitly allowlisted; registration and tool annotations never approve a
proposal. Calls are not retried by this adapter. Validation and unknown failures
produce redacted structured refusals. Input and output JSON are bounded, and a
ten-second call deadline interrupts even a transport that ignores its signal.

Closing aborts registration and active transport signals. Retained callbacks
refuse with zero attempts; late results from revoked calls are hidden. Once a
mutation was dispatched, cancellation or lost permission reports `unknown`, never
successful cancellation or proof that the server did not commit it. A transport
that ignores its abort signal may still finish remotely; reconcile that outcome
through the authorized application.

Run the synthetic contract tests from the repository root:

```sh
npm --prefix sdk/typescript ci --ignore-scripts
npm --prefix sdk/typescript run build
node --test sdk/tungsten/webmcp/adapter.test.mjs
```
