# Experimental scoped WebMCP application adapter

The optional [service-backed application](app/README.md) supplies a separate
authenticated HTTPS session boundary, holds workflow credentials on the server,
and requires explicit browser registration. It is included in the candidate
archive; live deployment and grant/device acceptance remain separate gates.

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
WebMCP runtime; actual browser implementations remain experimental. Unit tests
use an injected registry. The separate browser suite requires native
`document.modelContext.getTools` and `executeTool`; it never supplies a polyfill
or falls back to the legacy navigator API. It exercises a synthetic authenticated
transport boundary, not a real credential session, installed agent, or SMS delivery.

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

Run the native browser suite after the build above:

```sh
npm --prefix web/owner ci --ignore-scripts
web/owner/node_modules/.bin/playwright install chromium
node --test sdk/tungsten/webmcp/browser.test.mjs
```

This reuses the existing pinned Playwright development dependency. Set
`ZT_WEBMCP_BROWSER` to an alternate Chromium-family executable to qualify that
browser. Each run prints its version, launches a disposable headless profile with
the WebMCP experimental feature flags, and closes it afterward; it never changes
the user's profile or settings. Unsupported native APIs fail the suite. Registration,
result serialization, invalid arguments, revocation and execution cancellation are
checked through native APIs with a synthetic transport. These checks establish
browser adapter behavior only; stable WebMCP availability and real authenticated
application integration remain separate acceptance gates.

The native test driver passes JSON-string arguments to Chromium 153/154 and
object arguments on 155+, following the native execution API transition. Native
cancellation propagation is asynchronous: the test waits up to two seconds for
the tool callback's signal after the browser result rejects. Both execution and
permission-lifetime cancellation must abort the transport. The adapter's deadline
also bounds calls independently. Cancellation never proves that a dispatched
operation had no effect.


## Installed experimental package

`python sdk/tungsten/package-webmcp.py --out <external-directory>` builds
`@elysra/zrotext-webmcp@0.1.0-alpha.1`, checks every archive member, removes
build staging, and installs the archive in an isolated consumer. Install the
pinned Playwright browser as above before running this command. The package has
zero runtime dependencies; Playwright is only an acceptance-test dependency.
The archive contains the license, guides, reviewed adapter, three compiled
workflow modules, the optional authenticated application, and the digest-checked
generated catalog. The server entry point is `zrotext-webmcp-app`; application
hosts can also import `@elysra/zrotext-webmcp/app`.

After installing the archive, applications import `registerWorkflowTools` from
`@elysra/zrotext-webmcp` and the JSON catalog from
`@elysra/zrotext-webmcp/catalog`. Pass the catalog as `manifest` along with the
explicit allowlist, native document registry, permission lifetime signal and
trusted authenticated application transport described above. A bundler must
preserve the adapter's relative validator imports. Importing the package never
registers tools or supplies credentials.

The installed acceptance runs thirteen adapter cases, five native registry cases,
and ten authenticated application cases against package files and the packaged
catalog. Application checks use real HTTPS sessions and native registration with
a synthetic workflow upstream. They do not establish live grant authorization,
production deployment, stable browser support, SMS delivery or publication.
