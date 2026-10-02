# Authorized workflow clients

The TypeScript and Python clients use the same closed workflow tool model and
HTTPS transport. [OpenAPI](../protocol/v1/openapi/workflow-tools-v1.json) describes
the HTTP contract. The paired server integration in #616 is separately enabled through
`WORKFLOW_TOOLS_ENABLED`, defaults off, and requires a current dedicated `ztw_`
workflow credential. The MCP transport consumes these same schemas and client;
its integration is a separate implementation lane. Neither installation nor
readiness changes any messaging, line, sealed-content or release gate.

Build the existing SDK with `npm ci --ignore-scripts` and `npm run build` from
`sdk/typescript`. Python requires Python 3 and Node.js with built-in fetch and
Web Crypto (Node 22 or newer). Import `WorkflowClient` from
`sdk/python/workflow_client.py`, or `WorkflowToolClient` from the built
`sdk/typescript/dist/workflow-tool-client.js`. These source modules are not
registry publications. The simulator-only APIs remain available for their
original synthetic tests; they are not substitutes for these HTTPS clients.

Pass the HTTPS origin and credential from trusted local configuration. Never
place credentials in model arguments, URLs, command-line arguments or logs.
The Python bridge sends configuration through stdin to the existing SDK;
it stores no credential file and redacts subprocess diagnostics. Keep any
caller-managed credential file private with permissions limited to that user.
Owner cookies, ordinary API keys and agent keys cannot substitute for a workflow
credential. Origins with embedded credentials, paths, queries or fragments,
redirects and responses larger than the bounded contract are refused.

`readiness()` returns current context, device and line scope plus method hints.
Those hints are not reusable effect permits. `call(method, params)` uses the seven
shared contact/context/proposal/status/schedule/send methods. The Python
`preview`, `status` and `submit` convenience methods invoke proposal, action
status and owner-bound preparation respectively. Proposal persistence is not
approval. A `prepared` result is durable preparation metadata, not a submitted
or delivered SMS. Approval, cancellation, takeover, enrollment and arbitrary
plaintext sending are absent from the callable model.

The caller selects the exact request UUID before invoking an operation. The
client snapshots it and the complete parameters before transport. By default
there is one attempt; an explicit maximum of three attempts permits retries only
after an exact `rate_limited` refusal, using identical bytes and identity.
Disconnects, timeouts, malformed replies and `unavailable` are unknown outcomes
and stop without automatic resend. Review through the authorized status operation;
never create a new identity merely to escape an uncertain result. Frameworks must
not wrap these calls in their own automatic effect retry loops.

Successful replies must match the predictable context, action, proposal binding
or occurrence identities in that snapshot. A correctly shaped reply for another
identity is unknown and never permission to retry. Returned encrypted projection
bytes must also have a canonical base64url representation; format validation
does not establish their cryptographic authenticity.

`workflowFunctions` and Python `workflow_functions()` expose the same parameter
schemas used by MCP. They contain no credentials or administrative tools. The
existing SDK remains the authority for client-side sealing, manifest/signature
verification and selected-reader decryption. Transporting an encrypted projection
does not authenticate or decrypt it. Python `action_digest()` delegates to the
shared canonical SDK binding implementation and conveys no cryptographic trust
or approval. There is no alternate Python encryption or plaintext relay route.

Regenerate OpenAPI after building with
`node sdk/typescript/scripts/generate-workflow-openapi.mjs`. SDK tests enforce
schema/documentation drift and shared-vector digest compatibility. Synthetic
HTTPS tests exercise actual Python-to-SDK networking, TLS trust, refusal,
revocation and unknown outcomes; they do not establish gateway, physical-device
or carrier acceptance. Combined gateway/MCP integration requires its own exact
source verification before availability is claimed.
