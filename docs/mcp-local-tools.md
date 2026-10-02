# Local scoped SMS MCP tools

**Experimental local stdio server with an opt-in authenticated workflow transport.**
The eight shared workflow tools call the existing checked gateway service. Send
prepares metadata for an existing owner-confirmed sealed message; it does not
create content, approve an action, submit to a radio, or prove delivery.
The gateway HTTP mount is independently disabled by default.

## Run from source

Use Node.js 22 and the repository checkout. Build the SDK first:

```sh
cd sdk/typescript
npm ci --ignore-scripts
npm run build
cd ../..
node sdk/mcp/server.mjs
```

The last command waits for newline-delimited MCP JSON-RPC on stdin; stdout contains
only protocol responses. Configure a local MCP client's command as `node` with one
argument: the absolute path to `sdk/mcp/server.mjs`. Resolve the path from the
checkout; no installer edits existing client configuration. No npm package is
published. Additional command-line arguments, including remote HTTP options, are
rejected. Each subprocess has an isolated client session.

The server negotiates MCP `2025-11-25` or `2025-06-18`. Unsupported versions receive
`2025-11-25`, which a client must accept or disconnect. It advertises only tools,
with `listChanged: false`; resources, prompts and subscriptions are unsupported.
Initialize and send `notifications/initialized` before discovering/calling tools.
Messages are bounded to 65,536 UTF-8 bytes; oversized frames close the process with
exit code 2. Malformed JSON and UTF-8 return a redacted parse error. EOF with a
partial frame reports an unterminated-message error.

## Tools and authority

`tools/list` publishes the executable JSON input/output schemas and annotations.
Schemas forbid additional arguments. Annotations help clients display tools and
**cannot confer authority**. Results contain both `structuredContent` and matching
text JSON for client compatibility.

| Tool | Input | Current result |
| --- | --- | --- |
| `zrotext_readiness` | Empty object | `available: false`, `unavailable` |
| `zrotext_selected_line` | Empty object | `unavailable`; no broad fleet listing |
| `zrotext_preview` | `envelopeBase64` | Local SDK syntax/kind inspection, unsigned operation digest, byte length |
| `zrotext_submit` | `envelopeBase64` | `unavailable`; no dispatch or retry |
| `zrotext_status` | `messageId` | `unavailable`, `unknown` |
| `zrotext_cancel` | `messageId` | `unavailable`, `unknown`, `cancelled: false` |

With startup configuration, `zrotext_readiness` returns the actual authenticated
HTTP readiness DTO and `zrotext_selected_line` its selected context/device/line
scope. Their legacy unavailable responses remain when configuration is absent.
The other four legacy tools keep their existing behavior; an old envelope submit
is never translated into a workflow Send action.

The additional tools are `workflow.contact.read`, `workflow.context.metadata`,
`workflow.context.content`, `workflow.action.propose`, `workflow.action.status`,
`workflow.action.schedule`, and `workflow.action.send`. They reuse the SDK's exact
closed schemas, response validators and descriptive annotations. Read content
returns only the selected role-3 encrypted projection. Propose is not approval;
Schedule requires the existing exact owner decision and independent permission.
Send returns `waiting_owner_binding`, `waiting_window`, or `prepared`. Prepared
is a metadata transition for an existing owner binding, never a delivery receipt.
Approval and takeover have no integration tool authority. Cancellation is limited to the same Send grant's prepared output.

Preview accepts canonical base64 of an existing profile-01 outbound SDK envelope;
inputs are bounded and inbound/profile-02/plaintext inputs are rejected. It returns
`draft`, `preview_only`, `cryptoVerified: false` and `available: false`. This is a
syntax preview, not cryptographic verification, owner approval, or permission to
send. It returns no recipients, content, key material, signatures or envelope bytes.
The digest comes from the SDK's exact unsigned bytes, preserving its operation
identity semantics. No client-supplied idempotency identity is accepted.

The output schema distinguishes `draft`, `accepted`, `queued`, `submitted`,
`delivered` and `unknown` for future runtime integration. Current tools never claim
acceptance, radio submission, delivery or successful cancellation. Unknown work
must be reconciled through authenticated gateway state; do not resend it with a
new identity. Protocol errors use JSON-RPC codes; tool validation errors return
`invalid_request` and `isError: true`. A readiness result is informational;
unavailable action/status results carry `isError: true`.

## Credentials, remote mode and compatibility

For live scoped calls, configure the subprocess environment with
`ZROTEXT_WORKFLOW_ORIGIN` (an HTTPS gateway origin) and
`ZROTEXT_WORKFLOW_CREDENTIAL_FILE` (a customer-controlled file containing only the
dedicated workflow credential, optionally followed by one newline). Neither is a
tool argument. Both must be present together. `ZROTEXT_WORKFLOW_CREDENTIAL_ROOT`
is an independently chosen absolute private directory, defaulting to
`~/.config/zrotext/credentials`. The credential filename may be relative inside
that directory or an absolute path inside it. Normalized paths and resolved
symlinks must remain inside the canonical directory; sibling-prefix and traversal
paths are refused. Custom deployments set the root explicitly and launch the MCP subprocess with
its working directory set to that approved private directory (or a private
ancestor). Before filesystem access, the configured root must be inside either
that independently selected working directory or the fixed home credential
directory. Filesystem-root working directories are not custom anchors. Canonical
root resolution must stay inside the selected canonical anchor. The root is never
inferred from the credential filename. For example, configure
`ZROTEXT_WORKFLOW_CREDENTIAL_ROOT=/private/customer/credentials` and
`ZROTEXT_WORKFLOW_CREDENTIAL_FILE=workflow-token` in the subprocess environment.
The launch working directory, root and their ancestors are trusted operator configuration. This wrapper does
not protect against a privileged process concurrently replacing directory paths.
Windows network/device paths are refused; local ACL protection remains the
operator's responsibility. The file must be regular and at most
128 bytes; POSIX group/other permissions are refused. The canonical regular file is checked before opening; the opened descriptor must
retain the same inode and comparable device identity. A replaced file is refused.
Windows ACL protection is
the customer's responsibility and is not verified by this wrapper. No owner,
ordinary API, device, or agent credential fallback exists. Keep credentials out
of prompts, model arguments, logs and public repository files. Startup failures
are redacted; credential buffers are cleared after parsing, but JavaScript strings
cannot promise full memory zeroization during the subprocess lifetime.

Workflow credential issuance is currently the existing owner/MFA-checked server
library operation. This transport does not add a self-service grant-management
HTTP endpoint, UI, or enrollment flow. A normal API or agent credential cannot
substitute for that workflow grant. The authenticated simulator checks do not
establish a deployed customer provisioning experience.

The server must explicitly enable `WORKFLOW_TOOLS_ENABLED`; this does not enable
physical dispatch or other production gates. The shared client bounds requests,
responses and timeouts, refuses redirects and validates closed response shapes.
Tool failures contain only code, `refused` or `unknown` state, and attempt count.
The MCP wrapper makes one attempt. An ambiguous failure does not justify a new
action identity or automatic replay; reconcile authenticated state or explicitly
replay the original exact request. See the
[shared HTTP contract](../protocol/v1/workflow-runtime.md).

Remote mode is unsupported. A later deployment requires audience and Origin
validation, authenticated per-client consent, isolated credentials and no upstream
token passthrough; stdio does not supply remote authorization.

Verified locally on Windows with Node.js v22.16.0 and Python 3.12.9: official MCP
JavaScript SDK 1.31.0 and Python MCP client 2.2.0, both over stdio against the shared
synthetic protocol vector. Both exercised initialize, list, preview, unavailable
readiness and refused legacy UUID-only cancellation. These are library clients, not a claim that
Claude Desktop, ChatGPT or another hosted UI was tested. `npm test` in
`sdk/typescript` automatically runs lifecycle, schemas, shared-vector preview,
refusal, framing and redaction regression tests in ordinary CI.

The official JavaScript SDK 1.31.0 and Python MCP client 2.2.0 also exercised the
configured stdio wrapper through private synthetic HTTPS to the real workflow
HTTP router and disposable PostgreSQL stores. Checks covered scoped readiness,
metadata, proposal/status and exact replay, genuinely owner-bound Prepared
results including cross-client replay, foreign-scope refusal and unsuccessful
cancellation. The fixture used actual owner-issued workflow credentials and
normal sealed admission; no mocked principal or radio effect was used.
Two named end-user MCP
client applications, physical-device/carrier behavior, and production activation
remain unverified. Cancellation and owner approval are explicitly unsupported
integration operations rather than future success responses.

The implementation follows the official MCP [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
contracts. Treat SMS and client input as untrusted data; follow
[SECURITY.md](../SECURITY.md) for suspected vulnerabilities.

Send permission explicitly includes withdrawal of this same grant’s own prepared output through `workflow.action.cancel`. The closed input is `request_id` and exact `key`; callers cannot nominate a queue or message identifier. Cancellation discovers the immutable owner binding and verifies the actual preparing grant, then uses the existing job/message grant boundary and refund-once transaction. Status, Propose and another Send grant confer no withdrawal authority. Cancellation changes the bound message only; the historical owner decision and scheduling series are not cancelled or reapproved. Already granted, expired or uncertain work is refused; transport ambiguity stays unknown and never triggers resend. Exact retries still require live scope, credentials and authority. The UUID-only legacy cancellation tool remains unavailable.
