# Local scoped SMS MCP tools

**Experimental local stdio server; live scoped messaging remains unavailable.**
This runnable server for #616 supports tool discovery and local draft inspection
using the existing sealed SDK. It has no network transport, credentials, account
administration, recipient listing, policy editing or plaintext send route.
It does not enable a gateway feature flag.

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

No credential store is needed for this local slice: it accepts no owner token,
private key or secret path. Never put those values in prompts, MCP arguments or
client configuration. Before adding live operations, integrate #615 server-enforced
line/recipient/grant/expiry/approval/budget policy and a customer-controlled secret
store. Reuse #537 SDK encryption/signing and verified manifests. Do not replace
that with local policy annotations or hand-written cryptography.

Remote mode is unsupported. A later deployment requires audience and Origin
validation, authenticated per-client consent, isolated credentials and no upstream
token passthrough; stdio does not supply remote authorization.

Verified locally on Windows with Node.js v22.16.0 and Python 3.12.9: official MCP
JavaScript SDK 1.31.0 and Python MCP client 2.2.0, both over stdio against the shared
synthetic protocol vector. Both exercised initialize, list, preview, unavailable
readiness and refused cancellation. These are library clients, not a claim that
Claude Desktop, ChatGPT or another hosted UI was tested. `npm test` in
`sdk/typescript` automatically runs lifecycle, schemas, shared-vector preview,
refusal, framing and redaction regression tests in ordinary CI.

Remaining #616 acceptance: profile-02 SDK crypto/trust integration, #615 scoped
policy/runtime, authoritative selected-line/status/cancellation projections,
ambiguous live submission/reconnect reconciliation and two named end-user MCP
client applications. No physical-device or carrier behavior has been verified.

The implementation follows the official MCP [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
contracts. Treat SMS and client input as untrusted data; follow
[SECURITY.md](../SECURITY.md) for suspected vulnerabilities.
