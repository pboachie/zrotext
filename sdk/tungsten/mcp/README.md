# Local generated-name workflow adapter

This additive adapter maps a closed set of generated workflow tool names onto
ZROtext's existing guarded MCP session. It uses the guarded schemas, argument
validation, scoped workflow transport, refusal shapes and redacted errors.
Generated descriptions and schemas do not replace those contracts. Owner,
sealed and macro tools are omitted, and their names cannot be invoked.

Build `sdk/typescript` first (`npm ci --ignore-scripts` then `npm run build`).
Generate the separate Tungsten foundation manifest at
`sdk/tungsten/generated/mcp/manifest.json`, then launch:

```sh
node sdk/tungsten/mcp/server.mjs
```

Only local newline-delimited stdio is supported. All command-line arguments
(including HTTP flags) are refused. No network listener or raw generated MCP
server is started. `ZROTEXT_MCP_MODE`, if set, must be `stdio`.

Operator configuration reuses `ZROTEXT_WORKFLOW_ORIGIN`,
`ZROTEXT_WORKFLOW_CREDENTIAL_FILE` and `ZROTEXT_WORKFLOW_CREDENTIAL_ROOT` from the
existing guarded server. Its private-file and canonical scoped-token checks
remain authoritative. Credentials are never accepted in tool arguments. Owner
cookies, API keys and generated-runtime credential variables grant no access.
Without configured workflow credentials, calls refuse with zero attempts.

The existing owner-approval and exact action/context binding rules remain in
force. A model confirmation token cannot replace independent owner approval.
This adapter does not implement full generated-runtime parity, grant authority,
perform HPKE crypto, or make a deployment ready. Missing generated artifacts
produce a generic local startup refusal. Current tests use synthetic catalogs;
foundation integration additionally verifies the actual generated catalog.

Run `node --test sdk/tungsten/mcp/adapter.test.mjs` after building the existing
TypeScript SDK. Tests perform no live gateway requests.
