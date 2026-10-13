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

## Installed candidate

After generating the reviewed catalog, build a licensed npm archive:

The build gate requires Python 3.11+, Node 22+, npm and OpenSSL for synthetic TLS
tests (Git for Windows supplies the Windows test executable). Installed use only
requires Node/npm and the operator configuration described above.

```sh
python3 sdk/tungsten/package-mcp.py --out /tmp/zrotext-guarded-mcp
```

The command compiles only the maintained runtime modules needed by this adapter,
packages `@elysra/zrotext-mcp@0.1.0-alpha.1`, removes build/package staging, and
installs the archive into an isolated consumer. Its published-format shrinkwrap
pins the existing HPKE dependencies, including integrity hashes. The archive
contains no private paths, source overrides, generated raw server or operator
credentials. Every included file is checked against a bounded inventory.

Install the resulting `.tgz` with `npm install /path/to/archive.tgz` and configure
your MCP host to run `zrotext-mcp` over local stdio. Operator credential-file
configuration and refusal behavior above remain required. The public module
exports the guarded adapter; `/stdio` exposes the local transport module.

Installed tests retain all thirteen reviewed adapter cases, check the actual generated
nine-tool catalog, exercise a real stdio subprocess, refuse missing or malformed
operator credentials, and reject owner names and injected confirmation/credentials.
The seventeen test groups also connect an installed stdio process to a synthetic
HTTPS policy fixture using an operator credential file: exact scoped request
binding, owner-binding-required metadata, explicit scope refusal, single-attempt
unknown outcomes and untrusted-certificate refusal are checked. This fixture
does not establish deployed server authority or approval.
The alias differential controls compare all nine advertised contracts against
the maintained guarded definitions. Every workflow method checks exact argument
forwarding, authority-field and malformed-identity rejection, and preservation
of refused versus uncertain outcomes without retry or provider-error disclosure.
These comparisons use a trusted client seam to isolate alias behavior; the TLS
controls separately exercise the installed workflow transport. They do not
establish complete legacy tool replacement or live authorization parity.
No package publication, live authenticated server acceptance or stable sealed
profile acceptance is implied.
