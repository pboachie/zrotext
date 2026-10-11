# @elysra/zrotext

Dependency-free ESM client and webhook verifier for ZROtext's synthetic-alpha
test plane. Version `0.1.7-rc.1` is the first preview candidate; registry
availability requires the maintainer's reviewed bootstrap publication.

## Install

After publication, install the preview explicitly:

```sh
npm install @elysra/zrotext@0.1.7-rc.1
```

Subsequent approved previews are available through `@elysra/zrotext@next`.

This package exposes `AlphaClient`, its types and errors, `requiresReconciliation`,
and webhook signing/verification helpers through the package root. It requires
Node.js 24 or newer. It has no runtime dependencies or lifecycle scripts. Sealed
content modules and internal entry points are outside this package's public API.

## Read a test message's status

```js
import { AlphaClient, requiresReconciliation } from '@elysra/zrotext';

const client = new AlphaClient({
  baseUrl: process.env.ZROTEXT_BASE_URL,
  apiKey: process.env.ZROTEXT_API_KEY,
});
const status = await client.getStatus(process.env.ZROTEXT_MESSAGE_ID);
if (requiresReconciliation(status.state)) {
  console.log('Reconcile device or provider evidence before another submission.');
}
```

Run this on your server with an existing test message ID and a scoped API key.
The example reads status and never submits or retries a message.

## Synthetic-alpha limits

The client targets the allowlisted synthetic-alpha test plane of your own
self-hosted ZROtext server: submit, status and cancellation under
`/v1/alpha/messages`. It sends test-case identifiers, not caller-supplied message
content. Account, device and recipient enrollment are required. This package does
not provide a hosted service or a general message-send API.

Submission requires an explicit caller-selected idempotency key. The client never
retries automatically. If submission has an unknown transport outcome, reconcile
status or resubmit the identical request with the identical key. Never create a
new key for the same logical submission. Writer states `unknown` and
`delivery_unknown` require device/provider reconciliation and must never trigger
an automatic resend.

Webhook verification requires the exact raw request body, the timestamp and
signature headers, and decoded signing-secret bytes. The default clock window is
five minutes. Deduplicate the event ID in the verified body separately. Do not
verify reserialized JSON. Keep API keys and signing secrets on your server.

## Package preparation

From the repository root, install the existing SDK's locked build dependencies
with `npm ci --ignore-scripts --prefix sdk/typescript`. Compile only this package's
three source modules using the locked compiler:

```sh
node sdk/typescript/node_modules/typescript/bin/tsc -p sdk/npm/tsconfig.json --outDir "$TEMP_BUILD"
python scripts/package_npm.py stage --compiled "$TEMP_BUILD" --out "$TEMP_PACKAGE"
npm pack "$TEMP_PACKAGE" --ignore-scripts --pack-destination "$TEMP_PACK"
python scripts/package_npm.py verify-tarball "$TEMP_PACK/elysra-zrotext-0.1.7-rc.1.tgz"
```

All three destinations must be temporary directories outside the checkout; the
package destination must not exist yet. The verifier rejects unexpected entries,
unsafe tar paths or links, changed license/metadata, and imports outside the
selected modules. Release automation adds version, registry, artifact and approval
checks before publication. Preparing or packing a tarball grants no npm access.

## License

AGPL-3.0-only. The complete license is included as `LICENSE` in the tarball.
