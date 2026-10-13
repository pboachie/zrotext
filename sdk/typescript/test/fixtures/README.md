# Shared outbound03 time fixtures

These helpers are synthetic test producers and independent consumers, not SDK
exports or custody adapters. Build the maintained TypeScript SDK first. Pin the
ZROtext source revision when another language uses them.

```sh
node sdk/typescript/test/fixtures/profile03-time-cli.mjs --signer-point <uncompressed-p256-public-hex>
node sdk/typescript/test/fixtures/profile03-time-cli.mjs --case current-active-lifetime
```

The first command emits one JSON object with `cases`, covering the fourteen
shared policy inputs. Each case has freshly signed manifests and election
evidence, `accepted` and `authority` records, `observed`, `now`, `expires`,
`message`, `bodyText`, and three `recipients` with role, key ID, public point and
synthetic scalar. Binary fields use base64; clock and generation values use
small exact JSON integers. Supplying the native signer's public point never
supplies its private scalar. Without that option the producer creates a
synthetic software signer and emits `signerScalar`. These test-only scalars must
never be confused with protected recipient or signer custody.

Each native implementation must reconstruct genuine manifest/election handles,
apply the case's exact timing and all three recipient roles, then require the
specified accept/refuse outcome. Negative fixtures contain valid signed evidence;
their policy inputs are deliberately unsuitable for composition. Do not repair
the timestamps, substitute an earlier clock, remove recipients, or treat a
matching JSON record as authenticated authority.

For an accepted native envelope, send a JSON object on stdin to:

```sh
node sdk/typescript/test/fixtures/profile03-time-cli.mjs --consume
```

The object contains the original case as `fixture`, the base64 complete
`envelope`, and `expectedText` equal to `fixture.bodyText`. The consumer verifies
the shared policy identity, fresh signed authority/election evidence, routing
and timestamp bytes, signature and all three independent HPKE/AES plaintexts.
It emits `{verified:true,name,recipients:3}` on success and exits nonzero on
failure. It performs no HTTP, persistent authority update or device action.
