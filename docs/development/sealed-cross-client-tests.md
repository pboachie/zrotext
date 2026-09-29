# Sealed cross-client tests

The dedicated `sealed-interop` CI job tests encrypted candidate-02 content across
the TypeScript preparation functions, Rust admission transactions, PostgreSQL
storage and Android verification and body decoding. It does not enable a route,
grant or radio operation.

The Rust test starts with an independently provisioned synthetic root and a
current manifest. The SDK helper generates a next manifest and encrypted inbound
and outbound envelopes. The Rust transactions verify and store those bytes,
check exact replay and reject a changed signature. The test exports bytes read
back from PostgreSQL and a separate expected-context file. Android checks that
context, unwraps the content key and decodes the authenticated body.

Negative cases cover a changed signature, trusted fingerprint, message, decryption key and a
validly signed envelope with a changed body nonce. The adversarial extension
adds fail-closed vectors across all three clients: tampered manifests and
envelopes, expired, future and wrongly anchored manifests, replayed events with
different bytes, reused and zero local sequences, stale and future inbound
observations, truncated, oversized and profile-downgraded envelopes, unknown
recipient keys, misordered wrap roles, a parser-valid third wrap keyed to the
archive key the manifest grants under role 2 so only the ungranted role can
explain its rejection, foreign accounts, and expired or future-dated outbound
intents. Every server-side rejection asserts one stable error variant with no
partial writes; the Android cases assert the same inputs fail closed with the
verifiers' stable rejection type and, for the grant and freshness vectors,
the exact rejection reason, before any recipient unwrap; the SDK tests cover
manifest verification and envelope authorization rejections. Replay fences
and device-sequence ordering are enforced and tested server-side only. The
intent window is not server-side alone: Android's shipping envelope verifier
rejects expired and future-dated observations locally, and the SDK applies
the manifest's own issuance window; the envelope's account binding is checked
by the manifest authority on every client. The SDK has no envelope parser,
so envelope-level downgrade, truncation and wrap-order vectors do not apply
to it.

All keys and exchanged files are temporary synthetic test data. The workflow
does not upload them or use secrets. Software ECDH does not exercise Android
hardware key custody; the supplied test clock does not establish a trusted
device clock. This test does not exercise grants, journals, transport, carrier
delivery or the live sealed release gates.

## Run locally

Use the repository's documented Rust and Android toolchains and a disposable
PostgreSQL database. Set the three `ZT_*_TEST_DATABASE_URL` variables as for the
normal database tests. Set `DATABASE_ALLOW_PLAINTEXT=true` only when the disposable
database uses plaintext connections.

The Rust test passes setup data to the SDK helper on stdin and reads the
generated fixture from its stdout. It writes the Android inputs to a new
`target/zrotext-sealed-interop` directory at the repository root, which Git
ignores. It takes no path from the environment. It refuses to run if that
directory already exists, so a stale fixture cannot be reused. Delete the
directory after the Android step. Build the SDK, then run:

```sh
cd sdk/typescript
npm ci --ignore-scripts && npm test
cd ../..
cargo test --locked -p zrotext-server --lib --features sealed-interop-tests cross_client_interop:: -- --ignored --nocapture
```

Set `ZT_INTEROP_TEST_FIXTURE` to `persisted-fixture.json` in that directory, and set
`ZT_INTEROP_TEST_CONTEXT` to `expected-context.json`. Then run:

```sh
cd android
./gradlew --init-script sealed-interop.init.gradle :app:testDebugUnitTest --tests org.zrotext.gateway.SealedSdkPostgresInteropTest --no-configuration-cache --no-daemon --max-workers=2
```

Use `gradlew.bat` on Windows. All twenty Android cases must run without skips.
Missing inputs or malformed fixtures fail the dedicated test. The opt-in Rust
feature and explicit Android test source keep this fixture-dependent test out
of ordinary unit-test commands; the dedicated CI workflow runs it explicitly.
