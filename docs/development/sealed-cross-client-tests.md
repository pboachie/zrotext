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
context, unwraps the content key and decodes the authenticated body. Negative
cases cover a changed signature, trusted fingerprint, message, decryption key and a
validly signed envelope with a changed body nonce.

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

Set `ZT_INTEROP_TEST_DIR` to a fresh, empty absolute temporary directory outside
the checkout. The test refuses a nonempty directory to prevent stale fixture
reuse. Build the SDK, then run:

```sh
cd sdk/typescript
npm ci --ignore-scripts && npm test
cd ../..
cargo test --locked -p zrotext-server --lib --features sealed-interop-tests cross_client_interop:: -- --ignored --nocapture
```

Set `ZT_INTEROP_TEST_FIXTURE` to `persisted-fixture.json` in that directory and
`ZT_INTEROP_TEST_CONTEXT` to `expected-context.json`. Then run:

```sh
cd android
./gradlew --init-script sealed-interop.init.gradle :app:testDebugUnitTest --tests org.zrotext.gateway.SealedSdkPostgresInteropTest --no-configuration-cache --no-daemon --max-workers=2
```

Use `gradlew.bat` on Windows. All six Android cases must run without skips.
Missing inputs or malformed fixtures fail the dedicated test. The opt-in Rust
feature and explicit Android test source keep this fixture-dependent test out
of ordinary unit-test commands; the dedicated CI workflow runs it explicitly.
