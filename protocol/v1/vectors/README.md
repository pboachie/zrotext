# Unapproved sealed draft fixtures

`ztse-draft-01.json` contains nonsecret, synthetic candidate bytes. The fixture
keys are for tests only; the repeated `manifestDigest` bytes are a placeholder,
not a valid owner-signed manifest. `protectedHex`, `unsignedHex`, `signatureHex`
and `envelopeHex` pin byte boundaries for other runtimes. The TypeScript suite
checks RFC 9180 P-256 base mode, decrypts both fixture kinds and runs malformed
and re-signed tamper cases. The Python suite independently checks the byte
shape, transcript boundary and unsigned digest.

No production client may accept this fixture as an authorized message. The
accepted ZT-009 revision, Android and Rust differential results, manifest
chain/recovery and adversarial authorization corpus remain required before
these can become release vectors.

`ztse-manifest-identity-01.json` is a synthetic, unapproved profile-02
manifest-identity fixture for the ZT-009 Q6 correction: the manifest's
authorization identity is `SHA-256(exact_unsigned_bytes)`, not a digest of the
signature, and signatures are canonical low-s P-256. It pins one unsigned
Manifest02 prefix, two independently generated valid low-s signatures over it
(one semantic digest, two distinct complete-byte digests), the high-s twin a
strict receiver must reject, a strict DER corpus (nonminimal, negative, zero,
overflow, trailing and length-mismatch rejections plus one valid encoding), and
one mutated unsigned field with a different digest. The Rust suite
(`crates/server/tests/zt_manifest_identity_digest_vectors.rs`) and the
TypeScript suite (`sdk/typescript/test/manifest-identity-vector.test.mjs`), and
Android shared contract (`android/app/src/sharedTest/java/org/zrotext/gateway/ManifestIdentityCorpus.kt`)
consume these same bytes and must reach identical digests and accept/reject
verdicts. The root key was generated ephemerally and discarded; only its public
point is published.

The Android contract runs in JVM CI as `ManifestIdentityCorpusTest` and on a
test emulator as `ManifestIdentityCorpusDeviceTest`. Both load this file as a
test resource; it is not packaged in the application APK. Run the JVM class
from `android/` with `./gradlew :app:testDebugUnitTest --tests
org.zrotext.gateway.ManifestIdentityCorpusTest`. After installing the debug
and instrumentation APKs on a test emulator, run:

```sh
adb -s EMULATOR_SERIAL shell am instrument -w -r \
  -e class org.zrotext.gateway.ManifestIdentityCorpusDeviceTest \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

`ztse-body-text-01.json` is a synthetic, unapproved corpus for the ZT-009 Q9
strict body-text receive rules: strict UTF-8, 1-32,768 encoded bytes, no NUL
byte, no leading UTF-8 BOM and no Unicode normalization. `textCases` pins
plaintext bytes and accept/reject verdicts (empty, over-long by one, exactly
32,768, NUL, BOM, overlong/truncated/surrogate/out-of-range UTF-8, multi-byte
accepts and an interior BOM that stays data). `authenticatedCases` pins
independently signed draft-01/profile-02 sealed envelopes whose bodies were
AES-GCM encrypted with fixed synthetic CEKs, including cases that
authenticate correctly and still violate the text rules and one wrong-CEK
case that must fail authentication. The Rust suite
([zt_body_text_vectors.rs](../../crates/server/tests/zt_body_text_vectors.rs)),
the TypeScript suite ([body-text-vector.test.mjs](../../sdk/typescript/test/body-text-vector.test.mjs)),
the Android JVM corpus (`BodyTextCorpusTest`) and the Python suite
(`test_ztse_body_text_vectors.py`) consume these same bytes and must reach
identical verdicts. The keys are deterministic public test scalars from the
same construction as `android/test-fixtures/generate-sealed-preparation.mjs`;
no production client may accept any of these bytes as an authorized message.

The shared contract uses the signature verifier called by the test-only
Android manifest parser and the existing Android DER converter. This
owner-only fixture proves signature and digest behavior, not complete
manifest authorization, enrollment, trusted storage, or hardware key custody.

`sealed-execution-grant-01.json` holds the PROPOSED `sealed_execution_grant`
vectors (roadmap #539; see [device-stream.md](../device-stream.md)) and
`sealed-execution-grant.schema.json` their schema. One valid grant is bound to
the synthetic candidate-02 `normal` envelope in
`android/app/src/sharedTest/resources/candidate02-preparation.json`; each case
patches the frame, the device context or the envelope and pins `accept`,
`malformed` (schema and strict parser reject the frame) or `refuse` with the
exact reason. Every binding field (account, device, line and binding
generation, message, reader role, reader key, epochs, envelope digest, expiry
and segment count) has a refusal case. The Python reference
(`protocol/v1/tests/test_sealed_execution_grant_vectors.py`) and the Android
JVM suite (`SealedExecutionGrantVectorTest`) consume the same file and must
reach identical verdicts. No hub emits this frame and no client negotiates it.
