# Experimental sealed draft-01 TypeScript reader

This is a **test-only implementation of the unapproved ZT-009 byte candidate**.
It must not be published as a production SDK or connected to a send, inbound,
webhook, or radio path. Draft 01 has no trusted manifest bootstrap, approved
role/scope policy, revocation freshness, replay store, or production Android
Keystore HPKE path. The `manifestDigest` in the shared fixture is synthetic, not a real
owner-signed manifest.

`parseDraftEnvelope` bounds and reads the exact candidate binary layout.
`openDraftEnvelope` requires the caller to supply independently trusted
account/device/line/peer, signer point, manifest digest and recipient key. It
checks the raw origin signature, HPKE P-256 recipient wrap with nonempty `info`
and AAD, and AES-256-GCM body AAD before returning strict UTF-8. It does not
authorize a signer or line, validate manifest history, decide accepted clock
skew, check replay/expiry against wall time, or count SMS segments. A caller
must not treat a successful open as permission to send SMS.

From this directory run `npm ci --ignore-scripts` then `npm test`. The locked
dependency graph pins `@hpke/core` 1.7.5, above the nonce-reuse advisory's
affected range, and TypeScript 5.9.3. The RFC 9180 Appendix A.3.1 known answer
checks sender `enc`/ciphertext and recipient opening. Candidate outbound and
inbound fixtures exercise the same bytes in TypeScript and Python; the
re-signed mutation tests probe HPKE/body transcript binding after a valid
origin signature. `test/generate-vectors.mjs` uses fixed public test keys,
content keys, nonce and HPKE ephemeral inputs. Web Crypto ECDSA signing may
produce a different valid signature when regenerated; committed signature
bytes are fixed for consumers.

For an optional **emulator-only** browser-to-Keystore wrap check, build
`android/:app:assembleDebug` and `:app:assembleDebugAndroidTest`, install those
two APKs onto an API 31+ AVD at `emulator-5554`, set `ANDROID_HOME`, then run
`npm run test:android-keystore` here. The script checks `ro.kernel.qemu=1` and
refuses a physical serial. It generates a temporary non-exportable P-256
Keystore key, seals with independent `@hpke/core` using draft-01 nonempty
`info` and AAD, opens on Android, tests changed `info`/AAD, and removes the
test alias in a `finally` cleanup. Uninstall the test APKs when finished. This
is still test-only custom composition, not a maintained production provider.

This is one slice of ZT-010 evidence. Independent Rust cross-open, full manifest
chain/rollback vectors, production key lifecycle, and the Q1–Q11 decisions
remain separate gates. The candidate profile says vectors must be regenerated
after those decisions and versioning.
