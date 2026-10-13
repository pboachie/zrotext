# Candidate profile02 native readers

`SealedReader02` composes the managed manifest, envelope, HPKE and strict body
modules into software recipient decryption. Java, C#, and Ruby open actual signed
TypeScript inbound and outbound envelopes. No JavaScript runs in the native reader.

Pass a freshly verified profile02 manifest, positive trusted comparison time,
recipient role and key ID, native private key handle, and a trusted application
current-selection callback. The callback receives owned copies of the manifest
account/version/digest and complete signature-verified envelope. It must enforce
the application's independently authenticated current selection and intended
account, device, line, peer and message context. Returning true is an application
trust decision, not a permission minted by this module. It is called before HPKE
and again before returning plaintext. Changes after the final check require the
application's own transaction/lifetime handling; this API supplies no atomic
storage transaction or replay receipt.

The reader binds envelope version/digest/account to the supplied manifest,
signer role and line/device, and all recipient roles, points and scopes. Signer
and recipient keys must be active at both observation and comparison times.
Observation must be positive, within the manifest lifetime, and not in the future.
Outbound expiry must still be valid and within the manifest lifetime. Native
HPKE and body AEAD authenticate before strict UTF-8 plaintext is returned.
Working CEK and byte buffers are cleared best effort; immutable text and crypto
provider internals cannot be guaranteed erased. Caller key handles stay caller-owned.

The original `open` entrypoint requires the envelope's manifest to be the
application's current selection. `openHistoricalArchive` (Ruby
`open_historical_archive`) accepts profile02 inbound archive messages through an
authenticated successor chain. Its historical signer and wraps must be active at
observation time; the selected archive key must also remain active with inbound
scope in the current manifest. An independently signed rotation removing that
reader refuses before HPKE, even if the caller retains the old private key.
Currentness callbacks receive the selected current manifest identity plus the
historical signed wire snapshot. Historical outbound is explicitly unsupported.

Manifest tokens retain immutable predecessor references, never caller-supplied
digest lists. Semantic refresh preserves ancestry without adding duplicate links.
Root/account, profile, version and semantic digest identify ancestors; alternate
signatures over the same semantic manifest do not create a fork. Long-lived
applications must budget retained provenance memory or reconstruct verified chains
from authenticated storage; this module does not persist or compact trust history.

Profile03 election proofs, root rotation, replay/age
policy, durable selection, radio authority and protected hardware custody remain
separate gates. No software key is classified as nonexportable; there is no
protected-key fallback path. Java's existing native handle binding requires
signing capability as well as ECDH, so ECDH-only providers refuse.

The three unchanged body implementations are reused from PR1123 at their original
`sdk/native/crypto-candidate` paths. The fixture producer is independently pinned
to `a5fb59c2c5bc81e80b5b8d4b836afd51c5304653`, originally maintained for the Python
candidate reader. Its synthetic recipient material is temporary test input.
`backdated-fixture.mjs` uses that producer's public synthetic signer scalar to
sign an invalid earlier observation. Tests first prove this negative's signature
is valid, then prove authority refusal before the current-selection callback or
HPKE. Modified unsigned bytes alone are not the backdating regression test.

The dedicated workflow builds the pinned producer, adapts its JSON through the
negative-case generator and TSV exporter, then runs all native reader tests.
Successor controls from PR1170 are pinned to
`51402a99b6473a9d40d89a0f77755c4e109e6da7`. Tests verify both unchanged archive
successor acceptance and a separately signed archive rotation's refusal, with a
missing private handle to prove rejection occurs before HPKE. Ancestry survives
semantic currentness refresh and rejects reversed lineage and sibling forks.
Other controls cover current-selection refusal/revocation, wrong role/key ID,
expiry, clock regression, changed context bytes and signatures. Fixtures are not
published or committed. These checks qualify candidate code, not release readiness.
