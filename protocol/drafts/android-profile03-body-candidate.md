# Android profile-03 body authentication component

`Draft03Body.open` authenticates a body from a genuine `Draft03OutboundEnvelope`
using its genuine `Draft03ManifestAuthority`, independently selected request,
trusted comparison time and a supplied 32-byte content-encryption key (CEK).
The existing public envelope API rechecks its context and time before providing
owned ciphertext parts. AES-256-GCM uses the exact envelope nonce, ciphertext
and `ZTSE/body/v3` domain AAD provided by that API, with a 128-bit tag.

This internal component acquires no key and opens no HPKE wrap. It neither
implements another receiver nor calls the profile-02 body opener. Only the
unchanged stateless `Draft02Body.decodeText` rule is shared: strict UTF-8,
1..32768 plaintext bytes, no BOM, no NUL and no normalization. A tag-only body
for empty plaintext is rejected by the envelope framing boundary before this
operation can run.

The operation consumes and clears the caller's CEK on success and failure,
including refused context, invalid width, authentication and text failures.
Its copied key and decrypted byte array are cleared in `finally` blocks.
The returned `CharArray` is caller-owned and must be cleared after use. Provider
internal key/plaintext copies cannot be guaranteed erased by this API. It
retains the existing decoder's clearing of accessible backing character
storage; inaccessible decoder temporaries are likewise outside this guarantee.
It introduces no plaintext string, log, persistence or cache.

The shared corpus defines ten groups using freshly generated synthetic software
root/signer keys, genuine signed profile-02-to-03 authority and signed profile-03
envelopes. Real AES-GCM bodies use a known test CEK. Validly re-signed corruption
isolates body authentication from outer signature verification. Fixture wraps
are opaque framing data: these tests do not open HPKE, prove an SDK-to-Wolf
pair or use a device key. JVM and AndroidJUnit4 wrappers share the corpus.
Qualification ran all ten shared JVM controls: ten passed, with zero failures,
errors or skips. Production, shared/JVM corpus and the AndroidJUnit4 wrapper
compiled; device instrumentation was not executed. The ordinary offline Gradle
command succeeded and ran the unconditional owner-custody/root-material checks
for all four Android ABIs. No Wolf/CMake task was selected. These results qualify
the pure body component; they do not establish an installed runtime or radio path.

There is no mounted application caller. Public manifest/time comparison does
not establish a current session, durable election, installed SIM binding,
consent, one-use grant or replay choice. Future actual preparation must obtain
those facts, reserve the real journal before the maintained Wolf receiver,
validate and consume its CEK32 result, recheck currentness after waits, and own
plaintext through one-use handoff. This body operation itself can be repeated
with a new key and therefore grants no replay permission.

Selected-SIM activation, H2/H6 persistence and current readers, actual SDK-to-Wolf
opening, browser-to-phone send/reply and Play acceptance remain separate gates.
No profile-02, receiver, native, Room, custody, signing, activation or runtime
source is changed by this component.
