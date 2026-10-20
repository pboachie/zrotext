# Android profile03 inbound encryption primitives

The additive inbound sealer produces the existing profile03/type2 ciphertext
grammar. It is an **unmounted prerequisite**, not an SMS receiver, upload client,
capture authorization or enabled messaging feature. It does not change profile02
bytes, enrollment, pairing, recipient custody, journal history or release versions.

`Draft03ManifestAuthority.inboundContext` independently checks the expected
account, event, device, line, peer and selected role04 signer against genuine
root-signed03 public authority. The signer must be active both at the observed
instant and now, with scope2 and the exact device/line. Selected recipients are
exactly one account archive and up to six explicitly selected integration readers;
integration keys require scope12. Role01 phone recipients are not inbound readers.
All selected keys must remain active for the entire requested deadline. These are
public role checks; they supply no installed conversation or physical permission.

`Profile03InboundSealer` draws a fresh CEK32 and nonce12, preserves strict UTF8
text without normalization and produces unsigned ciphertext only. The AES body
uses `ZTSE/body/v3` plus NUL, header and protected bytes as AAD. Every HPKE wrap
uses separate nonempty `ZTSE/wrap/v3` info and `ZTSE/wrap-aad/v3` AAD, each
followed by NUL, the same header/protected bytes, role and key ID. Wrapping never
uses profile02's empty AAD. `Draft03InboundEnvelope` checks exact type2 framing,
positive capture sequence, independently expected routing/time/readers and the
canonical low-s role04 signature over the existing `ZTSE/sign/v3` transcript.

The sole production wrap implementation is `WolfHpkePublicSender`, using the
same pinned wolfSSL suite and crypto-callback-only ECC build as the maintained
receiver. A fresh transient P256 sender key stays a JCA private object. Its ECDH
answers the callback, while wolfSSL performs HPKE context derivation and AEAD.
No private encoding or scalar is requested, no recipient private material enters
the sender, and no library/provider fallback is installed. Existing recipient
opens still use their nonexportable Android Keystore alias. API28–30 refuse.

The pinned native library is built `SINGLE_THREADED`. Sender and receiver native
entries share a process gate, with admission checked after waiting and before
returning. Receiver lock order remains recipient custody, then process gate;
sender acquires no alias or storage lock inside that gate. Admission callbacks
must use RAM only. Full Room, framework and current authority checks belong
outside custody/gate locks. Failed post-operation admission clears retained
secret output. Owned plaintext/CEK/shared-secret copies are cleared; providers
and the runtime may retain internal copies beyond these guarantees.

`DeviceSigningKeyStore.signPreparedInbound03` only uses an already existing,
nonexportable TEE/StrongBox signing key whose public point actually matches the
selected role04 authority. It refuses missing, changed or unsupported custody;
it creates no identity. Enrollment keys and original SEALED approval keys are
not implicitly role04 keys. The method has no production caller in this change.

## Remaining capture and upload integration

The real inbound receiver still needs independently authenticated current113
consent, its three original proofs, current owner/device/full session, actual
physical selection and installed manifest highwater. It must retain a one-use
capture reservation and positive sequence before releasing a hardware signature,
then retain exact ciphertext and a distinct signed capture commitment before
upload. Existing type2 ciphertext alone does not bind the interval or full lease;
an unsigned interval ID cannot fill that gap. Stop, unknown effect, interrupted
upload and status/retry must preserve the original bytes and sequence history.
Those server, storage and receiver integrations are separate source work.

## Verification boundaries

JVM source tests use actual synthetic root/role signatures and software test
recipients to check exact03 encryption, selected-reader routing, text preservation,
tampering, expiry, withdrawal and API refusal. Their injected software HPKE port
is test-only and cannot establish production provider acceptance. Deterministic
two-thread gate tests cover withdrawal while waiting and after native work.

The host bridge KAT adds an independently produced RFC9180 CEK encryption vector,
reciprocal opening and negative framing/callback controls to all existing receiver
cases. The selected no-radio Android bridge suite also includes maintained sender
encryption to an actual temporary Keystore recipient and withdrawal at each
guard boundary. Host, JVM, instrumented execution and physical hardware custody
require separate executed results. No test in this change sends SMS or uploads
content, and source inclusion does not establish any of those outcomes.
