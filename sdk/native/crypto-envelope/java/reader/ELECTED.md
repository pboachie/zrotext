# Candidate elected profile03 software readers

`ElectedReader03.openSoftware` (C# `OpenSoftware`, Ruby `open_software`) combines
native election, manifest, envelope, HPKE and authenticated body verification.
Java, C#, and Ruby decrypt the actual maintained TypeScript composer's outbound
profile03 ciphertext, including its nonempty HPKE associated data.

Supply a verified election proof and current manifest, expected message ID and
peer, and the elected recipient's native private key handle. The authority source
must read independently authenticated current application authority and trusted
current time. Java returns `AuthoritySnapshot`, C# returns `AuthoritySnapshot`,
and Ruby returns `[record, now_ms]`. The source is read before key operations and
again before plaintext return. Both records must pass election/current-manifest
binding; the second clock cannot move backwards or cross envelope/permission
expiry. Source failure, revocation, or a newly selected incompatible manifest
suppresses the plaintext. Changes after the final read still require the caller's
transaction/lifetime handling; this is not an atomic replay or radio grant API.

The reader binds account, device, line, selected key, manifest identity, expected
message and peer. Signer and all wrapped recipients must be active both at
observation and comparison times; envelope expiry cannot exceed any involved
key, manifest or permission deadline. Native signature verification precedes
HPKE, and both wrap and body AEAD authenticate before decoded text is returned.
CEK and working buffers are cleared best effort; immutable text/native crypto
copies cannot be guaranteed erased.

The API explicitly selects software/native handles without classifying them as
protected custody. It does not export recipient scalars, select a hardware
provider, provide software fallback for protected policy, attest a device, issue
SMS permission, acknowledge a message, or commit replay state. Profile03 inbound
is unsupported. Java retains the existing key-binding requirement for a native
handle supporting signing as well as ECDH.

The dedicated workflow uses the same pinned independent producer as election
verification. Only its test adapter imports ephemeral recipient scalar material,
written to temporary test input rather than repository files. Native tests prove
actual ciphertext opening, wrong peer/message and wire mutation refusal, revoked
authority rejection before a missing key handle is used, and permission/envelope
expiry or revocation between opening and return. These prove candidate reader
behavior, not complete production receiver acceptance.
