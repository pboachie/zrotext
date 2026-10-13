# Experimental managed HPKE recipient component

The sibling Java, C#, and Ruby implementations decrypt one 32-byte content key
using RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM,
sequence number zero. They accept exact caller-supplied `info` and AEAD AAD.
Profile02's empty AAD and profile03's nonempty AAD remain distinct inputs.

The implementations perform native ECDH, labeled extract/expand, and AEAD tag
verification before returning the content key. Uncompressed SEC1 points must be
65 bytes and lie on P-256; compressed, infinity, off-curve and noncanonical field
coordinates refuse. Candidate ciphertext is exactly 48 bytes. Contexts are
bounded to 36,864 bytes. This API cannot be used as a multi-message HPKE context.

These are component primitives, **not complete envelope readers or custody
providers**. The caller must first verify the canonical envelope signature,
historical manifest chain and exact profile transcript, then independently apply
current account/device/line/audience authority. Supplying a key object does not
prove any of those facts. These methods must not be exposed as an unverified
envelope decryption endpoint.

Java takes a JCA private-key handle; C# takes an `ECDiffieHellman` handle; Ruby
takes an OpenSSL private-key object. None of the production methods exports a
private scalar. These generic interfaces do **not** attest hardware custody or
nonexportability, and software-provider tests do not qualify such capabilities.
An integration requiring nonexportable keys must refuse until a separately
reviewed provider enforces that policy. Atomic persistence, immutable replay and
full manifest authority remain follow-on requirements of issue #1128.

Recipient identity is checked independently of ciphertext authentication: C#
and Ruby compare public-only exports with the supplied point. Java's generic
private-key handle cannot derive a public key without scalar access, so this
component signs and verifies a fixed domain-separated binding challenge using
the native handle before ECDH. Java providers that permit ECDH but not signing
refuse; no scalar-export fallback exists. A provider-specific ECDH-only adapter
requires separate review rather than bypassing this check.

Working secret buffers are cleared on success or failure where the runtime
permits it. Providers, HMAC input copies, immutable values and Ruby allocations
may retain copies; guaranteed erasure is not claimed. The returned content key
and caller-owned input/key handles remain the caller's responsibility.

## Interoperability tests

The test-only producer `sdk/typescript/test/emit-native-hpke.mjs --tsv` from the
shared interoperability fixture change emits fresh component keys using
`@hpke/core`. Keep its stdout in temporary storage. Test programs accept nine
tab-separated fields on stdin: name, profile, recipient scalar, recipient public
point, encapsulated point, info, AAD, ciphertext, plaintext; binary fields are hex.
Private-scalar import occurs only in those test programs.

Compile Java with JDK17+, `--release 17 -Xlint:all -Werror`, and run
`org.zrotext.candidate.HpkeTest`. Run the sibling `csharp/HpkeTest.csproj` with .NET8+
and `ruby/hpke_test.rb` with Ruby3.2+ and OpenSSL3. Every six-case producer batch
executes 78 checks per language: successful independent unwrap plus public point,
encapsulation, info, AAD, ciphertext, curve encoding, and size mutations.

No real recipient keys, service calls, devices, registry packages, or production
profile acceptance are involved. RFC reference: https://www.rfc-editor.org/rfc/rfc9180.html
