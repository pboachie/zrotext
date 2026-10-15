# Candidate body crypto primitives

These Java 17+, .NET 8+ and Ruby 3.2+ source modules implement the symmetric
body step of the experimental sealed protocol: AES-256-GCM with a 12-byte nonce
and 16-byte appended authentication tag, followed by strict body-text decoding.
They use native cryptographic providers and have no third-party dependencies.
No packages are published and no generated client imports these modules.

**This is not a complete sealed-envelope reader.** Before calling `open`/`Open`,
the caller must independently verify the manifest and current authority, signer,
routing identity, expiry and replay policy, and recover the authorized content
key using the correct HPKE transcript. Supply the resulting 32-byte content
key and the exact verified associated data. This primitive does not establish
that provenance and intentionally has no envelope parser or HTTP entry point.
Possessing a content key or successfully decrypting bytes is not authorization.

The native APIs are `org.zrotext.candidate.CandidateBody.open`,
`Zrotext.Candidate.CandidateBody.Open`, and `Zrotext::CandidateBody.open`.
Each takes key, nonce, verified associated data and ciphertext. Ciphertext must
contain 17 through 32784 bytes; associated data must contain 1 through 36864.
Only after successful authentication is plaintext decoded as strict UTF-8,
with 1 through 32768 bytes, no NUL and no leading UTF-8 BOM. No normalization,
trimming or replacement characters are inserted. Typed failures expose `shape`,
`authentication`, `length`, `nul`, `bom`, or `utf8` without including plaintext.
`decode`/`Decode` performs the text check only and confers no authentication.

Decrypted temporary byte buffers are cleared on both success and failure where
available. Returned text, caller-owned keys and provider-internal copies are not
zeroized; this is not a secure-memory guarantee.

The test adapter consumes the existing
`protocol/v1/vectors/ztse-body-text-01.json` corpus. It extracts fixture data into
temporary TSV files solely to avoid adding native JSON parser dependencies.
That test adapter is not a production parser. Tests cover draft-01 and profile-02
authenticated body cases, all strict text vectors, and altered key, nonce,
associated data, ciphertext and tag. They do not establish profile-03 parity,
HPKE interoperability, manifest/signature verification, or physical SMS acceptance.

Run from the repository root (use any private temporary build directory):

```sh
build=$(mktemp -d)
python3 sdk/native/crypto-candidate/export_vectors.py > "$build/vectors.tsv"
javac --release 17 -Xlint:all -Werror -d "$build/java" sdk/native/crypto-candidate/java/*.java
java -cp "$build/java" BodyTest "$build/vectors.tsv"
dotnet run --project sdk/native/crypto-candidate/csharp/Tests.csproj < "$build/vectors.tsv"
ruby sdk/native/crypto-candidate/ruby/test_body.rb "$build/vectors.tsv"
```
