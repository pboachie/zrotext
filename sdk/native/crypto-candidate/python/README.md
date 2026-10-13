# Python candidate body authentication

Source-only Python 3.12+ companion for the existing unapproved body corpus.
`open_body(key, nonce, verified_aad, ciphertext)` uses PyCA AES-256-GCM with a
32-byte key, 12-byte nonce and appended 16-byte tag. AAD is 1–36864 bytes;
ciphertext is 17–32784 bytes. Authentication completes before strict UTF-8
decoding (1–32768 bytes, no NUL, no leading BOM, no normalization).

**This is not a sealed reader.** The caller must independently establish current
manifest, signer, routing identity, expiry, replay policy and authorized HPKE key
recovery, then supply the exact verified AAD and recovered CEK. Successful
decryption creates no permission. `decode(raw)` checks text only.

`CandidateBodyError.code` is `shape`, `authentication`, `length`, `nul`, `bom`,
or `utf8`, without plaintext diagnostics. Mutable working copies of the key,
inputs and plaintext are cleared on success and failure. Caller-owned inputs,
returned strings and provider-internal copies have no secure-erasure guarantee.
The `decrypt_into` API avoids creating an immutable plaintext byte string before
the text check. The module does not enter any stable wheel allowlist.

Use an isolated environment and the exact pinned dependencies:

```sh
python -m pip install --only-binary=:all: -r sdk/native/crypto-candidate/python/requirements.txt
python -m unittest discover -s sdk/native/crypto-candidate/python -p 'test_*.py'
```

PyCA `cryptography==50.0.2` supplies maintained native AES-GCM rather than a new
cryptographic implementation. Its binding dependencies are also pinned.
See [PyCA authenticated encryption](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/)
and the [release metadata](https://pypi.org/project/cryptography/50.0.2/).

Tests consume all 47 shared draft-01/profile-02 text, authentication and tamper
cases, plus bounds, authenticate-before-decode and buffer-clearing regressions.
Fixture slicing is test-only. These tests do not establish profile-03 provenance,
HPKE interoperability, custody, device behavior or carrier delivery.
