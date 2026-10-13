# Native candidate body primitive

AES-256-GCM with a 32-byte recovered CEK, 12-byte nonce and appended 16-byte tag.
The API receives exact caller-verified AAD (1..36864 bytes) and ciphertext
(17..32784 bytes). Authentication finishes before strict UTF-8 decoding. Text
must have 1..32768 bytes, no NUL, no leading BOM, and no normalization.

This low-level primitive is not a sealed reader. Callers must separately verify
manifest authority, signer, routing, expiry and replay, and use the authorized
HPKE transcript to recover the CEK. Successful decryption is not authorization.
The library has no envelope parser or network path. Input keys stay caller-owned.
Rust clears temporary plaintext and returned Zeroizing text on drop; Go clears
the temporary plaintext slice but cannot guarantee erasure of returned strings
or provider-internal copies. Do not log plaintext or keys.

Rust uses the application's aes-gcm 0.11.1 with zeroize enabled and declares the
repository compiler 1.97.1; this is separate from the Rust1.88 webhook package.
Go uses only its standard library and supports Go1.22. No publication is claimed.
Source tests directly consume existing public text and authenticated body vectors;
fixture slicing is test preparation, never a production authority verifier.
Run cargo test --locked / cargo clippy --locked --all-targets -- -D warnings in
rust, or go test ./... / go vet ./... in go. Source-only corpus tests are excluded
from Rust archives. Full HPKE, signatures, manifests and profile03 parity remain
separate acceptance work.
