# Candidate ZTSE body text rules

Validate authenticated plaintext with the same public body-text corpus used by
ZROtext's existing receivers. These source packages preserve strict UTF-8 bytes,
accept 1 through 32768 encoded bytes, reject NUL and a leading BOM, and perform
no normalization. Invalid UTF-8 is rejected rather than replaced.

This is one experimental parity layer. It does not parse or authenticate an
envelope, decrypt HPKE/AES-GCM, validate a manifest, manage keys, prevent replay,
or grant authority. Authenticate the envelope and body before using this helper.
Do not log body text. Callers own plaintext lifetime; Go strings do not provide
guaranteed zeroization. Rust returns a borrow without copying plaintext.

Native tests read the existing public `ztse-body-text-01.json` corpus directly.
They also verify decomposed Unicode preservation and multibyte byte-length bounds.
Run `cargo test --locked` in body-rust or `go test ./...` in body-go from a source
checkout. Rust requires 1.88; the Go source-language floor remains 1.22.
CI uses the supported Go 1.26.10 compiler, not the unsupported Go 1.22 compiler.
No oldest-Go-compiler qualification or registry release is claimed.
