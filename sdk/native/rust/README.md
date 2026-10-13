# ZROtext webhook companion

Verify the exact raw request body before decoding JSON or acting on a delivery.
Supply decoded signing-secret bytes, the timestamp and signature headers, the
current Unix time in seconds, and a tolerance (normally 300 seconds). Successful
verification authenticates the body; consumers must still deduplicate event IDs.
Keep the signing secret outside logs and application source.

The native verifier checks the existing server HMAC-SHA256 vector, canonical
header syntax, constant-time signature comparison, and an inclusive symmetric
five-minute window. It performs no network I/O and has no Tungsten dependency.
This package is source support for generated SDK consumers. It does not implement
sealed encryption or claim registry availability.

```rust
zrotext_webhook::verify(&key, &timestamp, &signature, &raw_body, now_seconds, 300)?;
```

Run `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
`cargo package --locked` from this directory. Minimum Rust: 1.88.
