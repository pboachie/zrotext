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

```go
err := webhook.Verify(key, timestamp, signature, rawBody, nowSeconds, 300)
```

Run `go test ./...` and `go vet ./...` from this directory. Source-language floor: Go 1.22.
CI and archive qualification use Go 1.26.10; they do not qualify the unsupported
Go 1.22 compiler.
The monorepo module release tag must use the `sdk/native/go/v` prefix.
