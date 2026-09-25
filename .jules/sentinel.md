## 2023-10-27 - Add Strict-Transport-Security (HSTS) header
**Vulnerability:** Missing `Strict-Transport-Security` header in several owner and billing HTTP responses.
**Learning:** Rust axum framework requires headers to be explicitly added to `IntoResponse` structures. Some were tuples (`(header, body)`), some were mutable `Response` objects modified via `response.headers_mut()`. It's important to identify all `IntoResponse` endpoints when making global security header changes since there's no single middleware configured for this currently.
**Prevention:** Check for a global middleware solution for adding security headers if more headers need to be added, otherwise carefully `grep` for `IntoResponse` and `secure_response` implementations.
