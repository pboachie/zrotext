## 2024-05-18 - Missing HSTS and CSP frame-ancestors headers
**Vulnerability:** Missing Strict-Transport-Security header across owner-facing API endpoints, and a missing frame-ancestors directive in some CSPs.
**Learning:** Even well-built endpoints can omit fundamental security headers when relying solely on custom header insertion.
**Prevention:** Ensure new response paths include a centralized set of security headers, using helper functions like `secure_response` wherever possible.
