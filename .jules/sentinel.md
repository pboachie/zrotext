## 2024-05-19 - DoS via ct_eq panics
**Vulnerability:** The subtle crate's `ct_eq` function panics when called on slices of unequal lengths. Several places in the code used `ct_eq` without first explicitly verifying the lengths of the slices being compared. An attacker who can control the length of one of the inputs could trigger a panic and crash the server (DoS).
**Learning:** In Rust, specifically with the `subtle` crate, cryptographic constant-time equality checks are not safe to call on arbitrary inputs without manual length validation.
**Prevention:** Always verify that `a.len() == b.len()` before calling `bool::from(a.ct_eq(b))`.
