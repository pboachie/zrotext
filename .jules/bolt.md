## 2024-06-11 - [Postgres Test Failures]
**Learning:** Postgres tests fail to run in the sandbox because Docker pull of `postgres:16` fails due to overlayfs permissions constraints.
**Action:** The test failures related to database connection (`ConnectionRefused` and `NotPresent`) in `cargo test` can be safely ignored when working on optimizations that don't depend on Postgres test setup if running them is impossible in the sandbox.
