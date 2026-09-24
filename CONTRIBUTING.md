# Contributing to ZROtext

Thanks for helping improve ZROtext. Application code is licensed under `AGPL-3.0-only`; see [LICENSE](LICENSE). Contributions remain yours under that license. Do not copy code, assets, or documentation from another project without checking its license and recording attribution.

## Before you start

- Search existing issues and discussions. Open an issue for a bug or a discussion for a proposed feature or design change, so maintainers can help settle scope before you invest in a large patch.
- For a security vulnerability, use [GitHub's private vulnerability reporting](https://github.com/pboachie/zrotext/security/advisories/new). Do not open a public issue.
- Use synthetic phone numbers and message content in tests and examples. Never post credentials, real message bodies, phone numbers, device identifiers, or private infrastructure details.
- Install the opt-in [public privacy hooks](docs/public-privacy-guard.md) with `python scripts/install_privacy_hooks.py`. They protect all worktrees of this repository without replacing existing hooks.

## Submit a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. Add tests when behavior changes and update relevant documentation.
3. Run the checks for the part you changed. The commands below match CI.
4. Sign off each commit with `git commit -s`. This adds a `Signed-off-by:` line and certifies the [Developer Certificate of Origin](DCO). Use your own name and email; they will be public. GitHub's web UI cannot add the trailer, so merge commits it creates for you — the *Update branch* button, for example — are exempt from the check; for merges you create yourself, use `git merge --no-commit` followed by `git commit -s` (or `git commit --amend -s` on an existing merge).
5. Open a pull request against `main` using the template. Explain the behavior, tests, and any deployment or compatibility impact. Link the relevant issue.

CI runs Rust, Android, hygiene, spelling, dependency, and commit sign-off checks on pull requests. A maintainer reviews contributor changes and may request revisions; the repository owner may merge their own PRs once required checks pass and review threads are resolved. For protocol, authentication, privacy, and billing changes, include the relevant threat or failure cases in your PR description. If you need a device to verify SMS behavior, say so in the PR; an emulator build does not prove carrier delivery.

## Tests and checks

From the repository root, run the checks relevant to your change:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
node --test web/owner/*.test.js
(cd sdk/typescript && npm ci --ignore-scripts && npm test)
python3 scripts/check_public_tree.py
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 -m unittest discover -s protocol/v1/tests -p 'test_device_stream_schema.py'
python3 -m unittest discover -s protocol/v1/tests -p 'test_ztse_draft_vectors.py'
node --check web/owner/devices.js
python3 scripts/check_env_example.py
node --test web/owner/devices.test.js
```

The schema test requires `jsonschema==4.25.1`, as installed in a separate virtual environment by CI. The CI-only `python3 scripts/check_public_tree.py --ci` and `python3 scripts/check_dco.py` commands also need pull request revision variables; CI sets those. CI additionally applies numbered migrations twice with `DATABASE_URL`, runs `cargo run --locked -p zrotext-device-sim`, builds and scans the server image, and runs the Android check from `android/`:

```sh
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug --no-daemon
```

On Windows, use `gradlew.bat` and `python` where appropriate. Return to the repository root after the `sdk/typescript` or `android` commands before running the next check.

### PostgreSQL-backed Rust tests

`cargo test --locked --workspace` reports PostgreSQL-backed tests as **ignored**. They are separate from the unit tests so a missing database cannot look like a passing SQL test. Start a disposable PostgreSQL instance bound to your machine only:

```sh
docker run --rm --name zrotext-test-postgres -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:18.6-bookworm
```

In another shell, set all three URLs and run the ignored database tests. Use a database you may create and drop test schemas in; do not point these at a production database.

```sh
export ZT_AUTH_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres
export ZT_DELIVERY_TEST_DATABASE_URL="$ZT_AUTH_TEST_DATABASE_URL"
export ZT_INBOUND_TEST_DATABASE_URL="$ZT_AUTH_TEST_DATABASE_URL"
cargo test --locked --workspace -- --ignored --skip real_stripe_ --test-threads=4
```

PowerShell equivalent:

```powershell
$env:ZT_AUTH_TEST_DATABASE_URL = 'postgresql://postgres@127.0.0.1:5432/postgres'
$env:ZT_DELIVERY_TEST_DATABASE_URL = $env:ZT_AUTH_TEST_DATABASE_URL
$env:ZT_INBOUND_TEST_DATABASE_URL = $env:ZT_AUTH_TEST_DATABASE_URL
cargo test --locked --workspace -- --ignored --skip real_stripe_ --test-threads=4
```

The `real_stripe_` exclusion is deliberate: those two ignored tests contact Stripe TEST and need separate explicit setup. The ordinary command plus the PostgreSQL command run the same Rust test sets as CI. Stop the container with Ctrl+C when finished.

The public repository contains application code and public development documentation. Keep production credentials, customer data, billing operations, and private marketing material out of it.
