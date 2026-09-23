# Contributing to ZROtext

Thanks for helping improve ZROtext. Application code is licensed under `AGPL-3.0-only`; see [LICENSE](LICENSE). Contributions remain yours under that license. Do not copy code, assets, or documentation from another project without checking its license and recording attribution.

## Before you start

- Search existing issues and discussions. Open an issue for a bug or a discussion for a proposed feature or design change, so maintainers can help settle scope before you invest in a large patch.
- For a security vulnerability, use [GitHub's private vulnerability reporting](https://github.com/pboachie/zrotext/security/advisories/new). Do not open a public issue.
- Use synthetic phone numbers and message content in tests and examples. Never post credentials, real message bodies, phone numbers, device identifiers, or private infrastructure details.

## Submit a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. Add tests when behavior changes and update relevant documentation.
3. Run the checks for the part you changed. Rust: `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `cargo test --locked --workspace`. Android: `cd android` followed by `./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug --no-daemon`. On Windows, use `gradlew.bat`. Run `python scripts/check_public_tree.py` for repository-wide hygiene.
4. Sign off each commit with `git commit -s`. This adds a `Signed-off-by:` line and certifies the [Developer Certificate of Origin](DCO). Use your own name and email; they will be public.
5. Open a pull request against `main` using the template. Explain the behavior, tests, and any deployment or compatibility impact. Link the relevant issue.

CI runs Rust, Android, hygiene, spelling, dependency, and commit sign-off checks on pull requests. A maintainer reviews contributor changes and may request revisions; the repository owner may merge their own PRs once required checks pass and review threads are resolved. For protocol, authentication, privacy, and billing changes, include the relevant threat or failure cases in your PR description. If you need a device to verify SMS behavior, say so in the PR; an emulator build does not prove carrier delivery.

The public repository contains application code and public development documentation. Keep production credentials, customer data, billing operations, and private marketing material out of it.
