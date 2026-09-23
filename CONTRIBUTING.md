# Contributing

ZROtext application changes are contributed under `AGPL-3.0-only`. Future SDKs will have a separate permissive license and must not copy application implementation code. Preserve copyright and license notices on reused material and identify its source in the change.

Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before a Rust change. Android changes should build with the checked-in Gradle wrapper and include the device model and OS when behavior depends on telephony or background execution. A simulator pass is not evidence of delivered SMS.

Every commit must include a Developer Certificate of Origin sign-off line. Add it with `git commit -s`. By signing off, you certify the contribution under the [DCO](DCO) and the component's license. Contributions retain their authors' copyright. Protocol, authentication, and billing changes require a second human reviewer before release.

Do not submit message bodies, phone numbers, credentials, private infrastructure details, or device logs containing them in issues or pull requests. Use synthetic test identifiers.
