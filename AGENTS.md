# Agent instructions

These rules apply to every automated contributor in this repository (Codex, Claude Code, Jules, Copilot and others) and to humans driving them. They add to [CONTRIBUTING.md](CONTRIBUTING.md); when they conflict, the stricter rule wins. Several agents work here in parallel, so most of these rules are about not stepping on each other.

## What this repository is

ZROtext is a **public, AGPL-3.0-only** Android SMS gateway. Everything committed here is published and permanent in Git history.

| Path | Contents |
|---|---|
| `crates/server` | Axum HTTP/WebSocket server: auth, billing, enrollment, device socket, inbound, webhooks |
| `crates/delivery-store` | PostgreSQL single-writer delivery transactions |
| `crates/domain`, `crates/postgres-connection`, `crates/migrator`, `crates/device-sim` | Shared types, DB connection, migration runner, delivery simulator |
| `deploy/compose` | Dockerfile, Compose stack, numbered SQL migrations, restore tooling |
| `android/` | Kotlin gateway app (`src/test` = JVM unit tests, `src/androidTest` = device/emulator tests) |
| `web/owner` | Owner dashboard HTML/JS/CSS, embedded into the server with `include_str!` |
| `protocol/v1` | Device-stream and webhook contracts, JSON schema, test vectors |
| `sdk/typescript` | Draft sealed-content reader and vectors |
| `scripts/` | Repository hygiene, privacy, DCO, release and Jules tooling |
| `docs/` | Public design, security, self-hosting, compliance and ADRs |

## Public/private boundary

The maintainer keeps a separate **private operations repository** (`zrotext-ops`). It is the home for anything that is not generic, publishable application source or documentation.

**Never commit these to this repository.** Put them in the private ops repository, or ask the maintainer if you cannot reach it.

- Hostnames, IP addresses, tunnel/DNS/Cloudflare details, server inventories, and runbooks for the hosted service
- Credentials, tokens, keys, `.env` files, or secret references tied to real infrastructure
- Real phone numbers, message bodies, device serials or IMEIs, SIM details, or raw device/emulator/server logs
- Dated evidence captures, test-session logs, PR-body drafts, agent transcripts, and investigation notes
- Business, pricing, founder, customer, or marketing material

Use synthetic data in tests and examples. The privacy guard rejects realistic phone numbers, personal paths, IPv4 addresses, and credential-shaped strings. **Do not weaken, allowlist around, or bypass `scripts/privacy_guard.py`** to get a change through; move the content instead. Install the hooks once per clone with `python scripts/install_privacy_hooks.py`.

Scratch output (probe scripts, logs, screenshots) belongs in your tool's temporary directory or the private ops repository, never in the working tree.

## Coordinating with other agents

- **One issue, one branch, one PR.** Before starting, check that no open PR or branch already covers the issue: `gh pr list --search "<issue number>"` and `git branch -r | grep <issue number>`. If one exists, stop and report it instead of starting a parallel fix.
- **Branch names:** `<agent>/<issue>-<short-slug>`, for example `codex/153-expired-idempotency` or `claude/145-data-retention`. Use `<agent>/<short-slug>` only when there is no issue.
- **Start from fresh `main`:** `git fetch origin && git switch -c <branch> origin/main`. Do not branch from another agent's branch unless you are deliberately stacking; then set the PR base to that branch and say so in the PR body.
- **Worktrees:** create them outside the repository under one shared parent, such as `git worktree add ../zrotext-wt/<slug> -b <branch> origin/main`. Remove them after the PR merges or closes (`git worktree remove`, `git worktree prune`). Do not create new sibling `zrotext-*` folders.
- **Stay in your lane.** Do not push to, rebase, or force-push a branch you did not create. Do not edit files outside the issue's scope just because they are nearby. If you find an unrelated problem, open or propose an issue.
- **Migrations are shared, serial state.** New files go in `deploy/compose/migrations/` as the next free `NNN_description.sql`. Before you open the PR, and again before merge, rebase on `origin/main` and check open PRs for a migration with the same number. Renumber yours if it collides. **Never edit a migration that is already on `main`**; add a new one.
- **Keep PRs reviewable.** Aim for one behavior change per PR. Split large work into stacked PRs rather than one very large diff.

## Things agents must not do

- Push to `main`, merge or approve PRs, enable auto-merge, or dismiss reviews
- Change repository settings, rulesets, secrets, branch protection, or release tags
- Modify `.github/workflows/jules-review.yml`, `release-*.yml`, or other workflows that use secrets or write tokens, unless the maintainer asked for that exact change in the current task
- Disable, delete, or `#[ignore]` a failing test to make CI pass, or loosen a lint (`#[allow(...)]`, `-D warnings`) without explaining why in the PR
- Bump `rust-toolchain.toml`, Android SDK levels, the Gradle wrapper, or Docker base images outside a PR dedicated to that bump
- Add a dependency without a one-line justification in the PR body. Prefer crates already in the workspace.

## Commits and pull requests

- Sign off every commit: `git commit -s`. CI rejects commits without an author-matching `Signed-off-by:` line. Agents may add a `Co-authored-by:` trailer.
- Write commit and PR titles as the final squash-merge title: imperative, specific, with no `Draft:`, `WIP`, or `[agent]` prefix. Use GitHub's draft-PR state to mark unfinished work.
- Use `.github/PULL_REQUEST_TEMPLATE.md`. Link the issue (`Fixes #123`). List the exact commands you ran and their results. For protocol, authentication, privacy, billing, migration, and deployment changes, state the threat or failure cases considered.
- Say plainly what was **not** verified, for example "no physical device", "PostgreSQL tests not run locally", or "emulator only". An emulator run does not prove carrier delivery.

## Checks before opening a PR

Run the checks for every area you touched. CI runs all of them.

```sh
# Rust
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
# PostgreSQL-backed Rust tests: set ZT_AUTH_TEST_DATABASE_URL, ZT_DELIVERY_TEST_DATABASE_URL and ZT_INBOUND_TEST_DATABASE_URL to a disposable database first
cargo test --locked --workspace -- --ignored --skip real_stripe_ --test-threads=4

# Android (use gradlew.bat on Windows)
cd android && ./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug --no-daemon

# Owner UI and TypeScript SDK
node --test web/owner/*.test.js
cd sdk/typescript && npm ci --ignore-scripts && npm test

# Repository hygiene, privacy and tooling
python scripts/check_public_tree.py
python scripts/check_env_example.py
python -m unittest discover -s scripts -p 'test_*.py'
python -m unittest discover -s protocol/v1/tests -p 'test_*.py'   # the schema test needs `pip install jsonschema`
```

If you cannot run a check, for example because PostgreSQL or the Android SDK is unavailable, say so in the PR instead of claiming it passed.

## Tests

- Every behavior change needs a test that fails without the change.
- **Rust:** put small, pure unit tests in an inline `#[cfg(test)] mod tests`. When a module's tests exceed about 300 lines or need PostgreSQL, put them in a sibling file (`foo/tests.rs`, declared as `#[cfg(test)] mod tests;`). `inbound/tests.rs` and `retention/tests.rs` follow this pattern. Put tests that use only the public API in `crates/<crate>/tests/`. Do not grow inline test modules in already-large files.
- **PostgreSQL tests** use `#[ignore = "requires ZT_<AREA>_TEST_DATABASE_URL; ..."]` and must clean up after themselves or use unique IDs so they can run in parallel.
- **Android:** JVM-testable logic goes in `src/test`. Device and emulator tests go in `src/androidTest` and must not send real SMS unless the maintainer explicitly runs them on a controlled device.
- **Name tests after behavior**, not milestones or dates. Use `ReconnectAfterRebootTest`, not `M0...Test` or `...20260924`.
- **A new test file must run in CI.** If a workflow does not already discover it, update the workflow in the same PR.

## Documentation

- Update docs in the same PR as the behavior they describe. Public docs describe what the code does now, or clearly label a proposal as a proposal.
- Do not add dated or session-style files (`*-2026-09-24.md`, `notes/`, "evidence", "review package") to `docs/`. Durable decisions go in `docs/adr/NNNN-title.md`. Evidence and working notes go in the private ops repository.
- Protocol changes go in `protocol/`, with vectors and schema updates in the same PR.
- Keep the README truthful about project status. Do not describe planned features as available.

## Security-sensitive areas

Changes to these paths need extra care and an explicit threat or failure discussion in the PR: `crates/server/src/{auth,http_auth,billing,enrollment,device_socket,sealed_inbound,inbound}`, `crates/delivery-store`, `deploy/compose/migrations`, `protocol/`, `android/**/*KeyStore*`, `.github/workflows`, and `scripts/privacy_guard.py`. Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues, PRs, or commit messages.
