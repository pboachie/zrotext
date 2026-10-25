# Contributing to ZROtext

Thanks for helping improve ZROtext. Application code is licensed under `AGPL-3.0-only`; see [LICENSE](LICENSE). Contributions remain yours under that license. Do not copy code, assets, or documentation from another project without checking its license and recording attribution.

## Before you start

- Search existing issues and discussions. Open an issue for a bug or a discussion for a proposed feature or design change, so maintainers can help settle scope before you invest in a large patch.
- For a security vulnerability, use [GitHub's private vulnerability reporting](https://github.com/pboachie/zrotext/security/advisories/new). Do not open a public issue.
- Use synthetic phone numbers and message content in tests and examples. Never post credentials, real message bodies, phone numbers, device identifiers, or private infrastructure details.
- Install the opt-in [public privacy hooks](docs/public-privacy-guard.md) with `python scripts/install_privacy_hooks.py`. They protect all worktrees of this repository without replacing existing hooks.

## Ask questions and share ideas

Use [GitHub Discussions](https://github.com/pboachie/zrotext/discussions) for questions, proposals and design ideas (Q&A, Ideas, Show and tell), the community [Discord](https://discord.gg/DugVBzpngQ) for informal chat, and issues for bugs and device reports. Decisions and design agreements are recorded in issues, discussions or ADRs, not only in chat. Keep all of them free of real phone numbers, message content, device identifiers and credentials; use synthetic data. Report vulnerabilities only through the private channel above.

## Submit a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. Add tests when behavior changes and update relevant documentation.
3. Run the checks for the part you changed. The commands below match CI.
4. Sign off each commit with `git commit -s`. This adds a `Signed-off-by:` line and certifies the [Developer Certificate of Origin](DCO). Use your own name and email; they will be public. GitHub's web UI cannot add the trailer, so merge commits it creates for you — the *Update branch* button, for example — are exempt from the check; for merges you create yourself, use `git merge --no-commit` followed by `git commit -s` (or `git commit --amend -s` on an existing merge).
5. Open a pull request against `main` using the template. Explain the behavior, tests, and any deployment or compatibility impact. Link the relevant issue.

CI runs Rust, Android, hygiene, spelling, dependency, and commit sign-off checks on pull requests. A pull request that changes only files the Rust or Android build cannot read, such as documentation, skips those test steps; the checks still run and report (see `scripts/ci_changes.py`). A new push to a pull request cancels its older CI runs. A maintainer reviews contributor changes and may request revisions; the repository owner may merge their own PRs once required checks pass and review threads are resolved. For protocol, authentication, privacy, and billing changes, include the relevant threat or failure cases in your PR description. If you need a device to verify SMS behavior, say so in the PR; an emulator build does not prove carrier delivery.

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

### CI toolchain qualification

Java CI keeps the existing JDK 17 and 21 major lines. Linux selects Temurin
`17.0.21+9` or `21.0.13+9` with `check-latest`. Until the corresponding Temurin
Windows builds are available, Windows uses official Corretto `17.0.21.0.10` or
`21.0.13.0.10` archives, verified against pinned vendor SHA-256 checksums before
installation. The runtime gate checks the actual vendor and same-major patch
floor; it does not infer patch status from a major selector or cached JDK.

Immediately after selection, `scripts/prepare_java_ci_trust.py` creates a new
per-job copy of `cacerts` under `RUNNER_TEMP`. It removes **every alias** matching
the four certificate DER fingerprints (emSign G1/G2/G3 and AAA) in the
[Java trust advisory](https://www.oracle.com/security-alerts/alert-cve-2026-114820.html).
G1/G2 belong to that additional advisory, not the older compromised-parent
finding. Every other alias, certificate, trusted-entry type and entry attribute must be
unchanged (including trust-usage attributes). A fresh copy enforces password
integrity even if the vendor source is passwordless PKCS12; the public vendor
integrity default is not an application secret. The installed store,
vendor security policy and certificate blocklist remain byte-for-byte unchanged.
Only after the effective default JSSE `TrustManager` matches the qualified copy
does the helper export its `JAVA_TOOL_OPTIONS` selection to subsequent job steps.
`scripts/check_java_toolchain.py` independently repeats the read-only checks.

This mitigation is **JSSE/TLS-only**: it does not change global/installed stores,
code-signing trust, custom trust managers, or other applications' trust stores.
HTTPS connections relying on the removed roots fail, as intended. Pre-existing
custom trust/security overrides, unreadable stores, or an unavailable qualified
runtime fail closed; no platform falls back to an older JDK or skips its checks.
Vendor archive availability and static checks do not establish runtime success
on every platform.

Go CI and native archive qualification use `1.26.10`, while existing `go.mod`
source-language floors remain unchanged. This does not qualify the unsupported
Go 1.22 compiler. Managed SDK CI uses Ruby `3.3.13`; exact .NET 10 SDK selectors
use `10.0.402` without changing target frameworks. A toolchain check is not
application exploitability, deployment, or all-platform runtime qualification.

### PostgreSQL-backed Rust tests

Some isolated-schema tests deliberately apply migrations001 through107. Their
legacy boundary is explicit and checked against the exact compiled current
migration names and SQL. Migrations108 onward require the actual public schema
and separate migration-owner and ordinary runtime connections; they must not be
replayed inside an arbitrary test schema. Current-schema ACL checks are distinct
from the legacy fixture tests, and neither proves a complete hosted flow.

The Windows sealed setup CI consumer owns a fresh disposable PostgreSQL fixture.
Before initialization it gives the current user and SYSTEM inheritable access to
that empty fixture directory, so PostgreSQL's restricted token can create its data
tree. It does not change ancestor permissions or existing databases and services.

The sealed setup phone-build wrapper emits only fixed Gradle failure indicators:
`dependency-verification`, `dependency-resolution`, `java-tls`, `gradle-daemon`,
or `unknown`. These are observed fixed-string signals, not proof of a root cause.
Its opt-in streaming matcher retains only integer match positions and category
flags; no raw stderr is retained or exported. The first failure freezes these
signals before process cleanup, and an output-bound failure reports `unknown`.
Other subprocesses do not enable the matcher.

Later compiled setup failures expose only fixed fixture substages, such as
browser launch, navigation, line challenge, native signing, or the aggregate
deadline. Branded exception identity supplies these labels; exception messages,
stacks, URLs, readiness and signing material are never diagnostic fields. Failed
cleanup remains a failure and records its fixed substage alongside the original
failure. Unconfirmed owned-process cleanup retains its stronger failure priority.

`cargo test --locked --workspace` reports PostgreSQL-backed tests as **ignored**. They are separate from the unit tests so a missing database cannot look like a passing SQL test. Start a disposable PostgreSQL instance bound to your machine only:

```sh
docker run --rm --name zrotext-test-postgres -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:18.6-bookworm -c max_locks_per_transaction=256
```

The lock setting matches CI: four concurrent full-schema fixtures need enough
lock entries for tables, indexes and foreign-key dependencies during cleanup.
It applies only to this disposable server, not an existing database or service.
In another shell, wait for `docker exec zrotext-test-postgres pg_isready -U postgres`
to succeed and verify the setting with:

```sh
docker exec zrotext-test-postgres psql -U postgres -d postgres -Atc 'SHOW max_locks_per_transaction'
```

The result must be `256`. The two registered-owner controls need two additional,
separately provisioned databases: schema isolation alone cannot exclude other
tests' old snapshots from concurrent index construction. On this fresh disposable
cluster, use the provisioning role to create the ordinary control login and its
two databases (existing objects deliberately refuse):

```sh
docker exec -i zrotext-test-postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 < scripts/registered_control_databases.sql
```

In PowerShell, pipe `Get-Content -Raw scripts/registered_control_databases.sql`
to the same `docker exec -i ...` command. The tested control role has no superuser,
CREATEDB, CREATEROLE, replication or BYPASSRLS privilege. CI previously ran these
controls as its privileged `postgres` fixture login; the dedicated role narrows
that access. Provisioning does not change any existing test role's privileges.

Both control URLs are mandatory, even when selecting only one control. Their
explicit database names must be distinct from each other and every configured
standard test URL's database name, conservatively even across hosts. The fixture
accepts only lowercase ASCII names starting with a letter, followed by letters,
digits or underscores, up to 63 bytes; no normalization or default dbname applies.
Control names `postgres`, `template0` and `template1` refuse. Each owned connection
checks its actual `current_database()` against its parsed explicit name before
schema creation. A missing URL fails the selected test rather than skipping it.
On UNKNOWN, retain that fixture/database for reconciliation for the disposable
cluster's lifetime; do not retry, force-drop it or terminate another backend.

Before running the database suite, build the TypeScript
SDK used by the authenticated workflow HTTP fixtures, as CI does. From
`sdk/typescript`, run `npm ci --ignore-scripts` and `npm run build`, then return
to the repository root.

Set the four standard URLs and both isolated control URLs, then run the ignored
database tests. Use databases you may create and drop test schemas in; do not point these
at a production database.

```sh
export ZT_AUTH_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres
export ZT_DELIVERY_TEST_DATABASE_URL="$ZT_AUTH_TEST_DATABASE_URL"
export ZT_INBOUND_TEST_DATABASE_URL="$ZT_AUTH_TEST_DATABASE_URL"
export ZT_FAILOVER_TEST_DATABASE_URL="$ZT_AUTH_TEST_DATABASE_URL"
export ZT_REGISTERED_OWNER_EMPTY_DATABASE_URL=postgresql://zt_registered_control@127.0.0.1:5432/zt_registered_empty
export ZT_REGISTERED_OWNER_MFA_DATABASE_URL=postgresql://zt_registered_control@127.0.0.1:5432/zt_registered_mfa
cargo test --locked --workspace -- --ignored --skip real_stripe_ --test-threads=4
```

PowerShell equivalent:

```powershell
$env:ZT_AUTH_TEST_DATABASE_URL = 'postgresql://postgres@127.0.0.1:5432/postgres'
$env:ZT_DELIVERY_TEST_DATABASE_URL = $env:ZT_AUTH_TEST_DATABASE_URL
$env:ZT_INBOUND_TEST_DATABASE_URL = $env:ZT_AUTH_TEST_DATABASE_URL
$env:ZT_FAILOVER_TEST_DATABASE_URL = $env:ZT_AUTH_TEST_DATABASE_URL
$env:ZT_REGISTERED_OWNER_EMPTY_DATABASE_URL = 'postgresql://zt_registered_control@127.0.0.1:5432/zt_registered_empty'
$env:ZT_REGISTERED_OWNER_MFA_DATABASE_URL = 'postgresql://zt_registered_control@127.0.0.1:5432/zt_registered_mfa'
cargo test --locked --workspace -- --ignored --skip real_stripe_ --test-threads=4
```

The `real_stripe_` exclusion is deliberate: those two ignored tests contact Stripe TEST and need separate explicit setup. The ordinary command plus the PostgreSQL command run the same Rust test sets as CI. Stop the container with Ctrl+C when finished.

CI divides the ignored tests into three disjoint package lanes: delivery store,
server, and every other workspace member. Each lane has its own disposable
PostgreSQL service and retains four test threads. The required `rust` check is
an aggregator, not just the residual workspace job: it requires all lanes and
the original lint, nonignored, migration, TLS, canary and simulator gates.
The existing documentation-only no-op requires a successful, explicit change
filter and successful no-op prerequisites; failed or skipped prerequisites refuse.

`scripts/ci_rust_postgresql.py` builds the complete workspace before dispatching
its ignored harnesses through a command-local native Cargo runner. Cargo retains
feature unification, package working directories and runtime library paths. Every
workspace package and eligible target is discovered from current metadata; each
lane inventories all harnesses and executes its assigned packages. Nonempty lane
coverage, exact passed-test identities and matching source-bound inventories are
required. Unsupported target selection or pre-existing runner overrides refuse
rather than silently narrowing coverage. The residual default lane separately
executes the full ignored Cargo doctest command, without the custom runner;
compiled harness inventory is not treated as doctest execution evidence.

The conversation workflow preserves its separate `conversation-simulator-tests`
feature selection, complete nonignored tests, ignored binary/integration targets,
ignored doctests, and external consumer fixtures. Its ignored libraries use the
same three package lanes and a strict prerequisite aggregator. The two workflows
allow at most three Rust test runners each, without increasing runner sizes or job
budgets. Lane receipts contain only structural test identities, not fixture logs.
Receipts are bound to one workflow attempt: after a failure, rerun the complete
workflow rather than only failed jobs, so every prerequisite produces fresh proof.
The dependency cache remains read-only for pull requests. To exercise the runner
without a database or workspace dependencies, after installing the pinned Rust
toolchain run `python3 scripts/test_ci_rust_postgresql.py --native-runner-smoke`.

With `--features conversation-simulator-tests`, the selected
`http_enrollment::setup_browser_fixture::ordinary_pairing_browser_android_fixture`
drives its composed owner, pairing and binding HTTP routes automatically. It
checks proof, exact comparison, approval recovery and revocation against the
disposable database. This is HTTP regression coverage, not browser, Android
Keystore, TLS or carrier acceptance.

For a separately selected browser/Android consumer, set the test-only
`ZT_PAIRING_SETUP_CONSUMER=external` before running that exact ignored test with
`--nocapture`. This mode emits private rendezvous readiness and waits for the
selected consumer; keep that output outside the public repository. Only
`snapshot` and `finish` are accepted fixture controls. The same 600-second outer
deadline covers consumer execution and server completion. An unknown mode or
failed external consumer never falls back to automatic success. Leave the mode
unset for bulk test runs; it is not an application or Compose setting.

The public repository contains application code and public development documentation. Keep production credentials, customer data, billing operations, and private marketing material out of it.
