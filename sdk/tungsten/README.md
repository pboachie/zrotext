# Experimental generated ZROtext clients

This integration generates TypeScript, Python, Rust, Go, Java, C#, and Ruby HTTP
clients from the current public contracts. It also generates a Rust `zrotext-api`
CLI, local MCP server, experimental WebMCP adapter, and API/LLM documentation.
Existing clients remain the supported entry points for their documented scope.
Generated clients do not implement sealed-content encryption or key custody.

The [package guide](PACKAGE-GUIDE.md) summarizes all seven coordinates, runtime
requirements and migration blockers. Packaging prepends it to staged SDK/source
README files and includes a hashed sidecar beside every binary feed. Generated
registry examples are intended coordinates, not public availability claims.

## Reproduce the output

Check out Tungsten at the revision in `generator.lock.json` into a clean external
directory using `git clone -c core.autocrlf=false` so embedded templates retain
their canonical LF bytes. Install that checkout's Rust toolchain and Go, then run
from this repo:

```sh
python3 scripts/tungsten_sdk.py --source /path/to/tungsten
python3 scripts/tungsten_sdk.py --source /path/to/tungsten --check
```

On Windows, run inside WSL when using Linux Rust/Go. Windows-created worktrees
are checked through Windows Git when it is on the WSL PATH. The runner builds
both tools from the verified clean source; a matching version string alone is
not accepted. `CARGO_TARGET_DIR` may select an external build cache.

`generated/` is ignored build output. The tracked `generated.lock.json` contains
SHA-256 digests of every generator-owned file for reviewable deterministic
checks without committing several megabytes of repeated generated contracts.
Required preserved `custom` modules live in the reviewed `extensions/` tree;
the runner stages and hashes them too. They are included in source packages.
Normal generation refreshes that lock; `--check` regenerates ignored artifacts,
runs Tungsten's own drift check, and compares the lock without updating it.
Both manifests use JSON syntax, a YAML subset, so policy tests need no YAML
dependency. Never hand-edit generated files.

For a local synthetic contract server, use the same command with `--mock`.
It models the API contract; it does not establish real server, device, carrier,
authorization, or sealed cryptographic acceptance.

## Boundaries and migration

- Only implemented public operations are callable. Planned aliases remain docs.
  Sealed and workflow operations retain their server feature gates and scoped
  credentials. Generation never enables a deployment gate.
- All automatic HTTP retries default to zero. Persist caller-owned idempotency
  keys. An uncertain response is not permission to create a new send. Sealed
  envelope replay identity remains the original bytes, without a new header key.
- Construct generated TypeScript clients with `validateResponses: 'strict'`.
  Tungsten defaults to warnings; this is not sufficient for legacy-client parity.
- The existing `@elysra/zrotext` package is preserved. Generated TypeScript uses
  that future identity in an isolated build tree, but must not be published over
  the current package. Method names, Result errors, previews and confirmations
  differ from existing clients; no compatibility replacement is claimed here.
- Existing crypto/custody, webhook verification and workflow schema refinements
  stay outside generated code. OpenAPI alone does not encode every executable
  workflow validation rule. Python's existing bridge remains until native parity.
- Generated MCP is an experimental separate artifact, not a replacement for
  `sdk/mcp`. Do not expose it remotely or give it owner credentials merely to
  bypass workflow restrictions. WebMCP requires deliberate registration inside
  an authenticated application; generation does not install browser tools.
- Profile03 candidate parity and durable authority/device integration remain
  gated by the current protocol and issue #1054. No physical SMS readiness is
  implied; controlled-device acceptance is tracked by #1004.

## Validation and package readiness

All seven languages have an experimental archive installation gate:

```sh
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target python --out /tmp/zrotext-python-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target ruby --out /tmp/zrotext-ruby-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target typescript --out /tmp/zrotext-npm-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target java --out /tmp/zrotext-maven-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target csharp --out /tmp/zrotext-nuget-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target go --out /tmp/zrotext-go-packages
python3 sdk/tungsten/package-artifacts.py --source /path/to/tungsten --target rust --out /tmp/zrotext-rust-packages
```

Use a new output directory outside the checkout. The gate verifies the pinned
runtime source and generated inventory, adds AGPL SDK and Apache runtime license
files in staging, builds ordinary wheels or gems, removes staging source, then
installs into an isolated consumer. Python additionally runs the ten injected
wire checks from the installed wheel. Ruby loads the packaged client and its
runtime and runs the managed wire checks described below. The Python build and consumer dependency versions are pinned in
`python-package-requirements.txt`; its binary dependencies make the feed specific
to the build platform. Each output has archive hashes and a qualification manifest.

For the three additional targets, put Node/npm, JDK 17 or newer/Maven, and the
.NET 10 SDK on PATH respectively. npm compiles an installed TypeScript consumer
and loads all namespaces. Its installed consumer also runs the twelve existing
injected transport contracts through public package exports, plus eight passing
real HTTP checks for authentication, pagination, validation, malformed responses,
cross-origin redirects, stalled bodies, gates/rate limits, and uncertain confirmed
sends. A ninth real HTTP case executes as an explicitly failing TODO for
[Tungsten #65](https://github.com/pboachie/tungsten/issues/65): same-origin reads
follow redirects. The artifact manifest records this compatibility blocker;
successful package construction does not qualify replacement of existing clients.
Maven builds JAR/POM pairs, resolves the SDK plus its
runtime from a file repository into a fresh dependency cache, and compiles/runs
a consumer. NuGet produces nupkg files, maps candidate coordinates exclusively to
the local feed, and restores/builds/runs a consumer from a separate package cache.
Java, C#, and Ruby each run twenty-five synthetic HTTP checks using the installed
archives after staging source removal. These reuse the reviewed managed wire
probes: owner cookie/CSRF and bearer authentication, missing-auth refusal,
malformed JSON and strict response validation, bounded read timeout, no automatic
rate-limit retry, cross-origin redirect refusal, uncertain mutation outcomes,
disabled sealed gates, caller-owned idempotency, preview confirmation, and
unknown/planned-operation exclusion. Maven compiles the probe against resolved
JARs; NuGet rebuilds its consumer against PackageReferences; Ruby retains its
installed-gem origin check and source-injection refusal. Six additional cases use
the generated typed owner-message page iterators to check decoded items, cursor
and credential propagation, explicit starting cursors, application page limits,
missing-auth refusal, and terminal second-page errors without retry. Same-origin
read redirects remain unqualified. Separate sealed-profile
suites remain required. No test invokes a live ZROtext server.

Go uses a temporary file module proxy, a fresh module/build cache, no `replace`,
and `go mod verify` after compiling/running the consumer. Its checksum database
is disabled only for that isolated, unpublished candidate feed. This does not
resolve the missing public runtime module tag tracked by
[Tungsten #60](https://github.com/pboachie/tungsten/issues/60).

Rust requires toolchain 1.88.0 and uses Cargo itself to package the runtime,
CLI kit, SDK and CLI. A direct installation without a rustup proxy can use
`--cargo /path/to/toolchain/bin/cargo`; the command verifies that Cargo and its
sibling rustc both report 1.88.0 and selects that compiler explicitly.
Staging resolves workspace metadata and local dependencies
into explicit candidate-registry versions. A temporary localhost sparse registry
serves those archives while ordinary transitive dependencies resolve from
crates.io. After removing all source staging, a fresh Cargo home compiles/runs an
SDK consumer and installs/runs the CLI with its packaged lock file. Besides help,
six subprocess acceptance groups run against that exact installed binary:
preview/partial confirmation sends nothing; missing authentication/idempotency
fails before transport; confirmed ambiguous sends make one attempt; status
reconciliation stays read-only; failed status reads do not retry; and auth status
redacts credentials without transport. The checks retain synthetic caller keys
and unknown-outcome semantics. There
are no path dependencies, patch tables or source-replacement configuration.

Rust's output is specifically **candidate-registry qualification**, not public
release archives: Cargo embeds the temporary registry references in its package
metadata and lock files. Rebuild against released runtime coordinates before
distribution. Runtime publication remains blocked by Tungsten #62; the generated
CLI also needs the versioned-dependency/MSRV repair in
[Tungsten #70](https://github.com/pboachie/tungsten/issues/70). The staging adaptation
proves crate compilation/installability without treating it as an emitter fix.

The installed Go and Rust consumers each run twelve synthetic HTTP checks adapted from
the native wire suite: bearer authentication and scope refusal, argument validation,
planned-operation exclusion, disabled sealed gates, pagination, malformed JSON and
response shapes, bounded body-read timeout, mutation/cross-origin redirects, and
single-attempt uncertain sends preserving caller idempotency. These execute against
the installed module archives after source staging is removed. Same-origin read
redirect policy remains blocked by Tungsten #65; this suite does not qualify that
missing policy or real server permission enforcement.

These feeds include locally built Tungsten runtimes. They prove archive usability,
not availability on public registries. Upstream runtime distribution issue
[Tungsten #62](https://github.com/pboachie/tungsten/issues/62) remains a release
gate. Native sealed companion packaging remains separate from these generated
HTTP-client archives.
No registry publication, legacy-client replacement, or sealed-profile acceptance
is performed by this command.

The guarded local MCP adapter has a separate distributable archive gate:
`python3 sdk/tungsten/package-mcp.py --out /tmp/zrotext-guarded-mcp`.
It packages the maintained workflow guard with the verified generated catalog,
not the raw generated MCP server. The isolated installed stdio/HTTPS tests and
operator setup are documented in [mcp/README.md](mcp/README.md).

CI builds the exact compiler and external emitter, regenerates all ten targets,
checks digests, compiles TypeScript and exercises synthetic transport failures.
It also compiles Rust/Go/Java/C#, loads Ruby, and builds/installs Python wheels
against the pinned runtime source. Installed Python and TypeScript wire checks
cover credentials, pagination, invalid inputs, redirects, malformed responses,
confirmation and caller-owned idempotency under uncertain outcomes. Python additionally runs twelve installed-consumer groups against an actual local
HTTP server after SDK/runtime source staging is removed. They cover installed
module origins, bearer and owner authentication, cursor pagination, preflight
refusal, malformed responses, gate/rate refusals, stalled reads, mutation and
cross-origin redirects, and exact caller idempotency after a lost response.
Two executed expected failures preserve the existing-client requirements:
[Tungsten #65](https://github.com/pboachie/tungsten/issues/65) follows same-origin
read redirects, and [#66](https://github.com/pboachie/tungsten/issues/66) settles
blocked non-streaming body reads only after the next chunk, beyond the total
call deadline. An unexpected
success fails the suite so the gate must be reviewed when the runtime changes.
The archive manifest records both blockers; ordinary passing cases do not qualify
the Python runtime for existing-client replacement. These HTTP fixtures do not
establish TLS, production authentication or sealed cryptographic parity.
Contract inputs use LF line endings on every
platform so their generator digests agree across Windows and Linux checkouts.
Run those tests locally after generation:

```sh
python3 -m unittest discover -s scripts -p 'test_tungsten_sdk.py'
cd sdk/tungsten/generated/typescript
cp ../../typescript.package-lock.json package-lock.json
npm ci --ignore-scripts
npm run build
node --test ../../contract.test.mjs
```

Generation is not compilation, behavioral parity, package installation, or device
acceptance. All generated packages remain experimental and unpublished. Their
licenses and archive contents must be checked before distribution. Independent
native companion packages have their own tests and readiness documentation.

Upstream dependencies are tracked in Tungsten issues
[#60](https://github.com/pboachie/tungsten/issues/60) (Go runtime resolution),
[#61](https://github.com/pboachie/tungsten/issues/61) (target documentation), and
[#62](https://github.com/pboachie/tungsten/issues/62) (runtime distribution).
Conditional JSON Schema refinement is also blocked by
[#63](https://github.com/pboachie/tungsten/issues/63): the generated webhook
selection validator accepts enabling without encrypted-transfer confirmation,
although the server rejects that combination. Retain the existing validators;
generated schema success alone is not equivalent client-side validation.
[#64](https://github.com/pboachie/tungsten/issues/64) tracks checkout-dependent
Rust template bytes; the runner rejects CRLF templates before building.
[#65](https://github.com/pboachie/tungsten/issues/65) tracks the missing
no-redirect policy: generated TypeScript/Python read calls follow same-origin
redirects even with retries disabled. Existing clients reject these redirects;
retain those clients until explicit redirect-policy parity is available.
Clean-consumer installation must work without sibling checkout dependencies,
editable installs or Go replacements before claiming registry readiness.

For generator updates, review the pinned source and manifest changes together,
regenerate, inspect the operation surface and digest changes, run native/runtime
conformance checks, and retain the existing clients until replacement gates pass.

For bounded Rust/Go source compilation (not registry installation), install
Rust 1.88.0 and run `python3 sdk/tungsten/check-rust-go.py --source /path/to/tungsten`.
This copies generated packages into temporary directories and binds dependencies
to the verified runtime source; it never changes the generated package manifests.

`check-managed.py --source /path/to/tungsten --target java` (or `csharp`, `ruby`)
and `check-python.py --source /path/to/tungsten` qualify the other source builds.
Java requires 17+, C# requires .NET 10, Ruby requires 3.3+, and Python requires
3.12+. These source checks do not establish clean registry installation.

After generation, `python3 sdk/tungsten/package-sources.py --out /external/output`
creates ten deterministic source archives, adds the application license, and
emits SHA256SUMS. It refuses modified generated files and packages only the
reviewed inventory, excluding installed dependencies and build caches. CI makes
these experimental source bundles available as a seven-day artifact. They are
not registry release packages or an approval to publish them.


Public local mock fixtures and an automated scenario command are documented in
[mock/README.md](mock/README.md). Run
`python scripts/tungsten_sdk.py --source <clean-pinned-tungsten> --mock-check`
to verify seeded IR responses, gates, authentication shapes, workflow mapping,
pagination and synthetic failure/replay behavior. These checks cannot establish
real token authority, cryptography, transaction durability or device acceptance.


Managed raw-body webhook companions have separate licensed archive gates:
`python sdk/native/package-webhooks.py --target java --out <external-directory>`
(and `csharp` or `ruby`). Their clean Maven, NuGet and gem consumers run the
shared raw-byte signature, tampering and replay-window vectors after source
staging removal. See the [Java](../native/java/README.md),
[C#](../native/csharp/README.md) and [Ruby](../native/ruby/README.md) guides for
candidate coordinates. These helpers remain outside generated files and require
receiver-owned event deduplication; they do not add sealed-content acceptance.
