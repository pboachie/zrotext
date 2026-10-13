# Experimental ZROtext package guide

These artifacts qualify generated clients against synthetic contracts. They do
not replace the existing supported clients or establish public registry
availability. Registry commands in the generated reference below describe
intended coordinates; they are not instructions to publish or proof that the
dependencies can currently be installed from public registries.

## Coordinates and runtimes

| Target | Generated SDK coordinate | Minimum runtime |
|---|---|---|
| TypeScript | `@elysra/zrotext@0.1.0` | Node 22; qualification uses Node 24 |
| Python | `zrotext-sdk==0.1.0`, import `zrotext_sdk` | Python 3.12 |
| Rust | `zrotext-sdk@0.1.0` | Rust 1.88 |
| Go | `github.com/pboachie/zrotext/sdk/tungsten/generated/go` | Go 1.22 |
| Java | `io.github.pboachie.zrotext:zrotext-sdk:0.1.0` | Java 17 |
| C# | `Zrotext.Sdk` version `0.1.0` | .NET 10 |
| Ruby | `zrotext-sdk` version `0.1.0`, require `zrotext_sdk` | Ruby 3.3 |

These requirements apply to generated HTTP clients. Independently packaged
sealed-content and webhook companions have their own runtime requirements.
Every generated SDK also needs its corresponding pinned Tungsten runtime.
The reviewed generator and runtime revision is
`b5d308db8327ce0a5feede77927176a7b0168e92`; exact language dependencies and versions
are in the archive metadata and maintained package lockfiles.

The TypeScript coordinate deliberately preserves the existing package identity.
Install a candidate in a separate test project; never publish it over the
supported package. Python's generated `zrotext_sdk` namespace is distinct from
the existing `zrotext_client` namespace. Do not remove either supported client
until replacement coverage passes.

## Build and install qualification

From the ZROtext repository, regenerate with the clean pinned Tungsten checkout:

```sh
python scripts/tungsten_sdk.py --source <clean-pinned-tungsten> --check
python sdk/tungsten/package-artifacts.py --source <clean-pinned-tungsten> --target python --out <new-external-directory>
```

Replace `python` after `--target` with any target in the table (`typescript`,
`python`, `rust`, `go`, `java`, `csharp`, or `ruby`). The output directory must be
new and outside the repository. This command builds licensed archives and
installs them into an isolated consumer after removing staging source. The
output manifest records file hashes and explicit compatibility blockers.
Candidate feeds include locally built runtimes; this does not establish public
registry installation. Python binary dependencies are platform-specific.

Rust qualification archives embed temporary candidate-registry references and
must be rebuilt against released runtime coordinates before distribution.
Do not redistribute them as public-registry-ready crates. Go qualification uses
a temporary module proxy without `replace`; it does not repair the unresolved
public nested-module version. See Tungsten
[#60](https://github.com/pboachie/tungsten/issues/60),
[#62](https://github.com/pboachie/tungsten/issues/62), and
[#70](https://github.com/pboachie/tungsten/issues/70).

Source bundles are deterministic reviewed inputs, not installable release
packages. Compilation, installed-consumer behavior, registry readiness, sealed
profile acceptance and physical-device acceptance are separate gates.

## Migration behavior

The [TypeScript/Python migration change](https://github.com/pboachie/zrotext/pull/1139)
contains executable method, request and error comparisons. It remains a proposed
change until merged. Generated resource names, Result values, diagnostic errors,
preview confirmations and pagination differ from supported entry points; do not
replace imports without adapting and testing the caller. The generated language
reference describes target-specific methods and error accessors.

Configure strict response validation. A successful generated validation result
does not replace existing conditional request refinements; Tungsten
[#63](https://github.com/pboachie/tungsten/issues/63) remains a blocker. Treat
Result errors explicitly and stop pagination on error or an application limit.
Do not confuse alpha bearer credentials, owner cookie/CSRF authority, and scoped
workflow credentials. A local preview confirmation is not server authorization.

Automatic retries default to zero. Persist caller-owned idempotency and the
original request before a mutation. A lost response is an uncertain outcome,
not a rejection or permission to send with a new key. Reconcile using the
existing message identity. Sealed replay preserves the exact envelope bytes.
No generated HTTP client supplies encryption, custody or durable authority.

Zero retries does not disable redirect hops. Same-origin read redirects remain
blocked on [Tungsten #65](https://github.com/pboachie/tungsten/issues/65), and
Python total body-read deadline behavior on
[#66](https://github.com/pboachie/tungsten/issues/66). Executed expected failures
are recorded by package qualification; they are not behavioral parity passes.

Only implemented operations are generated. Sealed and workflow routes retain
server gates. Keep handwritten validation, raw-byte webhook verification,
cryptography and protected-custody adapters outside generated code. Unsupported
custody must fail explicitly. Candidate profile03 integration remains under
[ZROtext #1054](https://github.com/pboachie/zrotext/issues/1054); controlled-device
SMS acceptance remains under [#1004](https://github.com/pboachie/zrotext/issues/1004).

Generated CLI/MCP/WebMCP source is also experimental. Use the separately guarded
local stdio MCP package, preserve authorization and confirmations, and register
WebMCP deliberately within an authenticated application. No generation or
package command enables production, publishes packages, or creates release tags.
