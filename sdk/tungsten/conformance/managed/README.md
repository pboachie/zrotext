# Managed SDK synthetic wire conformance

These probes compile or load the actual generated Java, C#, and Ruby clients
against the exact clean Tungsten runtime source in `generator.lock.json`. They
copy only generated files whose bytes match `generated.lock.json` into temporary
directories. C# uses a temporary source project reference. No registry installation
or publication is implied.

From the repository root, first reproduce the foundation's generated outputs:

```sh
python3 scripts/tungsten_sdk.py --source /path/to/tungsten --check
python3 sdk/tungsten/conformance/managed/run.py --source /path/to/tungsten --target java
python3 sdk/tungsten/conformance/managed/run.py --source /path/to/tungsten --target csharp
python3 sdk/tungsten/conformance/managed/run.py --source /path/to/tungsten --target ruby
```

Requirements: Python 3.10+, JDK 17+, .NET SDK 10.0.401, Ruby 3.3.9. Java compiles
with `--release 17 -Xlint:all -Werror`; C# treats warnings as errors. `--generated`
can point to another build directory; reviewed hashes are still mandatory.
`--dotnet` and `--ruby` select executable paths. The harness uses two ephemeral
numeric loopback HTTP servers, avoiding host DNS and any deployed gateway.

Each language runs the same 19 cases through generated dispatch and typed methods:

- Owner session cookies and CSRF pair are serialized without bearer leakage;
  missing authentication refuses before network.
- Malformed JSON and wrong success schemas fail in explicit strict mode.
- Read timeout and rate limits make one attempt under the manifest's zero-retry
  defaults. A cross-origin redirect never reaches the second test server.
- Lost webhook creation and confirmed alpha submission remain unknown outcomes.
  Alpha submission requires a caller-owned idempotency key and preview-bound
  confirmation; the lost response reports `same_key_only` and retains that key.
- Owner mutation origin and sealed bearer authentication reach the expected
  synthetic request. A sealed-plane 404 maps to the disabled gate diagnostic.
- Unknown operations and all six currently planned public operations refuse
  before network.

This tests client behavior against synthetic HTTP replies, not server grant or
CSRF enforcement, real deployment gates, production TLS, native crypto, device
delivery, or end-to-end application compatibility. It does not test opt-in retry
policies, all endpoint payloads, same-origin redirects, streaming, or persistence
across processes. Generated workflow schemas still lack refinements enforced by
the existing guarded workflow client. No SDK maturity gate advances from these
tests alone.
