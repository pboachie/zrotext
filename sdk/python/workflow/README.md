# Native workflow client candidate

`zrotext-workflow-candidate==0.1.0a1` supplies the normal `zrotext_workflow`
import for Python 3.11 or later. It contains the native eight-tool workflow
client, validators and exact shared schema resource. Runtime dependencies are
standard-library only. Setuptools 84.0.0 is pinned for building the distribution.
The package is an unpublished candidate; it does not replace `zrotext_client`
alpha/webhook or generated `zrotext_sdk` imports.

```python
from zrotext_workflow import WorkflowClient, WorkflowError, action_digest, workflow_functions

client = WorkflowClient("https://gateway.example", workflow_credential)
readiness = client.readiness()
```

Configure a dedicated, independently provisioned `ztw_` credential. Owner and
other credential realms refuse before transport. Readiness describes mounted
methods; it never grants permission. Native transport uses verified TLS, bounded
total deadlines and response bodies, no ambient proxy, no cookies and no redirect
following. Only an explicit rate-limit refusal may retry identical bytes, with
at most three caller-selected attempts. Unknown outcomes never retry. No Node
runtime, subprocess, live grant, plaintext SMS path or carrier action is supplied
by the client. Credential strings cannot be guaranteed erased by Python.

Existing source-checkout `workflow_client` and `workflow_validation` imports
remain forwarding compatibility modules. The installed distribution contains
only `zrotext_workflow` modules and its schema, plus AGPL-3.0-only license and
metadata. It includes no source-checkout bridge, tests, sample credentials,
private logs or fixture keys. Build both archives with
`python sdk/python/workflow/check_package.py --output <temporary-directory>`
after building `sdk/typescript`. The checker installs each archive into a fresh
environment and runs the actual local trusted-CA HTTPS acceptance/refusal
fixture through `python -I`; imports must resolve beneath that environment.
Node hosts the test fixture only, outside the installed client runtime.

`--alpha-source <reviewed-alpha-package-directory>` also builds and co-installs
the separate `zrotext-client==0.1.7rc1` artifact before checking both import
identities, webhook verification and installed workflow HTTPS. CI pins the alpha
source from #1114 at `dc4eac37d43f77b414cbc6d610c2a2754d4640a7`. This does not
publish either package or claim generated/crypto co-installation coverage.

## Replacement acceptance gaps

| Surface | Available evidence | Remaining gate |
|---|---|---|
| Existing Python alpha/webhook | Source client, tests, separate candidate package | Preserve imports, errors and idempotency; no generated replacement implied |
| Native workflow | Eight methods, correlated schemas/digest, bounded HTTPS; installed wheel/sdist tests | Live authenticated workflow permission and deployment acceptance remain independent |
| Native sealed companion | Separate `zrotext_native_candidate` cryptography, Windows TPM and journals | Candidate-only; no integrated Python sealed submit/status/cancel path |
| Selected original replies | Native signed selection and archive-wrap opening | Role-3 current/final grant checks, original-event pagination/consumption remain separate |
| Template/contact content | Maintained TypeScript implementations | Native encrypted-template encoding/seal/open and contact commitment/history coverage absent |
| Protected custody | Qualified Windows Platform Crypto Provider tests in companion | Linux/macOS protected adapters and remote attestation not supplied |
| Combined installation | Alpha and workflow co-installed with both import identities and real workflow HTTPS | Generated/crypto combined consumer acceptance remains required |
| Generated replacement | Pinned runtime builds and wire tests | Conditional validation, disable-all redirects and Python total timeout gaps: Tungsten #63/#65/#66 |
| Device and release | Synthetic component evidence | Production #1054 integration, controlled device acceptance and publication remain separate |

Outbound03 observation-time semantics also differ across native candidates;
[contract question #1226](https://github.com/pboachie/zrotext/issues/1226) tracks
the discrepancy. The workflow package does not change those crypto policies.

The native companion's root/election/currentness tokens never substitute for
server/session authority. Do not infer full native parity from individual APIs
or installed archives. TypeScript browser lifecycle/IndexedDB adapters also need
an explicit Python application-owned alternative, not a renamed browser API.
