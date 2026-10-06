# Reviewed local connector setup

**Experimental local preview setup. Live/hosted messaging is unavailable.** This
#618 slice supplies an actual doctor, synthetic first MCP exchange, configuration
preview/apply, idempotent rerun and owned-entry disconnect. It does not implement
owner pairing, grant creation/revocation, Android navigation or SMS activation.

## Supported artifacts and prerequisites

Use a trusted source checkout with Python 3.12 and Node.js 22. Windows was tested;
POSIX uses standard Python atomic replacement but was not verified locally.
The selected server artifact is the local-preview stdio server from
[#616 / PR #678](https://github.com/pboachie/zrotext/pull/678), built with its existing
SDK. That dependency remains a separate local-preview artifact; this installer does not download,
execute installation scripts, modify another branch, or publish a package.

Choose the server `.mjs` file from the source revision you reviewed and supply its
expected SHA-256 fingerprint. The doctor and every launcher invocation verify
that exact file. This detects replacement of the launch artifact; it is **not** a
signature, proof of publisher identity or verification of its imported module
graph. Review/build the SDK and use the locked dependency install instructions
from #616. Signed release/package provenance remains future work. Do not approve
an arbitrary downloaded file by merely hashing it.

Supported configuration formats are `mcp-json` and `claude-desktop`, both using
`mcpServers` with `command`/`args` entries. This validates the documented local
configuration shape; it does not claim a tested Claude Desktop application version.
The format follows the official
[Python MCP client host guide](https://py.sdk.modelcontextprotocol.io/get-started/real-host/).
Other formats are refused. Select the client configuration file explicitly; the
tool does not discover or edit a guessed global configuration location.

## Tested configurations and measured setup path

This records one measured verification run of the documented local path on a
single contributor host. It states which runtimes and deployment modes the
instructions on this page were exercised against. It is **not** an availability
claim, a supported-release matrix, or evidence of phone, SIM, carrier or
end-user-client readiness. All traffic was synthetic; nothing was sent.

### Versions and deployment modes tested

| Component | Tested version | Measured result on this host |
| --- | --- | --- |
| Host | Windows 11 Pro; commands run in a Git Bash (POSIX) shell | Complete documented path ran |
| Node.js runtime (SDK, MCP stdio server, guided journey fixture) | v24.13.0 (meets the documented 22+ prerequisite) | Full path ran |
| npm | 11.6.2 | `npm ci --ignore-scripts` completed; 0 vulnerabilities reported |
| Python runtime (setup tooling) | 3.12.9 | Full path ran |
| TypeScript SDK (`@zrotext/sealed-draft-v1`, built from this checkout; unpublished) | 0.0.0-draft | `npm test`: 884 tests — 874 passed, 10 skipped, 0 failed |
| MCP stdio server artifact (`sdk/mcp/server.mjs`, built from the same checkout) | reviewed per-revision SHA-256 fingerprint (computed at review time; not pinned here) | Doctor verified the artifact; synthetic demo exchange completed |
| Rust toolchain (simulator) | 1.97.1 (pinned in `rust-toolchain.toml`) | Simulator built and ran |
| Docker / Compose | 29.2.1 / Compose v5.1.0 | Stack built, migrated and served both health endpoints |
| End-user MCP client application (for example Claude Desktop) | none | Untested; doctor reports `clientVersion: "unknown"` and this page validates configuration formats, not an application version |

Deployment modes exercised, all local and loopback-only:

- **Simulator only** (no containers): `scripts/agent_setup.py journey` and the
  `zrotext-device-sim` delivery model.
- **Local dev Compose stack**: plain HTTP on loopback port 8080, no TLS edge and
  no HTTPS account origin.
- **Local-preview MCP setup**: doctor, synthetic demo, and preview/apply
  install and disconnect into a scratch `mcp-json` configuration file.

The MCP library clients previously verified against this server over stdio
(official JavaScript SDK 1.31.0 and Python MCP client 2.2.0) are recorded in
[mcp-local-tools.md](mcp-local-tools.md); those remain library clients, not
tested end-user applications. This run used the `sh`-style command forms later
on this page, in Git Bash on Windows; Linux/POSIX platforms and the PowerShell
command forms were not separately exercised.

### Measured setup path

Ordered steps that completed on the host above, from a fresh checkout. Elapsed
figures are a one-time record of that machine and cache state; expect different
values elsewhere, and treat none of them as support commitments.

1. Build and test the SDK: `npm ci --ignore-scripts` then `npm test` in
   `sdk/typescript` (install about 6 seconds; the suite reported 874 passed,
   10 skipped, 0 failed in about 44 seconds, and the test script builds `dist/`
   as a dependency of the run).
2. Guided simulator journey: `python scripts/agent_setup.py journey` from the
   checkout root. Exit 0; all 16 fixture steps returned their pinned states;
   the measured fixture subprocess time was 0.33 seconds; the output carried
   `synthetic: true` and `available: false`.
3. Delivery model: `cargo run --locked -p zrotext-device-sim`. The printed
   matrix included `agent_journey` with `final_state: submitted` and
   `radio_calls_modelled: 1` — a modeled boundary count, never a radio
   operation. Build plus run took about 11 seconds on this host.
4. Local stack: copy `.env.example` to `.env`; set one long random local value
   that stays valid inside the `DATABASE_URL` (hexadecimal is convenient) in
   both `POSTGRES_PASSWORD` and `DATABASE_URL`, and independently generate
   32 random bytes as 64 hexadecimal characters for `RUNTIME_DATABASE_PASSWORD`.
   Then run
   `docker compose --env-file .env -f deploy/compose/compose.yaml up -d --build`.
   The database became healthy, the migration and runtime-role
   jobs exited 0, and the API started (about 5 minutes with a cold image cache;
   under 2 minutes warm). `curl http://127.0.0.1:8080/healthz` returned
   `200 {"status":"live"}` and `/readyz` returned `200 {"status":"ready"}`.
   Health answers describe process and database availability, not SMS. Tear a
   scratch stack down afterwards with
   `docker compose -p <scratch-project> --env-file .env -f deploy/compose/compose.yaml down -v`.
   The Compose file
   pins its default project name, so `down -v` without `-p` removes the default
   project's database volume; never run it against a volume you keep.
5. Reviewed MCP setup against the built `sdk/mcp/server.mjs` and its computed
   SHA-256 fingerprint: `doctor` (exit 0; `artifactVerified: true`; Node and
   Python versions echoed; `clientVersion` still `"unknown"`), `demo` (exit 0;
   synthetic fixture exchange, 0.11 seconds), `install` preview then
   `install --apply --review-digest` into a scratch `mcp-json` file (exit 0;
   one `zrotext-local-preview` entry launched through this script's `stdio`
   subcommand), and `disconnect` preview then `disconnect --apply --review-digest`
   (exit 0; entry removed).
6. Closed-gate check: an unauthenticated `POST /v1/alpha/messages` against the
   running stack with placeholder values returned HTTP 404 while the
   synthetic-alpha gate was off. That is the documented closed behavior
   ([send your first message](SEND-FIRST-MESSAGE.md)), not a defect.

One host quirk worth repeating: `POSTGRES_PASSWORD` applies only when a fresh
database volume is initialized. A volume left by an earlier run keeps its
original credential, and the migration job then fails with a PostgreSQL
connection error. Keep the original password for an existing volume
([database role separation](../deploy/compose/README.md#database-role-separation))
or run scratch verifications against a fresh Compose project and volume, as
this run did after its first attempt failed that way.

Not exercised by this run: any authenticated or owner-account flow, Android
installation, SIM or line activation, a public HTTPS origin, and any named
end-user client application. The steps that precede a phone are in
[self-hosting](SELF-HOSTING.md).

### Remaining manual phone, SIM and permission steps

These steps stay manual and are not verified by the measured path above; this
setup neither performs nor authorizes them:

1. Configure the exact HTTPS account origin, TLS edge and verification mail
   ([public HTTPS and device WSS](SELF-HOSTING.md#public-https-and-device-wss)),
   then create the first owner with the local admin CLI
   ([owner registration](SELF-HOSTING.md#owner-registration)).
2. Provide a dedicated Android phone, install a reviewed artifact, and grant
   the gateway its Android permissions, including any default-SMS-app role it
   requests. Check [device compatibility](DEVICE-COMPATIBILITY.md) and
   [Android testing](ANDROID-TESTING.md); a local build can differ from a
   published artifact.
3. Create a one-use pairing request in the owner dashboard and pair the phone
   after reviewing each access purpose. Connection controls require a selected
   SIM ([from a healthy stack to a phone](SELF-HOSTING.md#from-a-healthy-stack-to-a-phone)).
4. Provide and activate the SIM/line through the owner-approved activation
   flow when that pilot path is available. Carrier charges and carrier rules
   apply to any real message.
5. Issue the scoped workflow grant, keep its credential in the customer OS
   secret store, and select it for the connector
   ([workflow grants](guided-workflow-grants.md)). Grant revocation during
   disconnect remains future work.
6. Before any availability claim, run the controlled-device pilot covering
   revocation, suppression, offline expiry, event replay and honest delivery
   states on a controlled device with the maintainer present (tracked under
   [#614](https://github.com/pboachie/zrotext/issues/614)).

## Guided local workflow

An explicit [narrow workflow grant setup candidate](guided-workflow-grants.md)
now authenticates the owner, stores only a metadata/status credential in the
customer OS secret store, and previews a private broker entry. It does not pair
a phone, grant content/send access or replace the simulator-first flow below.

The explicit `guided_workflow_setup.py verify` operation checks an already
reviewed metadata connector through its exact OS-custody launcher with the
official MCP Python client. It performs authenticated readiness and same-scope
context metadata without reinstalling, changing configuration or authenticating
an owner. See [connection verification and its limits](guided-workflow-grants.md#verify-the-installed-connection).

To try the complete bounded fixture journey without a client configuration,
build the SDK and run `python scripts/agent_setup.py journey` from the checkout
root. See [the synthetic quickstart](AGENT-QUICKSTART.md#launch) for prerequisites,
steps and limits. It invokes the source-controlled recipe/shared adapter,
verifies the pinned fixture reply, and removes its unique temporary checkpoint.
It accepts no server path, credential, endpoint or install options. Acceptance
is simulated; owner approval, radio submission and live reply-reader authority
remain unavailable. The existing `demo` operation below continues to mean only
the reviewed MCP readiness/preview exchange.

Commands below use `SERVER`, `EXPECTED_SHA256` and `CLIENT_CONFIG` for the reviewed
artifact path, reviewed fingerprint and explicit local client file. Quote paths.
Run from the checkout root. The selected configuration's parent directory must
already exist. Keep this checkout and built SDK in place: the installed launcher
references the setup script and server by absolute path.

Run the doctor before modifying configuration. In a POSIX shell:

```sh
python scripts/agent_setup.py doctor --server "$SERVER" --sha256 "$EXPECTED_SHA256" --client mcp-json
python scripts/agent_setup.py demo --server "$SERVER" --sha256 "$EXPECTED_SHA256"
python scripts/agent_setup.py install --server "$SERVER" --sha256 "$EXPECTED_SHA256" --client mcp-json --config "$CLIENT_CONFIG"
```

In PowerShell, explicitly set the reviewed paths and fingerprint. Replace both
placeholders below with the reviewed digest and selected existing client file.

```powershell
$Server = (Resolve-Path -LiteralPath 'sdk/mcp/server.mjs').Path
$ExpectedSha256 = 'REPLACE_WITH_REVIEWED_LOWERCASE_SHA256'
$ClientConfig = (Resolve-Path -LiteralPath 'REPLACE_WITH_SELECTED_CLIENT_CONFIG.json').Path
python scripts/agent_setup.py doctor --server "$Server" --sha256 "$ExpectedSha256" --client mcp-json
python scripts/agent_setup.py demo --server "$Server" --sha256 "$ExpectedSha256"
python scripts/agent_setup.py install --server "$Server" --sha256 "$ExpectedSha256" --client mcp-json --config "$ClientConfig"
```

Check each command's exit status before continuing (PowerShell:
`$LASTEXITCODE`). Success returns zero; setup refusals return 2 with a JSON `code`.
Do not overwrite an existing client file with a copied example.

The first exchange defaults to the shared synthetic envelope fixture. The demo
launches only the reviewed stdio artifact and exercises initialize, readiness and
SDK preview, without a phone, SIM, owner credential or AI provider. Every demo
result says `synthetic: true`, `liveAvailable: false`, and carrier delivery
unverified. Its measured elapsed time covers that subprocess exchange only; it is
not a clean-install-to-real-SMS measurement.

The installation command above only previews one new `zrotext-local-preview`
entry, its exact launcher command/arguments and a `reviewDigest`. It does not print
existing configuration, environment values or other servers' credentials. Review
the command and rerun with `--apply --review-digest` containing the displayed
digest. This explicitly confirms the concrete change; a different configuration
or plan requires another preview. There is no automatic apply or privilege change.
Reload the selected MCP client yourself after applying.

After inspecting the install preview in PowerShell, copy its `reviewDigest` and
apply that exact plan:

```powershell
$ReviewDigest = 'REPLACE_WITH_INSPECTED_INSTALL_REVIEW_DIGEST'
python scripts/agent_setup.py install --server "$Server" --sha256 "$ExpectedSha256" --client mcp-json --config "$ClientConfig" --apply --review-digest "$ReviewDigest"
```

The installed launcher rechecks the artifact fingerprint and Node version before
starting stdio. It supplies no tokens or secrets. Live gates cannot be enabled by
this setup command. Doctor reports unavailable pairing/policy/release, unknown
line health/Android permissions/SIM readiness and unknown installed client version;
those are actionable missing prerequisites, not healthy observations. Check the
existing [self-hosting guide](SELF-HOSTING.md) and Android permission/pairing UI
for a future controlled-device pilot; setup does not duplicate those flows.

## Resume and disconnect

Repeated install of the exact owned entry is unchanged. Unrelated servers and
all their JSON values are preserved; formatting is normalized only on a change.
An existing conflicting entry is refused. Invalid JSON, duplicate keys, oversized
files, symlinked target files and unsupported formats are refused without repair.
Configuration replacement is atomic, preserves POSIX file mode, and uses a private
temporary file in the selected client directory. On Windows the directory's ACL
controls replacement-file access; use a customer-private configuration directory.
This tool does not manage a secret store or copy tokens.

A configuration fingerprint check catches edits between preview and apply. A
per-target lock excludes concurrent tool instances; external editors do not honor
that lock, so close the client/editor while applying. An interrupted ordinary
write keeps the original and can be retried. A killed process can leave a lock:
confirm no setup process is running, then remove only that target's
`.zrotext-lock` file yourself before retrying; the tool never steals a lock.

Preview and confirm removal with the same reviewed artifact arguments:

```sh
python scripts/agent_setup.py disconnect --server "$SERVER" --sha256 "$EXPECTED_SHA256" --client mcp-json --config "$CLIENT_CONFIG"
```

Add `--apply --review-digest` with that removal preview's digest to remove only
the exact owned entry. Changed/foreign entries are refused. Restart the client
explicitly; removal does not stop an already-running child. `grantRevoked: false`
is deliberate: this local slice creates no grant and cannot revoke a future
remote grant. Never describe local configuration removal as server-side revocation.

In PowerShell, preview removal with the same original paths and fingerprint:

```powershell
python scripts/agent_setup.py disconnect --server "$Server" --sha256 "$ExpectedSha256" --client mcp-json --config "$ClientConfig"
```

Inspect that removal preview, then copy its new digest before applying:

```powershell
$RemovalReviewDigest = 'REPLACE_WITH_INSPECTED_REMOVAL_REVIEW_DIGEST'
python scripts/agent_setup.py disconnect --server "$Server" --sha256 "$ExpectedSha256" --client mcp-json --config "$ClientConfig" --apply --review-digest "$RemovalReviewDigest"
```

Do not reuse the install digest. Disconnect can remove the exact owned entry even
if the server artifact has disappeared, without launching it; the original server
path and fingerprint still identify the entry.

## Troubleshooting a refused local setup

These codes come from `scripts/agent_setup.py`. Resolve the prerequisite and rerun
the preview; refusal does not authorize overwriting a conflicting entry.

| JSON `code` | Next step |
| --- | --- |
| `invalid_artifact_digest` | Supply exactly 64 lowercase hexadecimal characters from the reviewed fingerprint. |
| `artifact_missing`, `artifact_changed` | Check the regular `.mjs` file and reviewed revision. Review a changed artifact before accepting a new fingerprint; hashing alone does not establish trust. |
| `node_missing`, `node_unavailable`, `node_unsupported` | Check `node --version` in this shell; use Node.js 22 or later on its PATH. |
| `invalid_config_path` | Select a nonsymlink file whose parent directory exists. |
| `invalid_config`, `duplicate_config_key`, `config_size_limit` | Review the selected UTF-8 JSON object and its `mcpServers` object through the client's normal configuration workflow. Remove duplicate keys; the tool refuses oversized files rather than truncating them. |
| `entry_conflict` | Inspect the existing entry locally. Use the original checkout, server path and fingerprint to preview disconnect; foreign or changed entries require manual review. |
| `review_required_or_configuration_changed`, `configuration_changed` | Close the client/editor, rerun the preview, inspect it and use its current digest. |
| `setup_busy` | Check for another setup process. Follow the lock recovery steps above only after confirming none is running. |
| `connector_demo_unavailable`, `unexpected_connector_response` | Check the reviewed server's [SDK build prerequisites](mcp-local-tools.md#run-from-source), then retry the synthetic demo. A failed demo does not diagnose phone or SIM readiness. |
| `local_io_failure` | Check local file/directory access, preserve the existing configuration and rerun the preview after resolving the I/O problem. |

Doctor's `artifactVerified: true` verifies the selected file fingerprint only.
`liveAvailable: false` and unknown phone/SIM observations are expected for this
local preview; repeated installation cannot turn them into live readiness.

The tested client runtimes, deployment modes, measured local path and the
remaining manual phone, SIM and permission steps are recorded in
[tested configurations](#tested-configurations-and-measured-setup-path) above;
the controlled-device pilot stays outstanding there.

Remaining #618 acceptance: authenticated short-lived pairing and least-privilege
grants/secret-store custody; authoritative server/version/gate/line/Android/SIM
checks; signed package provenance; grant revocation during disconnect; interrupted
pairing/resume; and clean-install-to-full-simulated-conversation measurement.
No physical-device, carrier or hosted service readiness has been verified.
