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

## Guided local workflow

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

Remaining #618 acceptance: authenticated short-lived pairing and least-privilege
grants/secret-store custody; authoritative server/version/gate/line/Android/SIM
checks; signed package provenance; grant revocation during disconnect; interrupted
pairing/resume; and clean-install-to-full-simulated-conversation measurement.
No physical-device, carrier or hosted service readiness has been verified.
