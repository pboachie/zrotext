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
SDK. That dependency remains a separate draft; this installer does not download,
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
Run the doctor before modifying configuration:

```sh
python scripts/agent_setup.py doctor --server "$SERVER" --sha256 "$EXPECTED_SHA256" --client mcp-json
python scripts/agent_setup.py demo --server "$SERVER" --sha256 "$EXPECTED_SHA256"
python scripts/agent_setup.py install --server "$SERVER" --sha256 "$EXPECTED_SHA256" --client mcp-json --config "$CLIENT_CONFIG"
```

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

Remaining #618 acceptance: authenticated short-lived pairing and least-privilege
grants/secret-store custody; authoritative server/version/gate/line/Android/SIM
checks; signed package provenance; grant revocation during disconnect; interrupted
pairing/resume; and clean-install-to-full-simulated-conversation measurement.
No physical-device, carrier or hosted service readiness has been verified.
