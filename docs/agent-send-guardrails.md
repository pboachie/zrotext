# Guarded agent send tools (simulator)

**Experimental, simulator only. Nothing here sends a real SMS.** The server in
[`sdk/mcp-send`](../sdk/mcp-send) gives an existing agent three local MCP tools:
`zrotext_text_send`, `zrotext_text_status` and `zrotext_text_readiness`. The
transport is a deterministic simulator. There is no hosted service, no general
`POST /v1/messages` route and no carrier path; real traffic stays behind the
existing [allowlisted synthetic pilot](SMS-COMPLIANCE.md) and release gates.
Acceptance means "the simulator admitted it", never submission or delivery.

This is a policy and guard layer in front of a transport. It complements, and
does not replace, the server-enforced scoped grants in
[agent authority](../protocol/v1/agent-authority.md) and the sealed workflow
tools in [local MCP tools](mcp-local-tools.md). It reuses none of their
credentials. Whether this server ships from this repository or a separate one is
an open maintainer decision; it is kept in its own directory so it can move.

## Set up in one snippet

Node.js 22 is the only requirement; no build step or package install.

```sh
node sdk/mcp-send/owner.mjs init "$HOME/.config/zrotext/send-policy.json" --agent my-agent --device my-device-1
```

Add this to an MCP client's server configuration (use absolute paths):

```json
{
  "mcpServers": {
    "zrotext-send-simulator": {
      "command": "node",
      "args": ["/absolute/path/to/zrotext/sdk/mcp-send/server.mjs"],
      "env": { "ZROTEXT_SEND_POLICY_FILE": "/absolute/path/to/send-policy.json" }
    }
  }
}
```

`ZROTEXT_SEND_LEDGER_FILE` (absolute path, optional) persists idempotency,
suppression and unknown-state memory across restarts. Without it, that memory
lives only for the process, so a restart forgets prior keys; set it. No
command-line argument is accepted, and none selects a device, credential or mode.

The owner approves a recipient in a terminal the agent cannot use. The command
asks for the number on a TTY and refuses piped input:

```sh
node sdk/mcp-send/owner.mjs approve "$HOME/.config/zrotext/send-policy.json"
```

Other owner commands: `revoke`, `suppress`, `unsuppress`, and
`resolve <ledger> <idempotency-key> sent|not_sent` for an unknown send after the
owner checked the phone. The grant lasts one hour by default and at most one day;
after it expires every send is refused and the owner re-runs `init`, which also
issues a new recipient salt and so clears all approvals. The client config
snippet is one block, but the policy file is a second, owner-only step.
This setup has not been tested in a named MCP client application.

## What each guard does

| Property | Behavior | Refusal code |
| --- | --- | --- |
| First send to a new recipient | Needs the owner's approval, held only in the owner-written policy file as a keyed digest. The tool returns the short recipient reference and sends nothing. | `owner_approval_required` |
| Idempotency | Every send needs a 16-64 character key. The same key and content returns the stored result without calling the transport; the same key with different content is refused. The record is written before the transport call. | `idempotency_key_required`, `idempotency_conflict` |
| Rate limits | Per agent: sends per minute, per day and new recipients per day, with owner-lowerable defaults (3, 20, 3) and hard ceilings. | `rate_limited` |
| Runaway loops | Repeated refusals in a minute open a circuit; the agent stops reaching other checks until the window passes. | `circuit_open` |
| Opt-out | A transport STOP signal and owner-recorded off-channel withdrawals block the recipient permanently for this guard, across new keys. Approval cannot override suppression, and no tool lifts it. See [SMS compliance](SMS-COMPLIANCE.md). | `recipient_suppressed` |
| Unknown | An ambiguous transport failure, malformed answer or crash records `unknown`. It is never retried, and no new send to that recipient is admitted until the owner resolves it. | `unknown_pending_review` |
| Credential scope | The policy's grant must be exactly `messages:send`, bound to one device and one agent, at most one day long. Any extra scope, other device, missing field or unknown key invalidates the whole policy. | `policy_invalid` |
| Fail closed | A missing, unreadable, group-writable, expired or malformed policy, an unreadable ledger or any internal error refuses the send. | `not_configured`, `policy_invalid`, `internal_error` |
| Redaction | Results and audit lines hold fixed codes and one-way references only; never numbers, bodies or keys. | - |

The policy is re-read on every send, so revocation, suppression and expiry apply
at once. The tool schemas forbid extra arguments, so the model cannot supply an
approval, device, scope or limit.

## Threat and failure discussion

### Prompt injection

Text from a web page, document or inbound SMS can instruct the model to send a
message, change the body, or message a different number. Authority never comes
from the model or from inbound content: the only way a recipient becomes sendable
is an edit to the owner's policy file through the owner CLI. An injected
request to an unapproved number returns `owner_approval_required` and sends
nothing, however it is phrased or retried. A reply saying "yes, approved" or
"START" is data. Residual risk: an injected agent can still send any text it
likes to an already approved recipient within the limits. Approve few recipients,
keep limits low, and treat body content as agent-controlled.

### Duplicate sends

Models and clients retry. Required idempotency keys plus a durable
reserve-then-send ledger mean a retry, a concurrent duplicate, or a restart
replays the stored outcome. A model that invents a new key for the same intent
defeats this; the per-recipient unknown block and rate limits bound the damage,
and the real design must also dedupe at the server. A deleted ledger file loses
this memory.

### Ambiguous outcomes

A timeout may follow a real submission. Treating it as failure invites a second
text. `unknown` is never retried automatically, by the same key or a new one,
and a process crash mid-send reloads as `unknown`. The owner resolves it after
checking the phone. The tool reports honest states: accepted by the simulator,
refused, unknown. It does not claim delivery.

### Runaway loops

An agent stuck in a loop can burn quota, annoy recipients or probe the guard.
Per-agent minute and day caps, a new-recipient cap and the refusal circuit bound
this. Limits are per process and per ledger; several server processes sharing one
ledger file are not coordinated and are unsupported.

### Credential scope

The grant is least privilege by construction: send only, one device, one agent,
at most a day. The server holds no owner, read, admin or ordinary API
credential and takes none from arguments. The credential here is a simulator
descriptor, not a bearer token for a real service; mapping it to the real
server-issued workflow grant is future work. The policy file is trusted: if the
agent can write it, run the owner CLI or read the owner's files, every guard is
void. Run the agent without access to the policy path and the terminal.

### Confused deputy

The server acts with the owner's grant on behalf of whoever can call the tool, so
a hostile prompt, document or other MCP server in the same client borrows that
authority. The guards limit what a borrowed call can do: approved recipients
only, bounded volume, and no approval path. They do not authenticate the
caller. Do not combine this server with tools that can read or edit the policy,
and do not expose it over a remote transport; remote use needs the audience
and consent controls described in [local MCP tools](mcp-local-tools.md).

### Privacy and logging

Policy and ledger hold keyed digests and truncated references, not numbers or
bodies. The audit stream on stderr carries event, state, code, time and 12-hex
references. Tests assert that canary numbers, bodies and keys appear in no output.
The simulator transport itself receives the plaintext request in memory; a real
transport would too, so keep transcripts and client logs private.

## Not covered

No real carrier, device or SIM behavior; no hosted or remote mode; no multi-process
coordination; no content moderation or consent verification for message
purpose (the owner remains responsible under [SMS compliance](SMS-COMPLIANCE.md));
no emergency messaging. Report suspected vulnerabilities as described in
[SECURITY.md](../SECURITY.md).

## Tests

`sdk/typescript/test/agent-send-guard.test.mjs` runs with `npm test` in
`sdk/typescript` and covers each guard above, including the injected-recipient,
duplicate, loop, scope, unknown, opt-out and redaction cases.
