# Managed original-grant current proof

Java, C# and Ruby `OriginalCurrentClient` connect the closed HTTPS transport to
the accepted original-reply checkpoint. A successful `current`/`CurrentAsync`
returns an immutable verified snapshot only after signed history and a local
clock floor have been durably committed. It is not perpetual permission, and
readers/effects still require their fresh before/after authority checks.

Construct the client with an independently configured `OriginalHttp` transport,
an explicitly created or reopened `OriginalReplyCheckpoint`, the independent
root pin and compared fingerprint, selected original-reply scope, and trusted
local time. Supply the original-grant credential and trusted clock on each call.
The client serializes its operations and refuses a stale checkpoint revision
before dispatch. It does not accept an arbitrary result or fetch callback as
authenticated service authority.

The proof must contain exactly the reviewed scope identifiers, reader ID,
generation, authority revision 1, expiry/observed times, current version/digest,
and a contiguous chain of 1–32 signed manifests beginning at the saved latest
version. Every manifest signature, canonical encoding, enrolled root, account,
generation and predecessor identity is reverified. Total accepted history stays
bounded to 64. Duplicate proof/chain names are refused, including before Java's
JSON tree conversion could collapse them.

This integration follows the maintained TypeScript original-reply client:
authenticated server `accepted_at_ms` rows may be up to 30 seconds ahead of the
sampled local clock. Each manifest is verified at that row's time, while the
current manifest is independently reverified at the final local time. These
server timestamps do **not** advance the durable local comparison floor and need
not match a previous local sample. A private profile02/generation-one adapter
implements this distinction. Generic manifest continuation, profile03 and root
transition APIs retain their existing comparison guards. This is a bounded
maintained-client compatibility rule, not a blanket timestamp permission.

The proof's observed time must stay within 30 seconds of every local freshness
sample and its expiry must remain in the future. Revision CAS, the trusted clock
callback and final signature checks run under checkpoint ownership before its
flushed append. A newer postcommit local sample is persisted through another
fenced acceptance before returning authority. Failure after entering persistence
poisons that client instance: reopen the checkpoint and construct a new client
to inspect what committed. It never silently retries the HTTP request or resets
accepted history. The checkpoint's trusted-path, torn-append and whole-file
rollback limitations still apply.

Run `original-current-run.py --language java|csharp|ruby --fixture FIXTURE
--producer PRODUCER`. The runner requires exact clean fixture commit
`50c7258eb7e616ba8f0574d167bff7b999a9bd8d` and the fixture requires maintained
producer `72124e1a3ff28e782f870eeddbdc33cacf8ca3b4` with its TypeScript build.
The same 47 signed local TLS/checkpoint cases exercise each language, including
the exact 30-second boundary, over-boundary refusal, scoped identity, tampering,
forks, missing fields, local rollback, locked and postcommit expiry, competing
writers, stale-instance refusal, reopen and retained floor. Two additional
controls duplicate otherwise valid proof/chain fields and require refusal.
Every driver also attempts reentry from its clock callback and requires refusal
without an extra request; Java explicitly excludes its lock's reentrant case.

These are synthetic native tests. Read/page/consume/status proof integration,
output Propose credentials, automatic reply execution, installed package
qualification, live service acceptance and registry publication are separate.
