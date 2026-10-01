# Authenticated quorum observation transport v1

The optional server adapter in `crates/server/src/failover_adapters.rs` accepts
explicit observation input from a pinned HTTPS probe authority and exchanges
member reports over authenticated HTTPS. Quorum is still disabled by default.
No address, deployment identity, key or operational report belongs in the public
repository. External watchdog fencing and epoch authority are separate adapters;
a network failure never proves an external fence or stopped PostgreSQL host.

## Configuration and transport

Only when `FAILOVER_QUORUM_ENABLED=true`, an optional nonempty
`FAILOVER_QUORUM_ADAPTER_CONFIG` names a private JSON file. With it absent or
empty, the reporter retains its abstaining source and mounts no report route.
Invalid supplied configuration fails startup closed. The file is at most 16 KiB
and contains these fields (unknown fields are rejected):

| Field | Meaning |
| --- | --- |
| `namespace` | Stable quorum identity, 1–128 ASCII letters/digits/hyphen/underscore; binds every signature and replay checkpoint |
| `signing_key_file` | Private file containing exactly one 32-byte P-256 signing scalar, unique to this member |
| `serving_bearer_file` | Private file containing a dedicated 32–256 printable ASCII bearer credential, optional trailing newline |
| `probe` | Explicit observation-authority endpoint for this instance's configured member |
| `peers` | Exactly two different other configured members; never this instance |
| `ca_certificate_file` | Optional PEM CA certificate file for private TLS trust; default system trust otherwise |

Each endpoint has `member_id`, an absolute credential-free HTTPS `url` (no
query/fragment), `public_key_base64` containing the pinned SEC1 P-256 public
point, and `bearer_file` for a separate outbound bearer credential. Members are
bounded file-safe identities. Probe signing identity is independent of the
local and both peer report signing identities; reuse of any quorum member's
key as the probe authority is rejected. This prevents one member credential from
signing its own vote and supplying facts that induce another member's local
vote. Distinct keys do not independently prove operational failure-domain
separation; the configured probe authorities remain explicit operator trust.
Pins are configuration authority, never learned from a remote response. Secret files/configuration are provisioned by
private operations and mounted read-only; Compose forwards only the private
configuration-file path, not its contents. Each replica owns its store and
replay directory; never share that directory between processes.

`GET /internal/failover/report` exists only with the adapter. It requires its
dedicated serving bearer, returns the latest local signed report, and refuses
missing/stale reports. Owner/API/device credentials confer no access. The
ordinary server listener may be behind the existing TLS terminator; expose this
route only over validated HTTPS to configured members. Restrict ingress in
private operations. The client validates certificates and hostnames, adds only
an explicitly configured CA, disables redirects and ambient proxies, and never
uses a certificate-validation bypass. HTTP is rejected at configuration time.

Each reporting round sequentially fetches the two peers and its own explicit
probe input. There is at most one request in flight, no retry queue, and no
more than three requests per round. Each complete response, including body,
is bounded by the configured `FAILOVER_QUORUM_PROBE_TIMEOUT_MS` (1–5000 ms).
The round therefore has a transport ceiling of three such deadlines plus local
bounded journal/checkpoint work. Request failures, HTTP authentication errors,
TLS failures, timeouts, malformed/oversized bodies and exhausted sequences
contribute no observation. Missing peer reports only reduce quorum; a failed
probe input yields a full abstention, never an unreachable vote.

## Signed wire format

A JSON object has precisely `namespace`, `purpose`, `journal`, `signature`.
The entire response is at most 4096 bytes, including chunked bodies. Purpose
is `probe` for explicit input or `report` for member exchange; the domains are
not interchangeable. `journal` is the canonical `JournalRecord::encode` text
from `crates/failover-quorum/src/store.rs`, including member identity, positive
sequence, original observation timestamp, writer state and optional evidence.
Re-encoding after strict decode must match the exact signed string. Signature
is standard Base64 of a 64-byte raw P-256 ECDSA signature over:

```
ASCII("ZT/quorum-report/v1") || 0x00 ||
u32be(namespace_utf8_length) || namespace_utf8 ||
u32be(purpose_utf8_length) || purpose_utf8 ||
u32be(journal_utf8_length) || journal_utf8
```

The wire namespace is the lowercase SHA-256 digest of the following topology
transcript: `ASCII("ZT/quorum-topology/v1") || 0x00`, followed by each UTF-8
value with its u32be byte-length prefix, in order: the configured namespace,
configured writer site, standby site and the three member IDs sorted in ASCII
order. All values are bounded to 128 bytes. Changing topology or deployment
identity therefore invalidates old signed reports and replay checkpoints;
it cannot silently reuse another site's fence attestation.

The configured pinned key authenticates this complete transcript. Member
identity must match the endpoint's configured member; namespace/purpose must
match this deployment and port. Epoch/evidence bounds use the existing journal
codec and member observer. An explicit signed `writer=unreachable` is accepted
only as a probe authority's attestation; failed HTTPS does not produce it.
Absent fence, stop or readiness evidence remains absent. A reachable writer
never carries a simultaneous stop confirmation through the observer.

## Freshness, replay and restart

Original observation time is preserved through local publication; receiving a
probe does not refresh its timestamp. Evidence is accepted only when
`observed_at <= trusted_now` and `trusted_now - observed_at <= 10000 ms`, the
same freshness window as the decision model. Future timestamps and regressing
per-member observation time abstain. Source sequence must increase strictly;
gaps are accepted after missed rounds, duplicates and reordered older sequences
are rejected. Sequence identity is per member and per purpose.

Authenticated replay high-water checkpoints are written and synced, atomically
replaced, before consensus append. A crash in between may lose a vote but cannot
count that report twice. A checkpoint write failure poisons its receiver until
restart; corrupt, cross-namespace/purpose/member or wrong-key checkpoints fail
startup. There is one bounded checkpoint per member/purpose plus a transient
replacement file. The existing consensus journal retains its compaction bound
and serves each durable report in at most one executor round, so repeated pulls
of a cached report cannot manufacture hysteresis checks. Source/member signing
keys and checkpoints must survive process restarts; deleting/restoring replay
state is not an authorized recovery procedure. Storage rollback and deployment
recovery require the external authority/recovery gates, not a silent reset.

No transport result changes writer authority directly. The existing independent
quorum, hysteresis, veto, fence/stop/readiness and dispatch-paused rules still
control decisions. Fencing/promotion, operator activation and real deployment
policies remain separate, and are not authorized by this transport contract.

Synthetic Rust conformance tests generate signatures and TLS certificates in
memory and cover pins/domain isolation, canonical bytes, delayed/future/replayed
reports, restart, corrupted/exhausted storage, adjacent member sequences,
distinct hysteresis, bearer failures, validated/untrusted TLS, body bounds,
missing/dead input and absent external-fence evidence. No real infrastructure
or operational report is captured.
