# Proposed authenticated profile03 authority adapter

**Candidate contract and byte fixtures only; no production adapter is mounted.**
Tracked by [#1466](https://github.com/pboachie/zrotext/issues/1466) under
[#1054](https://github.com/pboachie/zrotext/issues/1054). This is a new integration
allocation; frozen NONLINE and line-activation branches are not adopted.
The existing [E500/bundle628 contract](payload-profile-election-03.md), envelope
profiles, signature domains and profile02 behavior remain unchanged.

## Authentication boundary

Canonical bytes identify records; their hash does not authenticate the source
of those records. `sealed_payload_election03::adapter_contract` is an unmounted
encoder. It does not reserve a generation, verify a registration, accept an
election, install a fence, or grant permission. Its synthetic receipt vector is
deliberately **not** a valid signed registration or historical acceptance.

An HTTP challenge/commit adapter must first use the existing authenticated owner
session and exact configured canonical HTTPS origin, including request-origin
and CSRF checks. Inside its transaction it independently locks and rechecks the
account, verified owner membership/user, exact session, enabled MFA and required
step-up, idle/expiry/revocation, current enrollment keys, full device lease,
site and deployment authority. A copied role, `FreshVerification` shortcut,
client digest, bearer token, or historical proof cannot replace those checks.
Sample `clock_timestamp()` again after acquisition and before commit/effect.

The small socket `DeviceSession` is insufficient: its account/device/connection
epoch omits site, instance, deployment epoch, negotiated line-activation version,
and current enrolled signing-key identity. Read the full authenticated records.
Lease expiry, role/MFA status, revocation and heartbeat timestamps are current
permission predicates; they are not made immutable by hashing them into identity.

## Exact canonical bytes

`L(label, payload)` is the existing ASCII label, one NUL, u32be byte length, and
exact payload. Fixed UUIDs are nonzero raw16; counters/timestamps are u64be in
`1..=i64::MAX`. All digests below are SHA256. Received bytes are never normalized.
Strings are exact UTF-8, each prefixed by its own u32be byte length; site/instance
must be 1..256 bytes with no Unicode control character. Unsupported existing
identifiers refuse; there is no trimming, case folding or Unicode normalization.

| E500 field | Exact hash input |
|---|---|
| `origin_sha256` | Configured canonical HTTPS origin bytes, exactly the existing origin serialization, without a trailing slash; request origin is independently compared |
| Owner session digest | `L("ZTSE/line/payload-profile/owner-session/v1", account16 || user16 || session16)` |
| Device session digest | `L("ZTSE/line/payload-profile/device-session/v1", account16 || device16 || len32(site) || site || len32(instance) || instance || connection_epoch64 || deployment_epoch64 || line_activation_version16 || enrollment_signing_key_id32)` |
| Old-binding proof digest | `L("ZTSE/line/payload-profile/old-binding/v1", 02 || 02 || binding16 || account16 || device16 || line16 || generation64 || activation_challenge16 || registration16 || registration_evidence_digest32 || owner_approval_digest32 || device_confirmation_digest32 || selected_reader_key_id32)` |

The two leading old-binding bytes mean envelope profile02 and actual activation
origin version2, respectively. First upgrade supports only genuine version2
sealed activation and a live version2 phone lease. Version1 history is refused,
never relabelled or retried through another protocol. A fresh reviewer therefore
needs real root/manifest02 and registered nonexportable reader bootstrap, genuine
v2 line activation, then a root-authorized same-root 02-to03 election. A new03
genesis, software key, second root or synthetic bootstrap is not substituted.

`device_keys.fingerprint` is SHA256 of raw enrolled SEC1 bytes. It is **not**
`enrollment_signing_key_id`: independently check that stored fingerprint and the
current valid P-256 point agree, then derive the exact existing
`sealed_manifest::key_id(4, point)` used by the E500 verifier. Reader key identity
is independently derived from the registered reader and verified manifest role;
it cannot be copied from the device enrollment fingerprint either.

Registration evidence digest is:

```
SHA256(L("ZTSE/line/payload-profile/registration-evidence/v1",
  len32(transcript) || exact_transcript || root_signature_raw64 ||
  approval_signature_raw64 || approval_point_sec1_65 || approval_fingerprint32 ||
  paired_fingerprint32 || issued_ms64 || expires_ms64 || completed_ms64))
```

These are the immutable `sealed_line_key_receipts` columns. Before using their
digest, independently verify the existing RootLineRegister framing, both exact
canonical received signatures, point/fingerprint/account/device/line/generation
bindings and authenticated acceptance. Require a live, activated, unretired
receipt assigned to the exact consumed v2 activation challenge. Reconstruct and
verify stored v2 observation/device proof and owner approval, then match the
binding's immutable approval/confirmation digests. The hash encoder by itself
does none of that verification. Do not renew historical proof expiry to verify
its original acceptance; present permission is a separate locked read. In
particular, "live receipt" means currently activated/unretired and still bound
to the selected line/key, not an unexpired original registration challenge.

The canonical fixture pins bytes and digests independently of Rust. It is not
the signed/encrypted integration corpus and cannot qualify a service or device.

## Persistent binding identity and generation

Existing `device_line_bindings` has no binding UUID. An additive, insert-once
mapping must assign a CSPRNG UUID to an exact existing
`(account,line,device,generation)` only after the evidence checks above. A unique
tuple constraint returns that same UUID on authorized retry; a unique binding-ID
constraint prevents aliasing. Never cast a tuple, use the line/challenge UUID as
an implicit binding UUID, or generate a new identity on every read. The mapping
and its exact original evidence digest remain immutable historical records.
Any absent/incomplete/conflicting evidence refuses without an invented mapping.
An existing mapping with different evidence is a conflict, never an upsert that
overwrites its UUID or original proof digest.

Challenge issuance reserves a distinct new binding UUID, challenge UUID, nonce,
exact successor manifest identity and exact generation. Under the line lock use
`last_issued_generation + 1` with checked signed-storage bounds, not
`current_binding_generation + 1`. Persist the reservation and advance only the
issued high-water mark atomically; current binding/profile/authority stays02.
Abandoned/expired reservations remain burned. Retrying the same authenticated
opening and exact request returns its original challenge/reservation without
extending expiry; changed content conflicts. Distinct stale openings cannot
supersede a concurrently outstanding election or existing activation exchange.

The new binding UUID is absent from E500: return it only from the independently
authenticated durable accepted record that links the exact challenge, core,
received proof bundle, reserved generation and UUID. It cannot be supplied by
an untrusted receipt or inferred from a valid historical signature. Final
acceptance atomically archives the exact original02 checkpoint, creates the new
immutable binding/election, advances current line and same-root manifest
selection, consumes the exact challenge and invalidates old readiness/fetch.
Any exception/refusal rolls back every final-transition write; the earlier
issued reservation remains burned. Exact replay returns only the original
historical result; it never renews permission or creates another effect.

## Candidate exclusion; not elected for production

Global relation locks are not the default: they create unrelated-tenant
availability risk and can cycle with unchanged writers that already hold tuples.
Evaluate a per-account transaction-level advisory resource instead:

```
key = signed_i64be(first8(SHA256(
  L("ZTSE/line/payload-profile/account-fence/v1", account_uuid_raw16))))
```

A collision can cause contention/refusal only. All row account identities,
cryptographic contexts and predicates still compare full UUIDs. A lock is never
permission, proof of a qualified writer, or a replacement for currentness.

The candidate requires mandatory, schema-verified BEFORE INSERT/UPDATE/DELETE
guards on the complete reviewed writer graph. A writer obtains
`pg_try_advisory_xact_lock_shared(key)` before its relevant mutation or refuses
immediately. Upgrade obtains `pg_try_advisory_xact_lock(key)` before authority
and account rows; use NOWAIT for every subsequently required tuple lock. Thus
an unchanged READ COMMITTED writer actually participates through its guard.
No waiting lock upgrade or retry loop is allowed inside the transaction.
[PostgreSQL documents the try functions](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS)
as immediate acquisition or refusal, with transaction-end release.

Advisory acquisition does not refresh a transaction snapshot. After its shared
try-lock, every writer must lock a mandatory **pre-existing stable account
anchor** with `FOR SHARE NOWAIT` before reading selection. A transition must
actually advance that anchor's monotonic selection epoch in the same transaction
as its new current-selection record; locking an unchanged account row is not
enough. Under REPEATABLE READ or SERIALIZABLE, locking a newer anchor tuple must
produce serialization refusal, never authorize from the old snapshot. An absent
or snapshot-invisible anchor refuses before mutation; it never means default02.
Preserve the writer's isolation level. Retry only as a new authenticated,
idempotent transaction with bounded policy, never inside the failed transaction.

The production schema must enforce anchor/selection epoch coupling, backfill an
anchor for every existing account before enabling guards, and couple new-account
creation to its insert-once anchor. Define retained minimal deleted-account
anchors and immutable account identity so cascades/authorized erasure can still
resolve their fence without resurrecting permission or reusing an old identity.
This retention/erasure design and per-operation guards require separate review;
the synthetic fixture is not its implementation. New03 permission additionally
requires the actual live account and all locked authorization records.

Every trusted relation in a new guard/helper must be explicitly schema-qualified.
Putting `pg_catalog` first while omitting `pg_temp` does not prevent temporary
relations from shadowing unqualified names. The ordinary-role fixture deliberately
tests a temp-capable role as a stronger lookup negative, while stock runtime
provisioning also denies TEMP. Row locking requires UPDATE privilege on at least
one anchor column; the fixture grants only its guarded immutable identity column
for this purpose, not epoch mutation. Real runtime DML rights still require the
reviewed structural and immutable-state guards; fixture privileges do not
substitute for them.

After the account fence, proposed row order is existing authority, account,
owner/user/membership/session/MFA, line/current binding/challenge, then ordered
device/key/site/session/deployment records. Sets use exact stable ordering;
multi-account operations try every required account fence in UUID order before
mutating any account. Existing helper lock order must be reviewed individually;
calling it from this adapter does not make it compatible. Check time and all
live predicates again after locks and before final commit.

Two adversarial cases must be executed: (a) legacy writer already holds a shared
fence, so upgrade refuses before mutation; (b) writer holds an ordinary tuple
before reaching its guard, so upgrade refuses its NOWAIT tuple lock, or finishes
without touching that tuple and the writer then observes03 and refuses its
unsupported write. Neither side waits on the other. Whole-transaction refusal
must roll back earlier changes and preserve UNKNOWN/reconciliation evidence.

SQL enforces serialization and closed structural/provenance/current-selection
constraints. It does **not** verify P-256 or attest Rust's identity. Every03
admission/grant/fetch reader must independently verify exact stored signed
manifest/election/envelope bytes plus present authorization before disclosure or
effect. Forged but structurally plausible hashes must fail those actual readers.
No caller GUC, temporary table, application boolean, or advisory lock ownership
bypasses a guard. This preserves the existing trusted application/runtime SQL
boundary; it does not claim safety from arbitrary malicious runtime credentials.

Content/state rules must distinguish effect creation from invalidation:

| Operation | Required profile03 behavior |
|---|---|
| Enqueue/upload/grant/fetch/effect authority | Exact03 bytes and durable selected-election provenance, or refusal before mutation/effect; legacy02 framing cannot be relabelled |
| Manifest/root/line generation changes | Exact supported same-root transition and immutable selection consistency; unsupported replacement/new generation refuses |
| Device/account disable, key/session revocation | Remains available, fenced and immediately invalidates current permission |
| Heartbeat/lease expiry/reconnect | Remains available; changed epochs/site/deployment/version/key make old permission unusable |
| Retention/authorized erasure/FK cascades | Preserve original evidence/tombstone and UNKNOWN semantics; no cancellation or invented no-submit closure to pass quiescence |

## Required inventory and acceptance before mounting

`profile03-writer-inventory-candidate.json` pins the numbered migration111
catalog:186 public relations, each with an extraction class and explicit
operation policy. Migrations108/109 provide mandatory writer participation and
original activation retention;110 adds the narrow first-election ledger and
positive-epoch policy;111 retains separate same-phone physical approval and
installation without changing that epoch or permitting message effects.
Its fixture runs the actual migrator in a unique database
and compares column shape, FK edges and trigger definitions. Separate closed
validators pin bodies, declarations, rules, inheritance, RLS and privileges.
These structural checks do not replace cryptographic authentication or current
permission. See `docs/profile03-atomic-election-storage.md` for the bounded
initial selection and `docs/profile03-selection-refresh-storage.md` for the
separate physical selection and production-adapter obligations.

| Extraction class | Required treatment before installation |
|---|---|
| 136 ordinary required `account_id` columns | Fence exact OLD/NEW account sets; compare full UUIDs, independently classify every operation, and preserve invalidation/erasure |
| Lifecycle-only account anchor | Migration100 provides immutable identity and create/delete epoch guards, narrow privileges and retained tombstones; it is not an ordinary writer guard or an accepted profile selection |
| Nullable `billing_events` / `billing_risk_events` | Unbound audit state never supplies authority; account assignment must fence the resolved account before downstream effects |
| Nullable `device_sessions` / `dispatch_fences` | Reconcile exact enrolled device/message account; absent/mismatched account cannot become03 lease/grant authority |
| `accounts` | Fence immutable identity, account-create anchor coupling and disable/delete/erasure lifecycle |
| `users` | Stable complete membership account set for mutations affecting owner/MFA/session liveness; no silent skipped account |
| Four parent account mirrors | Migration101 backfills required immutable `account_id` on `password_reset_mail_outbox`, `verification_mail_outbox`, `sealed_event_delivery_attempts`, and `webhook_attempts`; qualified triggers populate unchanged INSERT callers and composite FKs preserve parent/account consistency. Mail cascades remain cascades and attempt parent deletion remains restrictive. OLD account identity survives parent erasure; full profile writer/state policy qualification is still required |
| Global billing audit/configuration/budget | Separate audit-only rows from current billing permissions and atomic global exposure accounting; a global lock is not an account fence |
| Global auth budget | Preserve existing abuse policy; counters do not confer owner/session permission |
| Review realm marker and broker | OOB owner-managed configuration and credential identity; never ordinary owner authority. Configuration revision prevents digest ABA revival; runtime has no table/column writes |
| Review broker sessions | Closed broker-only permission, current credential revision and original expiry; never an ordinary owner session |
| Review bootstrap attempts | Reserved is private prospective identity only, with NULL bound parents; provisioned requires the real live account anchor and exact bound account/user/member association. No generic missing-anchor exception |
| Review workspaces | Exact account/user/member identity and account anchor, erased with real parents; neither broker membership nor an ordinary login permission |
| Review browser preparations | Account-free continuity/closed operation state and exact generation; never derive an account or permission from this class |
| Review typed owner sessions | Exact current account anchor, workspace, broker session/event/credential, browser generation and configuration; no ordinary `SessionPrincipal` conversion |
| Review authentications | Broker-only branch has explicitly NULL account/user/owner-session fields; account-bound branch requires the actual account anchor and composite typed-session parent |
| Review root reauthentication | Account-bound exact typed session, original challenge/transcript and one-use state; no generic MFA fallback |
| Review private locator | Selection-only account-bound association until actual erasure, without session/result lifetime extension; configuration/key rotation may make a retained selector unusable |

| Deployment/site/failover authority | Independently recheck exact current global fence records under the established lock order; never treat them as account identity |
| Global key integrity | Preserve KEK commitment validation and qualified historical data handling |
| `schema_migrations` | Migrator-only ledger; runtime has no mutation privileges, and unreviewed graph/version changes cannot silently join03 support |

The structural inventory's source owners span `sealed_root_ceremony`,
`sealed_root_custody`, `sealed_manifest_store`, `sealed_inbound/line_activation`,
`http_owner_conversations/sealed_line_setup` and `send/queue`, `device_socket`,
`sealed_outbound`, `sealed_dispatch`, `workflow_runtime`, `agent_authority`,
`provider_sms`, `delivery-store`, `retention`, `maintenance`, and account
erasure/export. New source changes must identify exact hunks and maintain the
existing NONLINE and v2 branch boundaries. Catalog completeness alone does not
prove those paths use a qualified03 reader or correct per-operation policy.

The writer graph must include root custody/ceremony and manifest publication,
owner/agent/workflow admission, confirmed queue and retries, inbound reservations,
ordinary dispatch/grants/fetch, status/receipt/late callback and reconciliation,
binding/registration/activation, revocation, retention, export and erasure. Trace
database trigger and FK cascades, child rows lacking account columns, bulk and
multi-account updates; a text search of obvious sealed modules is insufficient.
Account extraction must be lossless even during parent erasure; no missing
parent lookup, trigger depth or untrusted attribute silently bypasses fencing.

Before selecting03, verify a finite catalog/privilege inventory against the
actual numbered migrator schema: exact writer relations, FK graph, mandatory
enabled triggers/function bodies, account extraction and state policies. Unknown
relations, changed dependencies, missing/disabled guards or an unreviewed schema
version refuse03 without weakening02 behavior. Runtime cannot own/alter the
guards or tables, disable triggers, TRUNCATE, set replication bypass, or create
objects in the trusted schema. Inventory evolution is a separate reviewed source
change, not automatic discovery that silently authorizes a new writer.

First upgrade supports one active sealed line and conservatively zero outstanding
or historically unqualified grants/attempts/effects/UNKNOWN liabilities, active
conversation/workflow authority, inbound reservations and concurrent exchanges.
Do not delete or translate work to satisfy this predicate. Existing02 payload
history must have qualified historical read/export/erasure behavior or make the
upgrade unsupported. Unlocked counts never substitute for the reviewed fence.

Admission must use the existing authenticated abuse budget, one outstanding
election per account, bounded challenge lifetime and request/crypto sizes, a
finite lock set, no wait/retry loop, and the established transaction deadline.
Test unrelated-account progress, held-tuple conflicts, duplicate/racing opens,
expiry/rollback, FK/cascade/multi-account failure, collision-only refusal and
ordinary-role direct legacy DML/privilege abuse. A fixture of the proposed
primitive does not prove this entire inventory participates in production.

Remaining #1054 gates are actual authenticated durable challenge/commit/current
read, SDK admission with an explicit authenticated segment ceiling and exact
ciphertext persistence, negotiated current grant/signed fetch, real Android
authority/journal reservation and maintained nonexportable receiver composition,
cross-profile negatives and integrated no-radio acceptance. A fresh same-cert
signed artifact and controlled device acceptance remain separate from source and
CI. No live configuration, deployment, radio or release action follows here.

Repeatable clean-phone onboarding after first03 acceptance is a further explicit
dependency in [#1469](https://github.com/pboachie/zrotext/issues/1469): it requires
a separately reviewed03-to03 current-reader replacement/recovery operation and
same-root manifest successor. Password login or one phone's acceptance does not
qualify a different reviewer's nonexportable key or current line. This first
upgrade contract cannot supply that operation by widening E500 or resetting
authority.


### Retained same-root03 successor storage

The112 candidate storage retains exact signed successor ancestry after the
original election. Browser role5 enrollment, same-point signed key-window
renewal and explicit current-line browser replacement share one narrow receipt
factory. Receipt, authority tip, accepted history, purpose-separated unique
signing-point claim and actual stable-anchor tuple version commit together.
Original historical bytes and current content contexts never translate.

A full-prefix commitment binds original root-signature bytes, possession
signatures and actual acceptance checkpoints for independently verified cache
provenance. It is no authentication or effect witness. Complete ancestry
verification, bounded transport pages and local highwater, current owner/phone
adapters and content/effect paths remain separate integration work. See
[manifest successor storage](../../docs/profile03-manifest-successors.md).
# Original content consent storage

Migration113 retains additive ZTCA03 consent reservations, exact owner/phone
proofs, installed acknowledgement and separately attributed owner/device
withdrawal. Its six narrow methods and closed ordinary-runtime capability
checks are storage primitives. Genuine authentication, fresh owner request
step-up, original signatures, local private custody and current physical/source
selection remain independent adapter obligations. An interval phase does not
authorize a reviewed send, grant, fetch or radio effect. Those typed paths remain
separate; no legacy conversation02 permission is inferred or translated.
