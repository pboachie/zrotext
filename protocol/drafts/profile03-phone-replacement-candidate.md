# Proposed existing-profile03 phone replacement

**Contract proposal only. No replacement service, wire format or capability is
installed.** Tracked in [#1469](https://github.com/pboachie/zrotext/issues/1469)
under [#1054](https://github.com/pboachie/zrotext/issues/1054). The
[authority adapter proposal](https://github.com/pboachie/zrotext/pull/1470)
and its durable account-anchor and writer-fence foundation are separate work.
This document neither implements nor reallocates that foundation.

The operation replaces one selected endpoint with one newly enrolled endpoint
under the **same account, root, root generation and archive identity**. It permits
a distinct new logical line for the new phone's selected SIM. There is at most
one selected active endpoint and one outstanding replacement for the account;
the new endpoint remains pending until the atomic transfer. This does not prove
an unchanged sender number, SIM ownership or carrier service. A same-line transfer
additionally needs a qualified continuity policy; it cannot be inferred from a
matching account or reused line identifier.

Reachable-phone transfer and unavailable-phone recovery are distinct operations
within this proposed contract. Unavailable-phone recovery and renewal after a
prior manifest expires are required for repeated clean-phone access without
depending on the previous phone or an external maintainer. They retain the
existing root and all authorization gates. A successful first-phone setup or
password login does not establish this outcome.

## Preserved contracts and unelected encoding

The [E500/bundle628 election](payload-profile-election-03.md) remains exactly
operation01, profile02 to profile03, with every existing byte, domain, signature,
negative control and replay rule unchanged. It is not widened to accept this
operation. Envelope profile03, line-activation protocol2 and grant3 remain distinct
namespaces. No provider, profile, activation-version or recovery-mode fallback is
permitted after refusal.

The replacement needs a separate, closed, explicitly versioned signed operation
and accepted-record type. **Its wire bytes, signature domains, native kind number,
route spelling and migration number are unelected.** The field and proof
obligations below are semantic requirements for that later review, not a binary
codec or permission to ship a generic signing interface. The existing
[After03 manifest contract](zt-sealed-draft-03-manifest-candidate.md) supplies the
root-signed same-root successor relation; it does not supply phone replacement.

## Existing paths and the bootstrap cycle

Existing custody recovery, same-owner HTTPS browser context and public-proposal
exchange are reusable prerequisites. There is no existing transaction that can
be composed unchanged into this operation:

- [Initial sealed-line registration](../../crates/server/src/http_owner_conversations/sealed_line_setup/registration.rs)
  requires authority version0 with no manifest and refuses an already activated
  sealed binding. Its approval-key replacement covers an unactivated registration
  for the same owner, device and line, not an existing03 phone transfer.
- [Browser signer enrollment](../../crates/server/src/sealed_manifest_store/outbound/enrollment.rs)
  adds one role5 record while preserving every original record. It cannot replace
  the role1 phone reader or atomically select another binding.
- [Initial manifest installation](../../crates/server/src/http_owner_conversations/genesis.rs)
  handles version0 or exact version1 replay. Root enrollment also rejects existing
  enrollment history. Neither is a way to reset an existing03 account.
- [Android reader enrollment](../../android/app/src/main/java/org/zrotext/gateway/ConversationAndroidEnrollment.kt)
  requires an authenticated device and an already current, activated local line
  binding. The replacement's new reader must be known before its successor and
  binding become current. Calling this entry early would invent current authority;
  making the binding current first would split the transfer across transactions.
- [Android After03 verification](../../android/app/src/main/java/org/zrotext/gateway/Draft03ManifestAuthority.kt)
  authenticates an exact same-root successor. It does not persist server selection,
  establish a device lease or perform durable Android installation. The current
  native typed signer has no phone-replacement operation.

The minimum missing bridge is a **pending enrollment capability** with no current
content or dispatch permission, followed by one atomic server transfer and a
separate durable phone installation acknowledgment. Reuse proof codecs and custody
primitives only after reviewing their lock order and scope. Do not compose helpers
that commit early or relax their initial-only checks.

## Authentication and retained provenance

Every owner request uses the existing live verified owner membership, exact owner
session, canonical HTTPS origin and CSRF checks. Challenge issuance and final
commit independently lock and recheck owner/user/session/MFA, expiry, revocation
and idle limits. Final positive approval consumes a fresh MFA factor in the same
transaction as the transfer. An account password, phone device bearer, imported
file, copied digest or advisory lock is not owner or root authority.

The owner must possess the same existing root through legitimate independent
recovery. Reuse the retained encrypted root backup, public card, separately held
recovery token and independently expected account/origin/fingerprint. Native
recovery and per-operation approval remain fresh and explicit; no root scalar or
root recovery token enters the browser or service. Root recovery is not the login
password. Archive recovery has its own encrypted kit and recovery material.

The clean phone also needs an authenticated retained checkpoint and exact signed
history from the qualified authority adapter. This includes the original accepted02
evidence and the accepted02-to03 and subsequent03 chain as applicable. Preserve
original signed bytes, semantic identities, acceptance times, root/anchor identity
and monotonic high-water state. Empty local storage, a directory response or a
downloaded proposal cannot manufacture the checkpoint or restart the chain.

An expired prior03 manifest may prove **history** at its authenticated accepted
checkpoint. It cannot supply current signer, reader, session or grant permission.
The new root-signed03 successor must be fresh, preserve the same root/account/root
generation, have exact versionN+1 and predecessor digest, and pass current owner,
root-revocation, new-device and transaction checks. Do not extend historical
expiry, lower a clock high-water, recreate02 or use a second genesis. An
unsupported chain, revoked root or missing recovery evidence refuses.

## Replacement selection and proofs

Opening fixes an immutable mode:

| Mode | Required distinction |
| --- | --- |
| Reachable transfer | Current authenticated new-device proof and fresh owner/MFA/root approval, plus an exact old-device release proof bound to this transfer |
| Unavailable-phone recovery | Explicit existing-root recovery and fresh owner/MFA/new-device proof; no old-device signature is fabricated or required from an unavailable device |

Both modes retain the same quiescence, history and effect-reconciliation rules.
Failure in reachable mode cannot automatically select recovery mode. Any different
opening must first reconcile the original operation under its cancellation and
idempotency rules; it gains no permission from the refusal.

The later canonical operation must commit to all of these independently obtained
facts, without relying on caller-provided expected values as authority:

- Operation version/mode, account, canonical origin, existing root identity and
  generation; exact old selected binding UUID, device, line, generation, reader,
  accepted transition evidence and expected account selection epoch.
- Exact current03 manifest version, semantic digest and retained signed-evidence
  digest; fresh successor03 version/digest and exact signed bytes.
- Request/challenge identity, CSPRNG nonce, original issue/expiry, reserved new
  binding UUID and generation, explicit new device/line, enrolled signing-key
  identity, new recipient public point/key ID and new approval-key identity.
- Exact genuine protocol2 selected-SIM registration, observation, device proof,
  owner approval and installation provenance required by the qualified adapter.
  Old profile02 binding encoders cannot be relabeled as03 evidence.
- Independently reconstructed owner and new-device session identities, complete
  lease/site/instance/connection/deployment fences and negotiated versions. Use
  the reviewed shared serializers where applicable, not hashes of partial socket
  records. Reachable mode additionally binds the old device's current release
  context; recovery uses an explicit absent-old-proof branch, not zero dummy IDs.

The new device's enrolled signing identity authenticates its selected recipient,
reservation and transfer context. An owner approval key proves possession under
fresh owner/MFA authorization. The existing root signs the03 successor and a
separately reviewed replacement approval binding that successor to the exact
transfer. Reachable mode also requires its old-device release proof. Exact
signature ordering, transcript framing and domains remain contract-review work.
No received signature is normalized or translated from another operation.

The native UI needs a new typed operation with authenticated expected context
from the exact proposal registry and current same-owner session/time. It must
display both endpoints, mode, recipient and successor before explicit consent,
recover the root afresh and recheck context after signing. Existing GENESIS,
activation or role5 operations must not sign an opaque replacement payload.

## State and transaction boundaries

### Reserve without transferring authority

An authenticated opening names the expected current03 selection, exact request
identity, mode and new endpoint. Under the qualified exclusive account fence and
stable anchor, validate the supported account and effect state. Reserve the
challenge, binding UUID and new line's checked `last_issued_generation + 1`.
Do not derive it from the current generation. Expired or abandoned reservations
stay burned. Existing current binding, manifest and permission do not advance.

At opening and final commit, the same fence must also exclude every live
authority, line-activation or election exchange that could change either endpoint
or the selected manifest. An existing conflicting exchange refuses replacement;
no priority, automatic cancellation or overwrite is inferred. One outstanding
replacement alone is not a complete exchange-exclusion policy.

An exact authorized retry returns its original reservation and expiry. Different
content conflicts. Bound request size, cryptographic work, challenge lifetime and
outstanding count. No transaction waits or loops to acquire a wider permission.

### Enroll the pending hardware recipient

The authenticated new device receives a bounded pending capability tied to this
account/device/line/reservation/generation, enrollment key, session and expiry.
It permits an explicit enrollment action only. The existing Keystore creation
primitive may create or reuse the one local pending recipient under that scope;
it never exports a scalar or regenerates a receive key after loss or refusal.

Persist local pending identity and return only the public point/key ID and the
authenticated new-device proof. Validate genuine current protocol2 selected-SIM
evidence within the qualified replacement workflow. Existing initial activation
must not publish the new binding early. The pending capability supplies no
Ready3, grant, signed fetch, content consent or current manifest authority.

### Commit the transfer once

Use the qualified account fence and mandatory stable-anchor/selection coupling
from the separate foundation. The reviewed row order is authority, account,
owner/user/membership/session/MFA, line/current selection/challenge, then ordered
device/key/site/lease/deployment records. Multi-record sets use stable ordering;
every later required tuple lock uses NOWAIT. There is no waiting lock upgrade or
retry inside the transaction. Recheck database time and every live predicate
after acquisition and before commit.

Final commit independently reconstructs and verifies exact retained provenance,
new-device/SIM evidence, all signatures, successor and currentness. In one
transaction it must:

1. Preserve the old exact manifest, binding, selected-reader and transition proof
   as historical records, without deleting attempts, grants or replay fences.
2. Persist the immutable accepted replacement and exact received proofs, new03
   binding and fresh root-signed03 successor.
3. Advance the single current endpoint and linked monotonic selection epoch
   together; retire the old endpoint's future permission and invalidate its
   readiness/fetch selections.
4. Consume the original challenge and fresh factor once and return the original
   accepted identity. Any refusal or exception rolls back every final-transition
   write; earlier issuance reservations remain burned.

Qualified current admission/grant/fetch readers must verify a closed accepted
provenance choice: first02-to03 acceptance or this03 replacement. Neither a
profile enum, raw manifest signature, structurally plausible hash, runtime GUC
nor caller assertion can synthesize the accepted replacement. New relations and
operations must join the complete reviewed writer/catalog/privilege inventory;
this draft does not qualify that inventory or alter existing migrations.

### Install and acknowledge before new grants

After commit the old endpoint cannot obtain new permission. The new endpoint is
selected but not dispatch-ready until its exact local installation is durable.
Android verifies the authenticated accepted record and retained chain/checkpoint,
compares the existing pending recipient, and installs the exact local binding and
authority through a reviewed crash-safe transaction. It never recreates a missing
key to make the receipt pass.

A device-signed installation acknowledgment commits to the accepted replacement,
binding, manifest identity and current lease/session. Only after independent
server verification may the normal current Ready3/grant3/signed-fetch3 path run.
That path retains authority checks and journal reservation before maintained
receiver use; replacement itself authorizes no SMS.

Loss or uncertainty after commit remains installation-pending or UNKNOWN. An
authenticated read/status operation returns the original historical result for
reconciliation; it does not renew expiry, repeat a factor, allocate another
generation or restore the old endpoint. Status and cancellation are separate
from positive approval. After commit, cancellation is not rollback.

## Effects, archive access and repeated use

The first supported replacement keeps the existing archive identity and requires
qualified historical02/03 read/export behavior. Retained archive recovery may
allow historical archive decryption under its existing independent authorization.
It does not recover the old phone's non-exportable key or promise that a new phone
can decrypt device-only historical ciphertext. Missing root/archive recovery or
unsupported history produces an explicit refusal, not an operator bypass.

Under all-writer exclusion, require no outstanding or historically unqualified
grants, attempts, submissions, retained effect fences, UNKNOWN liabilities,
inbound reservations or active execution authority needing reconciliation.
An expired lease or delivered label is not proof of no effect. Unavailable-phone
recovery cannot force-close an old unknown submission. Do not delete, translate,
relabel or invent a no-submit result to qualify a replacement. Retain authorized
invalidation, revocation, history, retention and erasure semantics.

An old offline phone must lose future server permission at commit without
cooperating in local cleanup. Historical verification never supplies new effect
authority. Reconnecting, changing the deployment epoch, replacing an approval key
or presenting an old install acknowledgment cannot reselect it.

Repeated access requires a real owner-controlled reusable MFA and existing-root
recovery journey, separate archive recovery where needed, and each new phone's
own keys and consent. Provisioning the first phone, finite one-use recovery codes
or requiring an external signer to return later does not demonstrate unattended
repeatability. This contract adds no key-sharing or credential-disclosure route.

## Required adversarial acceptance

These are implementation requirements, not executed results:

- Enroll two independently clean supported Android devices under one existing
  account/root. Start from genuinely accepted02-to03 history; transfer to the
  new phone using actual owner/browser/native steps and non-exportable recipient.
  Execute both reachable transfer and unavailable-old-phone recovery, or identify
  the latter as an unresolved blocker for unattended repeated access.
- Repeat replacement under the same root with the next03 successor. Exercise
  an expired prior03 as authenticated history and a clean phone without local
  high-water state. Reject rollback, same-version fork, missing accepted evidence,
  second genesis,02 rewind and root replacement.
- Run the actual production composer, authenticated admission, exact persisted
  ciphertext, current grant/signed fetch, durable Android journal and unchanged
  maintained receiver after installation. Account for exact source/artifact
  identities, positive plaintext hash/length, all cases and skips, and prove zero
  radio/provider calls. Separate component corpora do not establish this path.
- Prove new grants/fetch fail on the old phone immediately after commit, and on
  the new phone before durable installation acknowledgment. Preserve qualified
  historical read/export without reviving current old-reader permission.
- Reject wrong root/account/endpoint/line/reader/registration/session/epoch/mode,
  stale or revoked authority, noncanonical signatures, cross-operation proofs,
  malformed framing, altered successor and expired post-lock approvals before
  their applicable effect fence. Lost/substituted recipient keys never trigger
  software-key or profile fallback.
- Exercise racing openings/commits, exact replay versus conflicting proof bytes,
  factor replay, selection changes, stale transaction snapshots, mandatory writer
  participation, FK/cascade and erasure effects, privilege misuse and unrelated
  account progress. Verify complete rollback and burned issuance generations.
- Inject process/power failure around reservation, recipient creation, final
  commit, local authority/journal installation and acknowledgment. Reconcile the
  exact original receipt without duplicate grants, rewind, resend or fence loss.
- Exercise retained02/03 history, unresolved effects, multiple active endpoints,
  missing archive/root material and different selected-SIM mappings. Unsupported
  cases refuse explicitly. Existing02 bytes, E500 and provider controls remain.

Contract review, durable adapter delivery, exact-head hosted CI, signed artifacts,
two-phone no-radio execution, controlled physical/carrier behavior and reusable
store-review access remain separate gates. This proposal completes none of them.
