# Proposed immutable payload-profile election03

**Proposed contract; no production profile 03 implementation or capability is available.**
This contract/vector slice is tracked in [#1055](https://github.com/pboachie/zrotext/issues/1055).
The actual SDK → server → current grant/signed fetch → durable Android journal → maintained
receiver integration remains open in [#1054](https://github.com/pboachie/zrotext/issues/1054).
Synthetic signatures, software HPKE component checks and byte vectors do not establish
current session authority, durable transactions, Android interoperability or release readiness.
Existing profile 02 bytes, APIs and tests stay unchanged. Never retry another profile or provider
after refusal. Envelope profiles, line-activation transcript versions and grant versions are separate.

All binary integers are unsigned big-endian and bounded to signed-storage range where specified.
Identity UUIDs are nonzero raw16, except mandatory zero manifest role-subject slots.
`L(label, payload)` takes an ASCII label WITHOUT a NUL, appends exactly one NUL byte, then u32be payload length and exact payload. The label argument itself must contain no NUL.
Manifest, envelope and election object signatures are raw64 P-256/SHA256, strict scalar-range
and low-s checked before verification; received signatures are never normalized. **Fetch03 is
the explicit exception: its device proof is strict canonical DER, as specified in the dispatch contract.**


This is a distinct payload-profile election, not existing SIM/eSIM line activation protocol_version 1/2. Preserve selected SIM proof, key custody and all owner/session/MFA requirements. Initial supported operation is ONLY upgrade 02 to 03. Challenge issuing and final commitment need the original line owner; no current line transcript silently issues 03.

Canonical core E, fixed 500 bytes:

| Offset | Bytes | Field |
|---|---:|---|
| 0..5 | 5 | ASCII ZTPE then 03 |
| 5..6 | 1 | operation=01 (upgrade only) |
| 6..7 | 1 | old_envelope_profile=02 |
| 7..8 | 1 | new_envelope_profile=03 |
| 8..24 | 16 | account_id |
| 24..40 | 16 | device_id |
| 40..56 | 16 | line_id |
| 56..72 | 16 | challenge_id |
| 72..88 | 16 | old_binding_id |
| 88..96 | 8 | old_binding_generation |
| 96..104 | 8 | new_binding_generation |
| 104..136 | 32 | old_binding_proof_digest |
| 136..168 | 32 | root_fingerprint (RootPin02 algorithm) |
| 168..176 | 8 | vault_generation |
| 176..184 | 8 | prior_manifest_version N |
| 184..216 | 32 | prior_manifest02_semantic_digest |
| 216..224 | 8 | successor_manifest_version N+1 |
| 224..256 | 32 | successor_manifest03_semantic_digest |
| 256..288 | 32 | selected_payload_reader_key_id |
| 288..320 | 32 | device_enrollment_signing_key_id |
| 320..352 | 32 | owner_approval_key_id |
| 352..384 | 32 | challenge_nonce |
| 384..392 | 8 | issued_ms |
| 392..400 | 8 | expires_ms |
| 400..432 | 32 | origin_sha256 |
| 432..464 | 32 | authenticated_owner_session_binding_digest |
| 464..496 | 32 | authenticated_device_session_binding_digest |
| 496..500 | 4 | reserved=00000000, all other values refused |

Origin digest is SHA256 of the existing trusted canonical HTTPS origin serialization, not untrusted request text. Session binding digests are NOT new independently authoritative credentials: they are SHA256 over the existing canonical authenticated session identities/fences, fixed by the line/session owner's adapter and independently recomputed at verification. Before source phase 2 that owner MUST elect the exact existing serialization (see the deferred production adapters below); the contract vector uses explicit synthetic 32-byte values and cannot claim live-session validation. This clearly bounded adapter dependency is preferable to inventing a new owner/device session authorization protocol in this contract cut. The verifier requires exact challenge-persisted equality plus current live session/fence validation; no caller-provided digest authorizes itself.

The current immutable old binding id/generation/proof digest, payload key, current device signing key and owner approval key must come from independently authenticated locked records. New generation is strictly greater than old and equals the exact value reserved by the trusted challenge/line allocation adapter; do not assume old+1 when abandoned generation reservations exist. Manifest successor relation and root/account fields must match the accepted authority and exact supplied signed successor. Challenge nonce must be nonzero CSPRNG; issued/expiry interval 0<lifetime<=300,000ms; now must be inside it. All expected identity/digest fields compare exactly; zero dummy identities are not accepted in production.

Device signs `L("ZTSE/line/payload-profile/device/v1", E)` using the current registered device enrollment signing key. Owner approval key signs `L("ZTSE/line/payload-profile/owner/v1", E || SHA256(device_signature_raw64))`; the owner key's current owner/MFA/session authorization remains mandatory. The root signature on Manifest03 and owner approval signature on E are separate checks with different keys and domains. A role 06 root record does not authorize an owner HTTP session, and the owner approval key does not sign the manifest.

Bundle is exactly E[500] || device_signature[64] || owner_signature[64], total 628. Election semantic commitment is SHA256(`L("ZTSE/line/payload-profile/commitment/v1", E)`). Persist that commitment, each exact signature/proof digest, exact bundle digest, both manifest identities, root identity and old/new binding identities. Exact authorized replay of an already consumed challenge/bundle may return the ORIGINAL result without mutation or new permission; a different core OR different proof bundle for the consumed challenge conflicts. A timeout is not permission to allocate another generation or repeat a side effect. Do not normalize received signatures or replace evidence during replay. Expired or revoked sessions may not use replay to obtain a fresh grant or renew time.

## Transaction requirements; not implemented


Current root-custody/admission code locks existing manifest authority before account; line activation instead starts account/line locks. Never compose those helpers naÃ¯vely and invert this order. The proposed election adapter must explicitly adopt authority â†’ account â†’ authenticated owner/session/MFA records â†’ line/current binding/challenge â†’ relevant device/key/site/session/fence records, with a complete pairwise review against root ceremony/admission/dispatch and stable ordering for sets. This is a required owner integration review, not a claim that current helpers already implement this order. Existing bounded lock/statement timeouts and post-wait clock_timestamp freshness/live-role/session/device/site/deployment checks remain.

Challenge issuance is a separate authenticated transaction that reserves the exact immutable challenge fields/generation; it does not change current authority/profile/binding or cancel effects. Final election locks/rechecks all inputs and atomically: verifies the root-signed successor against exact current02 predecessor; verifies current owner/device proofs; proves supported-account/quiescence predicates; archives the original02 checkpoint and accepted historical metadata; writes the new immutable03 binding; advances authority profile/version/digest; advances line current generation; consumes the exact challenge; invalidates old readiness/fetch capability. Commit once. Any refusal, expiry after waiting, stale predecessor/binding/device/session, conflict, timeout, or exception rolls back ALL final-transition writes. No staged authority advance followed by a later binding transaction.

First upgrade supports exactly ONE active sealed line in the account and no unsupported profiles or simultaneous activation/exchange/election reservations beyond its own exact challenge. All account-level admissions, inbound writes, dispatch claims/grants/fetch/effects, manifest updates and line activation that could change this predicate must share a durable exclusion/fence with final election. An unlocked COUNT under READ COMMITTED is NOT a proof: authority/account/line row locks alone do not protect against uncoordinated phantom insertion. The storage owner must enumerate every writer and add the required common lock/guard; absent that review the transition stays unsupported.

Quiescence includes zero queued/claimed/submitting02 work AND no unresolved unknown/submitted/delivery_unknown attempt or delivery liability, no issued/unclosed grants, fetch claims, live/retained effect fences requiring reconciliation, active conversation/workflow execution authority, inbound upload reservations, delayed receipts or replay/reconciliation state that could still change effects. Expired leases and message labels are not proof of no submission. Existing fences, attempt history and late-reconciliation evidence are retained; nothing is deleted, force-cancelled, relabelled proved_no_submit, or translated to03 to make the check pass. The first cut conservatively refuses ANY old02 record with an issued grant/attempt/effect history whose closure/retention semantics have not been independently qualified; therefore accounts with such history may remain unsupported even when UI says delivered. Full outstanding-effect and multi-line migration is separately OPEN, not automatically solved by this design.

Historical02 read/export uses exact retained RootPin02 + signed Manifest02 + accepted profile/gen/version/digest/time checkpoint and original envelope/grant metadata. It does not call current03 lock_current/envelope_context or use03 key lists to authorize02. Historical expiry is assessed against authenticated historical acceptance/event checkpoints for verification only; a caller cannot pick an old time to obtain current effects. Current independent owner/export authorization is still required. Until that typed historical path is implemented, transition of an account with retained02 data must be unsupported, rather than promising readability or deleting data. Replay/tombstone uniqueness stays global per account/message/event across profiles, including after payload purge;03 cannot reuse an old02 identity to obtain another effect.


## Deferred production adapters

The existing line owner must define the old-binding proof digest and exact canonical owner/device
session identity/fence serialization, challenge/generation allocation, all-writer exclusion and
currentness adapter. Opaque synthetic session digests in the public vector prove only their bytes
are signed; they cannot authenticate sessions. No current line activation transcript or owner
boolean produces03. Full multi-line/outstanding-effect migration, historical02 read/export and
true03 new-account setup remain tracked dependencies; unsupported cases refuse before mutation.
