# Candidate native HPKE recipient

Implements RFC9180 base-mode DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM for opening one 32-byte CEK at sequence zero. Public and encapsulated
keys must be canonical 65-byte uncompressed valid P-256 points. The declared
recipient public point must exactly match the supplied private scalar. Info and
AAD are opaque exact bytes, each bounded to 36KiB; the ciphertext must be 48 bytes.
The recipient primitive supplies no sender, key derivation, PSK/auth mode, sequence advancement or exporter API. Separate candidate protected composition below uses fresh ephemeral sender keys. Never reuse this primitive as a streaming HPKE context.

`open_software_cek` / `OpenSoftwareCEK` explicitly accepts software, exportable
private material. Caller-owned keys are never consumed or claimed protected.
Rust uses zeroizing derived-key/output buffers; Go clears visible derived
buffers, but provider copies and caller buffers have no erasure guarantee.
Callers must clear returned CEKs after body decryption.

`open_protected_cek` / `OpenProtectedCEK` returns protected-provider-unavailable.
It never imports a scalar or silently falls back. This package does not supply a
provider through that generic entry point. The concrete Windows provider and local journal APIs described below are separate. Neither supplies live device authority.

Use only after independently verifying the envelope signature and canonical
transcript, historical provenance, current manifest authority, recipient scope
and replay state. Those layers are not implemented by this primitive. A valid
HPKE tag is not authorization. Unsupported provider paths remain unavailable.

Rust requires 1.97.1 and the same RustCrypto dependency versions used in this
repository; Go requires 1.26 for the maintained SQLite journal dependency, while cryptography continues to use its standard library. Both
interop executables read ephemeral JSON vectors on stdin from the independently
implemented TypeScript `@hpke/core` producer in issue1144. They check all six
profile02/profile03 role vectors and context/key/point/tag/length corruption.
No private scalar or CEK fixture is committed. This is candidate component
interop, not full sealed-reader, registry, production or protected custody
acceptance. See issue1128 for the remaining native protocol layers.

Reference: https://www.rfc-editor.org/rfc/rfc9180.html sections4-5 and7.

## Envelope integrity

`VerifyEnvelope` (Go) / `envelope::verify_envelope` (Rust) validate profile 02 outbound/inbound and profile 03 outbound, including canonical layout, signed-storage integers, recipient ordering and P-256 points, signer key-ID binding, and domain-separated low-S ECDSA. Owned tokens produce exact body/wrap transcripts and unsigned-content digests.

This is signature integrity, not authority: correct verified manifests, current signer/recipient authorization, replay state and protected custody remain caller requirements. Profile 01 and profile 03 inbound are refused. No full reader is claimed. The pinned public exporter supplies six recipient rows; native tests cover exact transcripts, every single-byte mutation, truncation, trailing data and input aliasing.

## Manifest provenance

Root enrollment requires the separately compared fingerprint of a generation-one root pin. The native manifest verifier validates profile 02 genesis and exact successors, profile 03 upgrades from a still-fresh verified 02 predecessor, and profile 03 successors. Re-verifying the same semantic unsigned identity accepts an independently valid alternate signature; forks, gaps, downgrades and comparison-clock regression refuse. Tokens own signed bytes and root identity, and validate native points, key IDs, role/subject/scope rules, owner/archive counts, low-S signatures and signed validity windows.

Initial enrollment supports generation one with the zero genesis anchor. Later profile02 generations require the dual-signed transition and independently compared new root described below; profile03 transitions remain refused. Manifest tokens prove signed provenance, not external current authority. The separate journal, reader and custody modules supply their documented candidate capabilities.

Run the `manifest` executable with `protocol/v1/vectors/sealed-profile03-contract-01.json` on stdin. Both native lanes exercise public signed genesis/successor/current fixtures and all single-byte mutations, root corruption, forks, gaps, downgrade, comparison rollback, wrong expected profile, and truncation/trailing data. No new private fixture material is introduced.

## Candidate archive reader

The software archive reader now joins verified same-generation profile02 manifest history, current archive-key permission, canonical inbound envelope signature verification, HPKE CEK recovery and strict AES256GCM UTF-8 body opening. Caller routing (account/device/line/peer), reader key ID, trusted time and independently selected current manifest are mandatory. Historical manifest membership is checked against the exact verified current chain, bounded to1024 versions. A valid current successor retaining the reader can open old ciphertext; a successor rotating away that reader refuses.

Only inbound profile02 with exactly one archive wrap is supported here. The generic protected entry point remains refusal-only; Windows callers use the qualified hardware adapter described below. Software scalars never silently satisfy protected custody. This reader returns text, never a radio grant, live audience permission, durable replay receipt or SMS authorization. Root transitions, profile03 elections/receiver integration and other platform providers remain separate work.

CI pipes the pinned maintained TypeScript producer directly through a synthetic successor-control adapter into both native readers. The adapter uses only the producer's publicly known synthetic signer and fresh replacement archive keys; no real credentials are read. Tests cover actual cross-client plaintext, signed current-key rotation, routing/time/profile/private-key failures and every single-byte corruption. Test outputs remain transient; no fixture scalar is archived. Rust's base64 dev dependency decodes the independent JSON producer format only.

## Windows protected recipient

The native Windows adapter now opens and creates P-256 keys in Microsoft Platform Crypto Provider. Qualification requires the hardware provider flag, export policy zero, private export refusal, exact ECDH P-256 public blob and a native ECDH comparison against an independent ephemeral software peer. A provider label or unsupported private-blob response alone does not qualify a key. No private recipient scalar is imported or exported, and no software fallback or provisioning is attempted. This is local platform evidence, not remote attestation.

Creation requires a trusted callback to durably record the fresh exact alias before the key is created. Keep that receipt private and retain it if any cleanup fails. Reopening requires the independently expected public point. Deletion targets only the owned handle, never a namespace enumeration. Close releases handles without deleting a persistent key. Unsupported platforms keep the refusal-only entry points; Windows callers explicitly use the qualified hardware adapter and hardware archive reader.

`run-cng.py` builds native examples and verifies the pinned public-point-only TS producer. It exercises fresh creation, native archive opening, persistent reopen, binding/closed-handle refusal and exact owned-key deletion. Windows CI without a suitable provider reports **not qualified**, rather than claiming protected acceptance; any failure after creation is a test failure. Private pending receipts remain outside the source tree and are never uploaded. Getrandom is used by Rust for fresh aliases and the qualification peer. Temporary buffers are wiped where owned; provider/runtime copies are not guaranteed erased.

## Accepted profile03 election and opening

The election verifier requires independently authenticated exact expected core, accepted record and registry signing points. It verifies the original signed profile02 predecessor, exact successor profile03 evidence hashes, commitment and bundle hashes, device and owner low-S signatures, and account/root/device/line/reader identity. Application records use closed binary/numeric field maps; all numeric values are positive signed-storage integers. The returned proof owns the accepted snapshot. `newBindingId` comes from the independently authenticated accepted record and is compared to current authority; it is not invented from the signed core.

Current verification requires the exact accepted election on the selected manifest lineage, current binding generation, selected reader, root identity, commitment/bundle hashes and permission deadline. The outbound03 reader additionally binds the independent expected message and peer, current signer/recipient permissions at observed and comparison time, manifest and permission deadlines, HPKE wrap transcript and AES-GCM body authentication before strict text decoding.

Software entry points explicitly accept exportable scalars. Windows hardware entry points accept only the existing qualified native recipient. The conditional native acceptance runner exercises actual profile03 ciphertext through independently qualified Windows custody; software fixture checks remain separate. No live audience grant, backend/MFA authority, durable replay receipt, remote attestation or radio permission is supplied.

The pinned maintained TypeScript election producer feeds fresh synthetic ciphertext directly to native examples. Controls cover closed records, binary/numeric identity changes, signatures after independently recomputing the accepted bundle hash, comparison/deadline failures, exact peer/message, actual plaintext and every single-byte envelope mutation. No private fixture is committed. Local durable CAS election persistence is described below; live authority and replay remain separate.

`run-cng.py --profile 3 --producer <pinned-checkout> --language rust|go` selects the reviewed election producer revision and refuses a fixture exporting the selected reader scalar. Both examples open the actual maintained TypeScript ciphertext through a freshly created and reopened native PCP key, refuse wrong peer/valid wrong public point/closed handles, then delete only that owned key and reject reopening it. The receipt is flushed before creation and stays private if cleanup fails. Profile02 remains the default runner mode. Hosted capability absence is explicitly unqualified, never a software fallback or hardware acceptance. These custody tests do not establish remote attestation, live authority or durable election selection.

## Local durable signed checkpoints

`Journal` stores bounded signed manifest ancestry and one accepted generation-one profile03 election in SQLite. `AppendManifest`/`append_manifest` and `AppendElection`/`append_election` require the expected revision; a competing writer gets a conflict. The election manifest and exact signed bundle, accepted record and signer expectations commit in one immediate transaction. WAL with synchronous FULL gives local transactional durability. At most 1024 manifest revisions are accepted. Same-version refresh is not a new journal revision.

Opening always requires an independently enrolled root pin and fingerprint. Every snapshot or append after election requires independently authenticated core, accepted record, device point and owner point; these are compared with persisted bytes and native signatures and ancestry are reverified. Restore never promotes stored data into an authority source. The caller must still supply fresh authenticated current authority to the elected reader. Comparison time may not precede the latest stored manifest checkpoint; read-only snapshots do not persist a high-water clock.

Keep the database in a private, trusted local directory with a filesystem that supports SQLite locking and durable writes. Unknown schema versions, existing empty files, extra schema objects, root substitution, missing evidence and signature corruption refuse; there is no automatic migration, repair or root reset. File identity is checked while an instance is open. This is not rollback-resistant storage, an anti-replay ledger, protection against a malicious local account, or live backend permission. A new journal file cannot detect deletion or substitution of a previous whole journal without an external checkpoint.

The executable `journal` example consumes the pinned maintained TypeScript election fixture through stdin. It verifies actual ciphertext after closing/reopening, races two processes against the same revision, exits a child with an uncommitted transaction and verifies rollback, and checks independent evidence, clocks, corruption and schema refusals. Fixtures contain only disposable synthetic keys and are never committed.

Dependency rationale: Rust uses MIT `rusqlite =0.40.2` with bundled SQLite for portable native transactional locking, plus MIT/Unlicense `same-file =1.0.6` for native file identity; its locked SQLite engine is 3.53.2. Go uses BSD-3-Clause `modernc.org/sqlite v1.60.1` for maintained CGo-free SQLite, with the upstream-required `modernc.org/libc v1.77.1`; its engine is 3.53.4. Upstream third-party notices apply, including public-domain SQLite. Rust remains 1.97.1; this native candidate Go module now requires 1.26, independently of generated HTTP SDK Go requirements. Candidate checks do not establish registry publication or an advisory-free release.

Sources: [rusqlite package](https://docs.rs/crate/rusqlite/0.40.2), [modernc changes](https://gitlab.com/cznic/sqlite/-/raw/v1.60.1/CHANGELOG.md), [modernc security policy](https://gitlab.com/cznic/sqlite/-/raw/v1.60.1/SECURITY.md), [SQLite 3.53.4 release fixes](https://www.sqlite.org/releaselog/3_53_4.html). The Rust bundled engine predates those later SQLite fixes; it must not be represented as the same engine revision as the Go lane.

## Protected profile03 outbound composition

Windows `HardwareSigner` qualifies the PCP hardware provider, export policy zero, private-export refusal, exact P-256 public blob and an independently verified native ECDSA signature. Durable private pending-alias receipts must succeed before creation. Opened handles cannot delete a persisted signing key through `DeleteCreated`/`delete_created`; that operation belongs only to the instance that created the exact key. Closing releases handles without deleting persisted state. There is no scalar import, software signing fallback, arbitrary digest signing or remote-attestation claim.

The candidate composer requires a verified manifest/election, a qualified signer, exact independently selected message/peer and a callback returning fresh authenticated current authority plus comparison time. It checks signer/recipient roles, active windows, selected device/line/key, permission deadlines, strict text and canonical recipient ordering. Fresh CSPRNG content keys, nonces and P-256 ephemeral sender keys produce native RFC9180 wraps and AES-256-GCM body ciphertext. The native low-S signature is verified before returning ciphertext, with authority checked again after composition. `ComposeProtected03`/`compose_protected03` is a fresh-ciphertext API; retryable applications must use the journal below.

`OutboundJournal` is a separate bounded SQLite store containing exact ciphertext and a hash of the complete immutable request intent. Initialize it before concurrent callers. It binds independently enrolled root identity, caps records at 256, and commits under an immediate transaction before exposing any ciphertext. Every replay re-verifies signature/prefix/recipient identity and current authority. Changed intent for the same account/message/device/line returns conflict. Comparison time cannot decrease below the durable journal-wide high-water mark; the floor advances with insert/replay and in a guarded transaction after the postcommit authority check. If authority or storage fails after commit, the outcome is uncertain: retry only the exact original intent; do not create fresh ciphertext or reset the journal. Whole-file rollback/deletion remains detectable only with external trusted state, not this local store.

The native acceptance examples exercise actual protected signing, reopened and closed handles, wrong public-point binding, exact owned deletion, input refusals, exact restart replay, concurrent first composition in two processes, postcommit authority-loss withholding and exact recovery, and restart clock rollback. The pinned maintained TypeScript consumer independently verifies the native signature and decrypts both recipient wraps. Hosted provider absence stays explicitly unqualified. These are synthetic component tests, not live dispatch, audience grants, production key enrollment or release acceptance.

Outbound03 composition and elected opening require every selected signer and recipient to cover the complete half-open message lifetime: key activation at or before observation, and message expiry at or before key expiry. Current authorization, trusted-clock monotonicity and permission deadlines also apply. Manifest issuance is checked independently with its allowed clock skew; it need not precede observation. The reviewed cross-language policy is tracked in [issue1226](https://github.com/pboachie/zrotext/issues/1226). This alignment does not change profile02 or inbound historical rules.


## Authenticated profile02 root succession

`VerifyRootTransition02` / `verify_root_transition02` requires a verified old profile02 manifest and an independently compared new public root. It checks both low-S P-256 signatures, exact account, consecutive generations, old root and latest old semantic manifest digest, distinct new root and bounded validity/comparison time. The resulting trust accepts only a version-one profile02 genesis whose predecessor is the exact unsigned transition digest; later manifests retain that generation and authenticated ancestry.

`OpenJournalWithTransitions` / `Journal::open_with_transitions` takes an owned map of independently compared new roots keyed by the journal revision that will contain the new genesis. Every stored transition needs the corresponding approval on restore; do not populate that map from persisted or received transition bytes. `AppendTransition02` / `append_transition02` commits the transition and new genesis together under expected-revision CAS, preserving old signed history and the checkpoint comparison floor. Restores reverify the complete chain, both signatures and every root comparison before exposing the current manifest. The archive reader can use that restored manifest and its authenticated same-generation successors. Historical reads across a root boundary and profile03 root transitions remain explicitly unsupported.

Checkpoint schema version 2 adds transition evidence. Version 1 files are refused without alteration: there is no automatic migration or re-enrollment. Preserve existing journals and arrange explicit reviewed migration before adopting this candidate version. The separately versioned outbound journal is unchanged. Root transition does not replace independent current routing/authority, external rollback detection, or key custody qualification.

The executable `root` acceptance consumes fresh synthetic transition/new-root ciphertext checked by the maintained TypeScript verifier/composer, plus the existing public rotation vector. It covers every transition-byte corruption, valid high-S twins, wrong roots/history/time, interrupted uncommitted writes, competing processes, missing/substituted approvals, durable restore, same-generation successors and actual archive decryption. `root-controls.mjs` accepts a reviewed TypeScript checkout; the CI producer is pinned to the same exact archive revision as the other archive-reader checks. Generated private keys are never committed; fixed public synthetic fixture inputs remain test-only.


## Protected profile02 candidate composition and replay

`ComposeProtected02` / `compose_protected02` uses the same qualified Windows PCP signer through an explicit profile02 signing entry point. Verified manifest keys supply recipient public points and active role/scope/device/line checks at a caller-supplied candidate comparison time. Native wraps use the profile02 info and empty wrap AAD; body encryption and signatures use the explicit v2 domains. No profile negotiation or live transport authority is inferred.

Fresh composition follows the maintained profile02 candidate grammar, including zero message IDs and observed time zero with a strictly greater expiry. It does not assert that such a candidate is currently deliverable. `ComposeOrReplay02` / `compose_or_replay02` additionally requires positive observed time at or before comparison and an unexpired original intent. Journal calls additionally require an independently selected current verified manifest and comparison callback at entry, replay and after commit. Current selection must retain the original manifest in the same-root/generation ancestry and reauthorize the signer and recipient key roles, scopes, device and line at the new comparison time; revocation withholds even already committed bytes. It uses the existing private SQLite journal core, immutable identity/intent binding, monotonic durable comparison floor, pre-exposure commit and final comparison check. After an uncertain result, retry only the original inputs. Comparison failure or expiry withholds committed bytes; it is never an instruction to reset the journal or generate a new message.

The verified manifest retains its original enrolled root through authenticated profile02 transitions. The outbound journal binds that original trust while the complete intent binds the current root/generation/manifest. Thus supported rotated-root candidates retain exact retry behavior without re-enrollment. A matching account or unverified current root alone cannot establish that provenance. Profile03 still requires its separate authenticated election/current-authority contract.

`run-compose02.py` pins the reviewed TypeScript producer/consumer and checks native protected signing, both recipient decryptions, fresh zero-value boundary cases, process CAS, postcommit comparison failure/recovery, persistent clock rollback refusal, and rotated-root replay after reopen. The rotated consumer uses the maintained manifest/transition verifier and HPKE/WebCrypto APIs to independently verify and decrypt that ciphertext. Shared profile03 native acceptance is rerun when the private composition/journal core changes. Candidate archive checks and conditional hosted provider tests do not establish release or live dispatch readiness.


## Selected original role3 replies

The original-reply selection verifier checks both phone approval and installation signatures and returns owned opaque provenance for an independently chosen role3 grant scope. The selected reader requires accepted activation/history ancestry, the exact signed wrap set and freshly authenticated current authority before decryption and again before releasing plaintext. Exportable-scalar and qualified Windows PCP APIs remain explicit; no protected fallback occurs.

This local reader does not implement HTTP read/current/consume/status or persist grant high-water/history. Its callback must come from a trusted independently authenticated grant integration. See `sdk/native/hpke-candidate/ORIGINAL-REPLY.md` in the source repository for the acceptance command and remaining integration boundaries. Existing archive-only readers do not gain role3 authority.

Original-reply accepted history and comparison clocks can be persisted with the experimental [scope-bound checkpoint](../ORIGINAL-CHECKPOINT.md). Independent enrollment, current grant authority and explicit durable acceptance remain required.

[Original-grant HTTPS transport](../ORIGINAL-HTTP.md) returns untrusted wire JSON; authenticated client integration remains required.

[Verified original current proof](../ORIGINAL-CURRENT.md) binds HTTPS scope and signed history before durable CAS advancement.

[Verified original HTTPS read](../ORIGINAL-READ.md) authenticates selection and ciphertext, then persists fresh current authority before releasing plaintext.

[Authenticated original pages](../ORIGINAL-PAGE.md) return bounded discovery metadata with exact cursor correlation after durable current-proof verification.

[Saved owner-review consumption/status](../ORIGINAL-CONSUMPTION.md) correlates caller-persisted descriptor-null intent with fresh proofs and preserves unknown outcomes without retry.

Typed saved original-reply proposal consumption/status is documented in [ORIGINAL-PROPOSAL.md](../ORIGINAL-PROPOSAL.md). This does not approve or send an action.

Local template content and preview APIs are documented in [TEMPLATE-CONTENT.md](../TEMPLATE-CONTENT.md); encryption and persistence remain separate.

[Candidate encrypted templates](../TEMPLATE-CRYPTO.md) add authenticated ZTWT01 sealing and software/protected opening with explicit current-authority callbacks. Storage and owner transport remain separate.

[Current owner-template loading](../OWNER-TEMPLATE.md) returns bounded opaque snapshots under independent owner/session authority. Save request/receipt helpers do not submit effects.
