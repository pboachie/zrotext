# Root rotation and lost-material state contract

**PROPOSED, unavailable.** Issue #624 supplies an explicit Q3/Q10 product/security
choice and deterministic design drills for review. It does not approve a new
profile, implement a runtime ceremony, change login/MFA recovery or enable sealed
traffic. The accepted [decision log](zt-009-decision-log.md), existing
[RootTransition02 bytes](zt-sealed-draft-02-manifest-candidate.md),
[root-only backup](root-backup-01.md) and [offline owner CLI](../../docs/offline-owner-cli.md)
remain the underlying groundwork. Their cryptographic vectors are not evidence
of end-to-end recovery or custody (#623); unlock signing (#592) is not rotation
authority. No paid external review prerequisite is added.

## Proposed identity and history choices

| Case | Required authority | Account/root outcome | Historical ciphertext |
|---|---|---|---|
| Normal rotation | Current authenticated owner/MFA, independently selected new root, old and new root signatures over the existing transition, current nonforked manifest and fresh one-use ceremony | Same account; root generation increments exactly once; first manifest version one anchors the transition | Readable only with retained matching payload/archive private keys, independent of root signatures |
| Lost login, cryptographic material retained | Existing account-login recovery policy separately proves ownership; independent comparison restores the same pin | Same account and generation; login recovery cannot change trust, revive a session/grant or sign a transition | Matching retained keys still decrypt retained ciphertext; login credentials alone cannot |
| Root lost, valid root backup and recovery secret retained | Both backup AEAD tags, independently expected account/origin/full root fingerprint, fresh owner/MFA and current comparison | Restore possession of the same root; no generation reset; if this root is no longer current, treat it as historical only | Root-only backup contains no archive keys and recovers no message history |
| Payload/archive key lost, root retained | Current owner root may enroll a fresh role-specific key under current policy | Same account/root; revoke lost key and use a new key ID, subject and grant | Ciphertext whose only surviving wrap targets the lost key is irrecoverable; no automatic re-encryption |
| All root and recovery material lost (or no authenticated usable root backup) | No signature continuity exists; fresh independent enrollment and ordinary new-account ownership checks | **New account identity, generation one and new root. Old account is not reset or reused.** Every client/connector enrolls afresh; no inherited line permission or grants | No recovery of old ciphertext without separately retained matching decryption keys; loss is explicit |

The proposed lost-all choice rejects keeping the old account ID with a silently
replaced pin. Keeping administrative access to an old account permits its normal
export/erasure controls, not new sealed authority. An independently held historical
archive key may still open an exported old envelope locally under its old identity;
this never creates continuity or imports old authorization into the new account.
Line/device ownership must be established afresh through its normal proof flow;
new-account creation cannot bypass uniqueness, carrier proof or retention policy.
Linking old and new accounts for administrative purposes is a separate design.

Root compromise is not repaired by restoring the compromised backup. Halt new
sealed work, revoke affected sessions/readers where account controls permit,
and rotate only if current old-root authority is still trustworthy; otherwise
follow visibly new trust identity enrollment. Login/MFA factors are not root
recovery secrets. A human password is not accepted as the random kit secret.

## Ceremony/state authority

Use the existing signed RootTransition02 transcript without changing its byte
grammar: same account, exactly old generation plus one, old last semantic
manifest digest, old/new root points, current bounded validity window, and the
new manifest anchor. Verify both canonical signatures and independent new-root
selection before publishing. Existing same-position semantic-digest and exact
signed-byte fork rules still apply; a different signed manifest at an occupied
position is not a harmless refresh. Missing predecessor, expired manifest,
withheld updates or a manifest fork pause acceptance, not reset high-water state.

A future authenticated request adapter separately binds a one-use challenge,
session/MFA, operation, expected current generation/root/manifest, proposed exact
new manifest digest, backup custody digest/version and independently compared
pin. A ceremony expires after at most five minutes using trusted time; retain
the existing RootTransition02 window limit. The adapter must not claim these
additional fields are already part of RootTransition02. Symbolic design
transcripts below bind them solely for state-model testing, not as wire bytes.

The trusted record contains account, generation, current root, accepted semantic
manifest and exact signed bytes, high-water/fork marker, ceremony receipts and
revocation tombstones. Reader/device/connector identity includes role and subject;
key IDs cannot be repurposed. Never clear permanent revoked identities on restore
or rotation. A replacement connector/device requires fresh enrollment, distinct
key identity and grants. Removed keys receive no future wraps. Revocation cannot
erase plaintext/key copies or ciphertext already readable by that recipient.

States: `current -> prepared -> committed` or `prepared -> aborted/expired`.
Prepare is a durable intent without new dispatch authority. It references the
currently accepted predecessor and verified encrypted custody record; partial
publish, wrong expected identity/material, missing independent comparison,
revocation race or failed factor leaves current authority unchanged. Before
commit, recheck trusted time, current session/MFA, predecessor and revocation
state under the same authority/account lock order as dependent admission.
Never consume fresh factors outside the transaction that commits authority.

Commit atomically advances root/manifest/high-water, retains or extends
revocations, invalidates old-generation grants/challenges, consumes the ceremony
and factor, and stores a public immutable result receipt. Publishing custody
bytes alone grants nothing. A lost response is reconciled through the receipt
and exact intended public pin; replay returns the original receipt, while changed
bytes conflict. A second ceremony against the old predecessor cannot commit.
Restart observes either the old complete state or the new complete state.

Rollback before commit removes/abandons only the prepared intent; the prior pin
and revocations survive. **No post-commit rollback to the old generation**: if a
new configuration fails, halt work and perform a separately authorized forward
transition. Old signatures, backup timestamps and login sessions cannot lower
high-water, re-enroll revoked keys or overwrite a fork. Old-root signing authority
ends on commit, even if old decryption material is retained for history.

## Backup and archive consequences

The implemented backup/kit/CLI support generation one and root-only restoration.
`restore-check` verifies the encrypted root against independently entered public
identity; it is not an online reset, archive restore or rotated-generation codec.
Do not pretend an old generation-one kit contains a later root or preserves the
complete manifest/revocation history. Multi-generation backup and custody require
separate versioned slices before normal runtime rotation can be supported.

Retain private archive keys only for the owner's selected history retention.
Archive rotation changes future wraps; prior envelopes need their original key
or an explicitly authorized separately tested migration. The relay cannot
re-encrypt history without an authorized content reader. Root rotation does not
re-wrap existing message content. Export includes retained encrypted envelopes,
public historical manifests/transitions and relevant tombstones, never private
keys/recovery tokens by default. Exporting a root backup alone promises no history.
Erasure follows the application's published account retention rules and deletes
custody/envelopes where required; it cannot retract recipient copies or guarantee
deletion from independently kept kits. No new retention duration is selected here.

## Deterministic drills and remaining release evidence

[Synthetic vectors](../v1/vectors/root-recovery-state-proposal.json) and
[design tests](../../scripts/test_root_recovery_state_proposal.py) bind symbolic
transcripts, independently compute digests, refuse altered fields, model authority
and compare complete pre/post-state. They use no private key or recovery token.
The tests cover normal rotation, incomplete publication, wrong material/context,
lost login/root/all, revoked device/connector resurrection, old-key readability,
replay/fork, concurrent predecessor conflict, transaction failure and restart.
Existing scripts discovery runs them in CI. These model drills cannot prove
signature verification, AEAD, durable database atomicity, clock trust or custody.

Before gate closure, implement authenticated adapters and current-generation
custody/restore, reuse existing byte verifiers, and repeat these cases against
disposable persistence with concurrent revocation and real process termination
at each write. Use the offline CLI's synthetic init/restore-check tests for the
existing generation-one path; multi-generation drills must fail unsupported until
its codec exists. Separately run independently distributed owner-client and
supported-device comparison/phishing tests, actual old-ciphertext decrypt/loss
tests with synthetic content, wrong-kit AEAD checks and leakage canaries. Preserve
all evidence, captures and real materials privately. Q3/Q10 and dependent runtime
gates remain open until reviewed implementation and reproducible evidence exist.
