# ADR 0009: Sealed HPKE AAD and Android receiver options

Status: proposed and unapproved. This document **selects no AAD rule, profile,
provider, library, dependency or key custody method**, changes no byte format,
vector or code, and enables nothing. Sealed mode stays disabled. It exists so
the maintainer can make the decisions that issue
[#625](https://github.com/pboachie/zrotext/issues/625) is waiting on from one
reviewed list of options and their consequences. It is a proposal, not evidence.

## Why this decision is open

The Q5 acceptance language in the [ZT-009 decision log](../../protocol/drafts/zt-009-decision-log.md)
requires a maintained exact-profile receiver, a non-exportable API 31+ Android
Keystore recipient key, and **distinct nonempty HPKE `info` and AAD**. Today the
repository contains two different transcripts:

| Profile | HPKE `info` | HPKE AAD | Where |
| --- | --- | --- | --- |
| Draft 01 | `"ZTSE/wrap/v1\0" \|\| SHA-256(protected) \|\| role \|\| key_id` | `"ZTSE/wrap-aad/v1\0" \|\| protected \|\| role \|\| key_id` (nonempty) | [zt-sealed-draft-01.md](../../protocol/drafts/zt-sealed-draft-01.md) |
| Profile 02 candidate | `"ZTSE/wrap/v2\0" \|\| received_P2 \|\| role \|\| key_id` (nonempty) | empty | [zt-sealed-draft-02-proposal.md](../../protocol/drafts/zt-sealed-draft-02-proposal.md), [draft02-android-recipient-provider.md](../../protocol/drafts/draft02-android-recipient-provider.md) |

Profile 02 deliberately moved the binding into `info` (the proposal cites
RFC 9180 section 8.1 and notes one `Seal` per wrap needs no per-message AAD).
That makes the current candidate fail the literal Q5 requirement, and the
issue forbids loosening info/AAD claims "to pass". Resolving that is a
maintainer decision about the profile, not an implementation detail, so this
repository does not change it unilaterally. Separately, no reviewed maintained
receiver that combines a non-exportable Keystore key with the chosen transcript
has been accepted; the [provider study](../../protocol/drafts/zt-009-android-provider-study.md)
records why the evaluated Tink, Bouncy Castle and platform HPKE paths do not
directly fit.

## Decision 1: the AAD rule (maintainer decision required)

| Option | Effect | Cost and risk |
| --- | --- | --- |
| 1A. Keep profile 02 (empty AAD, nonempty `info`) and amend the Q5 wording to "nonempty `info`; AAD defined by the profile" | No byte change. Tink's Keystore helper (empty AAD, internal package) becomes a possible oracle or receiver shape again. | Weakens the stated acceptance criterion; must be an explicit recorded decision with a security argument that `info` hashed into the HPKE key schedule gives the same context binding, and the log, ROADMAP and probe docs must be reworded together. |
| 1B. New profile (for example 03) with the profile-02 `info` plus a distinct nonempty AAD | Meets the literal requirement. Requires new vectors. | Regenerate and re-prove the Android, TypeScript SDK and Rust server corpora and the cross-client harness; the AAD byte layout and domain label need review; the dormant Android provider, SDK sealer and server fixtures all change. Existing profile-02 test vectors become a retired profile. |
| 1C. Return to draft-01 wraps | Nonempty `info` and AAD already specified. | Gives up profile 02's other changes (manifest binding and signature corrections); likely the most churn. |

Whichever option is chosen, the same PR set must keep info/AAD/key/point/profile
rejection corpora identical across Android, SDK and server, and must not
describe emulator or software-key results as provider acceptance.

## Decision 2: the Android receiver (maintainer decision required)

Options are described by class. Naming a class here does not select, endorse or
approve any library, and no dependency is added.

| Class | Fits | Open questions |
| --- | --- | --- |
| 2A. ZROtext-owned composition over public JCA and Keystore `KeyAgreement` (the existing dormant candidate shape) | Works with either AAD rule; no new dependency. | Ownership of a security-sensitive HPKE composition; needs the maintainer to accept that support burden and an independent review, so it is not "test-only promoted by default". |
| 2B. Tink Keystore helper | Only with 1A (it opens with empty AAD). | Lives in `hybrid.internal` with restricted-API construction, so no compatibility promise; must not move onto the release classpath without an explicit decision. |
| 2C. A maintained HPKE receiver with a delegated key-agreement hook, so the private scalar stays outside it | Could carry nonempty `info` and AAD with a maintained KEM and key schedule. | Needs independent API, crypto and license review, native packaging and JNI composition, an authentic Keystore bridge, bounded-length wrappers, and secret-lifetime rules. No library is selected here. |
| 2D. Bouncy Castle public HPKE receiver | Separate `info` and AAD inputs. | Per the study, its P-256 decapsulation consumes raw scalar parameters, so it cannot use a non-exportable Keystore key; listed to record the finding. |
| 2E. Platform HPKE API | Separate inputs. | Native API starts at 37 and the documented provider is X25519, so it does not serve the API 31+ P-256 floor. |
| 2F. Software key encrypted at rest under a Keystore AEAD key | Many libraries accept it. | Private bytes enter app memory, which is a different exposure claim than the accepted non-exportable one; excluded by the recorded no-software-fallback decision unless the maintainer reverses it. |

## Constraints that apply to every option

- API 31+ sealed eligibility and refusal on API 28-30 are preserved; there is no
  SDK-level bump and no unapproved software-key fallback.
- Key creation stays enrollment-only; receipt never regenerates a lost key.
- `KeyInfo.securityLevel` is reported metadata, not attestation.
- Provider acceptance, virtual (emulator) feasibility and physical security
  observations stay in separate sections of the decision documentation.
- Exact known answers (RFC 9180 P-256 vectors) and changed-info/AAD/key/point/profile
  negatives must pass through Android, SDK and server corpora before acceptance.

## Evidence still required after the decisions

This proposal gives none of it: independent receiver review, an API 31 device
matrix, separately controlled physical reboot, loss and revocation evidence on
supported hardware, and provisioning acceptance. The issue stays open until
those gates, not this document, are satisfied.

## Consequences if adopted

An accepted decision should be recorded by changing this ADR's status and
naming the chosen options, then landing the follow-up slices in order: protocol
text and vectors, SDK and server corpora, then the Android receiver, each as
its own reviewed change.
