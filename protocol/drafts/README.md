# Sealed-content protocol drafts

These documents describe the proposed ZT-009 sealed-content protocol, in which message bodies are encrypted on the customer's client and on the phone so the relay stores only ciphertext and routing metadata. **None of them is an accepted protocol.** No production route emits or accepts these formats, and nothing here supports a sealed-content product claim. The accepted wire contracts are in [protocol/v1](../v1/README.md).

| Document | Purpose |
|---|---|
| [zt-009-review.md](zt-009-review.md) | Threat model, security objectives and validation plan |
| [zt-009-decision-log.md](zt-009-decision-log.md) | Open questions (Q1–Q11) and the evidence needed to close each |
| [zt-009-decision-proposal.md](zt-009-decision-proposal.md) | Proposed answers, including the manifest-digest and low-`s` signature corrections |
| [zt-009-transcript-matrix.md](zt-009-transcript-matrix.md) | Candidate transcripts mapped to their authentication checks |
| [zt-009-android-provider-study.md](zt-009-android-provider-study.md) | Android Keystore HPKE implementation options |
| [draft02-android-recipient-provider.md](draft02-android-recipient-provider.md) | Dormant API 31+ recipient unwrap candidate and limits |
| [zt-sealed-draft-01.md](zt-sealed-draft-01.md) | Byte profile draft 01 |
| [zt-sealed-draft-02-proposal.md](zt-sealed-draft-02-proposal.md) | Profile 02 envelope proposal |
| [zt-sealed-draft-02-manifest-candidate.md](zt-sealed-draft-02-manifest-candidate.md) | Profile 02 manifest and authorization candidate |

Synthetic test vectors are in [protocol/v1/vectors](../v1/vectors/README.md). The TypeScript reader is in [sdk/typescript](../../sdk/typescript/README.md).
