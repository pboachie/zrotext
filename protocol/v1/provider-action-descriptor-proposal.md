# Proposed provider action descriptor

`workflow-action-02` is an **unavailable proposed profile**. The network-free conformance parser proves closed canonical metadata only. It is not accepted by existing action proposals, decisions, generic workflow tools, storage decoders, SDK producers, execution, or transport. Parsing or computing its digest grants no content access, approval or SEND authority. Phone actions continue to use the unchanged `workflow-action-01` contract.

## Exact original wire

The descriptor has exactly five fields: `profile`, `action`, `route`, `reader` and `disclosure`. The profile is the literal `workflow-action-02`. Objects at every depth are closed; missing and additional fields are invalid. The [structural schema](workflow-action-02-proposal.schema.json) accompanies [synthetic conformance vectors](vectors/workflow-action-02-proposal.json).

Before parsing, the complete original descriptor must be at most 4096 UTF-8 bytes. Deserialize directly to the closed typed grammar, validate every bound below, and require those original bytes to equal its canonical encoding exactly. Canonical encoding recursively sorts object keys by ASCII, uses no whitespace, emits ordinary decimal integers and uses JSON string escaping. Allowed strings are ASCII. Exponents, fractional spellings, negative zero, leading zero, escaped key aliases, duplicate keys, whitespace and trailing values are invalid even if a generic JSON parser normalizes them.

A proposed owner proposal envelope has exactly `descriptor` and `request_id`, with a nonnil canonical UUID request ID. Before parsing, its complete original body must be at most 8192 bytes. Validate the closed typed request and descriptor, require the canonical descriptor to be at most 4096 bytes, and require the **entire retained original request body** to equal its canonical encoding. This binds nested encoding and surrounding separators as well as the outer fields. A post-normalization generic object cannot establish original-wire conformance. No raw-value dependency feature or bespoke JSON scanner is necessary. This helper is not mounted in HTTP.

The binding digest is lowercase SHA-256 of the complete canonical descriptor. The future action key uses its nested account ID, action ID and revision with that whole digest. Request ID belongs to the request envelope, not the descriptor digest. Never relabel a previously approved 01 action as 02.

## Closed fields and bounds

UUIDs are nonnil lowercase canonical 36-character UUIDs. Digests are exactly 64 lowercase hexadecimal characters. Identity digests for keys, manifests and recipient commitments must be nonzero. Positive integers range from 1 through 9007199254740991; action and content revisions range from 1 through 128. Epoch seconds range from 0 through 9007199254740 so multiplication by 1000 remains exactly representable in JavaScript; expiry is positive and strictly greater than not-before. Booleans, floats, nulls and arrays cannot substitute for these fields.

| Object | Exact fields and types |
| --- | --- |
| action | UUID account_id, action_id, line_id, recipient_id, content_ref, routine_id; revision and content_version in 1..128; existing purpose_id UUID ending 001/002/003 for transactional/operational/marketing; content_digest; not_before and expires_at seconds; timezone ASCII 33..126, length 1..64 excluding `unknown`; window_id ASCII 33..126, length 1..128; positive authority_generation; commitment `informational` or `sensitive` |
| route | kind `provider`; adapter `telnyx-sms-v2`; UUID route_id, organization_id, messaging_profile_id, sender_config_id, eligibility_policy_id, exposure_route_policy_id; positive route_version, sender_config_version, eligibility_policy_version, exposure_policy_version; route_fingerprint and eligibility_digest |
| owner-local reader | kind `owner_local`; role 2; nonzero key_id and manifest_digest; positive trust_generation and manifest_version |
| customer-selected reader | kind `customer_selected`; role 3; the same key/manifest/trust fields; UUID grant_id and positive grant_version |
| disclosure | mode `provider_plaintext`; nonzero recipient_commitment; request_digest |

These are conformance bounds. Configuration, tenant ownership, actual supported timezone and current authorization must be checked independently by future consumers. The reader variants cannot include each other's fields. There is no implicit reader, fallback route, phone variant or alternate provider endpoint.

## Digest sources and unavailable authority

The action content digest binds the exact existing encrypted workflow content bytes. Route fingerprint uses the existing provider contract's account/organization/profile/sender/revision algorithm over trusted fixed configuration; the sender participates even though it is not repeated in the descriptor. It is linkage metadata, not anonymity or proof of sender ownership. Eligibility digest must bind complete independently provisioned policy evidence; no browser boolean can supply eligibility. That source is currently unavailable.

Reader key, trust generation, manifest version and digest must come from the actual current accepted manifest. A customer-selected grant must come from the real current grant, not from synthetic vectors or a fabricated stamp. These identifiers are not content handoff or provider execution permits. Current protected provider content handoff remains unavailable.

Recipient commitment uses the existing authenticated-peer commitment. Request digest uses the existing provider request algorithm over the fixed route, recipient and plaintext after a genuine authorized local read and explicit review. Ciphertext hashing alone cannot supply this digest or disclosure. No plaintext, recipient, sender, credential, arbitrary URL or callback authority is stored in this descriptor.

## Consumer migration obligations

| Consumer | Current behavior and required future review |
| --- | --- |
| Rust legacy Descriptor and action storage | Continue rejecting02. Preserve01 bytes and digest. A future profile-aware decoder must retain exact02 canonical bytes, derive the whole binding key and reject unsupported stored profiles |
| Owner HTTP proposal/edit | Continue rejecting02. Future typed intake must retain the whole bounded original body and enforce closed envelope canonical equality before normalization; edit also binds its actual key and expected version |
| Generic workflow RPC/tools | Continue rejecting02. Generic Value conversion loses original-body evidence; preserve original bytes before parsing or explicitly refuse02 |
| SDK/browser serializers | No02 producer. Future producer must snapshot all fields and recursively canonicalize the entire closed request before hashing/transmission; parsed JavaScript objects alone do not prove duplicate refusal |
| Approval, binding and execution | No02 support. Future route, reader, disclosure, policy and content changes require a new immutable revision and fresh complete owner review; existing phone binding never implies a provider route |
| Export, erasure and migration | No02 stored rows or schema change. Future storage must preserve complete bounded canonical bytes and current-owner export/erasure fences; serial schema allocation remains separate |

The inert module deliberately does not replace the shared legacy Descriptor or modify active original-reader/routine fences. Actual legacy Rust and SDK consumers have rejection tests. Production acceptance requires a separate reviewed consumer migration, real owner review, current route/eligibility/reader sources, atomic admission and existing exposure composition, durable intent, unconstructible writer authority and actual transport proofs. This proposed grammar establishes none of those capabilities.
