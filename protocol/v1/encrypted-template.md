# Encrypted template persistence candidate

This default-disabled library router and draft client wire persist opaque template
versions. Main does not mount the transport. Saving and local preview do not
approve, schedule, send, or issue reader keys. A separately reviewed owner action
and the actual selected Android subscription must still check `divideMessage`
and the six-part device cap before dispatch; estimates are not carrier guarantees.

ZTWT01 is distinct from ZTWC01. Bytes 0–3 are `ZTWT`, byte 4 is version 1, byte 5
is payload-contract version 1. Authenticated AAD is 222 bytes: account, device,
line, interval and template UUIDs; big-endian signed-positive 64-bit binding
 generation, template revision, expiry milliseconds, trust generation and
manifest version; peer digest, selected reader key ID and manifest digest (32
bytes each). Revision is 1–128. No nil UUID or all-zero digest is valid.

The 65-byte P-256 HPKE encapsulation follows AAD, then a four-byte big-endian
ciphertext length, then AES-128-GCM ciphertext with its 16-byte tag. Plaintext is
1–32768 bytes. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM use the
existing SDK HPKE dependency. Info is `ZT/workflow-template/hpke/v1` plus a NUL
and exact AAD. No context-kind relabeling or ciphertext reuse is allowed.
The shared synthetic `vectors/encrypted-template-01.json` fixes AAD and info.

Client plaintext is the exact canonical template-contract JSON `{v,template,values}`
with sorted substitution keys. It remains solely in the client. Validation,
literal nonrecursive substitution and GSM-extension/UTF-16 multipart estimates
reuse the existing bounded contracts. Missing/invalid placeholders, lone
surrogates, oversized inputs/output and estimates over six parts fail locally.
The relay never stores/evaluates plaintext or derives a plaintext fingerprint.
The version digest is SHA-256 of the complete encrypted envelope; every changed
save is a fresh encapsulation and a new revision, even if plaintext repeats.

The owner-session transport, when explicitly composed with `router(state,true)`,
has only these methods:

- POST `/v1/owner/workflow/templates`: binary
  `application/vnd.zrotext.workflow-template.v1`, UUID `Idempotency-Key`, canonical
  decimal `X-Zrotext-Template-Revision` expected previous revision; returns revision.
- GET that path with `interval_id` and optional `after`: at most 20 selected
  interval heads and encrypted digests, plus a continuation cursor.
- GET `/v1/owner/workflow/templates/{id}` with optional `revision`: exact opaque
  envelope. Responses are no-store. Existing real owner authentication and CSRF
  mutation extraction apply; a device or messages-read token grants no access.

Root-manifest/account/owner/session/line/interval and selected reader fences are
checked transactionally, including replay and final commit. Owner status is not
selected-reader decryption authority. Readable history still requires current
manifest authority. Templates are deliberately selected-recipient/interval
scoped: sharing across recipients requires explicit client re-encryption, not an
implicit reader or send grant. CAS has one winner; exact request retries cannot
rewrite or revive purged content. Account bounds are 256 template identities,
128 revisions each and eight MiB of retained encrypted bytes.

Ciphertext expiry/withdrawal removes bodies. Bounded immutable identities and
request digests remain as replay tombstones until explicit owner account erasure;
this can exhaust the finite identity budget and fails closed. Independent bounded
owner takeout pages include opaque revoked-reader history, never decryption
permission. Owner erasure deletes versions before heads atomically. No production
route, cross-recipient sharing, provider activation, physical SMS or carrier
acceptance is claimed by this candidate.
