# ZT-009 draft 01 transcript and trust-boundary matrix

**Draft validation aid only.** This maps the candidate bytes in [draft 01](zt-sealed-draft-01.md) to their intended authentication checks. It is not an approved protocol. Q7 in the [decision log](zt-009-decision-log.md) remains open until the mapping and resulting attack cases are tested.

The envelope uses HPKE **base mode** for each CEK wrap. Base mode does not authenticate the sender; the separate ECDSA signature and a trusted, owner-signed manifest are intended to do that. [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) defines the HPKE operations and explicitly leaves application replay and downgrade defenses to the embedding protocol.

## Exact candidate transcripts

`P` is the complete original `protected` byte slice, `U` is the original envelope byte slice from `magic` through the last wrap, and `M` is the complete original signed manifest including its signature. Lengths are unsigned big-endian as specified in draft 01. A verifier must use received bytes, not a reconstructed record.

| Operation | Input authenticated or derived | Secret or verification authority | Required check |
| --- | --- | --- | --- |
| Body AES-256-GCM | Plaintext; AAD `"ZTSE/body/v1\0" || magic || profile || kind || flags || protected_len || P`; `body_nonce` is the AEAD nonce | Fresh per-message CEK | Open with exact AAD and nonce; reject tag failure before using plaintext. Nonce uniqueness for a CEK is an implementation invariant, not supplied by the signature. |
| Each HPKE base-mode wrap | 32-byte CEK; `info = "ZTSE/wrap/v1\0" || SHA-256(P) || role || key_id`; AAD `"ZTSE/wrap-aad/v1\0" || P || role || key_id` | Manifest-authorized recipient key | Use one fresh sender context and one Seal; validate `enc` and open only the wrap matching a pinned authorized private key. HPKE base mode alone does not prove sender identity. |
| Origin signature | `"ZTSE/sign/v1\0" || u32(len(U)) || U` | Manifest-authorized signer public key | Verify P-256 ECDSA/SHA-256 over the exact original bytes, then enforce role, scope, validity, revocation, tenant, selected device and line. Do not prehash for a hashing API. |
| Manifest signature | `"ZTSE/manifest/v1\0" || u32(len(manifest_without_signature)) || manifest_without_signature` | Separately pinned owner-root public key | Verify exact bytes and root identity; persist `M`, `SHA-256(M)`, generation, version and prior-chain position before accepting cited commands. |
| Key ID | `"ZTSE/key/v1\0" || algorithm_u16 || public_point_65` | SHA-256, then owner-signed manifest record | Recompute and compare. A digest is an identifier, not proof of authorization. |

The body nonce, body ciphertext, every wrap role/key ID, every HPKE `enc` and ciphertext, and all structural length bytes are inside `U` and therefore covered by the origin signature. The signature's own bytes are outside `U`. The body tag also authenticates the body plaintext and its AAD; the HPKE tag authenticates each CEK plaintext and wrap AAD. Neither AEAD replaces the origin signature or manifest check.

## Field-to-check inventory

| Candidate bytes or external value | Covered by candidate transcript | Additional authorization or state check |
| --- | --- | --- |
| `magic`, `profile`, `kind`, `flags`, lengths, ordered wraps | Origin signature; envelope header and `P` also enter body AAD | Parse exact profile/kind, bounded lengths and EOF before allocation or cryptographic work; no plaintext or version fallback. |
| `account_id` | `P` in body AAD, HPKE info/AAD and origin signature | Equal authenticated HTTP/WSS tenant and pinned manifest account; reject cross-account lookup. |
| `message_id` | `P` in all three envelope transcripts | Stable outbound idempotency identity; inbound equals `event_id` under the candidate kind-02 rule. That inbound rule requires a new sealed ingest contract because M1 currently requires a prior outbound message and attempt. Use durable replay state. |
| `device_id`, `line_id` | `P` in all three envelope transcripts | Match enrollment, active WSS/grant identity and the selected physical line. A stable line registry and SIM mapping do not exist in M1; sealed grants remain disabled until implemented. Android subscription index alone is insufficient. |
| `keyset_version`, `manifest_digest`, `signer_key_id` | `P` in all three envelope transcripts | Resolve exact signed manifest bytes and accepted chain position; verify signer role/scope/time and recipient set. A server key directory alone is untrusted. |
| `created_or_observed_ms`, outbound `expires_ms` and `intent` | `P` in all three envelope transcripts | Apply chosen clock-skew, expiry and `SEND_SMS` policy; a signed time is not replay prevention. |
| Outbound destination or inbound observed sender `peer` | `P` in all three envelope transcripts | Compare with the queued/granted route or normalized inbound observation before action; enforce strict E.164 and length rules. |
| Inbound `event_id`, `local_sequence` | `P` in all three envelope transcripts | Durable one-event allocation, equality of inbound message/event IDs, sequence window and duplicate webhook handling. Multipart boundary and reset rules remain Q8. |
| `body_nonce`, `body_ct` | Nonce and ciphertext/tag in origin signature; nonce and AAD in body AEAD verification | Fresh CEK/nonce for a new message identity; replay the identical envelope on retry. No second radio attempt after ambiguous submission. |
| Wrap `role`, `key_id`, `enc`, `hpke_ct` and wrap order | Full wrap bytes in origin signature; role/key ID in HPKE info/AAD; CEK protected by HPKE AEAD | Exactly the allowed role set and authorized recipient keys; reject duplicate, reordered, invalid-point or added-reader wraps. Check opened CEK by opening the body. |
| Manifest account, root, generation, version, times, previous digest and key records | Exact owner-root manifest signature; `SHA-256(M)` bound by envelope `manifest_digest` | Separate root bootstrap, monotonic local high-water, fork/rollback/freshness, scope and revocation checks. Withheld updates remain a Q4 risk. |
| HTTP bearer/API key, host, route and content type | TLS and server authorization, **not** the origin signature | Authenticate tenant and allow only the sealed route/body type. Compare server route values to signed `P`; reject a plaintext downgrade. |
| Server grant/attempt/session epoch, quota and dispatch state | M1 server/device transport contract, **not** this origin signature | Verify live fenced grant and durable local one-attempt journal immediately before radio use. A valid envelope alone cannot authorize an SMS. |
| SMS segment count, SIM choice and Android callback | Phone-local observation, **not** cryptographically attested by this envelope | Enforce actual segment and line checks locally; keep unknown outcome after missing callback. Carrier delivery is outside the sealed-relay claim. |

## Adversarial test cases

For each changed signed field, the verifier should reject the altered original bytes before decrypt/radio. A newly signed envelope with a wrong but internally consistent value must also fail the corresponding **authorization** comparison; signature validity alone cannot catch an authorized key signing for the wrong tenant, device, line or peer. The vector suite should include:

1. Change each header, protected field, nonce, body ciphertext/tag, wrap record, wrap order and signature independently. Check length and parse failures separately from cryptographic failures.
2. Substitute a valid but wrong-tenant, wrong-device, wrong-line, expired, revoked or wrong-scope signed manifest; withhold a newer manifest; present same-version different exact bytes; and roll back an offline client's persisted high-water mark.
3. Copy a valid body/wrap under a different message identity, switch outbound/inbound kind, add an unauthorized reader, use a wrong HPKE point or key ID, or replay the same inbound event with a changed sequence.
4. Present a valid origin envelope without a live M1 grant, after dispatch is paused, or after durable submit intent. No case may trigger a second radio call.
5. Put a plaintext JSON body or downgrade header on the proposed sealed route, and a sealed envelope on the private synthetic-alpha route. Neither may be silently translated.

Open decisions: whether any role/subject/scope or reader-set comparison above is underspecified (Q2/Q7); whether the HPKE and body transcripts provide the desired cross-context separation (Q7); what freshness witness is needed against a malicious relay withholding a revocation (Q4); and whether the intended browser and Android libraries expose the exact bytes and non-exportable key operations (Q5/Q6). Resolve these in a versioned profile and adversarial vectors before production acceptance.
