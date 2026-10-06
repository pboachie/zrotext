# Dormant provider SMS submit body codec

The synchronous server `provider_sms::submit_codec::encode` function produces a bounded Telnyx SMS request body from an existing retained `Request` and resupplied explicitly disclosed content. It does not send, decrypt, read credentials, authorize an action, issue a permit, reserve money, write a submit intent, install a worker or accept a receipt. No runtime caller is connected. Encoding success proves representation consistency only. The provider SMS journey remains unavailable until its separate real authority, persistence, transport and reconciliation gates are implemented and qualified.

## Caller and identity contract

`encode(&Request, recipient: &str, Content)` returns an owned `EncodedBody` or a generic `CodecError`. A `Request` is an identity, not a grant. The recipient and text must be resupplied by their legitimate caller; no hash can recover their plaintext. Sealed envelopes are refused. The codec revalidates the retained route with the existing `Route::telnyx` constructor, reconstructs `Request::new` from the exact retained route values and supplied recipient/plaintext, then requires exact `Request::check_replay` equality before output serialization. This also refuses a changed digest/recipient hash or inconsistent retained route component. It does not create a trusted reader, disclosure acknowledgment or authority from a matching digest.

The unchanged request digest is SHA-256 over the following concatenation, with no JSON or text normalization:

1. ASCII domain `ZT/provider-request/v1` followed by NUL, then `telnyx-sms-v2` followed by NUL.
2. Binary 16-byte account, organization and messaging-profile UUIDs, in that order.
3. Big-endian unsigned 64-bit route revision.
4. Big-endian unsigned 64-bit UTF-8 sender length, then exact sender bytes.
5. SHA-256 of exact recipient UTF-8 bytes.
6. SHA-256 of exact plaintext UTF-8 bytes.

No caller-supplied alternate digest, configurable output profile, accepted boolean or JSON authority token exists. The existing domain and Request representation are unchanged. The fixed codec profile is a versioned representation rule; it does not make that identity an independently authorized network request. A future transport must bind the retained Request to the actual authoritative request/intent transaction.

## Closed output and project limits

The body is one UTF-8 JSON object with exactly these fields in this serialization order:

| Field | Value |
|---|---|
| `from` | Exact explicit retained route sender |
| `messaging_profile_id` | Exact retained nonnil profile UUID, lowercase canonical hyphenated form |
| `to` | Exact resupplied recipient, after request-identity comparison |
| `text` | Exact resupplied accepted plaintext, with JSON escaping |
| `type` | Fixed `SMS` |
| `encoding` | Fixed `ucs2` |

The [official Telnyx Send API](https://developers.telnyx.com/api-reference/messages/send-a-message) supports these fields and encoding choices. Its `auto` encoding uses smart encoding; `ucs2` disables it. This codec selects a narrower explicit phone-number profile. It omits MMS, media, scheduling, number pools, alphanumeric senders and per-request webhook overrides. Provider-side validation, billing, processing and delivery remain separate concerns.

Account, organization and profile UUIDs must be nonnil; revision must be nonzero. Sender and recipient use the existing project syntax: `+` followed by ASCII digits, first digit nonzero, total length 3 through 16 bytes. This shape is not proof of a verified, owned, current or permitted route.

Text must contain 1 through 4096 UTF-8 bytes, preserving the existing Request bound. This codec further restricts text to Basic Multilingual Plane Unicode scalar values: U+0000 through U+FFFF excluding surrogates. A Rust `str` is valid UTF-8 and cannot contain a surrogate; supplementary-plane scalars are explicitly refused. At most 4096 scalar values/UCS-2 units are accepted. These are project bounds, not provider-advertised segment or message limits. Supplementary characters may be valid in a Request but are deliberately unsupported by this fixed codec.

There is no normalization, substitution, truncation, forced expiry or fallback. Quotes, backslashes, NUL and other controls use JSON escaping. Selecting UCS-2 does not establish supported carrier content, lossless delivery, a segment count or a conservative price. A later authenticated policy/budget gate must account for this fixed profile before any send.

Serialization uses maintained serde_json with borrowed fields and an internal checked writer. The writer refuses overflow or growth beyond 32768 output bytes and returns only complete successful output. The independently bounded maximum expansion is six JSON bytes per accepted input byte plus fewer than 256 bytes of fixed fields: `6 * 4096 + 256 < 32768`. No BOM, trailing newline, alternate field order or appended data is emitted. A schema describes the closed object and lexical shape; separate vector controls enforce UTF-8/UCS-2 byte/count rules and identity layout, which schema alone cannot prove.

## Plaintext ownership and refusal

`EncodedBody` privately owns a zeroizing byte buffer and provides a borrowed `as_bytes` accessor. It has no Debug, Display, Clone or serialization implementation. The caller is responsible for any outward copy and must not log the body. Errors are closed generic variants without phone numbers, text, provider excerpts or partial output. Serialization, output-buffer reservation and output-limit failures discard the partially written buffer. This is not a promise that every standard-library allocation failure is recoverable. The input strings remain caller-owned.

Borrowed serialization avoids deliberate text cloning. Zeroization is best effort for the currently owned buffer, not a claim about allocator history, caller strings, past copied bytes or provider retention. No secret store, private key, credential loader, external callback or network destination is added. Repeated successful encoding is deterministic representation, not permission to retry a send; transport uncertainty must remain Unknown without retransmission or phone fallback.

## Controls and verification status

The sibling Rust controls are Cargo-discovered by `#[cfg(test)] mod tests`. They cover complete literal output, independent digest/wire vectors, every retained identity component, recipient/content mismatch, sealed input, ASCII/BMP UTF-8 limits, supplementary refusal, E.164 bounds, closed fixed profile, maximum escape expansion, bounded-writer refusal, generic serializer failure and unchanged retained identity. A test-only rejecting writer uses the existing internal serializer; it introduces no production transport injection.

`vectors/provider-submit-body-codec.json` contains synthetic positive bytes and independently computed hashes plus negative request cases. `vectors/provider-submit-body-codec.schema.json` models the six-field emitted object. `tests/test_provider_submit_body_codec.py` is discovered by the existing broad local protocol unittest command. The hosted quality job also explicitly selects this new file using its existing schema virtual environment. No other step, permission, dependency or required check is changed. Its independent standard-library digest layout and strict duplicate-aware byte reader check exact vectors, identity changes, key/type/profile closure, canonical nonnil UUIDs, exact integer revision, malformed phones, invalid UTF-8/surrogates/BOM/trailing data, Unicode bounds and maximum JSON expansion. These are representation controls, not authenticated disclosure or provider integration tests.

At source authoring, all new Rust and Python controls are unexecuted. Rust is also uncompiled; no formatter, Clippy, PostgreSQL, provider or native check has been performed for this cut. Verification results must be reported from actual later executions, without treating vectors, syntax review or matching digests as provider acceptance.

## Future authority and transport gates

Before a later worker can obtain bytes for network use, it needs actual current account/route/config/reader bindings and genuine protected disclosure; an eligible approved action; account/session/writer/suppression/expiry fences; atomic conservative shared exposure reservation, account-scoped idempotency and durable submit intent; independently retained request identity; and a real one-use transport capability. Current trusted-input snapshots, explicit profile data and successful formatting cannot substitute for those gates.

Only after real authority may independently configured credentials and an approved endpoint be accessed. Processing region, retention, cost, revocation, time limits, provider policy and signed receipt correlation are unresolved execution requirements. Callback verification does not create send authority or initial correlation. This codec neither installs the receipt proposal nor changes the existing admission, action-descriptor, disclosure, exposure or managed-AI owners' contracts.
