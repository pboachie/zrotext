# Customer-local selected-owner template opening

`sdk/typescript/src/owner-template-opening.ts` composes the opaque template
client's explicit `readLatest()` with the maintained encrypted-template HPKE
opening and bounded preview. It is a dormant SDK controller, available only
when the customer host explicitly enables and invokes it. It is not mounted
by the owner page and does not grant a reader, schedule work or send a message.

The host supplies a dedicated `OwnerEncryptedTemplateClient`, the independent
selected account/device/line/interval/session and template identifier, an
authenticated current owner/consent source with an SDK-verified manifest,
the current same-origin CSRF value, an abort signal and an optional timeout
of at most ten seconds. The controller takes ownership of that client's
lifetime. Do not share it with another host. Closing, invalidating a review,
losing authority or exceeding the budget closes and aborts the child client.
Its unresolved write identity remains available through `pending()`.

`openLatest({privateKey})` takes an explicit customer-local P-256 ECDH private
`CryptoKey` with `deriveBits` usage. It never prompts for a key, reads a key
store, exports a key itself, uploads a key or stores plaintext. Compatibility
is that of the maintained HPKE opening implementation. The supported tested
case uses an extractable customer-local key; the synthetic selected-reader
case with a nonextractable handle is refused by the maintained opening.
This controller makes no hardware or nonexportable custody guarantee.

The operation acquires its busy gate before inspecting caller input. It uses
one absolute budget for currentness reads, ciphertext GET, manifest verification,
HPKE authentication, preview and final checks. Every asynchronous result is
lifetime/deadline checked. Independent checks bind the complete selected tuple,
owner and consent liveness, active phase, authenticated monotonic time, exact
CSRF, opaque verified manifest trust, root and generation, manifest version
and digest floors, selected reader, template, peer and ciphertext scope.
Historical, ahead or contradictory scope cannot release plaintext. It opens
the authenticated canonical content with the maintained implementation and
rechecks currentness before returning a bounded local preview.

The result is a point-in-time `opened_current_preview` with composition segment
estimates, revision and encrypted transport digest. `requestAcknowledged` is
always false. A matching unresolved write observation can set `matchesPending`
but neither clears that write identity nor acknowledges its POST. This
controller only invokes GET; it never invokes preparation, commit or retry.
Actual Android subscription segmentation and dispatch authority remain separate.

The customer host must call `invalidate()` or `close()` on draft/review change,
hidden presentation, owner/session loss or custody replacement, and clear any
preview it already owns. Invalidation closes the lifetime; a new selected
lifetime requires a new controller and dedicated client. Late results are
observed without publication. The controller clears its owned envelope copy
best-effort; JavaScript strings, cryptographic library temporaries, browser
memory and already returned caller-owned previews cannot be securely erased.
The host callbacks are trusted local authority integrations, not browser-supplied
public flags or an assurance of continuous authority after a result returns.

The discovered SDK tests exercise genuine HPKE, authenticated tamper, refused
keys, full selection changes, opaque manifest refusal, reentry, unknown-write
GET semantics and held real AES results. Rendered owner tests run the actual
module and HPKE inside Chromium with synthetic same-origin cookies/CSRF and
ciphertext HTTPS responses, including revocation, cancellation and deadline
refusal. Synthetic fixture TLS exceptions do not alter production TLS.
