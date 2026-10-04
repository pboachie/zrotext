# Local phone pairing code

The owner device page displays an optional QR code for the existing one-use
phone pairing ticket. Rendering happens entirely in the browser. No QR service,
external image, analytics call, link navigation or clipboard write receives the
ticket. Manual details remain available as labeled readonly fields for keyboard
selection and copying. A failed or unavailable renderer opens that fallback.

The browser module must be served as `/owner/pairing-code.js` with the same
static-asset protections as the existing owner scripts. Until that asset is
registered by the server integration, the device page uses manual pairing.
The code display does not establish that an installed Android app has a scanner.
The scanner bridge remains a separate Android integration; manual entry works
with the existing app.

## Wire format and scanner adapter

The payload is canonical compact ASCII JSON, with exactly these fields in order:
`type`, `v`, `origin`, `pairing_id`, `token`. `type` is `zrotext-pairing`; `v`
is the integer `1`. The origin is the canonical browser HTTPS origin, without
userinfo, path, query or fragment. The ID is a lowercase UUID. The token is the
existing `ztp_` prefix followed by a canonical unpadded base64url encoding of
32 bytes. Encoded payloads are bounded to 512 bytes.

`ZrotextPairingCode.encode(origin, pairingId, token)` creates the payload;
`decode(text, expectedOrigin)` validates it and requires binding to the
independently selected canonical server; missing origins are refused.
`encodePairingPayload` and `decodePairingPayload` export the same operations for
scanner adapters. The decoder rejects unknown, missing,
nested, duplicate and reordered fields, unsupported versions and noncanonical
serialization. Errors never include encoded fields. Decoding performs no I/O.
`render(canvas, text)` draws an opaque black/white byte-mode QR with M error
correction and a four-module quiet zone. `clear(canvas)` discards its bitmap.

An Android decoder must apply the same strict bounds and field rules. It must
not interpret the scan as a URL or launch it. Confirm the decoded server with
the user before any request. Require an independently established server for
every scan and refuse a mismatch; echoing the scanned origin is not independent
trust. A successful scan supplies only the existing `PairingClient`
origin, pairing ID and token arguments. Serialize scans while claim/proof is in
progress and reconcile unknown outcomes rather than automatically submitting
again.

The existing claim response, account ID, pairing ID, phone-key fingerprint and
challenge nonce remain bound by the device proof. The authenticated browser
owner must still compare the exact phone code and fingerprint and explicitly
approve the phone. QR data is not owner authentication, a root pin, a recovery
proof, content-reader consent, line activation or dispatch authority. Do not
include cookies, API keys, recovery tokens, private keys or archive material.

## Lifetime and departure

The server remains authoritative for its five-minute, one-use ticket expiry and
replay protection. The current create API returns no absolute expiry time, so
the browser conservatively retires the display five minutes after dispatching
the create request. It updates remaining minutes, checks again before proof or
approval, and clears the QR and manual fields when the display expires. A local
countdown is not permission to use an expired server ticket.

Leaving the page, logging out, cancellation and completion clear the QR,
manual values and comparison fields. Late responses from a departed or replaced
pairing ceremony cannot redisplay a token or approval form. Only a public ID is
retained for retirement after departure or local expiry. An approval in flight
retains its public pairing ID and any late successful device ID within the
original owner epoch. Proof checks and replacement attempts first reconcile that
outcome; a missing ticket alone cannot establish that approval failed. Unknown
approval blocks replacement and repeated approval. A recovered approval is shown
with refreshed device observations before another setup attempt is offered.
The visible Check or cancel interrupted pairing action checks for completion
first, then explicitly cancels an unresolved ticket. Only confirmed cancellation
releases the attempt; an unavailable or missing response remains blocked.
Signing out discards this state. It is page-local, so after a full reload users
must check their device list before repeating interrupted setup.

When no approval outcome is unknown, the browser cancels a known retired ticket
before creating its replacement. An uncertain cancellation blocks replacement.
No automatic retry or approval is added.

## Encoder provenance

The locally bundled encoder is Project Nayuki's dependency-free MIT-licensed
QR-Code-generator v1.8.0, tag commit
`7ad95cedd8464a87f82221283612732ae4f3f305`. Its TypeScript source SHA256 is
`c4749095a91bf9696e3a303998b9905e467094f53041e64393e65e6d887737fd`.
The compiled library preserves its license and is enclosed with the application
adapter to avoid exposing another global namespace. See the
[upstream source](https://github.com/nayuki/QR-Code-generator/tree/v1.8.0)
and [library documentation](https://www.nayuki.io/page/qr-code-generator-library).

Tests run through the existing `node --test web/owner/*.test.js` discovery.
They exercise the application codec, malformed/wrong-server scans and real
controller lifecycle races. Scanner, camera denial and authenticated
browser/Android end-to-end acceptance require the coordinated mobile/server
integration; a QR rendered in a browser does not prove those behaviors.
