# Profile-03 ordinary-owner reviewed transport candidate

This component implements a fixed cookie/CSRF transport for explicit V2
reviewed packets. It does not mount a browser composer or establish installed
consent, current device permission, custody, hardware execution or delivery.
The server must independently admit the V2 contract and all current predicates;
historical V1 storage is not a substitute for that capability.

`OwnerReviewedSendClient03.send` accepts only a genuine private V2 verification
handle. It copies the exact envelope, intent and signature, checks their hashes
and configured original owner/session/device/line/root/origin, then awaits
`saveBeforeSubmit` before the first HTTP call. The retained record contains
ciphertext and public linkage only. Plaintext, content keys, passwords, factors
and signing keys are absent. This callback must durably retain the exact packet
and submit marker; it cannot replace the separate pre-signature burn journal.
The component does not sign, generate message identities, encrypt or retry.

Submission uses only `POST /v1/owner/conversation/send03`, same-origin cookies,
the original `x-zrotext-csrf`, no bearer, no redirects and no cache. Its closed
body is `{v:1,envelope,reviewed_intent,reviewed_signature}`. The request is capped
at 96 KiB. Response streaming counts actual bytes up to 192 KiB independently
of Content-Length. Strict UTF-8, flat JSON, decoded duplicate keys, exact field
sets, canonical identifiers/base64url/decimals, status and media type are checked.
Every response field, including the signed segment ceiling from one through six,
must agree with the exact retained packet. A receipt records admission only.

Stop/cancellation, CSRF rotation, timeout, clock regression, expired review,
storage failure, unexpected response or request failure closes the client.
Late completions cannot publish a result. Only one operation may be pending;
this is a per-client limit, not process-wide resource accounting. Each operation
rechecks withdrawal and the original time bounds around asynchronous boundaries.
There is no automatic retry, re-signing, re-composition or replacement identity.
Closing or aborting does not prove an already dispatched request was unaccepted.

Explicit passive reconciliation uses a fresh client and `status` with the exact
original retained record. It calls only
`POST /v1/owner/conversation/send03/status` with the original message, interval
and three packet hashes. A later session for the same original user may read
this history after review expiry or Stop without a live-device clock. This
never restores permission to send. Not-found, unavailable and interrupted
outcomes do not authorize a new packet. The public recovery validator checks
structure and hash linkage only; it cannot manufacture a private proof handle
or independently establish signature provenance/current authority.

The application still owns genuine fresh context and all three original
interval proofs, the protected two-signature burn journal, explicit review and
segment ceiling display, one-use submission control and UI recovery. Injected
fetch/storage/clock functions are trusted application boundaries. Component
tests use genuine SDK cryptography with simulated HTTP; they are not an actual
browser, hosted database, device, hardware or carrier acceptance result.
