# Dormant owner workflow context client

`sdk/typescript/src/owner-workflow-context-client.ts` supplies a browser-only
transport for already encrypted owner archive contexts. It uses the existing
ZTWC version 1 envelope and candidate owner context HTTP contract. This document
does not introduce a wire format, mount a router, or enable an owner application.

The caller can author revision 1 with expected revision 0, or write revision
2..128 with the preceding expected revision. It seals local plaintext with the
maintained `sealWorkflowContext` codec before passing opaque bytes to this
client. The client never accepts plaintext, private keys, integration credentials,
model/tool arguments, or arbitrary authentication headers.

## Supplied authority and owner review

Construction requires an explicit `enabled: true`, canonical HTTPS origin,
immutable selection, current-owner callback, current CSRF callback, consumed
owner review callback, and an abort signal. Disabled clients perform no work.
The current-owner adapter is a trusted application boundary, separate from
context content and integration credentials. It must supply the actual current
owner session, active interval, selected device/line/binding, peer and archive
reader, current verified manifest, authenticated time and remaining lease.
The library does not implement that adapter or infer authority from a context.

`readCurrent` returns the maintained `ConversationSignerCurrent02` shape plus
`phase: 'active'` and `validForMs` in 1..60000. The client requires the branded
manifest, independently re-verifies its encoded bytes using its verified trust,
checks the exact selected binding and scope, and uses the maintained role-2
workflow reader authorizer. Boolean owner/consent flags alone cannot authorize
an unverified manifest or substitute another binding. Role-3 integration
contexts are refused, even when their ciphertext and signed manifest are valid.

Selected account, session, device, line, interval, binding generation, peer,
archive reader, context ID and kind cannot change within a client. Manifest
version may advance under the same root/trust generation; rollback and a changed
digest at the same version close the client. Each operation must use the actual
current manifest. Compatible source refresh changes neither execution grants
nor their usage accounting. Server authorization and compare-and-swap still
apply to every request.

`consumeWriteReview` receives cloned scope bytes and frozen metadata identifying
request, context, expected/new revision and the complete ciphertext digest. It
must consume a real owner decision for that operation. The application owns the
local plaintext review and must bind it to these exact bytes. This callback is
not a model approval. Mutating its cloned arrays cannot change the internal
selection, ciphertext or request. Authority and CSRF are checked again after
review and immediately before publication.

## Tickets, transport and current content

`prepare({requestId, expectedRevision, scope, envelope})` validates closed data,
copies the caller's bytes before any await, verifies their complete header and
public encapsulation point, reviews them, and returns an opaque client-owned
ticket. A request ID is a canonical nonzero UUID. Expected revision is 0..127;
the header revision must be exactly expected revision + 1. The fixed header and
ciphertext length must describe an envelope of 308..33075 bytes.

`commit(ticket)` performs one POST to `/v1/owner/workflow/contexts` with:

- `Content-Type: application/vnd.zrotext.workflow-context.v1`;
- `idempotency-key` equal to the reviewed request ID;
- `x-zrotext-context-revision` equal to the reviewed expected revision;
- `x-zrotext-csrf` equal to the current browser CSRF value;
- the exact copied ciphertext as its body.

The browser manages session/CSRF cookies. Fetch uses `credentials: 'same-origin'`,
`mode: 'same-origin'`, `redirect: 'error'` and `cache: 'no-store'`; the client does
not synthesize Cookie, Origin or Authorization headers. Its default native
fetch is bound to the browser global. An injected fetch is a trusted test or
application transport, not an untrusted request input. Redirected responses or
responses identifying another URL are refused as unknown.

A successful POST must return HTTP 200 with JSON content type and exactly the
canonical compact object `{"revision":N}` for the reviewed revision. The
success stream is bounded to 64 bytes. Extra fields, duplicate JSON aliases,
unexpected revision, malformed UTF-8 or unexpected success representation leave
the result unknown.

Acknowledgment does not prove the acknowledged revision is still the head.
The client independently GETs `/v1/owner/workflow/contexts/{id}` with **no
revision query**. It requires the exact binary content type, reads at most
33075 bytes before aggregation, and compares every returned header/ciphertext
byte with the retained envelope. It then rechecks current authority.

The resulting receipt contains request ID, context ID, revision, ciphertext
digest, `state: 'verified_current_snapshot'`, and `requestAcknowledged`. This is
a momentary current-content observation, never an execution grant, reservation,
service input binding, or permission to bypass a later current-source check.
An explicit historical GET is not a latest-head proof.

After a known acknowledgment, a valid genuinely newer head under the current
manifest and the same immutable context binding returns
`OwnerContextError('head_changed', 'not_current')`. The client does not overwrite
that head, change CAS, or start another context automatically. Malformed or
foreign heads, altered bytes at the same revision, changed immutable scope and
unverifiable authority remain unknown; they do not establish `not_current`.

## Refusal, unknown outcomes and teardown

Actual candidate context failures use bare HTTP statuses. For a first attempted
POST, 400, 401, 403, 404, 409, 413 and 429 are known refusals; response JSON is not
required. A conflict remains a conflict. HTTP 503, unexpected statuses,
transport failures, timeouts, invalid success, or failed latest reconciliation
after an attempted write remain unknown.

An unknown write retains its request ID, context ID, revision and ciphertext
digest in `pending()`. Its owned ticket also retains the identical ciphertext,
expected revision and request ID while its original deadline remains live.
`retryUnknown(ticket)` is explicit and reuses the complete tuple; it never
reseals HPKE, changes request ID, advances CAS, or extends the deadline. There
are at most three POST attempts in total. A later 403/404/409 cannot erase an
earlier unknown write or turn it into permission to create a replacement.

`verifyUnknown(ticket)` performs only a latest read, at most three times. Matching
current bytes return `requestAcknowledged: false`: GET has no request ID or
stored request-digest metadata, so it cannot acknowledge a particular unknown
POST. The original ticket and pending identity remain. Only an acknowledged
exact POST replay followed by current-byte equality returns
`requestAcknowledged: true` and consumes them. An unacknowledged newer head
also leaves the original request unknown.

One client has at most one prepared/pending write and one operation in flight;
there is no implicit queue. The operation has a single absolute monotonic
deadline, at most 10 seconds, beginning at preparation and covering authority,
crypto, review, transport and streamed reads. Authenticated lease, manifest,
reader and context expiry can only shorten it. Attempts do not renew it.

`close()`, signal abort, deadline expiry, or loss of current owner/CSRF authority
aborts the owned transport and scrubs its ciphertext buffer. Late review,
authority and network completions cannot publish a receipt. Minimal unknown
identity remains observable after close; close does not prove cancellation,
free permission, or provide a reset/reopen operation. That identity is not
persisted by this library. The caller must keep the unresolved operation visible
and must not treat constructing another client as its resolution.

The application must connect pagehide, visibility/custody loss, logout and
session change to the supplied abort signal or `close()`, scrub its own transient
plaintext, and obtain fresh real authority before any later independent work.
This client writes no local/session storage or plaintext cache.

## Compatibility and acceptance boundary

`CustomerRoutineService.publishArchive` remains initial-only: expected revision
0 and produced revision 1. Routine output context identity, assigned call ID,
recorded ciphertext digest, `bindOutput` and `call()` are unchanged. Owner source
refresh is a separate operation; it cannot widen an existing service credential,
rebind a routine source, reset quota, or confer SEND permission.

Ordinary SDK tests use the maintained signed manifest and HPKE codec. The
packaging test uses the existing browser packager. The Chromium test imports
that actual ESM/HPKE graph and exercises native fetch, browser-managed HttpOnly
session cookies, CSRF, latest reads and bare failures against synthetic HTTPS
routes. The ordinary owner-browser CI job installs its pinned browser tooling
before SDK tests; a SDK-only environment without that tooling reports an
explicit Chromium prerequisite skip.

These tests do not prove a mounted candidate server, enrolled owner custody,
physical phone, carrier/provider delivery, purpose consent UI, a multi-peer
application journey, stable business-resource source rebinding, or the catalog's
application availability. Those prerequisites and acceptance criteria remain
separate from this dormant client capability.
