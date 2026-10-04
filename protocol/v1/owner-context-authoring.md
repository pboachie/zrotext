# Isolated owner facts authoring module

`sdk/typescript/src/owner-context-authoring.ts` provides an isolated browser
editor for local facts review and initial encrypted owner context publication.
It is packaged by the existing conversation browser packager. It is **not
integrated into the ordinary owner page**, and does not mount candidate routes,
issue credentials, enable SEND or make any application available.

The caller supplies real post-enrollment owner and custody callbacks. All
required signer/reader enrollments must finish before construction and the fresh
manifest used to encrypt the facts. Original-reader setup, separately approved
phone selection and accepted manifest history remain unchanged. The small real
page integration depends on that setup source and remains separate work.

## Closed construction and lifetime

`createOwnerContextAuthoring(options)` returns a frozen object exposing only
`close()` and `state()`. State contains the presentation phase and a copied
minimal pending unknown identity; it never exposes plaintext, keys, ciphertext
or the client's opaque ticket.

Required options are:

| Field | Supplied value |
| --- | --- |
| `enabled` | Boolean; only `true` enables authoring |
| `origin`, `host` | Canonical HTTPS origin equal to the host document's actual origin, and its presentation element |
| `binding` | Exact existing owner account/session/device/line/interval/generation/peer/phone-reader/archive-reader selection |
| `contextId`, `expiresMs` | Nonzero 16-byte context ID and positive signed-63-bit millisecond expiry, fixed for this authoring operation |
| `readCurrent` | Actual post-enrollment `custodyOptions.readCurrent` callback |
| `currentCsrf` | Existing setup transport's current CSRF callback |
| `archiveLease` | Existing archive lease; only its closure subscription is used |
| `onSetupClose`, `onCustodyClose` | Existing lifecycle subscriptions; optional returned unsubscribe functions are cleaned up |
| `signal` | Caller-owned abort signal |

Optional fields are `timeoutMs` and `observationMs`, each an integer in 1..10000
(default 10000), and trusted `fetchImpl` for a fixture/application transport.
Unknown option fields, accessors, invalid identifiers, mismatched origins and
invalid bounds are refused. Binding/context byte arrays are copied before work.
Disabled construction performs no authority, encryption or network operation.
Construction attaches lifecycle subscriptions before those operations.

The existing bootstrap provides authenticated observation time and current owner
status, but no session-expiry or authenticated lease duration. `observationMs`
is a conservative local freshness policy, **not a session lease**. Each actual
current callback is timed from its monotonic request start; elapsed callback and
verification time consume that budget. Current branded manifest, exact binding,
role-1 phone reader, role-2 archive reader and selected active role-4 device/line
signer are required. Their signed expiry and the context expiry shorten the
deadline. The underlying context client independently rechecks current authority
and server authorization/CAS still applies to every request.

One absolute owned deadline starts when review preparation begins, before
authority reads and HPKE sealing. It covers sealing, review, transport and
reconciliation, only shortens, and closes idle review/unknown records. Fresh
callbacks, retries and checks never renew it. Setup, archive or custody loss,
signal abort, pagehide, hidden document, invalid current owner or an edit during
the operation closes the module. Cleanup continues after a failing unsubscribe.
Void setup subscriptions remain owned by setup until its own closure.

## Genuine local review and outcomes

The editor labels its controls Facts, Review facts, Save encrypted facts, Retry
same save, Check saved facts and Clear. Facts are 1..32768 UTF-8 bytes. Review
shows the exact local facts as text, selected account/line/peer and expiry.
Plaintext is never interpreted as markup or included in a request or storage.

Review preparation snapshots facts and immutable scope. It uses maintained
`sealWorkflowContext`, current role-2 authority, fixed kind 1, revision 1 and
expected revision 0. One request UUID is generated for this exact operation.
The consumed visible Save decision is compared with the copied scope, request,
revision and complete encrypted-envelope SHA-256 digest. No fictitious routine
input credential or integration reader grant is introduced.

The underlying [owner context client](owner-workflow-context-client.md) publishes
the exact binary ciphertext using browser-managed same-origin cookies/CSRF.
Only the actual POST acknowledgment and byte-identical independent latest GET
produce a momentary saved/current observation. A historical acknowledgment
alone does not prove the source is current. Saved plaintext and caller buffers
are scrubbed; this one initial-authoring module does not restart for another
write. Compatible revision refresh is a future page integration cut.

Bare first refusals remain refusals. An unknown attempted write clears all local
plaintext immediately and keeps its original ticket/ciphertext only until the
original deadline. Retry same save explicitly reuses that ticket, request,
expected revision and ciphertext; there are at most three total POST attempts.
Check saved facts performs at most three latest reads. Matching current bytes
without request acknowledgment leave the operation unknown. Exhausted controls
are disabled and cannot create a replacement identity or advance CAS.

Close/expiry preserves the minimal unknown request/context/revision/digest
identity and useful unknown status if the document remains alive, while removing
plaintext, ciphertext and usable controls. Close never proves cancellation or
permits another context/client/business identity as a reset. This module writes
no persistent unknown store and cannot claim cross-reload resolution.

Owned plaintext/envelope buffers are zeroed and DOM values/references removed.
JavaScript strings and WebCrypto internal copies cannot promise physical
zeroization. Late callbacks/rejections are observed without restoring content,
creating a ticket or returning success after teardown. Shared custody is not
closed by this editor; its loss closes the editor, and no private-key accessor
is used.

## Evidence and deferred acceptance

SDK tests combine authentic signed manifests/HPKE with a presentation fixture.
The Chromium test imports the actual packaged ESM module, uses native browser
fetch and HttpOnly cookies/CSRF against synthetic HTTPS intercepted routes,
and exercises visible review, saved/current observation, conflict, unknown
checking and identical retry, archive loss and pagehide. Browser prerequisites
are an explicit skip in SDK-only environments; ordinary owner-browser CI
installs them before SDK tests.

This is isolated-module evidence. It does not execute the ordinary setup/sample
integration, an authenticated mounted server, root/phone enrollment, purpose
consent, original inbound application journey, physical device or carrier.
The real-page integration and mounted candidate routes remain unavailable until
their separate reviewed cuts. Customer routine output publication remains
initial-only with its assigned context/call/digest semantics; local owner facts
do not rebind a routine, reset quota or grant SEND. Complete catalog acceptance
remains open.
