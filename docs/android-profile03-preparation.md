# Journaled Android profile03 preparation

The Android source now composes the existing profile03 public proofs, reviewed
intent, durable preparation journal and maintained Wolf recipient. It remains
an **unmounted integration component** under [#1054](https://github.com/pboachie/zrotext/issues/1054).
The authenticated setup/current-projection reader and ordinary shipping socket
caller are separate requirements. An adapter input or persisted row does not
provide those missing authorities. This change does not enable messaging,
change a release version, approve an SMS or establish Play readiness.

`Draft02TrustStore.historicalElectionCheckpoint` supplies genuine02 history from
the previously compared and accepted encrypted root store. It verifies the
retained record and its original acceptance time, then rechecks the independent
current clock. It does not accept a downloaded checkpoint, create a root/key,
advance a revision, replace the original bytes or use stored time as present
permission. The store's accepted genesis has the original zero anchor; later02
updates were checked through that same store. Restored valid old snapshots still
require independent current selection and cannot claim rollback resistance.

## Local election and effect fences

Room schema15 adds bounded, permanent `profile03_elections` provenance. A reserve
burns the exact challenge before device signing. Signing and accepted installation
are separate compare-and-set transactions. The original core, device signature,
old/new immutable binding mapping and accepted identity cannot be replaced on
retry. Exact installed replay returns the original row without renewing time.
No read reconstructs a live SIM or session permit. There is no reset, eviction
or downgrade path; capacity exhaustion refuses.

The first transition refuses prior sealed preparation history and unresolved
local effects. Reservation and installation recheck the original line under the
same writer acquisition. Pending election fences the old02 preparation and
legacy radio reservations. An abandoned ceremony can release that fence only
while it has never released a device signature. Every ever-signed or accepted
election remains an irreversible unknown-effect/downgrade fence after retirement;
local retirement cannot retract an in-flight proof or establish remote rejection. A03
preparation requires its exact installed row within the same Room transaction as
the one-use preparation reservation. A03 radio reservation additionally requires
that exact installed row and its already prepared message/attempt row.

The physical selection remains the original, opaque complete-list v2 SIM permit.
Election's new binding generation is checked separately. The code does not edit
the old activation generation or manufacture a new v2 permit. Permission loss,
SIM/selection callbacks, process loss and a missing installed permit refuse.
An unresolved different local attempt blocks preparation; the current attempt is
excluded only so its own durable radio reservation can finish its existing
one-use consume path. A retained preparation still blocks replay of that attempt.

## Reviewed ciphertext and recipient ordering

`ReviewedIntent03` decodes the existing closed ZTRI01/03/03 contract, including
all IDs, full signed64 integers, exact ordered recipients and mandatory ceiling1..6.
It checks the role5 low-s raw64 signature, owner-session and origin commitments,
selected binding/election/manifest identity and the immutable authenticated
admission time. Later delivery verifies review expiry at the original admission
instant and independently checks current message/grant/permission deadlines.
It never extends either signed deadline or renews the review. The caller must
authenticate the receipt, current owner/interval and selection epoch.

`Draft03OutboundPreparation` requires that reviewed intent and its exact grant,
original election proof, fresh current selection, manifest and enrolled physical
recipient. It checks the actual same-Room installation and live v2 SIM permit,
then verifies the exact ciphertext signature, routing, readers and both digests.
Only after committing the permanent `sealed_preparations` row does it look up
the existing nonexportable hardware recipient and call
`WolfHpkeKeystoreReceiver`. The exact nonempty, distinct profile03 HPKE info/AAD
come from the verified envelope. There is no02/JCA, software-key, empty-AAD or
alternate-provider fallback, and API28–30 refuse before authority/key/journal use.

Every blocking authority, Room or key operation is followed by trusted-time and
currentness checks. The additive `openCurrent` receiver operation rechecks a
RAM-only session/time/installed-SIM guard after recipient acquisition, each
Keystore ECDH wait and the lifecycle's final identity check. It clears an opened
CEK if a later guard or lifecycle check refuses. The guard never acquires Room,
network or another key while custody is held. Full current-record checks remain
outside that lock, before and after opening. Original primitive opens and all
provider negatives remain separate; no callback failure chooses another provider.
The guard's RAM deadline is the minimum of the verified manifest and selected
keys' expiry, the checked message deadline, current permission, interval and grant.
An adapter-supplied lease cannot extend verified key or manifest validity.
The CEK is consumed and cleared; strict body authentication,
the signed UTF8 body digest and actual selected-subscription segment division
must pass. A prepared holder rechecks before its single consume and clears its
owned characters on consume, close or error. Failure after reservation aborts
the row but never deletes the replay fence. Platform/provider internal copies
cannot be guaranteed erased. No plaintext is logged or persisted.

The distinct [typed submit consumer](android-typed-submit03.md) accepts additive03
metadata without converting a03 grant into02 fields. Its exact durable command,
fresh submit-specific writer ACK, local suppression, selected-card continuity and
same-writer one-use entry remain mandatory. It does not insert an alpha event or
consume a legacy radio-start CAS. Throws after entry remain unknown, with no retry.

## Signed fetch transport and verification limits

`SealedEnvelope03Client` sends the existing exact Fetch03 transcript and canonical
DER device proof to the separate03 endpoint. It disables cookies, authentication
fallback, redirects, caching and automatic retries, bounds the response and
rechecks currentness around signing and network waits. A strict raw JSON decoder
rejects duplicate names before projection, integer coercion, malformed UTF8,
unpaired surrogates, unknown fields and noncanonical binary data. The returned
packet owns exact ciphertext/review bytes and remains explicitly **unverified
public evidence** until the real authenticated current-projection reader accepts
it. An empty projection in a transport unit fixture is not an authority handle.

JVM controls use genuine synthetic02/03/election/intent signatures and real body
GCM, plus the actual complete-list v2 runtime/Room journal with synthetic SIM
observations. The positive preparation-order control reaches the missing Android
Keystore boundary only after journal reservation, then aborts and refuses replay.
It does not open an HPKE wrap. Intercepted HTTPS tests prove transport framing,
not a hosted transaction. Full authenticated composer/admission/current fetch,
maintained-provider opening over the enrolled key, instrumentation, physical
carrier behavior, reconnect/bootstrap acceptance and Play readiness require
their own executed integration checks.

The maintained-bridge AndroidJUnit4 source also defines withdrawal at each actual
hardware guard boundary and callback cleanup before a separate primitive open.
That instrumentation requires its own explicit run; compilation or a JVM result
does not establish its outcome.
