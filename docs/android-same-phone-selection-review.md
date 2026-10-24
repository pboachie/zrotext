# Fresh same-phone selected-SIM review

`SamePhoneSelectionReview` is the local pending-review component for
[#1551](https://github.com/pboachie/zrotext/issues/1551). The connection screen's
“Review this phone's SIM again” action prepares and confirms a fresh observation.
`SelectionRefresh03Runtime` consumes the live profile03 socket's distinct
challenge, approved bundle and installation ACK. A local review alone issues no
owner approval, installed permit, Ready03 or radio permission.

Its Android adapter reads the actual authenticated phone host and nonce-bound03
metadata clock, existing nonexportable reader and enrollment signer, encrypted
compared root/02 position and original installed Room records. It captures a real
fresh complete-observation lease from the service's registered issuer. It never
reconstructs an old monitor, card/profile token, key or activation from saved bytes.

The review displays the retained logical line/generations and newly observed
selected subscription, SIM kind and complete-list count. The bounded first path
requires the same retained subscription ID; this does **not** establish the same
physical SIM across process lifetimes. The new observation requires a separate
current owner reapproval over the original registered sealed approval key, fresh
password/MFA and exact authenticated writer acknowledgment before any new live
permit can be published. The distinct496-byte core,745-byte bundle and80-byte
installed transcript are specified in the
[refresh03 candidate](../protocol/drafts/profile03-selection-refresh-candidate.md),
independently of the original v2 activation evidence.

A displayed decision expires after30seconds and is consumed on confirmation,
including failure. A confirmed pending decision lasts at most5minutes, remains
bound to the exact new issuer lease, existing identity and current host/clock,
and is handed to a later refresh consumer once. Cancel, close, a new review,
session/clock loss, complete-set callback, key/history change or expiry withdraws
even a previously handed pending decision. Checks repeat after blocking identity
reads; cancellation withdraws at entry before waiting for the controller monitor.
The monotonic RAM-only guard uses an atomic clock floor, so Room/custody checks
do not acquire the UI review monitor or read root storage, keys or the framework.

Room schema16 adds permanent `selection_refresh03` history. It reserves the
challenge before device signing and records acceptance plus a separate ACK
reservation before installed signing. Only the exact authenticated installation
ACK and same live issuer can publish a refreshed permit. It retains the original
activation/election and separately identifies the new physical approval. A stored
receipt cannot recreate a lost issuer. Every released proof remains fenced after
retirement, and unresolved bound or unbound radio effects refuse a refresh.

Schema18 retains a separate immutable `selection_refresh03_closures` journal.
An explicitly opened replacement for an expired never-approved refresh requires
the complete authenticated server chain, exact known records, original full
binding/election/device-session scope and a genuinely new foreground complete-SIM
confirmation after the old expiry. The chain and new reservation share one writer
before signing. Unknown intermediates remain server history without fabricated
local observations or proofs. Closed rows cannot accept late approval or install.
Every ever-signed refresh permanently fences original physical-selection fallback
for that full connection, including after retirement, expiry or closure. A fresh
opening cannot reuse an expired phone decision. Each binding/full connection is
bounded to sixteen retained reservations; no history is pruned to make room.

Device selection requires its closed `physical_selection` union, including the
actual installed refresh receipt when applicable. Message permission remains a
separate full current-owner projection. Preparation and radio checks retain the
exact opaque physical permit; a later review cannot translate existing prepared
plaintext or an older accepted message to a new selection. The server must also
retain and revalidate the exact physical receipt/session on admission/grant/fetch.

The original activation/election/binding generation and attempt history remain
unchanged. A pending phone decision cannot resolve an unknown effect or become
current SIM continuity. Source is mounted behind explicit encrypted-messaging
connection, but compilation, integrated server/database/provider qualification
and the complete no-radio reconnect journey still require executed checks.
The initial election's authenticated expired-unaccepted closure-chain recovery is
a separate dependent change; neither a timeout nor `not_accepted` releases an
ever-signed election. New-phone replacement is the distinct proposed
operation in [#1469](https://github.com/pboachie/zrotext/issues/1469).
