# Fresh same-phone selected-SIM review

`SamePhoneSelectionReview` is the local pending-review component for
[#1551](https://github.com/pboachie/zrotext/issues/1551). It is not mounted in the
phone UI or refresh transport yet. It issues no device signature, owner approval,
writer acknowledgment, installed permit, Ready03 or radio permission.

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
permit can be published. That distinct transcript/ledger/transport remains a
required integration, independently of the original v2 activation evidence.

A displayed decision expires after30seconds and is consumed on confirmation,
including failure. A confirmed pending decision lasts at most5minutes, remains
bound to the exact new issuer lease, existing identity and current host/clock,
and is handed to a later refresh consumer once. Cancel, close, a new review,
session/clock loss, complete-set callback, key/history change or expiry withdraws
even a previously handed pending decision. Checks repeat after blocking identity
reads; cancellation withdraws at entry before waiting for the controller monitor.

The original activation/election/binding generation and attempt history remain
unchanged. A pending phone decision cannot resolve an unknown effect or become
current SIM continuity. Genuine current-refresh installation, message fetch
binding to that receipt and the no-radio reconnect journey need their own executed
source and runtime checks. New-phone replacement is the distinct proposed
operation in [#1469](https://github.com/pboachie/zrotext/issues/1469).
