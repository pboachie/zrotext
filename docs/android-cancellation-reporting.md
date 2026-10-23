# Saved cancellation reporting on Android

The typed conversation journal can permanently close a send before platform entry.
This preserves the original attempt; it does not establish remote acceptance or
authorize a retry. Missing callbacks, expiry and process death are not cancellation
proofs.

Message details offers **Report saved cancellation** and **Check saved cancellation
status** for one saved cancellation on this phone's original authenticated device
connection. **Next saved cancellation** selects another metadata record without
opening message content. Each reporting action captures that exact displayed row,
the current connection and a new foreground decision. Leaving the foreground or
changing the displayed selection withdraws that decision.

Reporting uses a distinct fixed closure challenge and the original enrolled hardware
signer. The journal commits a signature reservation before calling the signer and
retains an actual returned result before any further progress. A missing result
stays uncertain; it is never signed again under that challenge. A later explicit
recovery can request a new challenge only after fresh authenticated status/time
checks and an exact immutable predecessor link. All previous attempts remain saved.

Status and clock reads grant no send permission. An already accepted exact receipt
can be reconciled after a genuine same-device reconnect, independently of current
message content or the old owner session. Only a matching retained server receipt
completes the cancellation report. This path does not locally release a busy slot,
refund usage, reset a grant, recreate a key or invoke the SMS platform.

This is a source component. Its tests use synthetic sockets and ephemeral in-memory
test signing keys at declared boundaries. Compilation, Room execution, hosted
instrumentation, actual nonexportable custody, service integration and carrier
behavior require their own qualification; none is implied by a parsed challenge
or a saved local phase. Timeout/crash outcome producers and inbound capture remain
separate components.

Only a newly finalized cancellation creates the local proof-eligibility witness. The
first proof command atomically records its root on that original cancellation row.
An older migrated cancellation, a missing root or any missing predecessor, signing
burn or transport history cannot be adopted as unused. Lost first-command responses
retain that root; a new explicit decision may reconcile only the same saved command.

While Message details stays open, a genuine connection replacement or app resume
refreshes only the displayed metadata. Old decisions and pending display loads are
withdrawn. Reporting and status checks still require a new explicit action; this
refresh never requests a proof, clock or signature automatically.
