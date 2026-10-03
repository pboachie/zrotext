# Customer-owned scheduled workflow runner

This default-off candidate uses the real HTTPS `WorkflowToolClient`. It is not a
relay worker, renderer, approval service or physical-send release. Install it
explicitly with `enabled: true`, a current customer-owned credential and a
private absolute SQLite journal path. The grant must independently include
Status, Schedule and Send; each backend call still rechecks current authority.

`enqueue` reserves the actual approved action and canonical server occurrence.
`run({signal})` polls at five-second intervals, bounded to twenty records per
cycle; `advance(action_id)` runs one cycle. The journal retains exact action,
occurrence, server window/expiry and returned dispatch identities across process
restart. It contains no credentials, plaintext, encrypted content or approval
capabilities. Its one thousand identities, including retired replay tombstones, cannot be
pruned to reopen an old action. Customer filesystem permissions must protect the file, directory,
WAL and backups. Windows ACLs require separate customer configuration.

Local wall time selects wakeups and conservative stops only. Server database
time, current owner decision and exact current credential remain the effect
authority. Missing owner ciphertext and offline phone responses stay waiting;
each subsequent known waiting poll uses a fresh request identity. A durable
unknown checkpoint precedes Send. After a timeout, lost response or restart,
only current action status is queried. Approved status alone cannot prove a
lost Send rolled back. The runner never automatically retries that unknown Send
or creates another binding. Prepared records also poll status only. A refusal,
expired/invalidated action phase or unavailable projection does not prove the
previous effect rolled back; the last receipt/request remain reconciliation metadata
and are never pruned as resolved. Only authoritative cancellation resolves cancellation. An exact action's observed dispatch resolves its
existing metadata; unknown or unavailable evidence does not imply delivery.

`cancel(action_id)` invokes the actual own-prepared cancellation tool and its
pre-grant refund CAS. It does not approve, render, revoke an owner decision,
cancel another grant's message, or cancel future recurrence. Disabling the local
runner stops local polling and invalidates pending reads before a new Schedule,
Send or Cancel request. Its own lease is released without replacing waiting or
unknown journal state, so a newly enabled instance can resume safely. A request
already dispatched may still complete and its actual result is recorded; disable
is not a remote grant withdrawal. Owner grant
withdrawal and independently authenticated owner decisions remain necessary for
broader cancellation. No credential is reconstructed from a stored actor ID.

`enqueueOccurrence` reserves one explicitly supplied recurring ordinal. Each
ordinal requires a distinct exact action and independent current owner approval;
neither the customer runner nor a previous ordinal can create or carry approval.
The server resolves civil-date recurrence with the existing timezone/window policy
and checks pacing and expiry. Missing authorized rendering still waits and expires;
this module does not create ciphertext or bypass exact owner binding.

`exportPage({after,limit})` exports all local schedule/recurrence metadata and
retired identity tombstones in bounded key order (default twenty, maximum one
hundred). Page cursors are local action IDs, not authority. `retain({beforeMs,limit})`
removes cancelled, expired or blocked records only after their occurrence expiry,
retaining a minimal replay tombstone. Request-bearing blocked/expired records from
older installations conservatively recover as status-only unknown; retention cannot
erase their reconciliation identity. Unknown and prepared records are not pruned:
absence of a receipt cannot prove an effect rolled back. `erase()` disables pending
calls, clears all records/tombstones and permanently fences this journal installation
across open instances and restart. It does not cancel remote work, erase owner/server
state or guarantee forensic deletion of SQLite pages, WAL, filesystem backups.

The owner-only shared `correlate_reply` service verifies an original signed phone
event and retained interval/manifest provenance before stopping its explicitly
selected request routine. The first bounded batch of unsent schedule cancellation commits with that stop,
including takeover; stopped authority fences all remaining work while the existing
worker drains further metadata batches. Prepared customer records continue status-only
polling to observe actual cancellation, without another Send; issued effects remain uncertain and cannot be refunded again.
The integration runner cannot submit a response classification or fabricate an
original event from owner-declared content. Current action status observes the stopped
authority and prevents a subsequent Send. The original-event selected customer-reader
bridge and physical phone/carrier activation remain separate, unavailable capabilities.
