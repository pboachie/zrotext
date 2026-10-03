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
capabilities. Its one thousand immutable identities cannot be pruned to reopen
an old action. Customer filesystem permissions must protect the file, directory,
WAL and backups. Windows ACLs require separate customer configuration.

Local wall time selects wakeups and conservative stops only. Server database
time, current owner decision and exact current credential remain the effect
authority. Missing owner ciphertext and offline phone responses stay waiting;
each subsequent known waiting poll uses a fresh request identity. A durable
unknown checkpoint precedes Send. After a timeout, lost response or restart,
only current action status is queried. Approved status alone cannot prove a
lost Send rolled back. The runner never automatically retries that unknown Send
or creates another binding. An exact action's observed dispatch resolves its
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

No renderer adapter or automatic independent approval of recurring actions is
provided. Each recurrence needs its own exact owner-approved encrypted action.
Physical phone/carrier acceptance and complete response/takeover projection
remain separate #639 acceptance requirements.
