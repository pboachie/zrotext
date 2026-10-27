# Passive typed assertion clock candidate

This source candidate is separate from current content selection and all older
status/session parsers. Its schema and synthetic vector describe structural
bytes. Neither establishes an authenticated clock, an original enrolled actor,
a retained accepted grant, a durable phone phase or an invocation permit. The
complete storage, transport and Android producer still need independent review
and actual application qualification.

The request is the closed `payload_profile_history_clock03_request` object with
`v`, `connection_epoch`, `request_id`, `message_id` and `attempt_id`. The closed
reply is `payload_profile_history_clock03` with those correlation fields plus
`account_id`, `device_id`, `server_time_ms`, `sample_expires_ms` and `lease`.
The lease contains only `site_id`, `instance_id`, `deployment_epoch`,
`line_activation_version`, `enrolled_signing_key_id`, `device_session_digest`
and `expires_ms`. Connection epoch and activation version are JSON integers;
other numeric lease values and times are canonical positive decimal strings.

The server must begin a genuine native transaction and require the distinct
typed-effect capability. Its held history reader checks the actual original
grant and enrolled point against the signature-verified socket claim and the
current full lease, under the root/account/anchor order. This read needs no old
owner, ciphertext, physical selection or suppression-health handle. Missing
original actor or attempt refuses. Current key lookup alone is no socket proof.

Only after the final held actor read and its waits does the server sample the
actual primary clock. The sample deadline is the lesser of that sample plus
thirty seconds and the actual held lease expiry. The server commits before
sending; it renews no anchor, business state, lease or deadline. Read admission
and the shared typed request budget apply across the actual actor's connections.

The phone retains the fresh request and actual epoch before I/O. It must compare
the actual authenticated host with its original configured-origin pin, require
exact nonce/message/attempt/actor/lease correlation and monotonic RTT at most two
seconds, and retain the original enrolled-key witness. Its conservative upper
at receive is server time plus RTT, then advances by monotonic elapsed time.
Overflow, regression, host/epoch change or an upper at either expiry refuses.
An old status, exact historical reply or wall-clock value cannot supply this
clock. A missing original origin pin remains unsupported historical state.

For a new outcome command, `observed_ms` is explicitly the first durable
authenticated assertion time. The raw callback and its original wall time stay
separate and immutable. Aggregate, timeout, crash and conflict evidence first
retain their own derived source fact and event ID with exact underlying facts;
they cannot reuse a sent-segment event ID or infer missing success. Once the
exact command exists, UNKNOWN, reconnect and Stop cannot replace its time, bytes
or identity. Earlier unqualified commands are not translated or backfilled.

Permanent pre-entry closure requires the same local writer to withdraw the RAM
permit and commit an entry-excluding closing barrier before any clock wait.
This barrier alone proves no server acceptance and releases no resource. Only
a genuine sample and a final CAS proving zero entry, callback or conflict can
retain the final closed record. Missing storage/time or ambiguous state remains
UNKNOWN. A separately signed closure proof and guarded server commit can release
only device busy, retaining quota, grant/attempt and all replay tombstones.
