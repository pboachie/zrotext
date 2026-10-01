# Authoritative message summaries

The owner dashboard reads account or selected-device metadata from
`GET /v1/owner/message-summary`. An owner session and its matching CSRF header
are required. Observers cannot use this endpoint. The optional `device_id` must
belong to the session's account. A foreign or missing device returns `404`.

`GET /v1/message-summary?device_id=<uuid>` exposes the same device summary to
clients using a bearer API key with `messages:read` permission and a compatible
device binding. This endpoint requires an explicit device; it never expands a
device request into an account aggregate. The Android home screen does not yet
consume this contract. Both endpoints return `Cache-Control: no-store`.

The response follows [the schema](../protocol/v1/message-summary.schema.json).
It contains scope, optional device identity, UTC day boundaries, observation
time, maximum age, count bound and three metadata counts. It contains no
recipient, body, SIM information or credential.

## What the counters mean

- **Submitted today:** distinct messages whose first complete successful sent
  callback produced the writer's `sent_callback_ok` / `submitted` event. The
  server receipt time determines the UTC day, not the device clock. Partial
  multipart callbacks, failed attempts and unknown outcomes do not qualify.
  Later duplicate callbacks or conflicting evidence do not recount a message.
  Submission is historical evidence, not proof of recipient delivery.
- **Waiting or claimed:** current `accepted`, `queued` or `claimed` messages.
  This includes claimed work with grants; it is not an ungranted queue depth or
  proof that a device is ready to send.
- **Submitting / awaiting receipt:** current `submitting` or `submitted`
  messages. Terminal and unknown states are excluded.

Counts use one database statement and one MVCC snapshot. Each indexed probe
reads at most 1,001 matching rows. Values through 1,000 are exact; more matches
return `value: 1000, capped: true`, rendered as `1000+`. Exact zero is distinct
from unavailable data. A timeout or absent metadata returns `503`, never zero.

The day is the half-open interval from UTC midnight to the next UTC midnight,
always 24 hours even when the database session uses a daylight-saving timezone.
The response is valid for at most 30 seconds and never beyond its day boundary.
The dashboard ages observations using elapsed time, including request latency,
and labels retained observations stale after failure or disconnection. Clock
rollback cannot revive an expired observation.

The dashboard offers an explicit scope selector and refresh button. Automatic
refresh is limited to approximately every 15 seconds while visible, online and
eligible for refresh; resume and reconnection restore freshness. Scope changes
clear old values and fence late responses. Sign-out clears the observation.
These totals are independent of paginated message history and local journals.

## Storage and deployment

Migration `070_message_summary_metadata.sql` stores one immutable first-submit
receipt per message. A database trigger captures writer evidence in the same
transaction as the event. Receipt metadata survives event-history retention;
message or device deletion cascades its removal. Admission, grants, quotas,
suppression and delivery state transitions are unchanged.

Before applying the migration, the migrator builds the account queue index
concurrently and validates its definition. The migration installs receipt
indexes, backfills the earliest retained qualifying event per message, and
installs capture under one transaction and a bounded event-table lock. Its
one-second lock deadline and ten-second statement deadline deliberately fail
deployment rather than exposing incomplete counts. Large retained histories
need a reviewed maintenance plan. Existing evidence already deleted by
retention cannot be reconstructed by this backfill.

Readiness checks reject missing, invalid, disabled or differently defined
indexes and capture triggers. They do not turn an unavailable aggregate into
an empty result. Apply the complete contiguous migration sequence with the
normal migrator; do not skip its migration checks.
