# Recipient-local encrypted scheduling

This is a dormant candidate library, not an activated scheduling service.
`encrypted_schedule::time` resolves recipient-selected windows using the
PostgreSQL IANA timezone database. `encrypted_schedule::policy` gives an
immutable identity to their bounded cadence and pacing metadata. No runtime
worker, HTTP route, provider call, phone command or sending gate is enabled by
these helpers.

## Exact time and policy identity

A local window names a calendar date, an explicit timezone and opening/closing
minutes. An earlier closing minute means the next calendar day. Missing or
unknown timezones wait for owner review. Nonexistent or ambiguous opening or
closing civil times also wait for review; they never select an arbitrary UTC
instant. PostgreSQL normally chooses an offset for those values, as described
in its [timestamp handling documentation](https://www.postgresql.org/docs/17/datetime-invalid-input.html),
so a bare `AT TIME ZONE` conversion is insufficient. The resolver enumerates
nearby offsets and verifies exact local-time round trips at both boundaries.
Its bounded query includes second-resolution historical offsets and the
skipped civil day of a dateline change. The server session timezone does not
change the result. A real invalid calendar date is rejected.

Occurrence resolution advances local calendar days rather than adding 24 UTC
hours, preserving the recipient's wall-clock window across DST. The timing
helper treats expiry as terminal even during owner review, honors not-before
and pacing, and identifies missed windows. Being inside a window is timing
metadata only; it never grants execution or authorizes a retry.

A policy includes timezone (or explicit unknown), first local date, opening and
closing minutes, optional recurrence interval, maximum occurrence count and
minimum pacing seconds. It allows at most 100 occurrences, recurrence every
1–365 days, and pacing of 60–86,400 seconds. With no recurrence, the count must
be one. The policy identity is `window-v1-` followed by lowercase SHA-256 of
`ZT/window-policy/v1\0` and UTF-8 JSON containing all fields with sorted keys
and no whitespace. Null timezone/recurrence values remain explicit fields.
Every policy change produces a different identity. Calendar validity and
timezone ambiguity still require resolution; a policy hash grants nothing.

## Shared authority boundary

The [exact workflow action contract](../protocol/v1/workflow-action-contract.md)
binds the policy identity in `window_id`, timezone, not-before and expiry, along
with the exact encrypted content reference and recipient/purpose/routine.
Scheduling integration must validate those bindings against a live approved
action, never accept a caller-selected authorization boolean or reconstruct
authority from a stored actor identity. The shared decision service owns
approval and context/routine takeover fences; the scheduler must consume its
transaction-scoped permit and recheck after blocking writes.

Each recurrence occurrence needs its own exact approved encrypted action. A
single action has one stable dispatch identity and becomes terminal; recurrence
metadata cannot make an old approval authorize another effect. An unavailable
authorized renderer or unconfirmed next occurrence waits and still expires.
Unknown outcomes require authoritative reconciliation and never automatically
become a new attempt. Consent withdrawal, qualifying responses, human takeover
and cancellation must share the decision service's fence and existing unsent
message cancellation semantics. A grant winner cannot be described as prevented.

Migration 077 and `encrypted_schedule::store` supply immutable account-scoped
policies, series and exact-action occurrences. Scheduling, claiming, deferring,
cancelling and starting dispatch consume the shared transaction-bound approved
action permit. A request replay preserves its occurrence and dispatch identity;
a changed request conflicts. A claim has a 30-second, expiry/window-capped lease,
and pacing applies across the request's routine rather than resetting for a new
series. Renderer/phone absence waits without creating another queue or extending
the deadline. An already-bound action cannot adopt an arbitrary dispatch marker:
reserve first, then separately confirm the exact encrypted message using that
reserved marker. Dispatch checks that immutable link again.

The initiating owner session remains part of the effect fence through actual
phone grant and durable intent. Missing, revoked or expired sessions refuse
effects; stored IDs cannot manufacture credentials. Migration 077's integration
actor branch refuses every effect until a separate real executor-grant adapter
extends its predicate. Such an actor identifies the exact executor grant UUID,
never a connector-wide identity. Independent schedule/send permissions cannot
replace owner approval. Deferred constraint guards check attempts, dispatch
fences and durable-intent events again at commit after blocking writes.

Authoritative reconciliation maps the existing message state; delivered means
this occurrence's transport completed, never that a shared commitment was
fulfilled. Unknown outcomes do not retry. Owner export includes independently
paged policy/series/occurrence/audit metadata with account-bound cursors. Account
erasure explicitly removes all four planes. Bounded retention uses the configured
sealed-content retention interval, preserves still-live action replay identities,
and removes ended expired work before orphan audit/series/policies.
A separately reviewed noninteractive capability is also required before an
unattended worker can replace live owner-session-driven candidate operations.

## Regression checks

The Rust suite discovers policy regressions automatically. PostgreSQL tests
under `encrypted_schedule::time::tests` are explicitly ignored without a
disposable `ZT_AUTH_TEST_DATABASE_URL`. They cover DST gaps/overlaps and windows
crossing transitions, overnight windows, unknown zones, timezone changes,
invalid dates, a skipped civil day and independence from session timezone.

```sh
cargo test --locked -p zrotext-server encrypted_schedule
cargo test --locked -p zrotext-server encrypted_schedule -- --include-ignored
```

The suite also executes the actual migration and real shared-action PostgreSQL
fixtures for replay, missing rendering, exact encrypted message links and live
owner-session effect refusal. These checks do not prove physical carrier delivery.
There is no unattended worker, owner scheduling UI, authorized content renderer,
or activated runtime endpoint in this candidate. Those remain integration work;
no gate is enabled by this library.
