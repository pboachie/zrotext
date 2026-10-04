# Owner provider configuration declarations

This is an unavailable configuration foundation. Its candidate owner router is
not mounted by the server, and ordinary migrations do not install
`provider-configuration-storage-proposal.sql`. Saving a declaration establishes
no verified provider identity, sender eligibility, accepted policy, cost bound,
SEND grant, billing authority or usable provider route. No provider network
operation or credential storage exists in this module.

An owner can record and revise their intended configuration for later review.
Every acknowledgement and current detail response says `acceptance: unavailable`.
The declaration's organization, profile, sender and policy references are owner
assertions, including after successful persistence. They are not trusted facts.

## Candidate authenticated API

The router uses the maintained owner-session mutation extractor, account ingress
slot, cookie and CSRF verifier. POST additionally requires the exact configured
Origin. GET uses the maintained content-bearing owner read header and session
checks; it does not require an Origin that same-origin browsers omit. The
maintained first-value cookie/header semantics remain unchanged. API bearer
authorization is refused. Every response is `no-store` and `nosniff`.

| Method and candidate path | Request | Response |
| --- | --- | --- |
| POST `/v1/owner/provider-configurations` | mutation, expected version 0 | immutable metadata ACK |
| POST `/v1/owner/provider-configurations/{config_id}/revise` | mutation, positive expected version | immutable metadata ACK |
| POST `/v1/owner/provider-configurations/{config_id}/withdraw` | withdrawal, positive expected version | immutable metadata ACK |
| GET `/v1/owner/provider-configurations/{config_id}` | authenticated headers | current detail or withdrawn metadata |
| GET `/v1/owner/provider-configurations?after={config_id}` | optional scoped cursor | at most 20 metadata heads |

A mutation has exactly `request_id`, `config_id`, `expected_record_version` and
`declaration`. A withdrawal has the first three fields only. IDs are non-nil,
lowercase canonical hyphenated UUID strings. A path ID must equal the body's ID.
The expected version is an integer in the signed 64-bit range. The collection
create expects zero; revisions and withdrawal expect the positive current record
version. Unknown fields and duplicate fields, including escaped aliases, are
rejected through direct typed JSON deserialization. Bodies are capped at 8,192
bytes; ordinary JSON whitespace is accepted. This API is not the proposed
`workflow-action-02` canonical wire grammar.

The closed declaration fields are:

| Field | Type and restriction |
| --- | --- |
| `adapter` | exactly `telnyx-sms-v2` |
| `organization_id`, `messaging_profile_id` | non-nil canonical UUID strings |
| `sender` | `+` followed by 2–15 digits, first digit 1–9 |
| `owner_label`, `intended_region` | 1–64 bytes, each printable ASCII 33–126 |
| `retention_policy_ref`, `eligibility_policy_ref`, `cost_policy_ref` | absent, null, or non-nil canonical UUID string |

No enable flag, accepted-policy field, credential or caller-selected provider
authority is accepted. Private declaration bytes use deterministic typed JSON
serialization and a SHA-256 digest. The request commitment binds account,
configuration, operation, expected record version and these exact bytes. It is an
internal replay commitment, not a signed approval or protocol action.

## Revisions, uncertainty and technical bounds

The retained account can hold at most 64 configuration heads, counting withdrawn
heads. Each configuration has at most 16 immutable versions. Ordinary new
mutations stop at 960 retained mutation identities, within the fixed total of
1,024. The remaining 64 slots are reserved for one irreversible withdrawal per
possible retained head. Withdrawal occupancy also counts toward the ordinary
960 threshold; no request identity is evicted. These are technical storage
bounds, not business quotas, message budgets or monetary limits.

An exact request replay returns its original ACK even after later revisions,
withdrawal or capacity exhaustion. An ACK contains only `config_id`,
`config_version`, `record_version`, `state` and `acceptance`. It never returns the
declaration. Reusing a request ID with another operation, configuration, expected
version or declaration conflicts. A create cannot reopen a retained withdrawn
configuration. Revision requires exact compare-and-set and cannot exceed version
16. Ordinary record advancement is checked; withdrawal alone uses a saturated
monotone record fence at the signed integer maximum. Normal bounded API history
does not reach that maximum.

After an unknown POST outcome, a caller retains the original configuration and
request identity and exact input. A current GET is not acknowledgement of that
request. A replay ACK may describe an older saved version; the caller must obtain
current details separately. This module introduces no client retry loop or UI.

Every store operation locks and rechecks the actual current owner/account/session
through the maintained owner fence. A fresh owner recheck precedes commit after
later row waits. Schema absence makes the candidate API unavailable. Partial
installation fails closed. The API exposes no declaration acceptance factory.

## Withdrawal, export and account erasure

Withdrawal and acknowledgement commit in one transaction. It permanently changes
the head to `withdrawn` and sets every version's sole private declaration byte
representation to NULL. This removes the sender, organization/profile and all
other declaration fields together. It retains minimal head metadata, declaration
digests and metadata-only request ACKs for the retained account. A withdrawn GET
contains no declaration. An old exact POST replay likewise contains no private
bytes and does not establish current authority.

The SQL proposal permits only the exact non-NULL to NULL version scrub, with all
other version columns unchanged. A withdrawn head rejects new version inserts,
restored bytes and reopening. Deferred constraint triggers enforce the head and
private-NULL relationship at COMMIT, so a head transition can precede its scrub
within the same transaction without allowing an incomplete committed withdrawal.
These invariants do not claim protection against a privileged database operator.

The maintained owner export includes three bounded metadata pages under
`provider_configurations`: `heads`, `versions` (digests only), and `mutations`
(request IDs and ACKs). Each page holds at most 20 rows; cursors are account-scoped
and cannot select another account. Private declaration bytes never appear in
this inventory. The optional export is empty on a wholly absent schema, after
the same current-owner fence; a supplied cursor then is not found. A partial
schema refuses export. Current details remain a separately authenticated read.

The maintained full account erasure deletes mutation, version and head rows in
its existing password/MFA/current-session transaction. Missing schema contributes
no rows; partial schema fails and rolls back the erasure. No cross-account
identity retention or global configuration tombstone is promised after complete
account deletion. This cut adds no financial attempt or unknown-liability rows.

## Validation and remaining integration

Pure tests cover typed duplicate/escaped-alias rejection, bounds and replay
commitments. Discoverable PostgreSQL tests apply all maintained migrations in
unique disposable schemas, then explicitly install the unnumbered proposal.
They use actual register, email verification, login and session authentication,
the candidate router, maintained owner export and password-proven account
erasure. Controls cover CAS/replay, current-owner loss, account isolation,
absence/partial installation, immutable scrub and deferred rollback, version
limits, pagination and all 64 reserved withdrawals at the full 1,024 cap.

Installing a numbered schema, mounting a router, presenting an ordinary owner
review journey, verifying provider identity/eligibility, accepting processing and
retention policies, binding a genuine provider usage subject, and proving atomic
monetary admission remain separate reviewed dependencies. Saving an unavailable
declaration does not close those acceptance gates.
