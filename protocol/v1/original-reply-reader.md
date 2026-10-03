<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Original reply reader candidate

This default-disabled candidate reads the original phone-signed profile-02
inbound event. It never substitutes an owner-declared workflow projection or
an archive wrap for integration-reader authority. Webhook authentication and
public envelope syntax alone do not authorize plaintext access.

## Explicit phone selection

An archive-only activation retains its exact `ZTCA` version-1 statement and
approval/install transcripts. A nonempty integration selection uses version 2.
All existing fields keep their original order. Its disclosure hash covers:

> With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.

After the existing site and instance fields, append one count byte (1-6), then
that many tuples: connector UUID (16 bytes), read-grant UUID (16 bytes), manifest
role-3 key ID (32 bytes). Tuples are strictly increasing by key ID. Duplicate
key IDs, connector IDs or read-grant IDs are invalid. Version 2 with zero
recipients is invalid. UUIDs use their network-order bytes.

Approval signs `zrotext/conversation/approve/v2` followed by NUL, the unsigned
statement length as four big-endian bytes, then the complete statement.
Installation uses `zrotext/conversation/install/v2` with the same framing.
Signatures remain canonical low-S P-256 SHA-256 signatures, serialized as
64-byte IEEE P1363. The exact selection is therefore part of both phone proofs.

The owner activation request adds `integration_readers`,
`integration_transfer_confirmed`, and `integration_disclosure_version`.
Each selected reader has `connector_id`, `read_grant_id`, and `key_id` (32
unsigned bytes). Nonempty selection requires confirmed transfer and the closed
disclosure version `customer-readers-v2`. Empty selection requires no added
confirmation/version. Public points come from the accepted manifest, never
from caller-supplied arbitrary key material.

Each selected grant must independently remain an active existing connector
read-inbound grant for the same line and interval restriction. Sending and
approving are separate authorities. Reader selection cannot revive a revoked
registration, key or grant, or broaden a restricted grant.

The original envelope contains exactly one archive wrap and the selected
role-3 wraps in canonical role/key order. All wrap the same content key using
the existing profile-02 HPKE info and body AAD; the phone signature covers all
wraps. Extra, missing and substituted wraps are refused.

The channel scope preserves its version-1 bytes for archive-only activation.
Under the version-2 disclosure hash only, append the count and exact tuples
after the peer. This extension precedes any following message/attempt fields;
its length is determined from its bounded count, never by consuming trailing
identities as recipients.

## Service and consumption boundaries

Original-event credentials are independently owner-issued for one interval,
connector, existing read grant and reader key. They inherit current root,
registration, creator session, line and interval fences. Workflow context
credentials cannot be substituted. An event response provides original opaque
bytes and accepted-manifest provenance; the client still supplies its own
independent root pin and accepted contiguous manifest history.

Consumption records bind the original event and consumer to one durable
request. Correlation uses an explicitly registered exact action/message link,
not the envelope's `message_id` (which equals its event ID). Ambiguous, expired
or unassociated replies go to owner review. Text classification is never an
approval, renewed consent or sending permission. Shared exact-action services
remain responsible for proposal, approval, scheduling and delivery.

Metadata STOP events remain separate. Withdrawal, takeover, deletion and
expiry fence new consumption; durable replay identities cannot be used to
retry an unknown action as new work. No physical-device, carrier, provider or
production-activation claim follows from this candidate contract.

## Optional startup and owner issuance

`ORIGINAL_REPLY_READER_ENABLED` defaults to false. Enabling it requires
`CONVERSATION_ENABLED`, `WORKFLOW_TOOLS_ENABLED`, an active MFA encryption
key, and migration 088. Disabled installations do not expose the original
reader or issuance routes. This does not enable phone capture automatically.

The browser may select up to six exact existing read-grant/key tuples and
separately confirms the reader-transfer disclosure. Nonempty activation
responses use `application/vnd.zrotext.conversation-statement.v2`; empty
archive-only responses retain the version-1 MIME type.

`POST /v1/auth/reply-grants` uses current owner cookie/CSRF, password and MFA.
Its closed JSON body contains `current_password`, `code`, `interval_id`,
`connector_id`, `read_grant_id`, `reader_key_id` (64 lowercase hexadecimal
characters), and `expires_at_ms`. The response returns `grant_id` and the
credential once. `DELETE /v1/auth/reply-grants/{grant_id}` irreversibly withdraws
it. Neither operation grants workflow execution or sending authority.
Credentials pin the current accepted root generation, manifest version and
digest. Root advance requires a fresh explicit owner issuance, rather than
silently extending old authority. Issuance is bounded to 128 retained grant
identities per account and at most 24 hours, further restricted by the current
creator, interval, registration, selected key and read-grant deadlines.

`GET /v1/owner/conversation/events/{event}/selection` uses the same current
owner archive-history fences as the opaque event route. Its closed JSON object
contains `v: 1`, `statement`, `approval_signature`, `installation_signature`,
`activation_manifest_version`, `activation_manifest_digest`, and
`accepted_at_ms`. Binary values use canonical standard base64; version/time
values use decimal strings. The acceptance time is the interval's phone
approval clock, not the later inbound receipt clock. The browser verifies
signatures using only independently pinned/ratcheted accepted manifests;
a response does not bootstrap historical trust. Missing accepted history is
explicitly unavailable. Withdrawing an integration read grant does not itself
withdraw the owner's independent archive permission.

## Reader methods

`POST /v1/reply-events` accepts JSON with `v: 1`, a closed `method`, and a
client-selected `accepted_manifest_version`. Authorization is a dedicated
`Bearer ztr_` credential. Cookies, Origin, query parameters, duplicate
Authorization and unrelated output credentials are refused. The optional
`x-zrotext-output-authorization` header carries a distinct `Bearer ztw_`
credential only for `consume`; it belongs in trusted customer configuration,
never model parameters. Responses are no-store, bounded JSON and are never
retried automatically after uncertainty.

Methods are `current`, `read` with `event_id`, `page` with `limit` (1–32) and
nullable `{accepted_at_ms,event_id}` cursor, `consume` with exact
`{request_id,event_id,active_request_id,descriptor}` params, and `status` with
`consumption_id`. Success is `{kind: method,result: ...}`. Failures disclose
only `invalid`, `refused` or `unavailable`, without credentials or plaintext.

Current proof binds account, interval, device, line, connector, read grant,
reader ID, root generation, immutable authority revision, expiry and observed
clock, current manifest version/digest, and a bounded contiguous accepted
manifest chain. The chain begins at a client-selected locally accepted
version and contains at most 32 snapshots. Missing stored acceptance is
unavailable, never fabricated from an unsigned response. Clients preserve
their own latest manifest high-water and reject conflicting snapshots or
regression before and after asynchronous HPKE opening.

Read returns the exact opaque original envelope, event and historical
manifest identity, signed activation statement/approval/install proof and
current proof. Its `accepted_at_ms` is the phone approval clock. Page metadata
uses the distinct event receipt clock for cursors. Cursor anchors must exist
in the exact current account/interval provenance; unknown, deleted or
cross-scope anchors are unavailable. Page availability is not qualification
or approval.

## Durable correlation and lifecycle

`POST /v1/auth/reply-requests` requires current owner cookie/CSRF and records
an exact approved action key, actual linked message, interval, deadline and
maximum turns (1–8). It cannot fabricate a legacy outbound message/attempt
from an original event ID. Each account retains at most 128 request identities;
registering another ID cannot reset turns for the same exact action revision.

Consumption independently examines every eligible exact request. A unique
qualifying association, matching supplied request, current independent
Propose credential and exact output descriptor can create a proposal. Multiple
qualifying associations remain owner review even if the agent picks one.
Proposal creation, original-source linkage, turn debit and consumption receipt
commit in one transaction. No sending or owner approval is inherited.
`consumption_id` equals the client's `request_id`, so a lost response can be
recovered by status after process restart. A different request/body cannot
reconsume the same event for the same connector. Replay returns metadata;
it does not repeat proposal creation or renew any authority.

Later owner decisions, preparation and queued first-intent database checks
retain the original read-grant, event, request and exact source-action fences.
Revocation, stop/takeover, source replacement, expiry or content deletion
refuses later effects. Retained consumption, turn and source identities survive
content retention and registry removal until account erasure. The 8192
account-lifetime consumption bound refuses exhaustion instead of pruning
identities and permitting replay. Audit rows are retained for 30 days; expired
grant authority is irreversibly revoked. Owner takeout pages original grant,
request, consumption, source, access and accepted-manifest metadata through
`original_reply_section` and `original_reply_before`; authenticating credential
hashes are excluded. Account erasure removes these retained identities.

### Retained source authority

Every generated proposal retains its exact original event, read grant and independently
registered request identity for the account lifetime. Later decisions and delivery
checks follow immutable parent action/revision/digest bindings for at most 128 original
request links. Cycles, changed current heads, missing marked bindings or expired/revoked
ancestor authority refuse. After ancestor row-lock waits, the complete chain is checked
again against the current database clock. The bounded SQL walk captures each hop's
minimum already-enforced deadline once and compares the accumulated minimum with
a fresh clock at termination. Original-read authority does not inherit the expired
phone approval challenge deadline; integration-origin authority retains its existing
context and interval deadline checks. Ordinary actions without original-source
markers retain the existing decision contract.

Source tombstones cannot be independently deleted, even after their associated action
is removed. A deferred database constraint permits deletion only when the account no
longer exists at transaction commit. Full account erasure therefore removes source
identities atomically with the account; content pruning never renews their authority.
