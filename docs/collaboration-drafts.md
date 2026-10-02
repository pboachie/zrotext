# Selected ciphertext drafting collaboration

The selected projection is **encrypted_drafter**, an explicit grant attached to
an existing account membership. It does not change the owner or device-status
observer role, invitations, login, MFA custody or API-key scopes. Other proposed
collaboration roles are not available.

The routes are unmounted by default. `COLLABORATION_DRAFTS_ENABLED=true` mounts
the browser-session projection after the complete migration sequence is applied.
No deployed gate is enabled by this implementation. Storage readiness failures
are unavailable errors; they never grant fallback authority.

Clients encrypt before uploading opaque artifact bytes. The server stores and
returns bytes and cannot prove their encryption or authenticity. This storage
contract is not a sendable message format: no recipient, plaintext, key, approval
or send operation is accepted. It contains no cryptographic implementation,
key provisioning or implicit content-reading grant. Any future agent route must
independently enforce its content-read, encrypted-draft, approve and send grants;
this membership projection does not satisfy those grants.

## Route and action authority

All paths below are relative to `/v1/auth/collaboration`. Every mounted route
requires a live cookie session, verified user, enabled account and unrevoked
membership. Reads require the matching CSRF header and cookie; mutations also
require the configured HTTPS Origin. Bearer API keys and device credentials
cannot substitute for a browser session.

| Method and path | Required authority | Scope and effect |
|---|---|---|
| `GET /grants` | Current owner | Account grant metadata, at most 100 records |
| `POST /grants` | Current owner, current password/MFA proof and `confirm_widening: true` | Grant only `encrypted_drafter` to a verified live member of the same account |
| `DELETE /grants/{grant_id}` | Current owner | Irreversibly revoke this account's grant and scrub its draft bytes |
| `GET /drafts` | Live encrypted-drafter grant | At most 20 live artifacts authored by this member under this grant |
| `POST /drafts` | Live encrypted-drafter grant | Create own opaque artifact; identical retry returns the existing artifact |
| `GET /drafts/{draft_id}` | Live encrypted-drafter grant | Own live artifact only; another author/account is not found |
| `DELETE /drafts/{draft_id}` | Live encrypted-drafter grant | Delete own bytes and retain an idempotency tombstone; repeated delete is harmless |
| `GET /export?before=<draft-uuid>:<author-uuid>` | Current owner | Account grant metadata and a capped page of ciphertext/tombstones |

## Cross-role authority matrix

The seven authority classes the collaboration design separates, across every
principal type that exists today. "Own" means scoped to the caller's own
account and own artifacts. No cell inherits from another: a drafting grant
never widens any other column, and no non-owner principal ever reaches the
root-operation column. Unselected future roles are intentionally absent and
must not be presented as available.

| Principal | Status read | Decrypted content | Draft ciphertext | Approve | Send | Team management | Root operations |
|---|---|---|---|---|---|---|---|
| Owner (live membership, password/MFA where noted) | Yes | Via account takeout export only | Only with a separate live drafting grant | Yes (owner confirmations) | Yes, via existing send paths | Yes (seats, invitations, grants, API keys) | Yes |
| Device-status observer (live seat) | Yes (own account device status) | No | No (grant required) | No | No | No | No |
| Observer additionally holding `encrypted_drafter` | Yes (unchanged) | No | Own artifacts only | No | No | No | No |
| Agent / API key | Per its own independent scopes; a drafting grant neither broadens nor satisfies them | No implicit | No (browser-session projection only) | Per scope | Per scope | No | No |
| Device credential | Device-stream status only | No | No | No | No (radio requires the grant machinery) | No | No |

Revocation is per half and propagates immediately: revoking a drafting grant
leaves the observer seat reading status; removing the observer seat ends the
membership, scrubs the introduced grants and ciphertext, and kills the
session's reads and drafts together. The mixed-role lifecycle is pinned by
`mixed_observer_drafter_role_adds_only_drafting_and_each_half_revokes_independently`.

An owner needs a separate live drafting grant for the draft CRUD routes. The
owner's account takeout and grant-management authority come from the existing
owner role, not from encrypted_drafter. An observer with the drafting grant
retains only its existing status reads plus own draft operations; it cannot
mint API keys, invite seats or approve an SMS line. No drafting grant adds
decrypted-content access, approval, sending, team management or root operations.
Existing independently authorized owner capabilities remain unchanged.

Grant widening rejects an absent confirmation, an unselected role, a wrong
password or missing/invalid MFA proof when MFA is enabled. Endpoint budgets are
spent before password work. A revoked grant cannot be restored; a separately
confirmed grant receives a new identity. Old artifact IDs cannot be reused to
resurrect old bytes or transfer them to that new grant.

## Bounds, retries and lifecycle

Requests keep the existing 16 KiB authentication body limit and reject unknown
fields. Artifact bytes must be canonical standard base64 and decode to between
28 and 8,192 bytes. These are format/size checks, not proof of encryption.
Grant identities and artifact authors, bytes, digests and creation times are
immutable. No artifact update or author transfer is exposed.

There are at most 20 live artifacts and 100 lifetime artifact IDs per grant,
and 100 grant records per account. Grant-row locking serializes create/delete
budget decisions. A live duplicate ID with identical bytes returns `200`; a
different payload, deleted ID or previous-grant ID returns `409`. A new ID
returns `201`. Read and write activity is limited per authenticated member,
and owner grant changes have a separate hourly budget. Limits are isolated
between tenants. Full body/storage budgets return `413`/`429`, not partial data.

Revocation scrubs ciphertext transactionally and blocks further grant use.
Every operation rechecks session, membership, account and grant authority after
lock waits and immediately before committing a mutation or releasing a read; cached principals cannot outlive those fences. Removing a member
through the existing seat lifecycle cascades grants and artifacts. Account or
user erasure also cascades them. A deleted artifact retains only immutable
identity/digest metadata until its grant/member/account is erased.

Export returns grant metadata and at most 20 artifacts per page, including
deletion tombstones. `drafts_truncated` and `next_cursor` identify remaining
records. The canonical lowercase `draft-uuid:author-uuid` cursor orders both identities, so equal draft IDs from different authors remain exportable. Cursor positions never change the authenticated account scope. Live bytes are base64 ciphertext; deleted bytes are null. Export never
decrypts them or gives the caller encryption keys. All responses are no-store.

The [schema](../protocol/v1/collaboration-drafts.schema.json) describes the
selected request and record shapes. There is no dashboard, Android or bearer
SDK presentation for these routes yet; they remain an explicitly gated API.
