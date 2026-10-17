# Isolated review workspace persistence

Migration 102 is an unmounted persistence foundation. It creates no installation
marker, broker, account, credential or session when applied. Runtime has SELECT
only on its five relations and cannot execute any `review_workspace_*` helper.
The migration owner can use the narrow constructors in disposable qualification;
they do not verify passwords, authenticate users or issue owner sessions.

`review_realm_installation` records an out-of-band realm/database identity,
origin, deployment/service commitments and five distinct key commitments: auth
token, enrollment token, reauthentication, grant and MFA. Stored origin syntax
checks are deliberately incomplete. A future adapter must enforce exact canonical
HTTPS serialization, authenticate the actual observed deployment, database and
key inventory, and reject every production identity overlap. A marker row alone
does not establish startup containment.

Broker identities and broker sessions are separate from `users`, `memberships`
and ordinary `sessions`. Current permission locks the stable broker row and
compares its active revision with the exact session/event/revision/origin. A
historical revision is not a foreign key to a mutable current revision. Allocation
and cleanup take broker UPDATE NOWAIT upfront; permission reads take SHARE
NOWAIT. They never convert SHARE to UPDATE. New reservation/provisioning requires
READ COMMITTED and refuses stronger snapshot modes without changing isolation.

A reserved attempt records private **prospective**, nonexclusive account/user
UUIDs and exact continuation/request commitments. Point-in-time absence is not a
namespace reservation. An ordinary creator may occupy a prospective UUID later.
Actual account/user inserts and migration 100's retained account anchor enforce
atomic collision and account-reuse refusal; the whole factory then rolls back
without attaching, overwriting or deleting unrelated rows. There is no retained
user-UUID history and no claim that an erased user UUID was never previously used.

The factory takes the candidate account exclusive try-fence before account row
locks. It rereads identity/state after that fence, then locks a real pre-existing
anchor for a provisioned result, current broker/session and exact attempt. Only
the new branch permits account and anchor absence. A new account gets its genuine
anchor, fresh user and owner membership atomically. Its password verifier is
unusable, email remains unverified, MFA remains disabled and no ordinary session
or MFA row is created. These records are not ordinary verified owners.

The state is exactly `reserved` or `provisioned`. Reserved rows have no bound
parents or completion time. Provisioned rows bind the exact prospective IDs with
real account/user/membership CASCADE foreign keys. Erasing either parent removes
the entire result, including the prospective ID copies. Workspace associations
also cascade, but deliberately have no restrictive attempt/session foreign key.
Cleanup of a reserved attempt deletes only that attempt, never prospective parents.
Bound deletion/reconciliation requires its actual anchor even during cascades.

The unmounted component bounds reservation creation to five minutes, broker
sessions to 14 days absolute and 72 hours idle, and provisioned reconciliation to
seven days from reservation. Expired never-provisioned attempts and expired or
revoked broker sessions have one hour cleanup slack. An expired session row may
remain until finite child receipts are eligible for cleanup; its authority is not
extended. There are independently 128 retained session, attempt and workspace
slots per broker. At capacity constructors refuse without eviction. Only genuine
eligible cleanup or authorized workspace erasure frees the corresponding slot.
These are source resource defaults, not an approved hosted retention policy.

All final decisions use qualified database wall time, reject clock regression
below the captured decision and last-activity floors, and recheck after potentially
waiting writes/reads. Helpers bound lock waits; a future admission adapter must
also set a finite overall statement/operation deadline. Exact completed retry
returns the original result without refreshing expiry or issuing authority.
A missing receipt after cleanup means unavailable/UNKNOWN. Future transport must
never automatically turn that into a new reservation, account, reset or no-effect
claim. A new constructor call is owner authority, not an UNKNOWN reconciliation API.

The five closed catalog labels are extraction-review obligations only. The
bootstrap label includes both private prospective and account-bound states; it
does not exempt provisioned results from anchor checks or qualify any profile03
writer. This foundation activates no HTTP, password/MFA alternative, root or line
ceremony, grant, fetch, journal, receiver or SMS path. A future typed session and
durable action-proof consumer must independently qualify those boundaries.
Existing unverified-owner age cleanup must also be reconciled before activation;
this migration neither forges verification nor silently changes that cleanup.
