# Mandatory account writer participation

Migration108 adds database participation to the complete numbered107 graph. It
does not accept an election, install a Profile03 reader, authorize a message or
advance an account selection epoch. Positive live epochs remain unsupported.
This is a prerequisite for the remaining work in #1484 and #1054.

The shipping installation supported by this migration is the exact `public`
namespace. Installation checks all179 accepted relation, column, foreign-key and
trigger entries and all211 existing function bodies and configurations before
changing the graph. Unknown, missing, disabled or changed entries abort the
migration transaction. Other namespaces are refused rather than substituted.

Predecessor function bodies must match one of two exact reviewed snapshots:
uniform LF or uniform CRLF source. Mixed per-function encodings and a carriage
return introduced inside a quoted SQL literal are refused. Stored bodies are
never normalized for this comparison. The new migration is pinned to LF.

## Operation policies

| Relation class | INSERT | UPDATE | DELETE |
| --- | --- | --- | --- |
| Required account column | Fence NEW owner; require live epoch0 | Fence the sorted distinct OLD and NEW owner set; require live epoch0 | Fence OLD owner; allow its live epoch0 or retained deleted anchor |
| Four immutable parent mirrors | Existing101 guard derives omitted owner from the actual parent, then fence NEW owner | Preserve101 immutable parent and account checks, then fence both identities | Fence immutable OLD owner even when a parent cascade removed the parent |
| Six nullable account columns | Fence nonnull NEW owner; coordinator rows also derive the actual device owner | Fence both nonnull owners, including NULL-to-bound changes; preserve existing reassignment restrictions | Fence all nonnull OLD owner identities |
| Accounts | Try-fence the new UUID; refuse any retained anchor; existing100 creates its insert-once anchor | Fence actual OLD and NEW identity; preserve immutable ID | Existing100 exclusive deletion fence and retained live-to-deleted epoch transition, plus mandatory writer participation |
| Users and memberships | Existing103 stable membership/account set protocol | Preserve103 sorted account set and real user tuple version change; refuse unsupported positive live epoch | Preserve users-before-accounts erasure, membership cascades and retained tombstone checks |
| Reviewer account associations | Require the existing constrained account association | Fence both actual associations, preserving104 state and owner-only factory guards | Fence OLD account even after its parent was erased |
| Reviewer prospective bootstrap | A prospective UUID is not an account and contributes no fictional anchor | A real provisioned `bound_account_id` joins the account set | Bound associations remain fenced; prospective IDs never become authority |
| Reviewer authentication operation2 and browser continuity | Require their explicit existing account-free operation/state | Preserve102/104 guards and typed continuity participation | Preserve existing pruning and erasure controls |
| Global authority/configuration/key integrity | Exclusive try-fence the explicit global class and update its stable row version | Same; an old RR/SSI view cannot lock a changed row version | Same; deletion never supplies account authority |
| Global budgets/audit/unbound provider inbox | Shared try-fence and lock the explicit class's stable row | Same, preserving independent counter/inbox row concurrency | Same; no account or current authority is inferred |
| Migration ledger and retained anchors | Existing migration/lifecycle authority only | Existing migration/lifecycle authority only | Anchors remain retained; no runtime erasure API |

Every nonnull account set takes the account SHARED try-fence and the actual
schema-qualified stable anchor `FOR SHARE NOWAIT`. Both locks survive the
statement until transaction end. A copied epoch, an advisory convention, a GUC,
trigger depth or a role name cannot replace that row lock. Missing or
snapshot-invisible anchors refuse; they never mean Profile02.

Explicit global classes have different policies. Changes to deployment/site
authority, signing-key integrity, billing configuration, hosted configuration
and reviewer broker authority update their own durable class row. Budgets,
append/audit records, provider inbox and browser continuity use shared class
participation, preserving their existing independent-row concurrency. No generic
runtime global/account epoch-advance function is provided.

## Closed validation and runtime authority

The migration retains an insert-once graph baseline covering relations, columns,
defaults, constraints, indexes, triggers and complete function bodies/configuration
and ownership. Matching it is a schema check, not P-256 authentication. Only the
existing reviewed equivalent catalog-first v2 trigger paths are normalized.
Unknown objects, changed bodies, disabled constraints/triggers, missing indexes
and added columns refuse the optional v2/workflow consumers and the required
future03 consumer. Pre108 isolated legacy fixtures retain their original checks.

`payload_profile_writer::require` additionally requires an ordinary non-owning
caller without role memberships, schema creation, helper execution or relation/
column write privileges on the baseline and global rows. Provisioning resets
those relation and column privileges on every rerun. Runtime cannot alter the
helpers, disable triggers, truncate tables or directly change a fence version.

The existing atomic management budget function keeps its invoker authority,
signature and counter/rollback policy, but now pins `pg_catalog` and qualifies
the real counter table. A catalog-only owner authentication transaction can use
that same budget without restoring a caller-controlled namespace.

## Qualification boundary

The test matrix uses actual numbered migrations, distinct ordinary migration
and runtime LOGINs, unmodified account writers, both fence/tuple contention
orders, unrelated-account progress, real account-deletion epoch changes under
REPEATABLE READ and SERIALIZABLE, snapshot-invisible account creation, and
schema/body/trigger/ACL pollution. Existing user/membership and account-erasure
tests remain mandatory. These tests establish no accepted election or device
execution. Future accepted-ledger transitions must add their exact state policy
and atomically couple any positive account epoch to the actual accepted record;
they cannot use a generic advance API or rewrite applied migrations100–107.
