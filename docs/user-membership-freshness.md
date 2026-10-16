# User and membership snapshot freshness

Migration 103 makes user and membership mutations participate in the account
snapshot fence. It does not authenticate a caller, select a payload profile, or
qualify every account writer for profile03. The remaining operation policies and
production integration stay under #1484 and #1054.

A user may be created before its membership. An old REPEATABLE READ transaction
can therefore observe no associated account. If another transaction only locks
that user while inserting a membership, the old snapshot can still update the
user without seeing the new account. A row lock alone does not invalidate it.

The mandatory membership trigger takes the canonical SHARED account try-fence
and qualified actual anchor SHARE NOWAIT, then locks the existing user NOWAIT
and performs a real `UPDATE users SET id=id`. That creates the tuple version
change needed to make old REPEATABLE READ and SERIALIZABLE user mutations refuse
with `40001`. Membership deletion also touches the existing user, so a stale
snapshot cannot silently retain the removed association. The nested users trigger
only reads memberships and locks anchors; it never writes another user or
membership, and needs no trigger-depth or session-variable exemption.

User mutations fence their associated account set. Membership mutations fence
the sorted distinct OLD/NEW account set. Each fence uses the full account UUID
to find the actual anchor; an advisory-key collision is contention, not identity
or permission. Missing, invisible or malformed anchors refuse. A real anchor
epoch change similarly invalidates old snapshots. These checks do not interpret
an epoch as cryptographic authorization.

Migration 048 already makes membership account/user/role identity immutable;
103 independently preserves account/user immutability. A current user's UUID is
also immutable. This does not retain user UUID history or prohibit a genuinely
new row from using an erased user UUID. Existing UUID collisions still refuse.

Unassociated users remain valid bootstrap state. Associated positive mutations
require a live anchor. Deletion and an exact full-row no-op touch may lock a
deleted anchor for reduction/cascade bookkeeping. A parent-user deletion may
have removed the user before its membership cascade; only membership DELETE
permits that missing user, after fencing its OLD account. Account erasure that
deletes memberships before the owner user remains valid. Absence never provides
authentication, a default profile, or permission to recreate a parent.

The helper is a fixed-search-path SECURITY DEFINER trigger function constrained
to the installed users/memberships relations, BEFORE ROW timing, exact operations
and zero arguments. Runtime/PUBLIC cannot execute it directly. The complete
runtime-role provisioner repeats that revocation after broad function grants;
runtime does not own or alter the function/tables or gain TRUNCATE authority.
Try-lock/NOWAIT checks bound the helper's account and user contention. Callers
must still set an overall operation deadline: ordinary statement row locking can
begin before a row trigger runs.

This narrow mechanism changes no profile02 ciphertext, signature, root, grant,
receiver or provider contract. Wider relation extraction, per-operation profile
and state policies, accepted-election coupling and current reader/effect checks
remain prerequisites before profile03 activation.
