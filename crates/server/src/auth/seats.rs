// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-managed device-status observer seats. An owner invites an address
//! with a bounded, single-use opaque invitation; the database stores only the
//! HMAC of that token. The invitee accepts it with a new password, verifies
//! the address independently, and receives read-only status access. Removing
//! a seat revokes it irreversibly and deletes the observer's user row so the
//! address is free again; the owner's history of the seat survives as a
//! tombstone on the accepted invitation, and no request can restore the seat.

use super::{
    AuthError, SessionPrincipal, TokenHasher, VERIFICATION_HOURS, account, mfa::MfaCipher,
    normalize_email, password_work, random_token, require_current_owner, valid_token,
    verification_token_for_id,
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Invitation lifetime. The token is handed to one person out of band and the
/// address must verify within a day of acceptance, so one week bounds a
/// leaked token without racing slow operators.
pub(crate) const INVITATION_DAYS: i32 = 7;
/// Seats and open invitations are bounded per account so neither table can be
/// used as unbounded storage through the owner surface.
const MAX_ACTIVE_OBSERVERS: i64 = 10;
const MAX_OPEN_INVITATIONS: i64 = 10;
const SEAT_PAGE_LIMIT: i64 = 100;
/// Bounded batch for the periodic removal of expired unverified observers.
const PENDING_OBSERVER_PRUNE_BATCH: i64 = 100;

/// One invitation as the owner dashboard lists it. No token material is read.
pub struct SeatInvitationSummary {
    pub id: Uuid,
    pub email: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub accepted_at_ms: Option<i64>,
    pub canceled_at_ms: Option<i64>,
    pub accepted_user_id: Option<Uuid>,
}

/// The single response that ever carries the raw invitation token.
pub struct IssuedInvitation {
    pub id: Uuid,
    pub email: String,
    pub expires_at_ms: i64,
    /// Secret: show once to the owner, never store, log, or repeat it.
    pub token: String,
}

pub struct SeatSummary {
    /// `None` for a removed seat whose user row was deleted with it.
    pub user_id: Option<Uuid>,
    pub email: String,
    pub email_verified: bool,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    /// True only for a removed seat whose address is free again. It is false
    /// for a live seat and for a removed seat whose user row could not be
    /// deleted, which keeps the address occupied.
    pub address_free: bool,
}

/// What removing a seat did, so the owner can see whether the address is free.
pub struct SeatRemoval {
    pub address_freed: bool,
}

pub struct SeatsPage {
    pub seats: Vec<SeatSummary>,
    pub invitations: Vec<SeatInvitationSummary>,
}

pub struct SeatAcceptance {
    pub account_id: Uuid,
    pub user_id: Uuid,
    /// Compatibility for internal tests. Delivery reconstructs this code from
    /// the challenge ID and the operational pepper; never log or URL-encode it.
    pub verification_token: String,
}

/// Invite one address to this account as a device-status observer. This is
/// the only public way to create an invitation and it mirrors API-key minting:
/// a persistent read seat needs the owner's current password and, once MFA is
/// enabled, a fresh authenticator or recovery code, so a stolen session cookie
/// alone cannot mint one. The caller charges the `SeatInvite` budget before
/// calling; a wrong code also charges the MFA step-up failure budget.
///
/// The result never depends on whether the address is registered here or
/// invited by another account: the owner always receives a real single-use
/// token, and any conflict surfaces only to the token holder at acceptance.
pub async fn create_invitation_with_proof(
    client: &mut Client,
    cipher: Option<&MfaCipher>,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    current_password: &str,
    code: Option<&str>,
    email: &str,
) -> Result<IssuedInvitation, AuthError> {
    let email = normalize_email(email)?;
    let tx =
        account::begin_owner_step_up(client, cipher, hasher, principal, current_password, code)
            .await?;
    let issued = create_invitation_in(&tx, hasher, principal, &email).await?;
    tx.commit().await?;
    Ok(issued)
}

/// The invitation write, run inside the step-up transaction. It performs the
/// same statements for every address: it never reads `users` or another
/// account's invitations, so a registered address, an unknown one, and one
/// already invited elsewhere are indistinguishable to the inviting owner in
/// status, body, list entry, slot use, and database work. Invitations are
/// unique per account and address, so re-inviting an address this account
/// already invited replaces the earlier invitation (its token stops working),
/// which also retires an expired open row instead of letting it block the
/// address.
async fn create_invitation_in(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    email: &str,
) -> Result<IssuedInvitation, AuthError> {
    require_current_owner(tx, principal).await?;
    let account_id = principal.tenant.account_id();
    // Replace this account's own open invitation for the address, live or
    // expired. It runs whether or not a row exists, and rolls back with the
    // transaction if a cap below refuses the request.
    tx.execute(
        "UPDATE seat_invitations SET canceled_at=now() WHERE account_id=$1 AND email=$2 AND accepted_at IS NULL AND canceled_at IS NULL",
        &[&account_id, &email],
    )
    .await?;
    let seats: i64 = tx
        .query_one(
            "SELECT count(*) FROM memberships WHERE account_id=$1 AND role='observer' AND revoked_at IS NULL",
            &[&account_id],
        )
        .await?
        .get(0);
    if seats >= MAX_ACTIVE_OBSERVERS {
        return Err(AuthError::Conflict);
    }
    let open: i64 = tx
        .query_one(
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at>now()",
            &[&account_id],
        )
        .await?
        .get(0);
    if open >= MAX_OPEN_INVITATIONS {
        return Err(AuthError::Conflict);
    }
    let token = random_token("zti_");
    let hash = hasher.digest(b"seat-invitation-v1", &token);
    let id = Uuid::new_v4();
    let inserted = tx
        .execute(
            "INSERT INTO seat_invitations(id,account_id,email,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+($5::integer * interval '1 day'))",
            &[&id, &account_id, &email, &&hash[..], &INVITATION_DAYS],
        )
        .await;
    if let Err(error) = inserted {
        if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            // Only this account's own concurrent request can collide, and the
            // owner's user-row lock serializes those; fail closed anyway.
            return Err(AuthError::Conflict);
        }
        return Err(error.into());
    }
    let expires_at_ms: i64 = tx
        .query_one(
            "SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM seat_invitations WHERE id=$1",
            &[&id],
        )
        .await?
        .get(0);
    Ok(IssuedInvitation {
        id,
        email: email.to_owned(),
        expires_at_ms,
        token,
    })
}

/// The owner's bounded view of seats and invitations for this account only.
/// Revoked seats stay listed as tombstones; they cannot be restored.
pub async fn list_seats(
    client: &Client,
    principal: &SessionPrincipal,
) -> Result<SeatsPage, AuthError> {
    require_current_owner(client, principal).await?;
    let account_id = principal.tenant.account_id();
    let mut seats: Vec<SeatSummary> = client
        .query(
            "SELECT m.user_id,u.email,(u.email_verified_at IS NOT NULL),(extract(epoch FROM m.created_at)*1000)::bigint FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.account_id=$1 AND m.role='observer' AND m.revoked_at IS NULL ORDER BY m.created_at DESC,m.user_id DESC LIMIT $2",
            &[&account_id, &SEAT_PAGE_LIMIT],
        )
        .await?
        .into_iter()
        .map(|row| SeatSummary {
            user_id: Some(row.get(0)),
            email: row.get(1),
            email_verified: row.get(2),
            created_at_ms: row.get(3),
            revoked_at_ms: None,
            address_free: false,
        })
        .collect();
    // Removed seats are read from the accepted invitation that created them,
    // because removal deletes the user row. They hold no seat or invitation
    // slot: only live memberships and unexpired open invitations are counted.
    seats.extend(
        client
            .query(
                "SELECT accepted_user_id,email,(extract(epoch FROM accepted_at)*1000)::bigint,(extract(epoch FROM removed_at)*1000)::bigint,removal_freed_address FROM seat_invitations WHERE account_id=$1 AND removed_at IS NOT NULL ORDER BY removed_at DESC,id DESC LIMIT $2",
                &[&account_id, &SEAT_PAGE_LIMIT],
            )
            .await?
            .into_iter()
            .map(|row| SeatSummary {
                user_id: row.get(0),
                email: row.get(1),
                email_verified: false,
                created_at_ms: row.get(2),
                revoked_at_ms: row.get(3),
                address_free: row.get::<_, Option<bool>>(4).unwrap_or(false),
            }),
    );
    let invitations = client
        .query(
            "SELECT id,email,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM expires_at)*1000)::bigint,(extract(epoch FROM accepted_at)*1000)::bigint,(extract(epoch FROM canceled_at)*1000)::bigint,accepted_user_id FROM seat_invitations WHERE account_id=$1 AND removed_at IS NULL ORDER BY created_at DESC,id DESC LIMIT $2",
            &[&account_id, &SEAT_PAGE_LIMIT],
        )
        .await?
        .into_iter()
        .map(|row| SeatInvitationSummary {
            id: row.get(0),
            email: row.get(1),
            created_at_ms: row.get(2),
            expires_at_ms: row.get(3),
            accepted_at_ms: row.get(4),
            canceled_at_ms: row.get(5),
            accepted_user_id: row.get(6),
        })
        .collect();
    Ok(SeatsPage { seats, invitations })
}

/// Cancel an outstanding invitation of this account. Consumed invitations
/// cannot be canceled, and a canceled token can no longer be accepted.
pub async fn cancel_invitation(
    client: &mut Client,
    principal: &SessionPrincipal,
    invitation_id: Uuid,
) -> Result<bool, AuthError> {
    require_current_owner(client, principal).await?;
    let tx = client.transaction().await?;
    let canceled = tx
        .execute(
            "UPDATE seat_invitations SET canceled_at=now() WHERE id=$1 AND account_id=$2 AND accepted_at IS NULL AND canceled_at IS NULL",
            &[&invitation_id, &principal.tenant.account_id()],
        )
        .await?;
    tx.commit().await?;
    Ok(canceled == 1)
}

/// Remove one observer seat of this account. The membership is revoked
/// irreversibly and every credential the seat could still use is revoked in
/// the same transaction: sessions, API keys created by the user, pending MFA
/// challenges, password reset codes and their queued mail, outstanding email
/// verification codes and their queued mail, and any still-open invitation
/// for the same address in this account. The owner's own rows never match.
///
/// The observer's user row is then deleted so the address is free again (the
/// person can be invited afresh or register their own account, with none of
/// the old identity carried over). Removal is a security action and is never
/// blockable: the delete runs in a savepoint and only for a user whose single
/// membership is this account's observer seat, and if the database refuses it
/// with an integrity error (a restricting reference, unreachable for
/// observers today) the savepoint is rolled back, every revocation above still
/// commits, and the result reports the address as still occupied.
pub async fn remove_observer(
    client: &mut Client,
    principal: &SessionPrincipal,
    user_id: Uuid,
) -> Result<Option<SeatRemoval>, AuthError> {
    require_current_owner(client, principal).await?;
    let account_id = principal.tenant.account_id();
    let mut tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.account_id=$1 AND m.user_id=$2 AND m.role='observer' AND m.revoked_at IS NULL FOR UPDATE OF m",
            &[&account_id, &user_id],
        )
        .await?
    else {
        return Ok(None);
    };
    let email: String = row.get(0);
    let revoked = tx
        .execute(
            "UPDATE memberships SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND role='observer' AND revoked_at IS NULL",
            &[&account_id, &user_id],
        )
        .await?;
    if revoked != 1 {
        return Ok(None);
    }
    tx.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND revoked_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE api_keys SET revoked_at=now() WHERE account_id=$1 AND created_by_user_id=$2 AND revoked_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE owner_mfa_login_challenges SET consumed_at=now() WHERE account_id=$1 AND user_id=$2 AND consumed_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE password_resets SET used_at=now() WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE password_reset_mail_outbox o SET canceled_at=now(),lease_id=NULL,leased_until=NULL FROM password_resets r WHERE o.reset_id=r.id AND r.account_id=$1 AND r.user_id=$2 AND o.canceled_at IS NULL AND o.delivered_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE email_verifications SET used_at=COALESCE(used_at,now()) WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE verification_mail_outbox o SET canceled_at=now(),lease_id=NULL,leased_until=NULL FROM email_verifications v WHERE o.verification_id=v.id AND v.account_id=$1 AND v.user_id=$2 AND o.canceled_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "UPDATE seat_invitations SET canceled_at=now() WHERE account_id=$1 AND email=$2 AND accepted_at IS NULL AND canceled_at IS NULL",
        &[&account_id, &email],
    )
    .await?;
    // The owner's record of the seat, written before the user row can go: the
    // delete below clears the invitation's user link. A seat without an
    // accepted invitation (never created through this flow) has no record.
    let tombstone: Option<Uuid> = tx
        .query_opt(
            "UPDATE seat_invitations SET removed_at=now(),removal_freed_address=false WHERE account_id=$1 AND accepted_user_id=$2 AND accepted_at IS NOT NULL AND removed_at IS NULL RETURNING id",
            &[&account_id, &user_id],
        )
        .await?
        .map(|row| row.get(0));
    // Free the address. The guards keep an owner, and any user with another
    // membership, out of reach even if a caller were ever to pass one.
    let savepoint = tx.transaction().await?;
    let deleted = savepoint
        .execute(
            "DELETE FROM users u WHERE u.id=$1 AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.account_id=$2 AND m.role='observer') AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND NOT (m.account_id=$2 AND m.role='observer'))",
            &[&user_id, &account_id],
        )
        .await;
    let address_freed = match deleted {
        Ok(count) => {
            savepoint.commit().await?;
            count == 1
        }
        // Class 23 is an integrity-constraint violation, such as a restricting
        // foreign key. It must not undo the revocations above.
        Err(error)
            if error
                .code()
                .is_some_and(|code| code.code().starts_with("23")) =>
        {
            savepoint.rollback().await?;
            false
        }
        Err(error) => return Err(error.into()),
    };
    if let (true, Some(invitation_id)) = (address_freed, tombstone) {
        tx.execute(
            "UPDATE seat_invitations SET removal_freed_address=true WHERE id=$1",
            &[&invitation_id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Some(SeatRemoval { address_freed }))
}

/// Indexed, read-only probe for the accept route's verified lane. It never
/// consumes the invitation or opens a transaction.
pub async fn invitation_token_is_live(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<bool, AuthError> {
    if !valid_token(token, "zti_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"seat-invitation-v1", token);
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM seat_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at>now())",
            &[&&hash[..]],
        )
        .await?;
    Ok(row.get(0))
}

/// Accept an invitation: claim it single-use under its row lock, refuse any
/// conflicting existing user for the bound address without touching it (the
/// token holder is the only party who ever learns of that conflict), then
/// create the unverified observer, its membership, and a verification code.
/// Unknown, canceled, expired, and replayed tokens all run one password
/// verification first so their timing matches a live acceptance.
pub async fn accept_invitation(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    password: &str,
) -> Result<SeatAcceptance, AuthError> {
    if !valid_token(token, "zti_") || !(12..=1024).contains(&password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let hash = hasher.digest(b"seat-invitation-v1", token);
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT id,account_id,email FROM seat_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at>now() FOR UPDATE",
            &[&&hash[..]],
        )
        .await?;
    let Some(row) = row else {
        password_work::verify(password, None).await?;
        return Err(AuthError::InvalidCredentials);
    };
    let invitation_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    let email: String = row.get(2);
    if tx
        .query_opt("SELECT 1 FROM users WHERE email=$1", &[&email])
        .await?
        .is_some()
    {
        // The address is taken: reject without changing its password or
        // membership, and without consuming the invitation.
        return Err(AuthError::Conflict);
    }
    let password_hash = password_work::hash(password).await?;
    let user_id = Uuid::new_v4();
    let verification_id = Uuid::new_v4();
    let verification_token = verification_token_for_id(hasher, verification_id);
    let verification_hash = hasher.digest(b"email-verification-v1", &verification_token);
    // Two accounts may hold open invitations for one address, and the address
    // may register concurrently, so a lost race is a conflict for the token
    // holder (nothing is consumed), not a server error.
    if let Err(error) = tx
        .execute(
            "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)",
            &[&user_id, &email, &password_hash],
        )
        .await
    {
        if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            return Err(AuthError::Conflict);
        }
        return Err(error.into());
    }
    tx.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
        &[&account_id, &user_id],
    )
    .await?;
    tx.execute(
        "INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+($5::integer * interval '1 hour'))",
        &[&verification_id, &account_id, &user_id, &&verification_hash[..], &VERIFICATION_HOURS],
    )
    .await?;
    tx.execute(
        "INSERT INTO verification_mail_outbox(verification_id) VALUES($1)",
        &[&verification_id],
    )
    .await?;
    let accepted = tx
        .execute(
            "UPDATE seat_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1 AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at>now()",
            &[&invitation_id, &user_id],
        )
        .await?;
    if accepted != 1 {
        return Err(AuthError::InvalidCredentials);
    }
    tx.commit().await?;
    Ok(SeatAcceptance {
        account_id,
        user_id,
        verification_token,
    })
}

/// Bounded cleanup of accepted-but-unverified observers whose pending window
/// has elapsed. Removing the user row cascades its membership, sessions,
/// verification codes, and queued mail; the consumed invitation keeps only its
/// audit columns. Verified or revoked seats are never matched. Safe for
/// concurrent workers through `SKIP LOCKED`.
pub async fn prune_expired_pending_observers(client: &mut Client) -> Result<u64, AuthError> {
    let tx = client.transaction().await?;
    let removed = tx
        .execute(
            "WITH expired AS (SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.role='observer' AND m.revoked_at IS NULL AND u.email_verified_at IS NULL AND u.created_at<=now()-($1::integer * interval '1 hour') ORDER BY u.created_at,u.id LIMIT $2 FOR UPDATE OF u SKIP LOCKED) DELETE FROM users u USING expired e WHERE u.id=e.id",
            &[&VERIFICATION_HOURS, &PENDING_OBSERVER_PRUNE_BATCH],
        )
        .await?;
    tx.commit().await?;
    Ok(removed)
}

#[cfg(test)]
mod tests;
