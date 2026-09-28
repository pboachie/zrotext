// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-managed device-status observer seats. An owner invites an address
//! with a bounded, single-use opaque invitation; the database stores only the
//! HMAC of that token. The invitee accepts it with a new password, verifies
//! the address independently, and receives read-only status access. Seats are
//! revoked, never deleted, so a removed observer cannot be resurrected by any
//! later request.

use super::{
    AuthError, SessionPrincipal, TokenHasher, VERIFICATION_HOURS, normalize_email, password_work,
    random_token, require_current_owner, valid_token, verification_token_for_id,
};
use tokio_postgres::Client;
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
    pub user_id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
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

/// Invite one address to this account as a device-status observer. The address
/// must not belong to any user on this server, and the account must be inside
/// both the live-seat and open-invitation caps. A second open invitation for
/// the same address is refused even from another account, so two owners can
/// never race to claim one recipient.
pub async fn create_invitation(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    email: &str,
) -> Result<IssuedInvitation, AuthError> {
    require_current_owner(client, principal).await?;
    let email = normalize_email(email)?;
    let account_id = principal.tenant.account_id();
    let tx = client.transaction().await?;
    if tx
        .query_opt("SELECT 1 FROM users WHERE email=$1", &[&email])
        .await?
        .is_some()
    {
        return Err(AuthError::Conflict);
    }
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
            // A concurrent invitation claimed this address first.
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
    tx.commit().await?;
    Ok(IssuedInvitation {
        id,
        email,
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
    let seats = client
        .query(
            "SELECT m.user_id,u.email,(u.email_verified_at IS NOT NULL),(extract(epoch FROM m.created_at)*1000)::bigint,(extract(epoch FROM m.revoked_at)*1000)::bigint FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.account_id=$1 AND m.role='observer' ORDER BY m.created_at DESC,m.user_id DESC LIMIT $2",
            &[&account_id, &SEAT_PAGE_LIMIT],
        )
        .await?
        .into_iter()
        .map(|row| SeatSummary {
            user_id: row.get(0),
            email: row.get(1),
            email_verified: row.get(2),
            created_at_ms: row.get(3),
            revoked_at_ms: row.get(4),
        })
        .collect();
    let invitations = client
        .query(
            "SELECT id,email,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM expires_at)*1000)::bigint,(extract(epoch FROM accepted_at)*1000)::bigint,(extract(epoch FROM canceled_at)*1000)::bigint,accepted_user_id FROM seat_invitations WHERE account_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2",
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
pub async fn remove_observer(
    client: &mut Client,
    principal: &SessionPrincipal,
    user_id: Uuid,
) -> Result<bool, AuthError> {
    require_current_owner(client, principal).await?;
    let account_id = principal.tenant.account_id();
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.account_id=$1 AND m.user_id=$2 AND m.role='observer' AND m.revoked_at IS NULL FOR UPDATE OF m",
            &[&account_id, &user_id],
        )
        .await?
    else {
        return Ok(false);
    };
    let email: String = row.get(0);
    let revoked = tx
        .execute(
            "UPDATE memberships SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND role='observer' AND revoked_at IS NULL",
            &[&account_id, &user_id],
        )
        .await?;
    if revoked != 1 {
        return Ok(false);
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
    tx.commit().await?;
    Ok(true)
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
/// conflicting existing user for the bound address without touching it, then
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
    tx.execute(
        "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)",
        &[&user_id, &email, &password_hash],
    )
    .await?;
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
