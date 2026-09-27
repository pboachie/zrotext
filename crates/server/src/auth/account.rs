// SPDX-License-Identifier: AGPL-3.0-only
//! Owner password and session controls. User-row locks serialize a password
//! rotation or reset with login/session creation across API sites.

use super::{
    AuthError, SessionPrincipal, TokenHasher, mfa, normalize_email, password_work, valid_token,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio_postgres::Client;
use uuid::Uuid;

const RESET_HOURS: i32 = 1;
const SESSION_PAGE_SIZE: i64 = 50;

pub struct SessionInfo {
    pub id: Uuid,
    pub current: bool,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
}

pub async fn list_sessions(
    client: &Client,
    owner: &SessionPrincipal,
) -> Result<Vec<SessionInfo>, AuthError> {
    let rows = client
        .query(
            "SELECT id,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM expires_at)*1000)::bigint,(extract(epoch FROM last_used_at)*1000)::bigint FROM sessions WHERE account_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() ORDER BY (id=$3) DESC,created_at DESC,id DESC LIMIT $4",
            &[&owner.tenant.account_id(), &owner.user_id, &owner.session_id, &SESSION_PAGE_SIZE],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.get(0);
            SessionInfo {
                id,
                current: id == owner.session_id,
                created_at_ms: row.get(1),
                expires_at_ms: row.get(2),
                last_used_at_ms: row.get(3),
            }
        })
        .collect())
}

pub async fn revoke_other_sessions(
    client: &mut Client,
    cipher: Option<&mfa::MfaCipher>,
    hasher: &TokenHasher,
    owner: &SessionPrincipal,
    current_password: &str,
    code: Option<&str>,
) -> Result<u64, AuthError> {
    let account_id = owner.tenant.account_id();
    let old_hash: String = client.query_opt(
        "SELECT u.password_hash FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id JOIN sessions s ON s.account_id=m.account_id AND s.user_id=u.id WHERE u.id=$1 AND m.account_id=$2 AND s.id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.disabled_at IS NULL",
        &[&owner.user_id, &account_id, &owner.session_id],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?
    .get(0);
    password_work::verify(current_password, Some(old_hash.clone())).await?;
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT password_hash,mfa_enabled FROM users WHERE id=$1 FOR UPDATE",
            &[&owner.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if row.get::<_, String>(0) != old_hash {
        return Err(AuthError::InvalidCredentials);
    }
    require_live_session(&tx, owner).await?;
    if row.get::<_, bool>(1) {
        let code = code.ok_or(AuthError::InvalidCredentials)?;
        mfa::ensure_factor_budget(&tx, account_id, owner.user_id).await?;
        if !mfa::use_factor(&tx, cipher, hasher, account_id, owner.user_id, code).await? {
            mfa::record_failed_factor(&tx, account_id, owner.user_id).await?;
            tx.commit().await?;
            return Err(AuthError::InvalidCredentials);
        }
    }
    let revoked = tx
        .execute(
            "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND id<>$3 AND revoked_at IS NULL",
            &[&account_id, &owner.user_id, &owner.session_id],
        )
        .await?;
    tx.execute(
        "UPDATE owner_mfa_login_challenges SET consumed_at=now() WHERE account_id=$1 AND user_id=$2 AND consumed_at IS NULL",
        &[&account_id, &owner.user_id],
    )
    .await?;
    tx.commit().await?;
    Ok(revoked)
}

async fn require_live_session(
    tx: &tokio_postgres::Transaction<'_>,
    owner: &SessionPrincipal,
) -> Result<(), AuthError> {
    tx.query_opt(
        "SELECT id FROM sessions WHERE id=$1 AND account_id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE",
        &[&owner.session_id, &owner.tenant.account_id(), &owner.user_id],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    Ok(())
}

pub async fn change_password(
    client: &mut Client,
    cipher: Option<&mfa::MfaCipher>,
    hasher: &TokenHasher,
    owner: &SessionPrincipal,
    current_password: &str,
    new_password: &str,
    code: Option<&str>,
) -> Result<(), AuthError> {
    if !(12..=1024).contains(&new_password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let account_id = owner.tenant.account_id();
    let row = client
        .query_opt(
            "SELECT u.password_hash FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id JOIN sessions s ON s.account_id=m.account_id AND s.user_id=u.id WHERE u.id=$1 AND m.account_id=$2 AND s.id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.disabled_at IS NULL",
            &[&owner.user_id, &account_id, &owner.session_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let old_hash: String = row.get(0);
    password_work::verify(current_password, Some(old_hash.clone())).await?;
    let new_hash = password_work::hash(new_password).await?;
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT password_hash,mfa_enabled FROM users WHERE id=$1 FOR UPDATE",
            &[&owner.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if row.get::<_, String>(0) != old_hash {
        return Err(AuthError::InvalidCredentials);
    }
    require_live_session(&tx, owner).await?;
    if row.get::<_, bool>(1) {
        let code = code.ok_or(AuthError::InvalidCredentials)?;
        mfa::ensure_factor_budget(&tx, account_id, owner.user_id).await?;
        let accepted =
            mfa::use_factor(&tx, cipher, hasher, account_id, owner.user_id, code).await?;
        if !accepted {
            mfa::record_failed_factor(&tx, account_id, owner.user_id).await?;
            tx.commit().await?;
            return Err(AuthError::InvalidCredentials);
        }
    }
    tx.execute(
        "UPDATE users SET password_hash=$2 WHERE id=$1",
        &[&owner.user_id, &new_hash],
    )
    .await?;
    tx.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND revoked_at IS NULL",
        &[&account_id, &owner.user_id],
    )
    .await?;
    tx.execute(
        "UPDATE api_keys SET revoked_at=now() WHERE account_id=$1 AND created_by_user_id=$2 AND revoked_at IS NULL",
        &[&account_id, &owner.user_id],
    )
    .await?;
    tx.execute(
        "UPDATE owner_mfa_login_challenges SET consumed_at=now() WHERE account_id=$1 AND user_id=$2 AND consumed_at IS NULL",
        &[&account_id, &owner.user_id],
    )
    .await?;
    tx.execute(
        "UPDATE password_resets SET used_at=now() WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL",
        &[&account_id, &owner.user_id],
    )
    .await?;
    cancel_reset_mail(&tx, account_id, owner.user_id).await?;
    tx.commit().await?;
    Ok(())
}

fn reset_token_for_id(hasher: &TokenHasher, id: Uuid) -> String {
    let secret = hasher.digest(b"password-reset-issue-v1", &id.to_string());
    format!("ztr_{}", URL_SAFE_NO_PAD.encode(secret))
}

async fn cancel_reset_mail(
    tx: &tokio_postgres::Transaction<'_>,
    account_id: Uuid,
    user_id: Uuid,
) -> Result<(), AuthError> {
    tx.execute(
        "UPDATE password_reset_mail_outbox o SET canceled_at=now(),lease_id=NULL,leased_until=NULL FROM password_resets r WHERE o.reset_id=r.id AND r.account_id=$1 AND r.user_id=$2 AND r.used_at IS NOT NULL AND o.canceled_at IS NULL AND o.delivered_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    Ok(())
}

/// Always report the same result to an HTTP caller. At most one code per user
/// is issued in a 15-minute window; earlier codes and their mail are canceled.
pub async fn request_password_reset(
    client: &mut Client,
    hasher: &TokenHasher,
    email: &str,
) -> Result<(), AuthError> {
    let Ok(email) = normalize_email(email) else {
        return Ok(());
    };
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&email],
        )
        .await?
    else {
        tx.commit().await?;
        return Ok(());
    };
    let user_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    let recent = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM password_resets WHERE user_id=$1 AND created_at>now()-interval '15 minutes')",
            &[&user_id],
        )
        .await?
        .get::<_, bool>(0);
    if recent {
        tx.commit().await?;
        return Ok(());
    }
    tx.execute(
        "UPDATE password_resets SET used_at=now() WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL",
        &[&account_id, &user_id],
    )
    .await?;
    cancel_reset_mail(&tx, account_id, user_id).await?;
    let id = Uuid::new_v4();
    let token = reset_token_for_id(hasher, id);
    let hash = hasher.digest(b"password-reset-v1", &token);
    tx.execute(
        "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+($5::integer * interval '1 hour'))",
        &[&id, &account_id, &user_id, &&hash[..], &RESET_HOURS],
    )
    .await?;
    tx.execute(
        "INSERT INTO password_reset_mail_outbox(reset_id) VALUES($1)",
        &[&id],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub struct ResetMail {
    pub reset_id: Uuid,
    pub lease_id: Uuid,
    pub email: String,
    /// Secret: never include in logs, URLs, response bodies, or metrics.
    pub token: String,
}

/// Remove at most one batch of expired reset codes and their queued mail.
/// The outbox rows cascade away, so they leave the due index as well.
pub async fn prune_expired_password_resets(client: &Client) -> Result<u64, AuthError> {
    Ok(client
        .execute(
            "WITH expired AS (SELECT id FROM password_resets WHERE expires_at<=now() ORDER BY expires_at,id LIMIT 500 FOR UPDATE SKIP LOCKED) DELETE FROM password_resets r USING expired e WHERE r.id=e.id",
            &[],
        )
        .await?)
}

pub async fn claim_reset_mail(
    client: &mut Client,
    hasher: &TokenHasher,
) -> Result<Option<ResetMail>, AuthError> {
    prune_expired_password_resets(client).await?;
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT o.reset_id,u.email,r.token_hash FROM password_reset_mail_outbox o JOIN password_resets r ON r.id=o.reset_id JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id WHERE o.delivered_at IS NULL AND o.canceled_at IS NULL AND o.dead_at IS NULL AND o.attempt_count<6 AND o.next_attempt_at<=now() AND (o.leased_until IS NULL OR o.leased_until<=now()) AND r.used_at IS NULL AND r.expires_at>now() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL ORDER BY o.next_attempt_at,o.reset_id LIMIT 1 FOR UPDATE OF o SKIP LOCKED",
            &[],
        )
        .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let reset_id: Uuid = row.get(0);
    let token = reset_token_for_id(hasher, reset_id);
    let hash = hasher.digest(b"password-reset-v1", &token);
    if row.get::<_, Vec<u8>>(2) != hash {
        tx.execute(
            "UPDATE password_reset_mail_outbox SET dead_at=now() WHERE reset_id=$1",
            &[&reset_id],
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let lease_id = Uuid::new_v4();
    tx.execute(
        "UPDATE password_reset_mail_outbox SET lease_id=$2,leased_until=now()+interval '5 minutes',attempt_count=attempt_count+1 WHERE reset_id=$1",
        &[&reset_id, &lease_id],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(ResetMail {
        reset_id,
        lease_id,
        email: row.get(1),
        token,
    }))
}

pub async fn ack_reset_mail(
    client: &Client,
    mail: &ResetMail,
    delivered: bool,
) -> Result<bool, AuthError> {
    let changed = if delivered {
        client
            .execute(
                "UPDATE password_reset_mail_outbox SET delivered_at=now(),lease_id=NULL,leased_until=NULL WHERE reset_id=$1 AND lease_id=$2 AND canceled_at IS NULL AND delivered_at IS NULL",
                &[&mail.reset_id, &mail.lease_id],
            )
            .await?
    } else {
        client
            .execute(
                "UPDATE password_reset_mail_outbox SET lease_id=NULL,leased_until=NULL,next_attempt_at=now()+(power(2,least(attempt_count,5))::integer * interval '1 minute'),dead_at=CASE WHEN attempt_count>=6 THEN now() ELSE dead_at END WHERE reset_id=$1 AND lease_id=$2 AND canceled_at IS NULL AND delivered_at IS NULL",
                &[&mail.reset_id, &mail.lease_id],
            )
            .await?
    };
    Ok(changed == 1)
}

pub struct ResetNotice {
    pub id: Uuid,
    pub lease_id: Uuid,
    pub email: String,
}

pub async fn claim_reset_notice(client: &mut Client) -> Result<Option<ResetNotice>, AuthError> {
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT o.id,u.email FROM password_reset_notice_outbox o JOIN users u ON u.id=o.user_id WHERE o.delivered_at IS NULL AND o.dead_at IS NULL AND o.attempt_count<6 AND o.next_attempt_at<=now() AND (o.leased_until IS NULL OR o.leased_until<=now()) ORDER BY o.next_attempt_at,o.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED",
            &[],
        )
        .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let id: Uuid = row.get(0);
    let lease_id = Uuid::new_v4();
    tx.execute(
        "UPDATE password_reset_notice_outbox SET lease_id=$2,leased_until=now()+interval '5 minutes',attempt_count=attempt_count+1 WHERE id=$1",
        &[&id, &lease_id],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(ResetNotice {
        id,
        lease_id,
        email: row.get(1),
    }))
}

pub async fn ack_reset_notice(
    client: &Client,
    notice: &ResetNotice,
    delivered: bool,
) -> Result<bool, AuthError> {
    let changed = if delivered {
        client
            .execute(
                "UPDATE password_reset_notice_outbox SET delivered_at=now(),lease_id=NULL,leased_until=NULL WHERE id=$1 AND lease_id=$2 AND delivered_at IS NULL",
                &[&notice.id, &notice.lease_id],
            )
            .await?
    } else {
        client
            .execute(
                "UPDATE password_reset_notice_outbox SET lease_id=NULL,leased_until=NULL,next_attempt_at=now()+(power(2,least(attempt_count,5))::integer * interval '1 minute'),dead_at=CASE WHEN attempt_count>=6 THEN now() ELSE dead_at END WHERE id=$1 AND lease_id=$2 AND delivered_at IS NULL",
                &[&notice.id, &notice.lease_id],
            )
            .await?
    };
    Ok(changed == 1)
}

/// Indexed, read-only proof for the verified rate-limit lane. It does not
/// consume the code; confirmation rechecks everything under the user lock.
pub async fn reset_token_is_live(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<bool, AuthError> {
    if !valid_token(token, "ztr_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"password-reset-v1", token);
    Ok(client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM password_resets r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id WHERE r.token_hash=$1 AND r.used_at IS NULL AND r.expires_at>now() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL)",
            &[&&hash[..]],
        )
        .await?
        .get(0))
}

pub async fn confirm_password_reset(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    new_password: &str,
) -> Result<bool, AuthError> {
    if !valid_token(token, "ztr_") || !(12..=1024).contains(&new_password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let hash = hasher.digest(b"password-reset-v1", token);
    let Some(identity) = client
        .query_opt(
            "SELECT account_id,user_id FROM password_resets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now()",
            &[&&hash[..]],
        )
        .await?
    else {
        return Ok(false);
    };
    let account_id: Uuid = identity.get(0);
    let user_id: Uuid = identity.get(1);
    let new_hash = password_work::hash(new_password).await?;
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
        &[&user_id, &account_id],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    let consumed = tx
        .execute(
            "UPDATE password_resets SET used_at=now() WHERE token_hash=$1 AND account_id=$2 AND user_id=$3 AND used_at IS NULL AND expires_at>now()",
            &[&&hash[..], &account_id, &user_id],
        )
        .await?;
    if consumed != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    replace_password_and_revoke(&tx, account_id, user_id, &new_hash).await?;
    tx.commit().await?;
    Ok(true)
}

/// Operator recovery for instances without SMTP. Only the local
/// `zrotext-admin reset-password` command calls this; no HTTP route reaches
/// it. It applies the same revocations as an emailed reset and preserves MFA
/// enrollment. Returns `false` when no verified owner of a live account has
/// that address.
pub async fn operator_reset_password(
    client: &mut Client,
    email: &str,
    new_password: &str,
) -> Result<bool, AuthError> {
    if !(12..=1024).contains(&new_password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let email = normalize_email(email)?;
    let new_hash = password_work::hash(new_password).await?;
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&email],
        )
        .await?
    else {
        tx.rollback().await?;
        return Ok(false);
    };
    let user_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    replace_password_and_revoke(&tx, account_id, user_id, &new_hash).await?;
    tx.commit().await?;
    Ok(true)
}

/// Caller holds the user-row lock. Revokes every session, owner API key,
/// pending MFA login challenge and outstanding reset code, then queues the
/// reset notification mail.
async fn replace_password_and_revoke(
    tx: &tokio_postgres::Transaction<'_>,
    account_id: Uuid,
    user_id: Uuid,
    new_hash: &str,
) -> Result<(), AuthError> {
    tx.execute(
        "UPDATE users SET password_hash=$2 WHERE id=$1",
        &[&user_id, &new_hash],
    )
    .await?;
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
    cancel_reset_mail(tx, account_id, user_id).await?;
    tx.execute(
        "INSERT INTO password_reset_notice_outbox(id,account_id,user_id) VALUES($1,$2,$3)",
        &[&Uuid::new_v4(), &account_id, &user_id],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
