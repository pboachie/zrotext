// SPDX-License-Identifier: AGPL-3.0-only
//! A short-lived proof of the original pending-owner registration, never an
//! email-code-only exception for another browser or another password version.

use super::{
    AuthError, TokenHasher, VERIFICATION_HOURS, random_token, valid_token,
    verification_token_for_id,
};
use subtle::ConstantTimeEq;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) const LIFETIME_SECONDS: i32 = 900;
pub(crate) const INTENT_COOKIE: &str = "__Host-zrotext_registration_intent";
pub(crate) const CSRF_COOKIE: &str = "__Host-zrotext_registration_csrf";
pub(crate) const CSRF_HEADER: &str = "x-zrotext-registration-csrf";

// Deliberately has no Debug or serialization implementation. Declined/opaque
// registration responses receive the same independently random shapes.
pub(crate) struct Credentials {
    pub(crate) token: Zeroizing<String>,
    pub(crate) csrf: Zeroizing<String>,
}

impl Credentials {
    pub(crate) fn random() -> Self {
        Self {
            token: Zeroizing::new(random_token("ztri_")),
            csrf: Zeroizing::new(random_token("ztrc_")),
        }
    }

    pub(crate) fn valid(&self) -> bool {
        valid_token(&self.token, "ztri_") && valid_token(&self.csrf, "ztrc_")
    }

    pub(crate) fn cookies(&self) -> [String; 2] {
        [
            format!(
                "{INTENT_COOKIE}={}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={LIFETIME_SECONDS}",
                self.token.as_str()
            ),
            format!(
                "{CSRF_COOKIE}={}; Secure; SameSite=Strict; Path=/; Max-Age={LIFETIME_SECONDS}",
                self.csrf.as_str()
            ),
        ]
    }
}

pub(super) struct Registration<'a> {
    pub(super) account_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) verification_id: Uuid,
    pub(super) email: &'a str,
    pub(super) password_hash: &'a str,
    pub(super) credentials: &'a Credentials,
}

/// Called before the account-creation transaction commits. No intent can exist
/// for an account that failed to register or for a colliding pending owner.
pub(super) async fn insert(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    registration: Registration<'_>,
) -> Result<(), AuthError> {
    if !registration.credentials.valid() {
        return Err(AuthError::InvalidInput);
    }
    let intent_hash = hasher.digest(
        b"registration-browser-intent-v1",
        &registration.credentials.token,
    );
    let csrf_hash = hasher.digest(
        b"registration-browser-csrf-v1",
        &registration.credentials.csrf,
    );
    let password_binding = hasher.digest(
        b"registration-browser-password-v1",
        registration.password_hash,
    );
    tx.execute(
        "WITH stamp AS (SELECT clock_timestamp() AS issued) \
         INSERT INTO registration_browser_intents \
         (intent_hash,csrf_hash,account_id,user_id,email,password_binding,verification_id,created_at,expires_at) \
         SELECT $1,$2,$3,$4,$5,$6,$7,issued,issued+($8::integer * interval '1 second') FROM stamp",
        &[
            &&intent_hash[..],
            &&csrf_hash[..],
            &registration.account_id,
            &registration.user_id,
            &registration.email,
            &&password_binding[..],
            &registration.verification_id,
            &LIFETIME_SECONDS,
        ],
    )
    .await?;
    Ok(())
}

/// This unlocked probe admits only the combined secret mailed code and bound
/// original browser to the existing verified abuse lane. It is never authority
/// to consume anything; the mutation reacquires and checks every row.
pub(crate) async fn live_code_for_budget(
    client: &Client,
    hasher: &TokenHasher,
    credentials: &Credentials,
    token: &str,
) -> Result<bool, AuthError> {
    if !credentials.valid() || !valid_token(token, "ztv_") {
        return Ok(false);
    }
    let intent_hash = hasher.digest(b"registration-browser-intent-v1", &credentials.token);
    let csrf_hash = hasher.digest(b"registration-browser-csrf-v1", &credentials.csrf);
    let code_hash = hasher.digest(b"email-verification-v1", token);
    let row = client.query_opt(
        "SELECT i.password_binding,u.password_hash FROM registration_browser_intents i \
         JOIN users u ON u.id=i.user_id JOIN memberships m ON (m.account_id,m.user_id)=(i.account_id,i.user_id) \
         JOIN accounts a ON a.id=i.account_id JOIN email_verifications v ON v.id=i.verification_id \
         AND (v.account_id,v.user_id)=(i.account_id,i.user_id) \
         WHERE i.intent_hash=$1 AND i.csrf_hash=$2 AND v.token_hash=$3 AND i.consumed_at IS NULL AND i.retired_at IS NULL \
         AND i.expires_at>clock_timestamp() AND i.verification_attempts<8 AND i.email=u.email \
         AND u.email_verified_at IS NULL AND NOT u.mfa_enabled AND u.created_at>clock_timestamp()-make_interval(hours=>$4) \
         AND m.role='owner' AND m.revoked_at IS NULL AND a.disabled_at IS NULL AND v.used_at IS NULL AND v.expires_at>clock_timestamp()",
        &[&&intent_hash[..], &&csrf_hash[..], &&code_hash[..], &VERIFICATION_HOURS],
    ).await?;
    Ok(row.is_some_and(|row| {
        let expected = hasher.digest(
            b"registration-browser-password-v1",
            row.get::<_, String>(1).as_str(),
        );
        let hash: Vec<u8> = row.get(0);
        hash.len() == expected.len() && bool::from(hash.as_slice().ct_eq(&expected))
    }))
}

struct Binding {
    intent_hash: [u8; 32],
    account_id: Uuid,
    user_id: Uuid,
    verification_id: Uuid,
    verification_hash: Vec<u8>,
}

/// Acquire real rows in account/user/membership/intent/generation order. NOWAIT
/// prevents waiting behind the older password-bound verification lock order.
/// Every result remains authoritative only while this transaction holds them.
async fn lock_binding(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    credentials: &Credentials,
) -> Result<Option<Binding>, AuthError> {
    if !credentials.valid() {
        return Ok(None);
    }
    let intent_hash = hasher.digest(b"registration-browser-intent-v1", &credentials.token);
    let Some(hint) = tx
        .query_opt(
            "SELECT account_id,user_id FROM registration_browser_intents WHERE intent_hash=$1",
            &[&&intent_hash[..]],
        )
        .await?
    else {
        return Ok(None);
    };
    let account_id: Uuid = hint.get(0);
    let user_id: Uuid = hint.get(1);
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
            &[&account_id],
        )
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let Some(user) = tx.query_opt(
        "SELECT email,password_hash FROM users WHERE id=$1 AND email_verified_at IS NULL \
         AND NOT mfa_enabled AND created_at>clock_timestamp()-make_interval(hours=>$2) FOR UPDATE NOWAIT",
        &[&user_id, &VERIFICATION_HOURS],
    ).await? else { return Ok(None); };
    if tx.query_opt(
        "SELECT user_id FROM memberships WHERE account_id=$1 AND user_id=$2 AND role='owner' AND revoked_at IS NULL FOR SHARE NOWAIT",
        &[&account_id, &user_id],
    ).await?.is_none() { return Ok(None); }
    let Some(intent) = tx.query_opt(
        "SELECT csrf_hash,email,password_binding,verification_id FROM registration_browser_intents \
         WHERE intent_hash=$1 AND account_id=$2 AND user_id=$3 AND consumed_at IS NULL AND retired_at IS NULL \
         AND expires_at>clock_timestamp() AND verification_attempts<8 FOR UPDATE NOWAIT",
        &[&&intent_hash[..], &account_id, &user_id],
    ).await? else { return Ok(None); };
    let csrf_hash = hasher.digest(b"registration-browser-csrf-v1", &credentials.csrf);
    let password_binding = hasher.digest(
        b"registration-browser-password-v1",
        user.get::<_, String>(1).as_str(),
    );
    let intent_csrf: Vec<u8> = intent.get(0);
    let intent_pwd: Vec<u8> = intent.get(2);
    if intent_csrf.len() != csrf_hash.len()
        || !bool::from(intent_csrf.as_slice().ct_eq(&csrf_hash))
        || intent.get::<_, String>(1) != user.get::<_, String>(0)
        || intent_pwd.len() != password_binding.len()
        || !bool::from(intent_pwd.as_slice().ct_eq(&password_binding))
    {
        return Ok(None);
    }
    let verification_id: Uuid = intent.get(3);
    let Some(verification) = tx.query_opt(
        "SELECT token_hash FROM email_verifications WHERE id=$1 AND account_id=$2 AND user_id=$3 \
         AND used_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE NOWAIT",
        &[&verification_id, &account_id, &user_id],
    ).await? else { return Ok(None); };
    Ok(Some(Binding {
        intent_hash,
        account_id,
        user_id,
        verification_id,
        verification_hash: verification.get(0),
    }))
}

/// Code and original password-version evidence are consumed together. This
/// operation deliberately never creates a session or an MFA challenge.
pub(crate) async fn verify(
    client: &mut Client,
    hasher: &TokenHasher,
    credentials: &Credentials,
    token: &str,
) -> Result<bool, AuthError> {
    let tx = client.transaction().await?;
    let Some(binding) = lock_binding(&tx, hasher, credentials).await? else {
        return Ok(false);
    };
    let charged = tx.execute(
        "UPDATE registration_browser_intents SET verification_attempts=verification_attempts+1 \
         WHERE intent_hash=$1 AND expires_at>clock_timestamp() AND verification_attempts<8 AND consumed_at IS NULL AND retired_at IS NULL",
        &[&&binding.intent_hash[..]],
    ).await?;
    if charged != 1 {
        return Ok(false);
    }
    let actual = hasher.digest(b"email-verification-v1", token);
    if !valid_token(token, "ztv_")
        || binding.verification_hash.len() != actual.len()
        || !bool::from(binding.verification_hash.as_slice().ct_eq(&actual))
    {
        tx.commit().await?;
        return Ok(false);
    }
    let consumed = tx.execute(
        "UPDATE email_verifications SET used_at=clock_timestamp() WHERE id=$1 AND account_id=$2 AND user_id=$3 \
         AND used_at IS NULL AND expires_at>clock_timestamp()",
        &[&binding.verification_id, &binding.account_id, &binding.user_id],
    ).await?;
    let verified = tx.execute(
        "UPDATE users SET email_verified_at=clock_timestamp() WHERE id=$1 AND email_verified_at IS NULL AND NOT mfa_enabled \
         AND created_at>clock_timestamp()-make_interval(hours=>$2)",
        &[&binding.user_id, &VERIFICATION_HOURS],
    ).await?;
    let spent = tx.execute(
        "UPDATE registration_browser_intents SET consumed_at=clock_timestamp() \
         WHERE intent_hash=$1 AND consumed_at IS NULL AND retired_at IS NULL AND expires_at>clock_timestamp()",
        &[&&binding.intent_hash[..]],
    ).await?;
    if consumed != 1 || verified != 1 || spent != 1 {
        return Err(AuthError::Conflict);
    }
    tx.execute(
        "UPDATE verification_mail_outbox SET canceled_at=clock_timestamp(),lease_id=NULL,leased_until=NULL \
         WHERE verification_id=$1 AND canceled_at IS NULL",
        &[&binding.verification_id],
    ).await?;
    if !tx.query_one(
        "SELECT expires_at>clock_timestamp() FROM registration_browser_intents WHERE intent_hash=$1",
        &[&&binding.intent_hash[..]],
    ).await?.get::<_, bool>(0) { return Err(AuthError::Conflict); }
    tx.commit().await?;
    Ok(true)
}

/// Resend always has an opaque HTTP result. It does not revive a retired
/// registration generation, extend the intent, or reset verification attempts.
pub(crate) async fn resend(
    client: &mut Client,
    hasher: &TokenHasher,
    credentials: &Credentials,
) -> Result<bool, AuthError> {
    let tx = client.transaction().await?;
    let Some(binding) = lock_binding(&tx, hasher, credentials).await? else {
        return Ok(false);
    };
    let permitted = tx.execute(
        "UPDATE users SET verification_resend_count=CASE WHEN verification_resend_window_at IS NULL OR \
         verification_resend_window_at<=clock_timestamp()-interval '24 hours' THEN 1 ELSE verification_resend_count+1 END, \
         verification_resend_window_at=CASE WHEN verification_resend_window_at IS NULL OR \
         verification_resend_window_at<=clock_timestamp()-interval '24 hours' THEN clock_timestamp() ELSE verification_resend_window_at END, \
         verification_resend_last_at=clock_timestamp() WHERE id=$1 AND \
         (verification_resend_last_at IS NULL OR verification_resend_last_at<=clock_timestamp()-interval '60 seconds') AND \
         (verification_resend_window_at IS NULL OR verification_resend_window_at<=clock_timestamp()-interval '24 hours' OR verification_resend_count<3)",
        &[&binding.user_id],
    ).await?;
    if permitted != 1 {
        return Ok(false);
    }
    tx.execute("UPDATE email_verifications SET used_at=clock_timestamp() WHERE user_id=$1 AND used_at IS NULL", &[&binding.user_id]).await?;
    tx.execute(
        "UPDATE verification_mail_outbox SET canceled_at=clock_timestamp(),lease_id=NULL,leased_until=NULL \
         WHERE verification_id IN (SELECT id FROM email_verifications WHERE user_id=$1) AND canceled_at IS NULL",
        &[&binding.user_id],
    ).await?;
    let id = Uuid::new_v4();
    let token = verification_token_for_id(hasher, id);
    let token_hash = hasher.digest(b"email-verification-v1", &token);
    tx.execute(
        "INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) \
         SELECT $1,$2,u.id,$4,u.created_at+make_interval(hours=>$5) FROM users u WHERE u.id=$3",
        &[
            &id,
            &binding.account_id,
            &binding.user_id,
            &&token_hash[..],
            &VERIFICATION_HOURS,
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO verification_mail_outbox(verification_id) VALUES($1)",
        &[&id],
    )
    .await?;
    let changed = tx.execute(
        "UPDATE registration_browser_intents SET verification_id=$2 \
         WHERE intent_hash=$1 AND expires_at>clock_timestamp() AND consumed_at IS NULL AND retired_at IS NULL",
        &[&&binding.intent_hash[..], &id],
    ).await?;
    if changed != 1 {
        return Err(AuthError::Conflict);
    }
    if !tx.query_one(
        "SELECT expires_at>clock_timestamp() FROM registration_browser_intents WHERE intent_hash=$1",
        &[&&binding.intent_hash[..]],
    ).await?.get::<_, bool>(0) { return Err(AuthError::Conflict); }
    tx.commit().await?;
    crate::wakeups::account_mail_queued();
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests;
