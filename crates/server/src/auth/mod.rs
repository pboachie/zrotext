// SPDX-License-Identifier: AGPL-3.0-only
//! Database-backed owner authentication. Callers must keep the token pepper in
//! operational secret storage, independent of password verifiers and vault keys.
//! Every resource repository must accept a `Tenant` and filter by its account ID.

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio_postgres::{Client, types::Type};
use uuid::Uuid;

const SESSION_DAYS: i32 = 14;
/// A session unused for this long is rejected even before its absolute
/// `SESSION_DAYS` expiry. Activity is recorded at most every
/// `ACTIVITY_WRITE_MINUTES`, so a session may lapse up to that much earlier
/// than its true last use.
const SESSION_IDLE_HOURS: i32 = 72;
/// Coarse write guard shared by session and API key `last_used_at`, so an
/// authenticated request rewrites the row at most once per window.
const ACTIVITY_WRITE_MINUTES: i32 = 15;
/// Lifetime of a verification code and of the unverified owner that requested
/// it. The pending window is anchored at `users.created_at` and is not
/// extended by resends, so an unverified sign-up cannot reserve an address
/// beyond this bound.
const VERIFICATION_HOURS: i32 = 24;
/// Bounded batch for the periodic removal of expired unverified owners.
const PENDING_PRUNE_BATCH: i64 = 100;
const MAX_EMAIL_BYTES: usize = 254;
/// Serialize operator bootstrap and HTTP registration across API processes.
const REGISTRATION_ADVISORY_LOCK: i64 = 0x5a54524547495354;

pub mod abuse_limits;
pub mod account;
pub mod agent_grants;
pub mod collaboration;
pub mod mfa;
mod password_work;
#[cfg(test)]
mod roles_tests;
pub mod seats;
mod verification_outbox;
pub use verification_outbox::{
    VerificationMail, ack_verification_mail, claim_verification_mail, request_verification_resend,
};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid input")]
    InvalidInput,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("email verification required")]
    EmailNotVerified,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("conflicting account state")]
    Conflict,
    #[error("revoke the active SMS owner approval key before disabling MFA")]
    SmsOwnerKeyActive,
    #[error("authentication storage failed")]
    Database(#[from] tokio_postgres::Error),
    #[error("password hashing failed")]
    Password,
    #[error("second factor required")]
    MfaRequired { account_id: Uuid, user_id: Uuid },
    #[error("authentication cryptography failed")]
    Crypto,
    #[error("authentication rate limit exceeded")]
    RateLimited,
}

/// This pepper must be generated once, backed up, and shared across API sites.
/// Rotating it requires a planned token invalidation or a verifier key ring.
pub struct TokenHasher(Vec<u8>);

impl TokenHasher {
    pub fn new(pepper: Vec<u8>) -> Result<Self, AuthError> {
        if pepper.len() < 32 {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self(pepper))
    }

    pub(crate) fn workflow_credential_hash(&self, token: &str) -> [u8; 32] {
        self.digest(b"workflow-credential-v1", token)
    }

    fn digest(&self, domain: &[u8], token: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts all key sizes");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(token.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

pub struct Signup {
    pub account_id: Uuid,
    pub user_id: Uuid,
    /// Compatibility for internal tests. Delivery reconstructs this code from
    /// the challenge ID and operational pepper; never log or put it in a URL.
    pub verification_token: String,
}

pub struct SessionCredentials {
    pub id: Uuid,
    pub token: String,
    pub csrf_token: String,
}

pub struct ApiKeyCredentials {
    pub id: Uuid,
    pub token: String,
    pub public_prefix: String,
}

/// Safe to return to the owner dashboard: neither token nor verifier is read.
pub struct ApiKeyMetadata {
    pub id: Uuid,
    pub public_prefix: String,
    pub scopes: Vec<String>,
    pub bound_device_id: Option<Uuid>,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    /// Coarse: updated at most once per 15 minutes of use.
    pub last_used_at_ms: Option<i64>,
}

pub struct ApiKeyPage {
    pub keys: Vec<ApiKeyMetadata>,
    pub next_cursor: Option<Uuid>,
}

/// Scope names are intentionally narrow. API keys do not unlock content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Scope {
    MessagesSend,
    MessagesRead,
    DevicesRead,
    DevicesManage,
    WebhooksRead,
    WebhooksManage,
    BillingRead,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessagesSend => "messages:send",
            Self::MessagesRead => "messages:read",
            Self::DevicesRead => "devices:read",
            Self::DevicesManage => "devices:manage",
            Self::WebhooksRead => "webhooks:read",
            Self::WebhooksManage => "webhooks:manage",
            Self::BillingRead => "billing:read",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "messages:send" => Self::MessagesSend,
            "messages:read" => Self::MessagesRead,
            "devices:read" => Self::DevicesRead,
            "devices:manage" => Self::DevicesManage,
            "webhooks:read" => Self::WebhooksRead,
            "webhooks:manage" => Self::WebhooksManage,
            "billing:read" => Self::BillingRead,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Owner,
    Observer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Observer => "observer",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "observer" => Some(Self::Observer),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tenant {
    account_id: Uuid,
}

impl Tenant {
    pub fn account_id(self) -> Uuid {
        self.account_id
    }

    /// Use this before operating on a resource returned from another source.
    /// SQL queries must also include `WHERE account_id = $tenant`.
    pub fn require_account(self, resource_account_id: Uuid) -> Result<(), AuthError> {
        if self.account_id == resource_account_id {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

#[derive(Clone)]
pub struct SessionPrincipal {
    pub tenant: Tenant,
    pub user_id: Uuid,
    pub session_id: Uuid,
    /// Current role of the membership this session belongs to. Owner routes
    /// must recheck it against the database instead of trusting this copy.
    pub role: Role,
    csrf_hash: [u8; 32],
    /// Unspent proof that [`authenticate_session`] validated this session for
    /// the current request. See [`SessionPrincipal::spend_fresh_verification`].
    verification: FreshVerification,
}

/// How long `authenticate_session`'s validation stands in for the next
/// unlocked owner re-check. Owner handlers make that re-check microseconds
/// later on the same request; anything slower re-queries.
const FRESH_VERIFICATION_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// Only [`authenticate_session`] creates an unspent verification; principals
/// built any other way start spent, so every re-check runs.
struct FreshVerification {
    at: Option<std::time::Instant>,
    unspent: std::sync::atomic::AtomicBool,
}

/// A clone never inherits the shortcut: only the principal that
/// `authenticate_session` returned may spend its validation.
impl Clone for FreshVerification {
    fn clone(&self) -> Self {
        Self {
            at: None,
            unspent: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl FreshVerification {
    #[cfg(test)]
    fn spent() -> Self {
        Self {
            at: None,
            unspent: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn now() -> Self {
        Self {
            at: Some(std::time::Instant::now()),
            unspent: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

impl SessionPrincipal {
    /// Spends this request's session validation in place of one unlocked
    /// owner re-check. True at most once per principal, and only within
    /// [`FRESH_VERIFICATION_WINDOW`] of `authenticate_session` returning it.
    ///
    /// An unlocked re-check is point-in-time evidence only: a revocation can
    /// commit immediately after it just as after `authenticate_session`, so
    /// the operation that follows is ordered before that revocation either
    /// way. Locking re-checks inside transactions (`FOR UPDATE`/`FOR SHARE`),
    /// and the session joins inside INSERT statements, never use this.
    pub(crate) fn spend_fresh_verification(&self) -> bool {
        let Some(at) = self.verification.at else {
            return false;
        };
        at.elapsed() < FRESH_VERIFICATION_WINDOW
            && self
                .verification
                .unspent
                .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    /// Cookie-authenticated mutations require both exact origin and a matching
    /// CSRF cookie/header value. Origin is the configured canonical HTTPS origin.
    pub fn require_csrf(
        &self,
        hasher: &TokenHasher,
        origin: &str,
        expected_origin: &str,
        csrf_cookie: &str,
        csrf_header: &str,
    ) -> Result<(), AuthError> {
        if !expected_origin.starts_with("https://") || origin != expected_origin {
            return Err(AuthError::Forbidden);
        }
        self.require_csrf_token(hasher, csrf_cookie, csrf_header)
    }

    /// Read-only owner metadata requests carry the token in a custom header.
    /// Browsers do not send Origin on ordinary same-origin GET requests.
    pub fn require_csrf_token(
        &self,
        hasher: &TokenHasher,
        csrf_cookie: &str,
        csrf_header: &str,
    ) -> Result<(), AuthError> {
        if csrf_cookie.len() != csrf_header.len()
            || !bool::from(csrf_cookie.as_bytes().ct_eq(csrf_header.as_bytes()))
            || !valid_token(csrf_cookie, "ztc_")
        {
            return Err(AuthError::Forbidden);
        }
        let actual = hasher.digest(b"csrf-v1", csrf_cookie);
        if bool::from(actual.ct_eq(&self.csrf_hash)) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

pub struct ApiPrincipal {
    pub tenant: Tenant,
    pub key_id: Uuid,
    scopes: Vec<Scope>,
    bound_device_id: Option<Uuid>,
}

impl ApiPrincipal {
    pub fn require(&self, scope: Scope, device_id: Option<Uuid>) -> Result<(), AuthError> {
        if !self.scopes.contains(&scope) {
            return Err(AuthError::Forbidden);
        }
        if let Some(bound) = self.bound_device_id
            && device_id != Some(bound)
        {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }
}

fn random_token(prefix: &str) -> String {
    let bytes: [u8; 32] = rand::random();
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn verification_token_for_id(hasher: &TokenHasher, id: Uuid) -> String {
    let secret = hasher.digest(b"email-verification-issue-v1", &id.to_string());
    format!("ztv_{}", URL_SAFE_NO_PAD.encode(secret))
}

fn valid_token(token: &str, prefix: &str) -> bool {
    token
        .strip_prefix(prefix)
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .is_some_and(|bytes| bytes.len() == 32 && token.len() == prefix.len() + 43)
}

fn password_engine() -> Result<Argon2<'static>, AuthError> {
    // Baseline: 64 MiB, 3 passes, 1 lane. Calibrate against the deployed VM
    // before exposure and bound concurrent login attempts at the HTTP edge.
    let params = Params::new(64 * 1024, 3, 1, None).map_err(|_| AuthError::Password)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Unknown accounts must incur the same password verification work as known
/// accounts. The verifier is process-local and never represents a real user.
fn dummy_password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        password_engine()
            .expect("fixed Argon2 parameters")
            .hash_password(b"unregistered-account")
            .expect("fixed Argon2 parameters and random salt")
            .to_string()
    })
}

pub(crate) fn normalize_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_ascii_lowercase();
    if email.len() < 3
        || email.len() > MAX_EMAIL_BYTES
        || email
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || email.matches('@').count() != 1
    {
        return Err(AuthError::InvalidInput);
    }
    Ok(email)
}

pub async fn register(
    client: &mut Client,
    hasher: &TokenHasher,
    email: &str,
    password: &str,
) -> Result<Signup, AuthError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let email = normalize_email(email)?;
    let password_hash = password_work::hash(password).await?;
    let account_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let verification_id = Uuid::new_v4();
    let verification_token = verification_token_for_id(hasher, verification_id);
    let token_hash = hasher.digest(b"email-verification-v1", &verification_token);
    let mut transaction = client.transaction().await?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1::bigint)",
            &[&REGISTRATION_ADVISORY_LOCK],
        )
        .await?;
    // An unverified owner whose pending window has elapsed no longer holds the
    // address. Its row lock serializes concurrent sign-ups: a waiter re-reads
    // the deleted row, skips it, and then meets the unique email constraint.
    let stale = transaction
        .query_opt(
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.role='owner' AND u.email=$1 AND u.email_verified_at IS NULL AND u.created_at<=now()-($2::integer * interval '1 hour') AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&email, &VERIFICATION_HOURS],
        )
        .await?;
    if let Some(row) = stale {
        discard_pending_owner(&mut transaction, row.get(0), row.get(1)).await?;
    }
    transaction
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await?;
    transaction
        .execute(
            "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)",
            &[&user_id, &email, &password_hash],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account_id, &user_id],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+($5::integer * interval '1 hour'))",
            &[&verification_id, &account_id, &user_id, &&token_hash[..], &VERIFICATION_HOURS],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO verification_mail_outbox(verification_id) VALUES($1)",
            &[&verification_id],
        )
        .await?;
    transaction.commit().await?;
    crate::wakeups::account_mail_queued();
    Ok(Signup {
        account_id,
        user_id,
        verification_token,
    })
}

/// Local operator-only bootstrap. A verified owner is created exactly once on
/// an empty database, without an HTTP registration request or verification
/// email. Hold the same cross-process lock as HTTP registration while checking
/// emptiness and inserting all three rows.
pub async fn bootstrap_owner(
    client: &mut Client,
    email: &str,
    password: &str,
) -> Result<bool, AuthError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let email = normalize_email(email)?;
    let password_hash = password_work::hash(password).await?;
    let account_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let transaction = client.transaction().await?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1::bigint)",
            &[&REGISTRATION_ADVISORY_LOCK],
        )
        .await?;
    let occupied: bool = transaction
        .query_one("SELECT EXISTS(SELECT 1 FROM accounts)", &[])
        .await?
        .get(0);
    if occupied {
        return Ok(false);
    }
    transaction
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await?;
    transaction
        .execute(
            "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
            &[&user_id, &email, &password_hash],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account_id, &user_id],
        )
        .await?;
    transaction.commit().await?;
    Ok(true)
}

/// Removes one locked, expired, unverified owner together with its membership,
/// verification codes, queued mail, and any session state (all cascade from
/// the user row), then its otherwise-empty account. The caller must hold the
/// user row lock. Verified owners are never matched. If unexpected dependent
/// rows exist, nothing is removed and `false` is returned.
async fn discard_pending_owner(
    transaction: &mut tokio_postgres::Transaction<'_>,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<bool, AuthError> {
    let savepoint = transaction.transaction().await?;
    let removed = async {
        let users = savepoint
            .execute(
                "DELETE FROM users WHERE id=$1 AND email_verified_at IS NULL AND created_at<=now()-($2::integer * interval '1 hour')",
                &[&user_id, &VERIFICATION_HOURS],
            )
            .await?;
        if users != 1 {
            return Ok(false);
        }
        savepoint
            .execute(
                "DELETE FROM accounts a WHERE a.id=$1 AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.account_id=a.id)",
                &[&account_id],
            )
            .await?;
        Ok::<_, tokio_postgres::Error>(true)
    }
    .await;
    match removed {
        Ok(true) => {
            savepoint.commit().await?;
            Ok(true)
        }
        Ok(false) => {
            savepoint.rollback().await?;
            Ok(false)
        }
        Err(error)
            if error.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) =>
        {
            savepoint.rollback().await?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// Bounded cleanup of unverified owners whose pending window has elapsed.
/// Safe for concurrent workers and concurrent sign-ups due to SKIP LOCKED.
pub async fn prune_expired_pending_owners(client: &mut Client) -> Result<u64, AuthError> {
    let mut transaction = client.transaction().await?;
    let rows = transaction
        .query(
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.role='owner' AND u.email_verified_at IS NULL AND u.created_at<=now()-($1::integer * interval '1 hour') AND a.disabled_at IS NULL ORDER BY u.created_at,u.id LIMIT $2 FOR UPDATE OF u SKIP LOCKED",
            &[&VERIFICATION_HOURS, &PENDING_PRUNE_BATCH],
        )
        .await?;
    let mut removed = 0;
    for row in rows {
        if discard_pending_owner(&mut transaction, row.get(0), row.get(1)).await? {
            removed += 1;
        }
    }
    transaction.commit().await?;
    Ok(removed)
}

/// Cheap indexed probe for a live code after the anonymous invalid-code
/// budget is exhausted. This never consumes a code or opens a transaction.
pub async fn verification_token_is_live(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<bool, AuthError> {
    if !valid_token(token, "ztv_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"email-verification-v1", token);
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM email_verifications v JOIN users u ON u.id=v.user_id
             JOIN memberships m ON (m.account_id,m.user_id)=(v.account_id,v.user_id)
             WHERE m.revoked_at IS NULL AND v.token_hash=$1 AND v.used_at IS NULL AND v.expires_at>now()
             AND (u.email_verified_at IS NOT NULL OR u.created_at>now()-($2::integer * interval '1 hour')))",
            &[&&hash[..], &VERIFICATION_HOURS],
        )
        .await?;
    Ok(row.get(0))
}

/// Consumes a live verification code after the registrant proves the password
/// stored for the pending owner. A mailed code alone must never verify an
/// address: a third party can register any address with its own password, and
/// the recipient must not be able to activate that foreign account by pasting
/// the code. Unknown, expired and consumed codes incur the same password work
/// as live ones, and every `false` result must share one HTTP response.
pub async fn verify_email_with_password(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    password: &str,
) -> Result<bool, AuthError> {
    let row = if valid_token(token, "ztv_") {
        let hash = hasher.digest(b"email-verification-v1", token);
        client
            .query_opt(
                "SELECT u.id,u.password_hash FROM email_verifications v JOIN users u ON u.id=v.user_id JOIN memberships m ON (m.account_id,m.user_id)=(v.account_id,v.user_id) WHERE m.revoked_at IS NULL AND v.token_hash=$1 AND v.used_at IS NULL AND v.expires_at>now() AND (u.email_verified_at IS NOT NULL OR u.created_at>now()-($2::integer * interval '1 hour'))",
                &[&&hash[..], &VERIFICATION_HOURS],
            )
            .await?
    } else {
        None
    };
    let user_id = row.as_ref().map(|row| row.get::<_, Uuid>(0));
    let stored = row.as_ref().map(|row| row.get::<_, String>(1));
    match password_work::verify(password, stored.clone()).await {
        Ok(()) => {}
        Err(AuthError::InvalidCredentials) => return Ok(false),
        Err(error) => return Err(error),
    }
    let (Some(user_id), Some(stored)) = (user_id, stored) else {
        return Ok(false);
    };
    consume_verification_code(client, hasher, token, Some((user_id, stored))).await
}

/// Invalidates every outstanding verification code and queued mail of the
/// unverified owner holding `email`, if any. A registration that collides
/// with a pending owner calls this so that a code issued for the earlier
/// registrant's password can never verify the address for someone else.
/// Verified owners are never touched. Returns whether a code was canceled.
pub async fn cancel_pending_verification(
    client: &mut Client,
    email: &str,
) -> Result<bool, AuthError> {
    let email = normalize_email(email)?;
    let tx = client.transaction().await?;
    let canceled = tx
        .query(
            "UPDATE email_verifications v SET used_at=now() FROM users u WHERE u.id=v.user_id AND u.email=$1 AND u.email_verified_at IS NULL AND v.used_at IS NULL RETURNING v.id",
            &[&email],
        )
        .await?;
    for row in &canceled {
        let verification_id: Uuid = row.get(0);
        tx.execute(
            "UPDATE verification_mail_outbox SET canceled_at=now(),lease_id=NULL,leased_until=NULL WHERE verification_id=$1 AND canceled_at IS NULL",
            &[&verification_id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(!canceled.is_empty())
}

/// Test-fixture entry point that consumes a live verification code without
/// a password proof. Every production path goes through
/// [`verify_email_with_password`], so this function does not exist outside
/// test builds.
#[cfg(test)]
pub(crate) async fn verify_email(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<bool, AuthError> {
    consume_verification_code(client, hasher, token, None).await
}

/// When `bound` is set, the code is consumed only while it still belongs to
/// that user with that password hash, so a password proof cannot be reused
/// against a record that changed after it was checked.
async fn consume_verification_code(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    bound: Option<(Uuid, String)>,
) -> Result<bool, AuthError> {
    if !valid_token(token, "ztv_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"email-verification-v1", token);
    let (bound_user, bound_hash) = match bound {
        Some((user_id, password_hash)) => (Some(user_id), Some(password_hash)),
        None => (None, None),
    };
    let tx = client.transaction().await?;
    // A code only verifies an owner still inside its pending window, even if
    // the code itself was issued with a later expiry by an older release.
    let row = tx
        .query_opt(
            "UPDATE email_verifications v SET used_at=now() FROM users u WHERE u.id=v.user_id AND EXISTS(SELECT 1 FROM memberships m WHERE m.account_id=v.account_id AND m.user_id=v.user_id AND m.revoked_at IS NULL) AND v.token_hash=$1 AND v.used_at IS NULL AND v.expires_at>now() AND (u.email_verified_at IS NOT NULL OR u.created_at>now()-($2::integer * interval '1 hour')) AND ($3::uuid IS NULL OR u.id=$3) AND ($4::text IS NULL OR u.password_hash=$4) RETURNING v.id,v.user_id",
            &[&&hash[..], &VERIFICATION_HOURS, &bound_user, &bound_hash],
        )
        .await?;
    if let Some(row) = row {
        let verification_id: Uuid = row.get(0);
        let user_id: Uuid = row.get(1);
        let verified = tx
            .execute(
                "UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1",
                &[&user_id],
            )
            .await?;
        if verified != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.execute(
            "UPDATE verification_mail_outbox SET canceled_at=now(),lease_id=NULL,leased_until=NULL WHERE verification_id=$1 AND canceled_at IS NULL",
            &[&verification_id],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    } else {
        tx.rollback().await?;
        Ok(false)
    }
}

pub async fn login(
    client: &Client,
    hasher: &TokenHasher,
    email: &str,
    password: &str,
) -> Result<SessionCredentials, AuthError> {
    let email = normalize_email(email).map_err(|_| AuthError::InvalidCredentials)?;
    let row = client
        .query_opt(
            "SELECT u.id,m.account_id,u.password_hash,u.email_verified_at IS NOT NULL,u.mfa_enabled,m.role FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.revoked_at IS NULL AND u.email=$1 AND a.disabled_at IS NULL",
            &[&email],
        )
        .await?;
    let stored = row.as_ref().map(|row| row.get::<_, String>(2));
    password_work::verify(password, stored.clone()).await?;
    // Even a password matching the dummy verifier cannot authenticate.
    let row = row.ok_or(AuthError::InvalidCredentials)?;
    let user_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    if !row.get::<_, bool>(3) {
        return Err(AuthError::EmailNotVerified);
    }
    // The second factor belongs to the owner surface. An observer row with
    // MFA material cannot complete a challenge, so it never signs in at all.
    if row.get::<_, bool>(4) {
        if Role::from_db(row.get::<_, String>(5).as_str()) == Some(Role::Owner) {
            return Err(AuthError::MfaRequired {
                account_id,
                user_id,
            });
        }
        return Err(AuthError::InvalidCredentials);
    }
    let token = random_token("zts_");
    let csrf_token = random_token("ztc_");
    let token_hash = hasher.digest(b"session-v1", &token);
    let csrf_hash = hasher.digest(b"csrf-v1", &csrf_token);
    let id = Uuid::new_v4();
    let inserted = client
        .execute(
            "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) SELECT $1,$2,$3,$4,$5,now()+($6::integer * interval '1 day') FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.revoked_at IS NULL AND u.id=$3 AND m.account_id=$2 AND u.password_hash=$7 AND NOT u.mfa_enabled AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&id, &account_id, &user_id, &&token_hash[..], &&csrf_hash[..], &SESSION_DAYS, &stored],
        )
        .await?;
    if inserted != 1 {
        let current = client
            .query_opt(
                "SELECT u.password_hash,u.mfa_enabled,m.role FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.revoked_at IS NULL AND u.id=$1 AND m.account_id=$2 AND a.disabled_at IS NULL",
                &[&user_id, &account_id],
            )
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if Some(current.get::<_, String>(0)) != stored {
            return Err(AuthError::InvalidCredentials);
        }
        // Only an owner is offered the second-factor challenge; an observer
        // with stray MFA material keeps failing closed.
        if current.get::<_, bool>(1)
            && Role::from_db(current.get::<_, String>(2).as_str()) == Some(Role::Owner)
        {
            return Err(AuthError::MfaRequired {
                account_id,
                user_id,
            });
        }
        return Err(AuthError::InvalidCredentials);
    }
    Ok(SessionCredentials {
        id,
        token,
        csrf_token,
    })
}

pub async fn authenticate_session(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<SessionPrincipal, AuthError> {
    if !valid_token(token, "zts_") {
        return Err(AuthError::Unauthorized);
    }
    let hash = hasher.digest(b"session-v1", token);
    // A session that has not been used within the idle window is treated as
    // expired. A never-used session is measured from its creation.
    let row = client
        .query_typed_opt(
            "SELECT s.id,s.account_id,s.user_id,s.csrf_hash,m.role,(s.last_used_at IS NULL OR s.last_used_at<now()-($3::integer * interval '1 minute')) FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id WHERE m.revoked_at IS NULL AND s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND COALESCE(s.last_used_at,s.created_at)>now()-($2::integer * interval '1 hour') AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
            &[(&&hash[..], Type::BYTEA), (&SESSION_IDLE_HOURS, Type::INT4), (&ACTIVITY_WRITE_MINUTES, Type::INT4)],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let csrf: Vec<u8> = row.get(3);
    let csrf_hash: [u8; 32] = csrf.try_into().map_err(|_| AuthError::Unauthorized)?;
    let role = Role::from_db(row.get::<_, String>(4).as_str()).ok_or(AuthError::Unauthorized)?;
    // Coarse activity metadata for the owner's session inventory and the idle
    // timeout. The guard avoids a row rewrite on every authenticated request.
    let session_id: Uuid = row.get(0);
    if row.get::<_, bool>(5) {
        client.execute_typed(
            "UPDATE sessions SET last_used_at=now() WHERE id=$1 AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at<now()-($2::integer * interval '1 minute'))",
            &[(&session_id, Type::UUID), (&ACTIVITY_WRITE_MINUTES, Type::INT4)],
        ).await?;
    }
    Ok(SessionPrincipal {
        session_id,
        tenant: Tenant {
            account_id: row.get(1),
        },
        user_id: row.get(2),
        role,
        csrf_hash,
        verification: FreshVerification::now(),
    })
}

pub async fn revoke_session(
    client: &Client,
    principal: &SessionPrincipal,
    session_id: Uuid,
) -> Result<bool, AuthError> {
    require_unlocked_member(client, principal).await?;
    Ok(client
        .execute(
            "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL",
            &[&principal.tenant.account_id, &principal.user_id, &session_id],
        )
        .await?
        == 1)
}

/// Applied when `lifetime_days` is omitted, so a key minted without an explicit
/// lifetime cannot outlive the longest lifetime an owner may request.
pub const API_KEY_DEFAULT_LIFETIME_DAYS: i32 = 365;

/// The lifetime an owner asked for. `Unspecified` is a request that omitted
/// `lifetime_days` and gets the capped default; `Never` is the explicit,
/// discouraged opt-in that leaves `expires_at` NULL (the state keys created
/// before the default existed carry). JSON `null` maps to `Never`, an integer
/// to `Days`, so the two are distinct on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiKeyLifetime {
    #[default]
    Unspecified,
    Days(i32),
    Never,
}

impl<'de> serde::Deserialize<'de> for ApiKeyLifetime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match Option::<i32>::deserialize(deserializer)? {
            None => Ok(ApiKeyLifetime::Never),
            Some(days) => Ok(ApiKeyLifetime::Days(days)),
        }
    }
}

impl ApiKeyLifetime {
    /// The number of days to store, or `None` for a key that never expires.
    fn stored_days(self) -> Option<i32> {
        match self {
            ApiKeyLifetime::Unspecified => Some(API_KEY_DEFAULT_LIFETIME_DAYS),
            ApiKeyLifetime::Days(days) => Some(days),
            ApiKeyLifetime::Never => None,
        }
    }
}

pub(crate) fn validate_api_key_request(
    scopes: &[Scope],
    lifetime: ApiKeyLifetime,
) -> Result<(), AuthError> {
    if scopes.is_empty()
        || scopes.len() > 7
        || matches!(lifetime, ApiKeyLifetime::Days(days) if !(1..=API_KEY_DEFAULT_LIFETIME_DAYS).contains(&days))
    {
        return Err(AuthError::InvalidInput);
    }
    Ok(())
}

/// Test-only mint without the step-up proof. Production code must go through
/// `account::create_api_key_with_proof`, which requires the owner's password
/// (and, with MFA enabled, a fresh code); keeping this visible only to tests
/// means no future route can link against the proof-free path.
#[cfg(test)]
pub async fn create_api_key(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    scopes: &[Scope],
    bound_device_id: Option<Uuid>,
    lifetime: ApiKeyLifetime,
) -> Result<ApiKeyCredentials, AuthError> {
    validate_api_key_request(scopes, lifetime)?;
    // Recovery locks this same user row before revoking keys and sessions.
    // The lock closes the race where a pre-reset session mints a key after
    // recovery has already revoked the keys it could see.
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.role='owner' AND u.id=$1 AND m.account_id=$2 AND a.disabled_at IS NULL FOR UPDATE OF u",
        &[&principal.user_id, &principal.tenant.account_id()],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    let key = insert_api_key(&tx, hasher, principal, scopes, bound_device_id, lifetime).await?;
    tx.commit().await?;
    Ok(key)
}

/// Inserts a key inside `tx`, whose caller must already hold the owner's
/// user-row lock. The session is re-checked inside the insert so a session
/// revoked while the caller waited for the lock cannot mint.
pub(crate) async fn insert_api_key(
    tx: &tokio_postgres::Transaction<'_>,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    scopes: &[Scope],
    bound_device_id: Option<Uuid>,
    lifetime: ApiKeyLifetime,
) -> Result<ApiKeyCredentials, AuthError> {
    validate_api_key_request(scopes, lifetime)?;
    // `Never` stores NULL: `now() + (NULL * interval '1 day')` is NULL, and a
    // NULL `expires_at` never excludes the key from authentication.
    let lifetime_days = lifetime.stored_days();
    let mut normalized = scopes.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    let scope_names: Vec<String> = normalized
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let token = random_token("ztk_");
    let public_prefix = token.chars().skip(4).take(12).collect::<String>();
    let hash = hasher.digest(b"api-key-v1", &token);
    let id = Uuid::new_v4();
    let inserted = tx
        .execute(
            "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,now()+($8::integer * interval '1 day') FROM sessions s WHERE s.id=$9 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()",
            &[&id, &principal.tenant.account_id, &principal.user_id, &public_prefix, &&hash[..], &scope_names, &bound_device_id, &lifetime_days, &principal.session_id],
        )
        .await?;
    if inserted != 1 {
        return Err(AuthError::Unauthorized);
    }
    Ok(ApiKeyCredentials {
        id,
        token,
        public_prefix,
    })
}

pub async fn authenticate_api_key(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<ApiPrincipal, AuthError> {
    if !valid_token(token, "ztk_") {
        return Err(AuthError::Unauthorized);
    }
    let prefix = token.chars().skip(4).take(12).collect::<String>();
    let hash = hasher.digest(b"api-key-v1", token);
    let row = client
        .query_typed_opt(
            "SELECT k.id,k.account_id,k.token_hash,k.scopes,k.bound_device_id,(k.last_used_at IS NULL OR k.last_used_at<now()-($2::integer * interval '1 minute')) FROM api_keys k JOIN memberships m ON (m.account_id,m.user_id)=(k.account_id,k.created_by_user_id) JOIN users u ON u.id=k.created_by_user_id JOIN accounts a ON a.id=k.account_id WHERE m.role='owner' AND m.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM agent_authority_grants g WHERE g.api_key_id=k.id) AND k.public_prefix=$1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
            &[(&prefix, Type::TEXT), (&ACTIVITY_WRITE_MINUTES, Type::INT4)],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let stored: Vec<u8> = row.get(2);
    if stored.len() != 32 || !bool::from(hash.as_slice().ct_eq(stored.as_slice())) {
        return Err(AuthError::Unauthorized);
    }
    let names: Vec<String> = row.get(3);
    let scopes = names
        .iter()
        .map(|name| Scope::from_str(name).ok_or(AuthError::Unauthorized))
        .collect::<Result<Vec<_>, _>>()?;
    let key_id: Uuid = row.get(0);
    // Recorded only after the verifier matched, so a caller who knows a
    // public prefix but not the secret cannot move a key's last-use time.
    // The guard bounds writes to one per key per window.
    if row.get::<_, bool>(5) {
        client
            .execute_typed(
                "UPDATE api_keys SET last_used_at=now() WHERE id=$1 AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at<now()-($2::integer * interval '1 minute'))",
                &[(&key_id, Type::UUID), (&ACTIVITY_WRITE_MINUTES, Type::INT4)],
            )
            .await?;
    }
    Ok(ApiPrincipal {
        key_id,
        tenant: Tenant {
            account_id: row.get(1),
        },
        scopes,
        bound_device_id: row.get(4),
    })
}

pub async fn revoke_api_key(
    client: &Client,
    principal: &SessionPrincipal,
    key_id: Uuid,
) -> Result<bool, AuthError> {
    require_unlocked_owner(client, principal).await?;
    Ok(client
        .execute(
            "UPDATE api_keys SET revoked_at=now() WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL",
            &[&principal.tenant.account_id, &key_id],
        )
        .await?
        == 1)
}

/// A stable, bounded owner-only list. The cursor must belong to this tenant;
/// metadata reads never select token_hash or reveal the one-time secret.
pub async fn list_api_keys(
    client: &Client,
    principal: &SessionPrincipal,
    before: Option<Uuid>,
) -> Result<ApiKeyPage, AuthError> {
    require_unlocked_owner(client, principal).await?;
    let account_id = principal.tenant.account_id();
    let cursor = if let Some(id) = before {
        let row = client
            .query_opt(
                "SELECT created_at FROM api_keys WHERE account_id=$1 AND id=$2",
                &[&account_id, &id],
            )
            .await?
            .ok_or(AuthError::InvalidInput)?;
        Some((id, row.get::<_, std::time::SystemTime>(0)))
    } else {
        None
    };
    let rows = client
        .query(
            "SELECT id,public_prefix,scopes,bound_device_id, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint, \
             (extract(epoch FROM revoked_at)*1000)::bigint, \
             (extract(epoch FROM last_used_at)*1000)::bigint \
             FROM api_keys WHERE account_id=$1 AND \
             ($2::timestamptz IS NULL OR (created_at,id)<($2,$3)) \
             ORDER BY created_at DESC,id DESC LIMIT 51",
            &[
                &account_id,
                &cursor.map(|(_, at)| at),
                &cursor.map(|(id, _)| id),
            ],
        )
        .await?;
    let has_more = rows.len() > 50;
    let keys: Vec<_> = rows
        .into_iter()
        .take(50)
        .map(|row| ApiKeyMetadata {
            id: row.get(0),
            public_prefix: row.get(1),
            scopes: row.get(2),
            bound_device_id: row.get(3),
            created_at_ms: row.get(4),
            expires_at_ms: row.get(5),
            revoked_at_ms: row.get(6),
            last_used_at_ms: row.get(7),
        })
        .collect();
    Ok(ApiKeyPage {
        next_cursor: has_more.then(|| keys.last().expect("nonempty page").id),
        keys,
    })
}

/// Normalized address of a session's user, for binding a login-client token
/// after a second-factor sign-in.
pub async fn session_email(client: &Client, session_id: Uuid) -> Result<Option<String>, AuthError> {
    Ok(client
        .query_opt(
            "SELECT u.email FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND m.role='owner' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND a.disabled_at IS NULL",
            &[&session_id],
        )
        .await?
        .map(|row| row.get(0)))
}

/// Identity and current password hash of a live session's owner, for minting
/// a trusted-browser cookie right after a completed sign-in.
pub struct SessionOwner {
    pub user_id: Uuid,
    pub account_id: Uuid,
    pub password_hash: String,
    pub trusted_browser_epoch: i64,
}

/// The owner row a trusted-browser cookie binds to: the session's user and
/// account plus the current password hash, or `None` when the session is not
/// live (in which case no cookie is minted).
pub async fn session_owner(
    client: &Client,
    session_id: Uuid,
) -> Result<Option<SessionOwner>, AuthError> {
    Ok(client
        .query_opt(
            "SELECT u.id,m.account_id,u.password_hash,u.trusted_browser_epoch FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND m.role='owner' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND a.disabled_at IS NULL",
            &[&session_id],
        )
        .await?
        .map(|row| SessionOwner {
            user_id: row.get(0),
            account_id: row.get(1),
            password_hash: row.get(2),
            trusted_browser_epoch: row.get(3),
        }))
}

/// The unlocked, outside-a-transaction form of [`require_current_owner`].
/// It skips the query only when this request's `authenticate_session`
/// validation is unspent and under a second old, because an unlocked
/// re-check moments later cannot add a revocation guarantee (see
/// [`SessionPrincipal::spend_fresh_verification`]). Use
/// [`require_current_owner`] on a transaction.
pub(crate) async fn require_unlocked_owner(
    client: &Client,
    principal: &SessionPrincipal,
) -> Result<(), AuthError> {
    // authenticate_session also admits observers, so the fast path must not
    // stand in for the owner-role recheck on a non-owner principal.
    if principal.role == Role::Owner && principal.spend_fresh_verification() {
        return Ok(());
    }
    require_current_owner(client, principal).await
}

/// The unlocked, outside-a-transaction form of [`require_current_member`],
/// with the same fresh-verification shortcut as [`require_unlocked_owner`]
/// but valid for any live role. Use [`require_current_member`] on a
/// transaction.
pub(crate) async fn require_unlocked_member(
    client: &Client,
    principal: &SessionPrincipal,
) -> Result<(), AuthError> {
    if principal.spend_fresh_verification() {
        return Ok(());
    }
    require_current_member(client, principal).await
}

/// Recheck a caller's owner role from the database. A previously constructed
/// principal is not evidence of a current role or live session. Member routes
/// must use [`require_current_member`] instead; observers must never pass this
/// check even with a structurally valid session.
pub(super) async fn require_current_owner(
    client: &(impl tokio_postgres::GenericClient + Sync),
    principal: &SessionPrincipal,
) -> Result<(), AuthError> {
    client.query_opt(
        "SELECT 1 FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND m.role='owner' AND m.revoked_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
        &[&principal.session_id, &principal.tenant.account_id(), &principal.user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    Ok(())
}

/// Recheck that the caller's membership is currently live, in any role. This
/// gates only self-service routes: session inventory, sign-out, password
/// change, and read-only status scoped to the caller's own account. Every
/// owner-authority route must additionally use [`require_current_owner`].
pub(super) async fn require_current_member(
    client: &(impl tokio_postgres::GenericClient + Sync),
    principal: &SessionPrincipal,
) -> Result<(), AuthError> {
    client.query_opt(
        "SELECT 1 FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND m.revoked_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
        &[&principal.session_id, &principal.tenant.account_id(), &principal.user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    Ok(())
}

pub const LOGIN_CLIENT_COOKIE: &str = "__Host-zrotext_login_client";
const LOGIN_CLIENT_DAYS: i32 = 180;

/// Issued to a browser after it presents the correct password for `email`.
/// It is not a credential: it only lets that browser keep a login budget of
/// its own once anonymous callers have spent the shared one. The value is
/// bound to the normalized email under the auth pepper and reveals neither.
pub fn login_client_cookie(hasher: &TokenHasher, email: &str) -> Option<String> {
    let email = normalize_email(email).ok()?;
    let id = random_token("ztl_");
    let tag = hasher.digest(b"login-client-v1", &format!("{id}\0{email}"));
    Some(format!(
        "{LOGIN_CLIENT_COOKIE}={id}.{}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        URL_SAFE_NO_PAD.encode(tag),
        LOGIN_CLIENT_DAYS * 86_400
    ))
}

/// Returns this browser's own login budget subject when `value` was issued
/// for `email`. Tokens for other addresses or forged tags yield `None`.
pub fn login_client_subject(hasher: &TokenHasher, value: &str, email: &str) -> Option<String> {
    let email = normalize_email(email).ok()?;
    let (id, tag) = value.split_once('.')?;
    if !valid_token(id, "ztl_") {
        return None;
    }
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    let expected = hasher.digest(b"login-client-v1", &format!("{id}\0{email}"));
    bool::from(expected.as_slice().ct_eq(&tag)).then(|| format!("{email}\0{id}"))
}

/// Marks a browser that completed a sign-in for one owner, so password-reset
/// requests from it can spend a budget an email-only attacker cannot reach
/// (issue #526). Not a credential: it unlocks no account route.
pub const TRUSTED_BROWSER_COOKIE: &str = "__Host-zrotext_trusted_browser";
/// Server-side lifetime of a trusted-browser cookie. The cookie's own
/// `Max-Age` is advisory; verification enforces this bound on the embedded
/// issue time.
pub const TRUSTED_BROWSER_DAYS: i64 = 90;

/// Pepper digest binding a trusted-browser cookie to the current password
/// hash of its user. Password change and reset replace the hash and account
/// erasure removes the row entirely, so binding to this digest revokes the
/// cookie on those flows without any stored cookie state. Flows that revoke
/// sessions without touching the password (revoke-other-sessions and the MFA
/// changes) bump the trust epoch instead; see [`trusted_browser_tag`].
fn trusted_browser_password_digest(hasher: &TokenHasher, password_hash: &str) -> String {
    URL_SAFE_NO_PAD.encode(hasher.digest(b"trusted-browser-pw-v1", password_hash))
}

/// HMAC tag over every fact a trusted-browser cookie must stay bound to: its
/// random id, its issue time, the owner's user and account ids, the owner's
/// current trust epoch, and a digest of the owner's current password hash,
/// all under the auth pepper. Bumping the epoch (revoke-other-sessions and
/// the MFA flows that revoke sessions) or replacing the password therefore
/// invalidates the cookie with no stored cookie state.
fn trusted_browser_tag(
    hasher: &TokenHasher,
    id: &str,
    issued_at_unix: u64,
    user_id: Uuid,
    account_id: Uuid,
    trusted_browser_epoch: i64,
    password_hash: &str,
) -> [u8; 32] {
    hasher.digest(
        b"trusted-browser-v1",
        &format!(
            "{id}\0{issued_at_unix}\0{user_id}\0{account_id}\0{trusted_browser_epoch}\0{}",
            trusted_browser_password_digest(hasher, password_hash)
        ),
    )
}

/// The full `Set-Cookie` value marking `password_hash`'s owner's browser as
/// trusted, issued at `now`. The cookie is bound to the account and user and
/// carries no readable account data.
pub fn trusted_browser_cookie(
    hasher: &TokenHasher,
    user_id: Uuid,
    account_id: Uuid,
    trusted_browser_epoch: i64,
    password_hash: &str,
    now: std::time::SystemTime,
) -> String {
    let issued_at_unix = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let id = random_token("ztb_");
    let tag = trusted_browser_tag(
        hasher,
        &id,
        issued_at_unix,
        user_id,
        account_id,
        trusted_browser_epoch,
        password_hash,
    );
    format!(
        "{TRUSTED_BROWSER_COOKIE}={id}.{issued_at_unix}.{}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        URL_SAFE_NO_PAD.encode(tag),
        TRUSTED_BROWSER_DAYS * 86_400
    )
}

/// Whether `value` is a trusted-browser cookie that this exact user, account,
/// and current password hash issued within its lifetime. A forged, expired,
/// or other-account value is simply invalid; callers fall back to the normal
/// lanes with no difference in response.
pub fn trusted_browser_valid(
    hasher: &TokenHasher,
    value: &str,
    user_id: Uuid,
    account_id: Uuid,
    trusted_browser_epoch: i64,
    password_hash: &str,
    now: std::time::SystemTime,
) -> bool {
    let mut parts = value.split('.');
    let (Some(id), Some(issued), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() || !valid_token(id, "ztb_") {
        return false;
    }
    let Ok(issued_at_unix) = issued.parse::<u64>() else {
        return false;
    };
    let now_unix = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Not yet issued (beyond trivial clock equality) or past its lifetime.
    if issued_at_unix > now_unix
        || now_unix - issued_at_unix
            > (TRUSTED_BROWSER_DAYS * 86_400)
                .try_into()
                .unwrap_or(u64::MAX)
    {
        return false;
    }
    let Ok(tag) = URL_SAFE_NO_PAD.decode(tag) else {
        return false;
    };
    let expected = trusted_browser_tag(
        hasher,
        id,
        issued_at_unix,
        user_id,
        account_id,
        trusted_browser_epoch,
        password_hash,
    );
    tag.len() == expected.len() && bool::from(tag.as_slice().ct_eq(expected.as_slice()))
}

/// Pass these only over HTTPS. The session cookie is inaccessible to script;
/// the CSRF cookie is read by same-origin script and mirrored in a header.
pub fn session_cookies(credentials: &SessionCredentials) -> [String; 2] {
    [
        format!(
            "__Host-zrotext_session={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            credentials.token,
            SESSION_DAYS * 86_400
        ),
        format!(
            "__Host-zrotext_csrf={}; Path=/; Secure; SameSite=Lax; Max-Age={}",
            credentials.csrf_token,
            SESSION_DAYS * 86_400
        ),
    ]
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_schema;
