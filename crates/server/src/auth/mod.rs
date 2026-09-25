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
use tokio_postgres::Client;
use uuid::Uuid;

const SESSION_DAYS: i32 = 14;
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
pub mod mfa;
mod password_work;
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

pub struct SessionPrincipal {
    pub tenant: Tenant,
    pub user_id: Uuid,
    pub session_id: Uuid,
    csrf_hash: [u8; 32],
}

impl SessionPrincipal {
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
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND u.email_verified_at IS NULL AND u.created_at<=now()-($2::integer * interval '1 hour') AND a.disabled_at IS NULL FOR UPDATE OF u",
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
            "SELECT u.id,m.account_id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email_verified_at IS NULL AND u.created_at<=now()-($1::integer * interval '1 hour') AND a.disabled_at IS NULL ORDER BY u.created_at,u.id LIMIT $2 FOR UPDATE OF u SKIP LOCKED",
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
             WHERE v.token_hash=$1 AND v.used_at IS NULL AND v.expires_at>now()
             AND (u.email_verified_at IS NOT NULL OR u.created_at>now()-($2::integer * interval '1 hour')))",
            &[&&hash[..], &VERIFICATION_HOURS],
        )
        .await?;
    Ok(row.get(0))
}

/// Atomically consumes a live verification code. The caller supplies this
/// token in a POST body, never as a query parameter, to avoid referrer leakage.
pub async fn verify_email(
    client: &mut Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<bool, AuthError> {
    if !valid_token(token, "ztv_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"email-verification-v1", token);
    let tx = client.transaction().await?;
    // A code only verifies an owner still inside its pending window, even if
    // the code itself was issued with a later expiry by an older release.
    let row = tx
        .query_opt(
            "UPDATE email_verifications v SET used_at=now() FROM users u WHERE u.id=v.user_id AND v.token_hash=$1 AND v.used_at IS NULL AND v.expires_at>now() AND (u.email_verified_at IS NOT NULL OR u.created_at>now()-($2::integer * interval '1 hour')) RETURNING v.id,v.user_id",
            &[&&hash[..], &VERIFICATION_HOURS],
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
            "SELECT u.id,m.account_id,u.password_hash,u.email_verified_at IS NOT NULL,u.mfa_enabled FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND a.disabled_at IS NULL",
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
    if row.get::<_, bool>(4) {
        return Err(AuthError::MfaRequired {
            account_id,
            user_id,
        });
    }
    let token = random_token("zts_");
    let csrf_token = random_token("ztc_");
    let token_hash = hasher.digest(b"session-v1", &token);
    let csrf_hash = hasher.digest(b"csrf-v1", &csrf_token);
    let id = Uuid::new_v4();
    let inserted = client
        .execute(
            "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) SELECT $1,$2,$3,$4,$5,now()+($6::integer * interval '1 day') FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$3 AND m.account_id=$2 AND u.password_hash=$7 AND NOT u.mfa_enabled AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&id, &account_id, &user_id, &&token_hash[..], &&csrf_hash[..], &SESSION_DAYS, &stored],
        )
        .await?;
    if inserted != 1 {
        let current = client
            .query_opt(
                "SELECT u.password_hash,u.mfa_enabled FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND a.disabled_at IS NULL",
                &[&user_id, &account_id],
            )
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if Some(current.get::<_, String>(0)) != stored {
            return Err(AuthError::InvalidCredentials);
        }
        return if current.get::<_, bool>(1) {
            Err(AuthError::MfaRequired {
                account_id,
                user_id,
            })
        } else {
            Err(AuthError::InvalidCredentials)
        };
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
    let row = client
        .query_opt(
            "SELECT s.id,s.account_id,s.user_id,s.csrf_hash FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
            &[&&hash[..]],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let csrf: Vec<u8> = row.get(3);
    let csrf_hash: [u8; 32] = csrf.try_into().map_err(|_| AuthError::Unauthorized)?;
    // Coarse activity metadata for the owner's session inventory. The guard
    // avoids a row rewrite on every authenticated request.
    let session_id: Uuid = row.get(0);
    client.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1 AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at<now()-interval '15 minutes')",
        &[&session_id],
    ).await?;
    Ok(SessionPrincipal {
        session_id,
        tenant: Tenant {
            account_id: row.get(1),
        },
        user_id: row.get(2),
        csrf_hash,
    })
}

pub async fn revoke_session(
    client: &Client,
    principal: &SessionPrincipal,
    session_id: Uuid,
) -> Result<bool, AuthError> {
    Ok(client
        .execute(
            "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL",
            &[&principal.tenant.account_id, &principal.user_id, &session_id],
        )
        .await?
        == 1)
}

pub async fn create_api_key(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    scopes: &[Scope],
    bound_device_id: Option<Uuid>,
    lifetime_days: Option<i32>,
) -> Result<ApiKeyCredentials, AuthError> {
    if scopes.is_empty()
        || scopes.len() > 7
        || matches!(lifetime_days, Some(days) if !(1..=365).contains(&days))
    {
        return Err(AuthError::InvalidInput);
    }
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
    // Recovery locks this same user row before revoking keys and sessions.
    // The lock closes the race where a pre-reset session mints a key after
    // recovery has already revoked the keys it could see.
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND a.disabled_at IS NULL FOR UPDATE OF u",
        &[&principal.user_id, &principal.tenant.account_id()],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    let inserted = tx
        .execute(
            "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,CASE WHEN $8::integer IS NULL THEN NULL ELSE now()+($8::integer * interval '1 day') END FROM sessions s WHERE s.id=$9 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()",
            &[&id, &principal.tenant.account_id, &principal.user_id, &public_prefix, &&hash[..], &scope_names, &bound_device_id, &lifetime_days, &principal.session_id],
        )
        .await?;
    if inserted != 1 {
        return Err(AuthError::Unauthorized);
    }
    tx.commit().await?;
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
        .query_opt(
            "SELECT k.id,k.account_id,k.token_hash,k.scopes,k.bound_device_id FROM api_keys k JOIN memberships m ON (m.account_id,m.user_id)=(k.account_id,k.created_by_user_id) JOIN users u ON u.id=k.created_by_user_id JOIN accounts a ON a.id=k.account_id WHERE k.public_prefix=$1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
            &[&prefix],
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
    Ok(ApiPrincipal {
        key_id: row.get(0),
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
             (extract(epoch FROM revoked_at)*1000)::bigint \
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
            "SELECT u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1",
            &[&session_id],
        )
        .await?
        .map(|row| row.get(0)))
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_operator_bootstrap_creates_one_verified_owner_under_concurrency() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("bootstrap_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut first, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (mut second, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in [
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        ] {
            first.batch_execute(sql).await.unwrap();
        }
        let first_password = Uuid::new_v4().to_string();
        let second_password = Uuid::new_v4().to_string();
        let third_password = Uuid::new_v4().to_string();
        let (a, b) = tokio::join!(
            bootstrap_owner(&mut first, "first@example.test", &first_password),
            bootstrap_owner(&mut second, "second@example.test", &second_password),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_ne!(a, b);
        assert!(
            !bootstrap_owner(&mut first, "third@example.test", &third_password)
                .await
                .unwrap()
        );
        for table in ["accounts", "users", "memberships"] {
            let count: i64 = first
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(count, 1, "{table}");
        }
        assert_eq!(
            first
                .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0,
        );
        assert!(
            first
                .query_one("SELECT email_verified_at IS NOT NULL FROM users", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        let (email, password) = if a {
            ("first@example.test", first_password.as_str())
        } else {
            ("second@example.test", second_password.as_str())
        };
        let hasher = TokenHasher::new(crate::test_keys::key(37)).unwrap();
        assert!(login(&first, &hasher, email, password).await.is_ok());
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    // Tokio's default test runtime stays on one thread; separate tests cannot
    // satisfy this counter through concurrent password checks. Capture its Arc
    // before offloading so the blocking worker increments the originating test.
    thread_local! {
        pub(super) static PASSWORD_VERIFICATIONS: std::sync::Arc<std::sync::atomic::AtomicUsize> = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    }

    #[test]
    fn tenant_context_rejects_cross_account_ids() {
        let owner = Uuid::new_v4();
        let foreign = Uuid::new_v4();
        let tenant = Tenant { account_id: owner };
        assert!(tenant.require_account(owner).is_ok());
        assert!(matches!(
            tenant.require_account(foreign),
            Err(AuthError::Forbidden)
        ));
    }

    #[test]
    fn api_scopes_and_device_restriction_fail_closed() {
        let permitted = Uuid::new_v4();
        let key = ApiPrincipal {
            tenant: Tenant {
                account_id: Uuid::new_v4(),
            },
            key_id: Uuid::new_v4(),
            scopes: vec![Scope::MessagesSend],
            bound_device_id: Some(permitted),
        };
        assert!(key.require(Scope::MessagesSend, Some(permitted)).is_ok());
        assert!(key.require(Scope::MessagesRead, Some(permitted)).is_err());
        assert!(
            key.require(Scope::MessagesSend, Some(Uuid::new_v4()))
                .is_err()
        );
        assert!(key.require(Scope::MessagesSend, None).is_err());
    }

    #[test]
    fn token_domains_are_separate_and_csrf_needs_origin() {
        let hasher = TokenHasher::new(crate::test_keys::key(7)).unwrap();
        let token = random_token("ztc_");
        let principal = SessionPrincipal {
            tenant: Tenant {
                account_id: Uuid::new_v4(),
            },
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            csrf_hash: hasher.digest(b"csrf-v1", &token),
        };
        assert_ne!(
            hasher.digest(b"csrf-v1", &token),
            hasher.digest(b"session-v1", &token)
        );
        assert!(
            principal
                .require_csrf(
                    &hasher,
                    "https://example.test",
                    "https://example.test",
                    &token,
                    &token
                )
                .is_ok()
        );
        assert!(
            principal
                .require_csrf(
                    &hasher,
                    "https://evil.test",
                    "https://example.test",
                    &token,
                    &token
                )
                .is_err()
        );
        assert!(
            principal
                .require_csrf(
                    &hasher,
                    "https://example.test",
                    "https://example.test",
                    &token,
                    "wrong"
                )
                .is_err()
        );
    }
    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_tenant_revocation_and_scope_contract() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("auth_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/002_auth.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/005_verification_outbox.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/013_owner_mfa.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
            ))
            .await
            .unwrap();
        let hasher = TokenHasher::new(crate::test_keys::key(11)).unwrap();
        let a_password = Uuid::new_v4().to_string();
        let b_password = Uuid::new_v4().to_string();
        let a = register(&mut client, &hasher, "A@example.test", &a_password)
            .await
            .unwrap();
        let b = register(&mut client, &hasher, "b@example.test", &b_password)
            .await
            .unwrap();
        for _ in 0..2 {
            let password = Uuid::new_v4().to_string();
            let before = PASSWORD_VERIFICATIONS
                .with(|count| count.load(std::sync::atomic::Ordering::SeqCst));
            assert!(matches!(
                login(&client, &hasher, "unknown@example.test", &password).await,
                Err(AuthError::InvalidCredentials)
            ));
            assert_eq!(
                PASSWORD_VERIFICATIONS
                    .with(|count| count.load(std::sync::atomic::Ordering::SeqCst)),
                before + 1
            );
        }
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM sessions", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        assert!(matches!(
            login(&client, &hasher, "a@example.test", &a_password).await,
            Err(AuthError::EmailNotVerified)
        ));
        assert!(
            verify_email(&mut client, &hasher, &a.verification_token)
                .await
                .unwrap()
        );
        assert!(
            !verify_email(&mut client, &hasher, &a.verification_token)
                .await
                .unwrap()
        );
        assert!(
            verify_email(&mut client, &hasher, &b.verification_token)
                .await
                .unwrap()
        );
        let sa = login(&client, &hasher, "a@example.test", &a_password)
            .await
            .unwrap();
        let sb = login(&client, &hasher, "b@example.test", &b_password)
            .await
            .unwrap();
        let pa = authenticate_session(&client, &hasher, &sa.token)
            .await
            .unwrap();
        let pb = authenticate_session(&client, &hasher, &sb.token)
            .await
            .unwrap();
        assert!(pa.tenant.require_account(b.account_id).is_err());
        assert!(!revoke_session(&client, &pb, sa.id).await.unwrap());
        let bound_device = Uuid::new_v4();
        let key = create_api_key(
            &mut client,
            &hasher,
            &pa,
            &[Scope::MessagesSend],
            Some(bound_device),
            Some(30),
        )
        .await
        .unwrap();
        let api = authenticate_api_key(&client, &hasher, &key.token)
            .await
            .unwrap();
        assert_eq!(api.tenant.account_id(), a.account_id);
        assert!(api.require(Scope::MessagesSend, Some(bound_device)).is_ok());
        assert!(
            api.require(Scope::MessagesSend, Some(Uuid::new_v4()))
                .is_err()
        );
        assert!(api.require(Scope::MessagesRead, None).is_err());
        assert!(!revoke_api_key(&client, &pb, key.id).await.unwrap());
        assert!(revoke_session(&client, &pa, sa.id).await.unwrap());
        assert!(matches!(
            authenticate_session(&client, &hasher, &sa.token).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            create_api_key(&mut client, &hasher, &pa, &[Scope::BillingRead], None, None).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(revoke_api_key(&client, &pa, key.id).await.unwrap());
        assert!(matches!(
            authenticate_api_key(&client, &hasher, &key.token).await,
            Err(AuthError::Unauthorized)
        ));
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }

    fn is_unique_violation(result: &Result<Signup, AuthError>) -> bool {
        matches!(result, Err(AuthError::Database(error))
            if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION))
    }

    async fn pending_signup_schema(base_url: &str, schema: &str) -> (Client, Client, String) {
        let (setup, connection) = tokio_postgres::connect(base_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        (setup, client, url)
    }

    /// Moves an owner's sign-up past the pending window. Its codes are left
    /// live on purpose: the window, not only the code expiry, must bind.
    async fn age_signup(client: &Client, user_id: Uuid) {
        client
            .execute(
                "UPDATE users SET created_at=now()-interval '25 hours' WHERE id=$1",
                &[&user_id],
            )
            .await
            .unwrap();
    }

    async fn count(client: &Client, sql: &str, id: Uuid) -> i64 {
        client.query_one(sql, &[&id]).await.unwrap().get(0)
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_expired_unverified_signup_releases_its_email() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let schema = format!("pending_signup_test_{}", Uuid::new_v4().simple());
        let (setup, mut client, _) = pending_signup_schema(&base_url, &schema).await;
        let hasher = TokenHasher::new(crate::test_keys::key(13)).unwrap();
        let first_password = Uuid::new_v4().to_string();
        let owner_password = Uuid::new_v4().to_string();

        // A third party registers the address first and never verifies it.
        let first = register(
            &mut client,
            &hasher,
            "claimed@example.test",
            &first_password,
        )
        .await
        .unwrap();
        // Within the pending window the address stays reserved.
        assert!(is_unique_violation(
            &register(
                &mut client,
                &hasher,
                "Claimed@example.test",
                &owner_password
            )
            .await
        ));
        // State tied to the pending record must disappear with it.
        client
            .execute(
                "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$4,now()+interval '1 day')",
                &[&Uuid::new_v4(), &first.account_id, &first.user_id, &&[7u8; 32][..]],
            )
            .await
            .unwrap();

        age_signup(&client, first.user_id).await;
        // After the window the stale record can neither be verified, nor
        // mailed, nor resent, even though its code row has not yet expired.
        assert!(
            !verification_token_is_live(&client, &hasher, &first.verification_token)
                .await
                .unwrap()
        );
        assert!(
            claim_verification_mail(&mut client, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !request_verification_resend(
                &mut client,
                &hasher,
                "claimed@example.test",
                &first_password
            )
            .await
            .unwrap()
        );

        // The real owner can now sign up; the stale record is replaced.
        let owner = register(
            &mut client,
            &hasher,
            "claimed@example.test",
            &owner_password,
        )
        .await
        .unwrap();
        assert_ne!(owner.account_id, first.account_id);
        for sql in [
            "SELECT count(*) FROM users WHERE id=$1",
            "SELECT count(*) FROM memberships WHERE user_id=$1",
            "SELECT count(*) FROM email_verifications WHERE user_id=$1",
            "SELECT count(*) FROM sessions WHERE user_id=$1",
        ] {
            assert_eq!(count(&client, sql, first.user_id).await, 0, "{sql}");
        }
        assert_eq!(
            count(
                &client,
                "SELECT count(*) FROM accounts WHERE id=$1",
                first.account_id
            )
            .await,
            0
        );
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        // The stale code is dead; only the new owner's code verifies.
        assert!(
            !verify_email(&mut client, &hasher, &first.verification_token)
                .await
                .unwrap()
        );
        let mail = claim_verification_mail(&mut client, &hasher)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mail.token, owner.verification_token);
        assert!(
            verify_email(&mut client, &hasher, &mail.token)
                .await
                .unwrap()
        );
        assert!(matches!(
            login(&client, &hasher, "claimed@example.test", &first_password).await,
            Err(AuthError::InvalidCredentials)
        ));
        let session = login(&client, &hasher, "claimed@example.test", &owner_password)
            .await
            .unwrap();

        // A verified owner is never replaced, however old the sign-up.
        age_signup(&client, owner.user_id).await;
        assert!(is_unique_violation(
            &register(
                &mut client,
                &hasher,
                "claimed@example.test",
                &first_password
            )
            .await
        ));
        assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 0);
        let principal = authenticate_session(&client, &hasher, &session.token)
            .await
            .unwrap();
        assert_eq!(principal.tenant.account_id(), owner.account_id);
        assert!(
            login(&client, &hasher, "claimed@example.test", &owner_password)
                .await
                .is_ok()
        );

        // An operator-disabled pending account is left for the operator.
        let disabled = register(
            &mut client,
            &hasher,
            "disabled@example.test",
            &first_password,
        )
        .await
        .unwrap();
        age_signup(&client, disabled.user_id).await;
        client
            .execute(
                "UPDATE accounts SET disabled_at=now() WHERE id=$1",
                &[&disabled.account_id],
            )
            .await
            .unwrap();
        assert!(is_unique_violation(
            &register(
                &mut client,
                &hasher,
                "disabled@example.test",
                &owner_password
            )
            .await
        ));
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_concurrent_signups_replace_a_stale_record_once() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let schema = format!("pending_race_test_{}", Uuid::new_v4().simple());
        let (setup, mut client, url) = pending_signup_schema(&base_url, &schema).await;
        let hasher = TokenHasher::new(crate::test_keys::key(17)).unwrap();
        let stale = register(
            &mut client,
            &hasher,
            "race@example.test",
            &Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
        age_signup(&client, stale.user_id).await;
        let (mut a, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (mut b, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let a_password = Uuid::new_v4().to_string();
        let b_password = Uuid::new_v4().to_string();
        let (ra, rb) = tokio::join!(
            register(&mut a, &hasher, "race@example.test", &a_password),
            register(&mut b, &hasher, "race@example.test", &b_password),
        );
        let winners = [&ra, &rb].iter().filter(|result| result.is_ok()).count();
        assert_eq!(winners, 1);
        assert!(is_unique_violation(&ra) || is_unique_violation(&rb));
        let row = client
            .query_one(
                "SELECT count(*),(SELECT count(*) FROM accounts),(SELECT count(*) FROM email_verifications) FROM users",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, i64>(2), 1);
        assert!(
            !verify_email(&mut client, &hasher, &stale.verification_token)
                .await
                .unwrap()
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_prune_removes_only_expired_unverified_owners() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let schema = format!("pending_prune_test_{}", Uuid::new_v4().simple());
        let (setup, mut client, _) = pending_signup_schema(&base_url, &schema).await;
        let hasher = TokenHasher::new(crate::test_keys::key(19)).unwrap();
        let password = Uuid::new_v4().to_string();
        let stale = register(&mut client, &hasher, "stale@example.test", &password)
            .await
            .unwrap();
        let fresh = register(&mut client, &hasher, "fresh@example.test", &password)
            .await
            .unwrap();
        let verified = register(&mut client, &hasher, "verified@example.test", &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut client, &hasher, &verified.verification_token)
                .await
                .unwrap()
        );
        age_signup(&client, stale.user_id).await;
        age_signup(&client, verified.user_id).await;
        assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 1);
        assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 0);
        let users = "SELECT count(*) FROM users WHERE id=$1";
        assert_eq!(count(&client, users, stale.user_id).await, 0);
        assert_eq!(count(&client, users, fresh.user_id).await, 1);
        assert_eq!(count(&client, users, verified.user_id).await, 1);
        assert_eq!(
            count(
                &client,
                "SELECT count(*) FROM accounts WHERE id=$1",
                stale.account_id
            )
            .await,
            0
        );
        assert!(
            !verify_email(&mut client, &hasher, &stale.verification_token)
                .await
                .unwrap()
        );
        assert!(
            verify_email(&mut client, &hasher, &fresh.verification_token)
                .await
                .unwrap()
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
