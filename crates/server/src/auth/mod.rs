// SPDX-License-Identifier: AGPL-3.0-only
//! Database-backed owner authentication. Callers must keep the token pepper in
//! operational secret storage, independent of password verifiers and vault keys.
//! Every resource repository must accept a `Tenant` and filter by its account ID.

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio_postgres::Client;
use uuid::Uuid;

const SESSION_DAYS: i32 = 14;
const VERIFICATION_HOURS: i32 = 24;
const MAX_EMAIL_BYTES: usize = 254;

pub mod abuse_limits;
pub mod mfa;
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
    let password_hash = password_engine()?
        .hash_password(password.as_bytes())
        .map_err(|_| AuthError::Password)?
        .to_string();
    let account_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let verification_id = Uuid::new_v4();
    let verification_token = verification_token_for_id(hasher, verification_id);
    let token_hash = hasher.digest(b"email-verification-v1", &verification_token);
    let transaction = client.transaction().await?;
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

/// Consumes the challenge once. The caller supplies this token in a POST body,
/// never as a query parameter, to avoid history/referrer leakage.
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
    let row = tx
        .query_opt(
            "UPDATE email_verifications SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING id,user_id",
            &[&&hash[..]],
        )
        .await?;
    if let Some(row) = row {
        let verification_id: Uuid = row.get(0);
        let user_id: Uuid = row.get(1);
        tx.execute(
            "UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1",
            &[&user_id],
        )
        .await?;
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
    let Some(row) = row else {
        return Err(AuthError::InvalidCredentials);
    };
    let user_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    let stored: String = row.get(2);
    let parsed = PasswordHash::new(&stored).map_err(|_| AuthError::InvalidCredentials)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AuthError::InvalidCredentials)?;
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
            "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) SELECT $1,$2,$3,$4,$5,now()+($6::integer * interval '1 day') FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$3 AND m.account_id=$2 AND NOT u.mfa_enabled AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR UPDATE OF u",
            &[&id, &account_id, &user_id, &&token_hash[..], &&csrf_hash[..], &SESSION_DAYS],
        )
        .await?;
    if inserted != 1 {
        return Err(AuthError::MfaRequired {
            account_id,
            user_id,
        });
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
    Ok(SessionPrincipal {
        session_id: row.get(0),
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
    client: &Client,
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
    let inserted = client
        .execute(
            "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,CASE WHEN $8::integer IS NULL THEN NULL ELSE now()+($8::integer * interval '1 day') END FROM sessions s WHERE s.id=$9 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()",
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
        let hasher = TokenHasher::new(vec![7; 32]).unwrap();
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
    async fn postgres_tenant_revocation_and_scope_contract() {
        let Ok(url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
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
        let hasher = TokenHasher::new(vec![11; 32]).unwrap();
        let a = register(&mut client, &hasher, "A@example.test", "correct horse 123")
            .await
            .unwrap();
        let b = register(&mut client, &hasher, "b@example.test", "correct horse 456")
            .await
            .unwrap();
        assert!(matches!(
            login(&client, &hasher, "a@example.test", "correct horse 123").await,
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
        let sa = login(&client, &hasher, "a@example.test", "correct horse 123")
            .await
            .unwrap();
        let sb = login(&client, &hasher, "b@example.test", "correct horse 456")
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
            &client,
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
            create_api_key(&client, &hasher, &pa, &[Scope::BillingRead], None, None).await,
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
}
