// SPDX-License-Identifier: AGPL-3.0-only
//! Browser-facing account routes. All cookie-authenticated writes require an
//! exact, configured HTTPS Origin and the double-submit CSRF token.

use crate::auth::{
    self, AuthError, Scope, SessionPrincipal, TokenHasher,
    abuse_limits::{self, Limit},
    account,
    mfa::{self, MfaCipher},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac, digest::KeyInit};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

mod sms_lines;
mod sms_owner_keys;

const SESSION_COOKIE: &str = "__Host-zrotext_session";
const CSRF_COOKIE: &str = "__Host-zrotext_csrf";
const CSRF_HEADER: &str = "x-zrotext-csrf";

/// A deployment supplies a reviewed mail transport here. The default server
/// deliberately keeps registration closed until that transport and an explicit
/// registration policy are configured.
/// Implementations must not log the token or place it in a URL.
pub trait VerificationDispatcher: Send + Sync {
    fn ready(&self) -> bool;
    fn password_reset_ready(&self) -> bool {
        false
    }
    fn dispatch<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>>;
    fn dispatch_password_reset<'a>(
        &'a self,
        _email: &'a str,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async { Err(()) })
    }
    fn dispatch_password_reset_notice<'a>(
        &'a self,
        _email: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async { Err(()) })
    }
    fn check_connection<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DispatchFailure>> + Send + 'a>> {
        Box::pin(async { Ok(false) })
    }
}

/// Only fixed categories cross the mail transport boundary. SMTP responses may
/// contain addresses or other private data and must never enter logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchFailure {
    Message,
    Connect,
    Tls,
    Auth,
    Rejected,
    Timeout,
}

impl DispatchFailure {
    fn from_smtp(error: &lettre::transport::smtp::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_tls() {
            Self::Tls
        } else if error
            .status()
            .is_some_and(|code| matches!(code.to_string().as_str(), "530" | "534" | "535"))
        {
            Self::Auth
        } else if error.is_transient() || error.is_permanent() {
            Self::Rejected
        } else {
            Self::Connect
        }
    }

    pub fn warning(self) -> &'static str {
        match self {
            Self::Message => "verification mail delivery failed (category=message)",
            Self::Connect => "verification mail delivery failed (category=connect)",
            Self::Tls => "verification mail delivery failed (category=tls)",
            Self::Auth => "verification mail delivery failed (category=auth)",
            Self::Rejected => "verification mail delivery failed (category=rejected)",
            Self::Timeout => "verification mail delivery failed (category=timeout)",
        }
    }
}

/// Limit repeated warnings when many queued messages encounter the same
/// transport problem. A successful send clears the failure streak.
#[derive(Default)]
pub struct VerificationWarningGate {
    last_warning: Option<Instant>,
}

impl VerificationWarningGate {
    pub fn on_failure(&mut self, category: DispatchFailure, now: Instant) -> Option<&'static str> {
        if self
            .last_warning
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(300))
        {
            return None;
        }
        self.last_warning = Some(now);
        Some(category.warning())
    }

    pub fn on_success(&mut self) {
        self.last_warning = None;
    }
}

pub struct DisabledVerificationDispatcher;

impl VerificationDispatcher for DisabledVerificationDispatcher {
    fn ready(&self) -> bool {
        false
    }

    fn dispatch<'a>(
        &'a self,
        _email: &'a str,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>> {
        Box::pin(async { Err(DispatchFailure::Connect) })
    }
}

/// TLS-only SMTP delivery. Configuration is loaded by the runtime from a
/// secret store or environment; values are never included in errors or logs.
pub struct SmtpVerificationDispatcher {
    from: lettre::message::Mailbox,
    reply_to: Option<lettre::message::Mailbox>,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

fn verification_email_body(token: &str) -> String {
    format!(
        "Your ZROtext email verification code is:\n\n{token}\n\nOpen /owner/account#verify on your ZROtext server and enter this code. It expires in 24 hours.\n"
    )
}

impl SmtpVerificationDispatcher {
    pub fn new(
        host: &str,
        port: u16,
        username: String,
        password: String,
        from: &str,
        from_name: Option<&str>,
        reply_to: Option<&str>,
    ) -> Result<Self, &'static str> {
        if host.is_empty() || host.contains('/') || username.is_empty() || password.is_empty() {
            return Err("invalid SMTP configuration");
        }
        let mut from: lettre::message::Mailbox = from.parse().map_err(|_| "invalid SMTP sender")?;
        if let Some(name) = from_name {
            if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
                return Err("invalid SMTP sender name");
            }
            from.name = Some(name.to_owned());
        }
        let reply_to = reply_to
            .map(|value| value.parse().map_err(|_| "invalid SMTP Reply-To"))
            .transpose()?;
        let credentials = Credentials::new(username, password);
        let transport = if port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|_| "invalid SMTP relay")?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|_| "invalid SMTP relay")?
        }
        .port(port)
        .credentials(credentials)
        .build();
        Ok(Self {
            from,
            reply_to,
            transport,
        })
    }

    pub async fn test_connection(&self) -> Result<(), DispatchFailure> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(DispatchFailure::Connect),
            Err(error) => Err(DispatchFailure::from_smtp(&error)),
        }
    }
}

impl VerificationDispatcher for SmtpVerificationDispatcher {
    fn ready(&self) -> bool {
        true
    }

    fn password_reset_ready(&self) -> bool {
        true
    }

    fn dispatch<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>> {
        Box::pin(async move {
            let recipient = email.parse().map_err(|_| DispatchFailure::Message)?;
            let mut builder = Message::builder().from(self.from.clone()).to(recipient);
            if let Some(reply_to) = &self.reply_to {
                builder = builder.reply_to(reply_to.clone());
            }
            let message = builder
                .subject("Verify your ZROtext email")
                .body(verification_email_body(token))
                .map_err(|_| DispatchFailure::Message)?;
            self.transport
                .send(message)
                .await
                .map_err(|error| DispatchFailure::from_smtp(&error))?;
            Ok(())
        })
    }

    fn dispatch_password_reset<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async move {
            let recipient = email.parse().map_err(|_| ())?;
            let mut builder = Message::builder().from(self.from.clone()).to(recipient);
            if let Some(reply_to) = &self.reply_to {
                builder = builder.reply_to(reply_to.clone());
            }
            let message = builder
                .subject("Reset your ZROtext password")
                .body(format!(
                    "Your ZROtext password reset code is:\n\n{token}\n\nPaste this code into the password reset form. It expires in one hour. If you did not request it, ignore this message. The code is not a link.\n"
                ))
                .map_err(|_| ())?;
            self.transport.send(message).await.map_err(|_| ())?;
            Ok(())
        })
    }

    fn dispatch_password_reset_notice<'a>(
        &'a self,
        email: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async move {
            let recipient = email.parse().map_err(|_| ())?;
            let mut builder = Message::builder().from(self.from.clone()).to(recipient);
            if let Some(reply_to) = &self.reply_to {
                builder = builder.reply_to(reply_to.clone());
            }
            let message = builder
                .subject("Your ZROtext password was reset")
                .body("Your ZROtext password was reset and all sessions were signed out. If you did not do this, contact support immediately.\n".to_owned())
                .map_err(|_| ())?;
            self.transport.send(message).await.map_err(|_| ())?;
            Ok(())
        })
    }
    fn check_connection<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DispatchFailure>> + Send + 'a>> {
        Box::pin(async move { self.test_connection().await.map(|_| true) })
    }
}

/// Admission applies only to new accounts. Closing registration never disables
/// login, verification, or recovery for owners already in the database.
#[derive(Clone, Default)]
pub enum RegistrationPolicy {
    #[default]
    Closed,
    Allowlist {
        emails: HashSet<String>,
        domains: HashSet<String>,
        enrollment_key: [u8; 32],
    },
    Open,
}

impl RegistrationPolicy {
    pub fn parse(
        mode: Option<&str>,
        allowed_emails: Option<&str>,
        allowed_domains: Option<&str>,
        enrollment_key_b64: Option<&str>,
    ) -> Result<Self, &'static str> {
        let enrollment_key = enrollment_key_b64
            .map(|encoded| {
                let decoded = Zeroizing::new(
                    STANDARD
                        .decode(encoded)
                        .map_err(|_| "invalid REGISTRATION_ENROLLMENT_KEY_B64")?,
                );
                decoded
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid REGISTRATION_ENROLLMENT_KEY_B64")
            })
            .transpose()?;
        let emails = parse_entries(
            allowed_emails,
            "invalid REGISTRATION_ALLOWED_EMAILS",
            |entry| {
                let email = auth::normalize_email(entry).ok()?;
                let (local, domain) = email.split_once('@')?;
                (!local.is_empty() && valid_domain(domain)).then_some(email)
            },
        )?;
        let domains = parse_entries(
            allowed_domains,
            "invalid REGISTRATION_ALLOWED_DOMAINS",
            |entry| {
                let domain = entry.to_ascii_lowercase();
                valid_domain(&domain).then_some(domain)
            },
        )?;
        match mode.unwrap_or("closed") {
            "closed" if emails.is_empty() && domains.is_empty() && enrollment_key.is_none() => {
                Ok(Self::Closed)
            }
            "open" if emails.is_empty() && domains.is_empty() && enrollment_key.is_none() => {
                Ok(Self::Open)
            }
            "allowlist"
                if (!emails.is_empty() || !domains.is_empty()) && enrollment_key.is_some() =>
            {
                Ok(Self::Allowlist {
                    emails,
                    domains,
                    enrollment_key: enrollment_key.expect("checked above"),
                })
            }
            "closed" | "open" | "allowlist" => Err("REGISTRATION_MODE and allowlists disagree"),
            _ => Err("REGISTRATION_MODE must be closed, allowlist, or open"),
        }
    }

    fn admitted_email(
        &self,
        headers: &HeaderMap,
        raw_email: &str,
    ) -> Result<Option<String>, AuthError> {
        match self {
            Self::Closed => Ok(None),
            Self::Open => auth::normalize_email(raw_email).map(Some),
            Self::Allowlist { enrollment_key, .. } => {
                let candidate = headers
                    .get("x-zrotext-registration-token")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| STANDARD.decode(value).ok())
                    .map(Zeroizing::new);
                let Some(candidate) = candidate.filter(|candidate| candidate.len() == 32) else {
                    return Ok(None);
                };
                let Ok(email) = auth::normalize_email(raw_email) else {
                    return Ok(None);
                };
                let expected = invite_digest(enrollment_key, &email);
                let valid = bool::from(expected.as_slice().ct_eq(candidate.as_slice()));
                let allowed = self.admits(&email);
                Ok((allowed & valid).then_some(email))
            }
        }
    }

    /// Mint a token bound to one allowlisted email. Only the operator CLI
    /// should expose this; the master key never leaves private configuration.
    pub fn issue_invite(&self, raw_email: &str) -> Result<String, &'static str> {
        let email = auth::normalize_email(raw_email).map_err(|_| "invalid invited email")?;
        let Self::Allowlist { enrollment_key, .. } = self else {
            return Err("invite issuance requires allowlist mode");
        };
        if !self.admits(&email) {
            return Err("email is not allowlisted");
        }
        Ok(STANDARD.encode(invite_digest(enrollment_key, &email)))
    }

    fn admits(&self, normalized_email: &str) -> bool {
        match self {
            Self::Closed => false,
            Self::Open => true,
            Self::Allowlist {
                emails, domains, ..
            } => {
                emails.contains(normalized_email)
                    || normalized_email
                        .split_once('@')
                        .is_some_and(|(_, domain)| domains.contains(domain))
            }
        }
    }
}

fn invite_digest(key: &[u8; 32], normalized_email: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"zrotext-registration-invite-v1\0");
    mac.update(normalized_email.as_bytes());
    mac.finalize().into_bytes().into()
}

fn parse_entries<F>(
    value: Option<&str>,
    error: &'static str,
    normalize: F,
) -> Result<HashSet<String>, &'static str>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = value else {
        return Ok(HashSet::new());
    };
    if value.len() > 4096 {
        return Err(error);
    }
    value
        .split(',')
        .map(|entry| normalize(entry.trim()).ok_or(error))
        .collect()
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Clone)]
pub struct AuthHttpState {
    pub database_url: String,
    pub hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    pub dispatcher: Arc<dyn VerificationDispatcher>,
    pub registration_policy: RegistrationPolicy,
    pub hash_limit: Arc<Semaphore>,
    pub mfa_cipher: Option<Arc<MfaCipher>>,
    pub mfa_enrollment_enabled: bool,
    /// Dormant owner routes for SMS line activation; off by default.
    pub sms_line_activation_enabled: bool,
}

impl AuthHttpState {
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        canonical_origin: String,
        dispatcher: Arc<dyn VerificationDispatcher>,
    ) -> Result<Self, String> {
        if !valid_canonical_origin(&canonical_origin) {
            let message = match canonical_origin_serialization(&canonical_origin) {
                Some(expected) => format!("AUTH_ORIGIN must be a canonical HTTPS origin; use {expected}"),
                None => "AUTH_ORIGIN must be a canonical HTTPS origin with no path, query, fragment, or userinfo".to_owned(),
            };
            return Err(message);
        }
        Ok(Self {
            database_url,
            hasher,
            canonical_origin,
            dispatcher,
            registration_policy: RegistrationPolicy::Closed,
            // Argon2id uses 64 MiB per operation. Limit concurrent hashes.
            hash_limit: Arc::new(Semaphore::new(2)),
            mfa_cipher: None,
            mfa_enrollment_enabled: false,
            sms_line_activation_enabled: false,
        })
    }

    pub fn with_registration_policy(mut self, policy: RegistrationPolicy) -> Self {
        self.registration_policy = policy;
        self
    }

    pub fn with_mfa_cipher(mut self, cipher: Arc<MfaCipher>) -> Self {
        self.mfa_cipher = Some(cipher);
        self
    }

    pub fn with_sms_line_activation_enabled(mut self) -> Self {
        self.sms_line_activation_enabled = true;
        self
    }

    pub fn with_mfa_enrollment_enabled(mut self) -> Self {
        self.mfa_enrollment_enabled = true;
        self
    }
}

pub fn router(state: AuthHttpState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/resend-verification", post(resend_verification))
        .route("/verify-email", post(verify_email))
        .route("/login", post(login))
        .route("/login/mfa", post(complete_mfa_login))
        .route("/logout", post(logout))
        .route("/session", get(session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/revoke-others", post(revoke_other_sessions))
        .route("/password", post(change_password))
        .route("/password/reset/request", post(request_password_reset))
        .route("/password/reset/confirm", post(confirm_password_reset))
        .route("/mfa", get(mfa_status))
        .route("/mfa/enroll", post(begin_mfa_enrollment))
        .route("/mfa/confirm", post(confirm_mfa_enrollment))
        .route("/mfa/disable", post(disable_mfa))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/{key_id}", delete(revoke_api_key))
        .route(
            "/sms-line-owner-keys/challenge",
            post(sms_owner_keys::challenge),
        )
        .route(
            "/sms-line-owner-keys",
            get(sms_owner_keys::list).post(sms_owner_keys::register),
        )
        .route(
            "/sms-line-owner-keys/{fingerprint}",
            delete(sms_owner_keys::revoke),
        )
        .route("/sms-lines/{line_id}/activations", post(sms_lines::open))
        .route(
            "/sms-lines/{line_id}/activations/{challenge_id}",
            get(sms_lines::view),
        )
        .route(
            "/sms-lines/{line_id}/activations/{challenge_id}/approve",
            post(sms_lines::approve),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(state))
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    no_store(&mut response);
    response
}

#[derive(Debug)]
pub enum AuthHttpError {
    BadRequest,
    Unauthorized,
    Forbidden,
    SmsOwnerKeyActive,
    NotFound,
    TooManyRequests,
    Unavailable,
    Internal,
}

impl IntoResponse for AuthHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::SmsOwnerKeyActive => (StatusCode::CONFLICT, "revoke_sms_owner_key_first"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(ErrorBody { code }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn map_auth(error: AuthError) -> AuthHttpError {
    match error {
        AuthError::InvalidInput => AuthHttpError::BadRequest,
        AuthError::InvalidCredentials | AuthError::Unauthorized | AuthError::MfaRequired { .. } => {
            AuthHttpError::Unauthorized
        }
        AuthError::EmailNotVerified | AuthError::Forbidden => AuthHttpError::Forbidden,
        AuthError::SmsOwnerKeyActive => AuthHttpError::SmsOwnerKeyActive,
        AuthError::Database(_) => AuthHttpError::Unavailable,
        AuthError::Password => AuthHttpError::Internal,
        AuthError::Crypto => AuthHttpError::Unavailable,
        AuthError::RateLimited => AuthHttpError::TooManyRequests,
    }
}

async fn connect(database_url: &str) -> Result<crate::runtime_db::PooledClient, AuthHttpError> {
    crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)
}

fn canonical_origin_serialization(origin: &str) -> Option<String> {
    let Ok(parsed) = url::Url::parse(origin) else {
        return None;
    };
    (parsed.scheme() == "https"
        && parsed.has_host()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none())
    .then(|| parsed.origin().ascii_serialization())
}

fn valid_canonical_origin(origin: &str) -> bool {
    canonical_origin_serialization(origin).as_deref() == Some(origin)
}

fn require_origin(headers: &HeaderMap, expected: &str) -> Result<(), AuthHttpError> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(expected)
    {
        Ok(())
    } else {
        Err(AuthHttpError::Forbidden)
    }
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// Shared by account and enrollment HTTP handlers. `mutation=true` enforces
/// the exact Origin and CSRF header/cookie, in addition to the session cookie.
pub async fn require_owner(
    client: &Client,
    hasher: &TokenHasher,
    canonical_origin: &str,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<SessionPrincipal, AuthHttpError> {
    let token = cookie(headers, SESSION_COOKIE).ok_or(AuthHttpError::Unauthorized)?;
    let principal = auth::authenticate_session(client, hasher, token)
        .await
        .map_err(map_auth)?;
    if mutation {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthHttpError::Forbidden)?;
        let csrf_cookie = cookie(headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
        let csrf_header = headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthHttpError::Forbidden)?;
        principal
            .require_csrf(hasher, origin, canonical_origin, csrf_cookie, csrf_header)
            .map_err(map_auth)?;
    }
    Ok(principal)
}

#[derive(Deserialize)]
struct RegisterBody {
    email: String,
    password: String,
}

async fn register(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    // Private modes first require an address-bound operator invite. Missing
    // or malformed credentials return before email parsing; every denied
    // request avoids the database, abuse budget, and password hashing.
    let Some(subject) = state
        .registration_policy
        .admitted_email(&headers, &body.email)
        .map_err(map_auth)?
    else {
        return Ok(StatusCode::ACCEPTED);
    };
    if !state.dispatcher.ready() {
        return Err(AuthHttpError::Unavailable);
    }
    let mut client = connect(&state.database_url).await?;
    if !abuse_limits::consume(&client, &state.hasher, Limit::Registration, Some(&subject))
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    match auth::register(&mut client, &state.hasher, &body.email, &body.password).await {
        Ok(_) => {}
        // Avoid leaking whether this address is already registered.
        Err(AuthError::Database(ref error))
            if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) =>
        {
            return Ok(StatusCode::ACCEPTED);
        }
        Err(error) => return Err(map_auth(error)),
    }
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct ResendBody {
    email: String,
    password: String,
}

async fn resend_verification(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<ResendBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    if !state.dispatcher.ready() {
        return Err(AuthHttpError::Unavailable);
    }
    let mut client = connect(&state.database_url).await?;
    let subject = auth::normalize_email(&body.email).ok();
    if !abuse_limits::consume(&client, &state.hasher, Limit::Resend, subject.as_deref())
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    // Valid, unknown, verified and throttled accounts all have the same
    // outward result. No code or account-existence signal enters the body.
    let _ =
        auth::request_verification_resend(&mut client, &state.hasher, &body.email, &body.password)
            .await
            .map_err(map_auth)?;
    Ok(StatusCode::ACCEPTED)
}

/// Run from a periodic background task at every API site. The outbox claim
/// makes concurrent polling safe; this routine performs at most one send.
/// SMTP acceptance can be ambiguous, so failed claims retry at least once.
pub async fn dispatch_one_verification(state: &AuthHttpState) -> Result<bool, AuthHttpError> {
    Ok(!matches!(
        dispatch_one_verification_report(state).await?,
        VerificationDispatchOutcome::Idle
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDispatchOutcome {
    Idle,
    Delivered,
    Failed {
        category: DispatchFailure,
        dead_lettered: bool,
    },
}

pub async fn dispatch_one_verification_report(
    state: &AuthHttpState,
) -> Result<VerificationDispatchOutcome, AuthHttpError> {
    if !state.dispatcher.ready() {
        return Ok(VerificationDispatchOutcome::Idle);
    }
    let mut client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let Some(mail) = auth::claim_verification_mail(&mut client, &state.hasher)
        .await
        .map_err(map_auth)?
    else {
        return Ok(VerificationDispatchOutcome::Idle);
    };
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        state.dispatcher.dispatch(&mail.email, &mail.token),
    )
    .await;
    let delivered = matches!(&result, Ok(Ok(())));
    let acknowledged = auth::ack_verification_mail(&client, &mail, delivered)
        .await
        .map_err(map_auth)?;
    Ok(match result {
        Ok(Ok(())) => VerificationDispatchOutcome::Delivered,
        Ok(Err(category)) => VerificationDispatchOutcome::Failed {
            category,
            dead_lettered: acknowledged && mail.attempt_count >= 6,
        },
        Err(_) => VerificationDispatchOutcome::Failed {
            category: DispatchFailure::Timeout,
            dead_lettered: acknowledged && mail.attempt_count >= 6,
        },
    })
}

/// At-least-once delivery of a one-use reset code. Concurrent hubs use the
/// same leased PostgreSQL claim and cannot generate different codes for it.
/// Returns whether a claimed code was delivered; `false` when idle or failed.
pub async fn dispatch_one_password_reset(state: &AuthHttpState) -> Result<bool, AuthHttpError> {
    if !state.dispatcher.password_reset_ready() {
        return Ok(false);
    }
    let mut client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let Some(mail) = account::claim_reset_mail(&mut client, &state.hasher)
        .await
        .map_err(map_auth)?
    else {
        return Ok(false);
    };
    let delivered = tokio::time::timeout(
        Duration::from_secs(30),
        state
            .dispatcher
            .dispatch_password_reset(&mail.email, &mail.token),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let _ = account::ack_reset_mail(&client, &mail, delivered)
        .await
        .map_err(map_auth)?;
    Ok(delivered)
}

/// Returns whether a claimed notice was delivered; `false` when idle or failed.
pub async fn dispatch_one_password_reset_notice(
    state: &AuthHttpState,
) -> Result<bool, AuthHttpError> {
    if !state.dispatcher.password_reset_ready() {
        return Ok(false);
    }
    let mut client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let Some(notice) = account::claim_reset_notice(&mut client)
        .await
        .map_err(map_auth)?
    else {
        return Ok(false);
    };
    let delivered = tokio::time::timeout(
        Duration::from_secs(30),
        state
            .dispatcher
            .dispatch_password_reset_notice(&notice.email),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let _ = account::ack_reset_notice(&client, &notice, delivered)
        .await
        .map_err(map_auth)?;
    Ok(delivered)
}

#[derive(Deserialize)]
struct VerifyBody {
    token: String,
}

async fn verify_email(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    let mut client = connect(&state.database_url).await?;
    let budget_available = abuse_limits::consume(&client, &state.hasher, Limit::Verify, None)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    if !budget_available
        && !auth::verification_token_is_live(&client, &state.hasher, &body.token)
            .await
            .map_err(map_auth)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    if auth::verify_email(&mut client, &state.hasher, &body.token)
        .await
        .map_err(map_auth)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else if budget_available {
        Err(AuthHttpError::BadRequest)
    } else {
        Err(AuthHttpError::TooManyRequests)
    }
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Result<Response, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    let client = connect(&state.database_url).await?;
    let subject = auth::normalize_email(&body.email).ok();
    // A browser that already proved this password keeps its own budget, so
    // anonymous guesses cannot lock the owner out by exhausting the shared
    // route or per-address budget. Unknown browsers never learn whether the
    // address exists: they see the same 429 either way.
    let known_client = subject.as_deref().and_then(|email| {
        cookie(&headers, auth::LOGIN_CLIENT_COOKIE)
            .and_then(|value| auth::login_client_subject(&state.hasher, value, email))
    });
    let admitted =
        abuse_limits::consume(&client, &state.hasher, Limit::Login, subject.as_deref()).await;
    let admitted = match (admitted, &known_client) {
        (Ok(false), Some(known)) => {
            abuse_limits::consume_verified(&client, &state.hasher, Limit::Login, known).await
        }
        (admitted, _) => admitted,
    };
    if !admitted.map_err(|_| AuthHttpError::Unavailable)? {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    let credentials = match auth::login(&client, &state.hasher, &body.email, &body.password).await {
        Ok(credentials) => credentials,
        Err(AuthError::MfaRequired {
            account_id,
            user_id,
        }) => {
            let challenge_token = mfa::begin_login_challenge(
                &client,
                &state.hasher,
                account_id,
                user_id,
                &body.password,
            )
            .await
            .map_err(map_auth)?;
            let mut response = (
                StatusCode::ACCEPTED,
                Json(MfaChallengeBody { challenge_token }),
            )
                .into_response();
            no_store(&mut response);
            return Ok(response);
        }
        Err(error) => return Err(map_auth(error)),
    };
    let mut response = session_response(&credentials)?;
    if known_client.is_none() {
        remember_login_client(&state.hasher, &body.email, &mut response)?;
    }
    Ok(response)
}

/// Set after a full sign-in from a browser without a valid login-client token
/// for this address. An existing token is kept, so repeated sign-ins cannot
/// mint fresh budgets.
fn remember_login_client(
    hasher: &TokenHasher,
    email: &str,
    response: &mut Response,
) -> Result<(), AuthHttpError> {
    if let Some(value) = auth::login_client_cookie(hasher, email) {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&value).map_err(|_| AuthHttpError::Internal)?,
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct MfaChallengeBody {
    challenge_token: String,
}

#[derive(Deserialize)]
struct MfaLoginBody {
    challenge_token: String,
    code: String,
}

async fn complete_mfa_login(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<MfaLoginBody>,
) -> Result<Response, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    let mut client = connect(&state.database_url).await?;
    if !abuse_limits::consume_or_verify(
        &client,
        &state.hasher,
        Limit::MfaChallenge,
        &body.challenge_token,
        mfa::login_challenge_is_live(&client, &state.hasher, &body.challenge_token),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let credentials = mfa::complete_login(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &body.challenge_token,
        &body.code,
    )
    .await
    .map_err(map_auth)?;
    let mut response = session_response(&credentials)?;
    // Best effort: a lookup failure must not undo a completed sign-in.
    if let Ok(Some(email)) = auth::session_email(&client, credentials.id).await
        && cookie(&headers, auth::LOGIN_CLIENT_COOKIE)
            .and_then(|value| auth::login_client_subject(&state.hasher, value, &email))
            .is_none()
    {
        remember_login_client(&state.hasher, &email, &mut response)?;
    }
    Ok(response)
}

fn session_response(credentials: &auth::SessionCredentials) -> Result<Response, AuthHttpError> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    for value in auth::session_cookies(credentials) {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&value).map_err(|_| AuthHttpError::Internal)?,
        );
    }
    no_store(&mut response);
    Ok(response)
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[derive(Serialize)]
struct SessionBody {
    account_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
}

async fn session(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let mut response = Json(SessionBody {
        account_id: owner.tenant.account_id(),
        user_id: owner.user_id,
        session_id: owner.session_id,
    })
    .into_response();
    no_store(&mut response);
    Ok(response)
}

#[derive(Serialize)]
struct SessionInfoBody {
    id: Uuid,
    current: bool,
    created_at_ms: i64,
    expires_at_ms: i64,
    last_used_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct SessionsBody {
    sessions: Vec<SessionInfoBody>,
}

async fn list_sessions(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<SessionsBody>, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let sessions = account::list_sessions(&client, &owner)
        .await
        .map_err(map_auth)?
        .into_iter()
        .map(|entry| SessionInfoBody {
            id: entry.id,
            current: entry.current,
            created_at_ms: entry.created_at_ms,
            expires_at_ms: entry.expires_at_ms,
            last_used_at_ms: entry.last_used_at_ms,
        })
        .collect();
    Ok(Json(SessionsBody { sessions }))
}

#[derive(Deserialize)]
struct RevokeOtherSessionsBody {
    current_password: String,
    code: Option<String>,
}

async fn revoke_other_sessions(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RevokeOtherSessionsBody>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::SessionsRevokeOthers,
        Some(&owner.user_id.to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    match account::revoke_other_sessions(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        &body.current_password,
        body.code.as_deref(),
    )
    .await
    {
        Ok(_) => {}
        Err(AuthError::InvalidCredentials) => return Err(AuthHttpError::BadRequest),
        Err(error) => return Err(map_auth(error)),
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
    code: Option<String>,
}

async fn change_password(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Result<Response, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    let subject = owner.user_id.to_string();
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::PasswordChange,
        Some(&subject),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    match account::change_password(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        &body.current_password,
        &body.new_password,
        body.code.as_deref(),
    )
    .await
    {
        Ok(()) => {}
        Err(AuthError::InvalidCredentials) => return Err(AuthHttpError::BadRequest),
        Err(error) => return Err(map_auth(error)),
    }
    cleared_session_response()
}

fn cleared_session_response() -> Result<Response, AuthHttpError> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [SESSION_COOKIE, CSRF_COOKIE] {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
            ))
            .map_err(|_| AuthHttpError::Internal)?,
        );
    }
    no_store(&mut response);
    Ok(response)
}

#[derive(Deserialize)]
struct ResetRequestBody {
    email: String,
}

async fn request_password_reset(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<ResetRequestBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    if !state.dispatcher.password_reset_ready() {
        return Err(AuthHttpError::Unavailable);
    }
    let mut client = connect(&state.database_url).await?;
    let subject = auth::normalize_email(&body.email).ok();
    let admitted = if let Some(subject) = subject.as_deref() {
        abuse_limits::consume_or_verify(
            &client,
            &state.hasher,
            Limit::PasswordResetRequest,
            subject,
            async {
                client
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL)",
                        &[&subject],
                    )
                    .await
                    .map(|row| row.get::<_, bool>(0))
            },
        )
        .await
    } else {
        abuse_limits::consume(&client, &state.hasher, Limit::PasswordResetRequest, None).await
    }
    .map_err(|_| AuthHttpError::Unavailable)?;
    if !admitted {
        return Ok(StatusCode::ACCEPTED);
    }
    account::request_password_reset(&mut client, &state.hasher, &body.email)
        .await
        .map_err(map_auth)?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct ResetConfirmBody {
    token: String,
    new_password: String,
}

async fn confirm_password_reset(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<ResetConfirmBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    let mut client = connect(&state.database_url).await?;
    let admitted = abuse_limits::consume_or_verify(
        &client,
        &state.hasher,
        Limit::PasswordResetConfirm,
        &body.token,
        account::reset_token_is_live(&client, &state.hasher, &body.token),
    )
    .await
    .map_err(map_auth)?;
    if !admitted {
        // A missing, expired, or rate-limited code has one outward result.
        return Err(AuthHttpError::BadRequest);
    }
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    if account::confirm_password_reset(&mut client, &state.hasher, &body.token, &body.new_password)
        .await
        .map_err(map_auth)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthHttpError::BadRequest)
    }
}

#[derive(Serialize)]
struct MfaStatusBody {
    enabled: bool,
    pending: bool,
}

async fn mfa_status(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let status = mfa::status(&client, &owner).await.map_err(map_auth)?;
    let mut response = Json(MfaStatusBody {
        enabled: status.enabled,
        pending: status.pending,
    })
    .into_response();
    no_store(&mut response);
    Ok(response)
}

async fn mfa_manage_budget(
    client: &Client,
    state: &AuthHttpState,
    owner: &SessionPrincipal,
) -> Result<(), AuthHttpError> {
    let subject = owner.user_id.to_string();
    if abuse_limits::consume(client, &state.hasher, Limit::MfaManage, Some(&subject))
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
    {
        Ok(())
    } else {
        Err(AuthHttpError::TooManyRequests)
    }
}

#[derive(Deserialize)]
struct MfaEnrollBody {
    password: String,
}

#[derive(Serialize)]
struct MfaEnrollBodyResponse {
    secret_base32: String,
    provisioning_uri: String,
}

async fn begin_mfa_enrollment(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<MfaEnrollBody>,
) -> Result<Response, AuthHttpError> {
    if !state.mfa_enrollment_enabled {
        return Err(AuthHttpError::NotFound);
    }
    let cipher = state
        .mfa_cipher
        .as_ref()
        .ok_or(AuthHttpError::Unavailable)?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    let enrollment = mfa::begin_enrollment(&mut client, cipher, &owner, &body.password)
        .await
        .map_err(map_auth)?;
    let mut response = Json(MfaEnrollBodyResponse {
        secret_base32: enrollment.secret_base32,
        provisioning_uri: enrollment.provisioning_uri,
    })
    .into_response();
    no_store(&mut response);
    Ok(response)
}

#[derive(Deserialize)]
struct MfaCodeBody {
    code: String,
}

#[derive(Serialize)]
struct MfaRecoveryBody {
    recovery_codes: Vec<String>,
}

async fn confirm_mfa_enrollment(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<MfaCodeBody>,
) -> Result<Response, AuthHttpError> {
    if !state.mfa_enrollment_enabled {
        return Err(AuthHttpError::NotFound);
    }
    let cipher = state
        .mfa_cipher
        .as_ref()
        .ok_or(AuthHttpError::Unavailable)?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let codes = mfa::confirm_enrollment(&mut client, cipher, &state.hasher, &owner, &body.code)
        .await
        .map_err(map_auth)?;
    let mut response = Json(MfaRecoveryBody {
        recovery_codes: codes.codes,
    })
    .into_response();
    no_store(&mut response);
    Ok(response)
}

#[derive(Deserialize)]
struct MfaDisableBody {
    password: String,
    code: String,
}

async fn disable_mfa(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<MfaDisableBody>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let _permit = state
        .hash_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthHttpError::TooManyRequests)?;
    mfa::disable(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        &body.password,
        &body.code,
    )
    .await
    .map_err(map_auth)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn logout(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    auth::revoke_session(&client, &owner, owner.session_id)
        .await
        .map_err(map_auth)?;
    cleared_session_response()
}

#[derive(Deserialize)]
struct CreateKeyBody {
    scopes: Vec<String>,
    bound_device_id: Option<Uuid>,
    lifetime_days: Option<i32>,
}

#[derive(Serialize)]
struct CreatedKeyBody {
    id: Uuid,
    token: String,
    public_prefix: String,
}

#[derive(Deserialize)]
struct KeyListQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct KeyMetadataBody {
    id: Uuid,
    public_prefix: String,
    scopes: Vec<String>,
    bound_device_id: Option<Uuid>,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
    status: &'static str,
}

#[derive(Serialize)]
struct KeyListBody {
    keys: Vec<KeyMetadataBody>,
    next_cursor: Option<Uuid>,
}

async fn list_api_keys(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<KeyListQuery>,
) -> Result<Json<KeyListBody>, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let csrf_cookie = cookie(&headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    owner
        .require_csrf_token(&state.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let page = auth::list_api_keys(&client, &owner, query.before)
        .await
        .map_err(map_auth)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthHttpError::Internal)?
        .as_millis() as i64;
    Ok(Json(KeyListBody {
        keys: page
            .keys
            .into_iter()
            .map(|key| {
                let status = if key.revoked_at_ms.is_some() {
                    "revoked"
                } else if key.expires_at_ms.is_some_and(|expires| expires <= now_ms) {
                    "expired"
                } else {
                    "active"
                };
                KeyMetadataBody {
                    id: key.id,
                    public_prefix: key.public_prefix,
                    scopes: key.scopes,
                    bound_device_id: key.bound_device_id,
                    created_at_ms: key.created_at_ms,
                    expires_at_ms: key.expires_at_ms,
                    revoked_at_ms: key.revoked_at_ms,
                    status,
                }
            })
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

fn parse_scope(value: &str) -> Option<Scope> {
    Some(match value {
        "messages:send" => Scope::MessagesSend,
        "messages:read" => Scope::MessagesRead,
        "devices:read" => Scope::DevicesRead,
        "devices:manage" => Scope::DevicesManage,
        "webhooks:read" => Scope::WebhooksRead,
        "webhooks:manage" => Scope::WebhooksManage,
        "billing:read" => Scope::BillingRead,
        _ => return None,
    })
}

async fn create_api_key(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyBody>,
) -> Result<Response, AuthHttpError> {
    let scopes = body
        .scopes
        .iter()
        .map(|name| parse_scope(name).ok_or(AuthHttpError::BadRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    // Charge the account, not its session or live key count: logging in again
    // and revoking issued keys must not reset the database growth budget.
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::ApiKeyCreate,
        Some(&owner.tenant.account_id().to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let key = auth::create_api_key(
        &mut client,
        &state.hasher,
        &owner,
        &scopes,
        body.bound_device_id,
        body.lifetime_days,
    )
    .await
    .map_err(map_auth)?;
    let mut response = (
        StatusCode::CREATED,
        Json(CreatedKeyBody {
            id: key.id,
            token: key.token,
            public_prefix: key.public_prefix,
        }),
    )
        .into_response();
    no_store(&mut response);
    Ok(response)
}

async fn revoke_api_key(
    State(state): State<Arc<AuthHttpState>>,
    Path(key_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    if auth::revoke_api_key(&client, &owner, key_id)
        .await
        .map_err(map_auth)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthHttpError::NotFound)
    }
}

#[cfg(test)]
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests;
