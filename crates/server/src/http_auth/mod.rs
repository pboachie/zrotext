// SPDX-License-Identifier: AGPL-3.0-only
//! Browser-facing account routes. All cookie-authenticated writes require an
//! exact, configured HTTPS Origin and the double-submit CSRF token.

use crate::api_json::ApiJson;
use crate::auth::{
    self, ApiKeyLifetime, AuthError, Role, Scope, SessionPrincipal, TokenHasher,
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
use preauth::{MemberMutation, OwnerMutation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_postgres::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod preauth;
mod seats_http;
mod sms_lines;
mod sms_owner_keys;

pub(crate) const SESSION_COOKIE: &str = "__Host-zrotext_session";
pub(crate) const CSRF_COOKIE: &str = "__Host-zrotext_csrf";
const CSRF_HEADER: &str = "x-zrotext-csrf";
/// Argon2id uses 64 MiB per operation, so a process runs at most this many
/// password hashes at once.
const HASH_PERMITS: usize = 2;
/// How many requests may queue for one of the [`HASH_PERMITS`] slots. Each
/// waiter already holds one of the 16 request-pool connections
/// (`crate::runtime_db`), so an uncapped queue could pin the whole request
/// pool for [`HASH_PERMIT_WAIT`]. Four waiters plus two hashing requests
/// leave at least ten connections for every other owner route.
const HASH_WAIT_SLOTS: usize = 4;
/// Two queued 64 MiB Argon2id operations normally finish well inside this.
/// [`HASH_WAIT_SLOTS`] bounds how many requests can wait at once; this bounds
/// how long.
const HASH_PERMIT_WAIT: Duration = Duration::from_secs(2);

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
        "Your ZROtext email verification code is:\n\n{token}\n\nOpen /owner/account#verify on your ZROtext server and enter this code together with the password you chose at sign-up. It expires in 24 hours. If you did not sign up for ZROtext, ignore this message.\n"
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
        match unix_now_secs() {
            Some(now) => self.admitted_email_at(headers, raw_email, now),
            // A pre-epoch clock cannot prove token liveness; the clock-free
            // policies keep their own behavior and allowlist fails closed.
            None => match self {
                Self::Closed => Ok(None),
                Self::Open => auth::normalize_email(raw_email).map(Some),
                Self::Allowlist { .. } => Ok(None),
            },
        }
    }

    /// The admission decision for `now_secs` seconds after the Unix epoch.
    /// [`Self::admitted_email`] reads the wall clock; tests pin the instant
    /// here so no assertion depends on scheduling granularity.
    fn admitted_email_at(
        &self,
        headers: &HeaderMap,
        raw_email: &str,
        now_secs: u64,
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
                let Some(candidate) =
                    candidate.filter(|candidate| candidate.len() == INVITE_TOKEN_LEN)
                else {
                    return Ok(None);
                };
                let Ok(email) = auth::normalize_email(raw_email) else {
                    return Ok(None);
                };
                let expires_at =
                    u64::from_be_bytes(candidate[..8].try_into().expect("length checked above"));
                let expected = invite_mac(enrollment_key, &email, expires_at);
                let valid = bool::from(expected.as_slice().ct_eq(candidate[8..].as_ref()));
                // The API server's own clock decides liveness; a client cannot
                // extend a token by delaying or replaying the request.
                let live = expires_at > now_secs;
                // Defense in depth for a compromised or misused master key:
                // admission holds the same lifetime cap as issuance, so even a
                // validly signed token cannot outlive INVITE_MAX_LIFETIME.
                let within_cap =
                    expires_at <= now_secs.saturating_add(INVITE_MAX_LIFETIME.as_secs());
                let allowed = self.admits(&email);
                Ok((live & valid & allowed & within_cap).then_some(email))
            }
        }
    }

    /// Mint a token bound to one allowlisted email, expiring after the
    /// default [`INVITE_MAX_LIFETIME`]. Only the operator CLI should expose
    /// this; the master key never leaves private configuration.
    pub fn issue_invite(&self, raw_email: &str) -> Result<String, &'static str> {
        self.issue_invite_with_lifetime(raw_email, INVITE_MAX_LIFETIME)
    }

    /// Mint an invite that stops admitting after `lifetime`, which must be
    /// at least one second and no longer than [`INVITE_MAX_LIFETIME`]. The
    /// expiry is part of the signed token, so no database row is needed to
    /// enforce it.
    pub fn issue_invite_with_lifetime(
        &self,
        raw_email: &str,
        lifetime: Duration,
    ) -> Result<String, &'static str> {
        let now_secs = unix_now_secs()
            .ok_or("invite issuance requires the system clock after the Unix epoch")?;
        self.issue_invite_with_lifetime_at(raw_email, lifetime, now_secs)
    }

    /// Issuance pinned to `now_secs` seconds after the Unix epoch, so tests
    /// can assert the exact signed expiry instead of wall-clock bounds.
    fn issue_invite_with_lifetime_at(
        &self,
        raw_email: &str,
        lifetime: Duration,
        now_secs: u64,
    ) -> Result<String, &'static str> {
        let email = auth::normalize_email(raw_email).map_err(|_| "invalid invited email")?;
        let Self::Allowlist { enrollment_key, .. } = self else {
            return Err("invite issuance requires allowlist mode");
        };
        if !self.admits(&email) {
            return Err("email is not allowlisted");
        }
        // Sub-second lifetimes are refused outright: `as_secs()` truncates
        // them to zero and would silently mint an already-expired token.
        if lifetime < MIN_INVITE_LIFETIME || lifetime > INVITE_MAX_LIFETIME {
            return Err("invite lifetime must be at least one second and at most seven days");
        }
        let expires_at = now_secs
            .checked_add(lifetime.as_secs())
            .ok_or("invite expiry does not fit the token format")?;
        Ok(invite_token(enrollment_key, &email, expires_at))
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

/// Default and maximum invite lifetime. Invites are handed to one person and
/// verified by email within a day, so seven days covers slow operators while
/// keeping a leaked token useful only for a bounded window.
const INVITE_MAX_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Shortest accepted invite lifetime. Below one second, `Duration::as_secs`
/// truncates to zero and issuance would sign an already-expired token, so
/// sub-second requests are rejected explicitly instead.
const MIN_INVITE_LIFETIME: Duration = Duration::from_secs(1);

/// `expires_at` seconds (big-endian) followed by the HMAC tag.
const INVITE_TOKEN_LEN: usize = 8 + 32;

fn unix_now_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn invite_token(key: &[u8; 32], normalized_email: &str, expires_at_unix: u64) -> String {
    let mut token = [0u8; INVITE_TOKEN_LEN];
    token[..8].copy_from_slice(&expires_at_unix.to_be_bytes());
    token[8..].copy_from_slice(&invite_mac(key, normalized_email, expires_at_unix));
    STANDARD.encode(token)
}

fn invite_mac(key: &[u8; 32], normalized_email: &str, expires_at_unix: u64) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"zrotext-registration-invite-v2\0");
    mac.update(normalized_email.as_bytes());
    mac.update(&expires_at_unix.to_be_bytes());
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
    /// Caps how many requests may wait for a `hash_limit` permit at once.
    /// Each waiter holds a request-pool connection for up to
    /// `hash_permit_wait`, so beyond this cap a request is refused fast
    /// instead of idling a shared connection.
    pub hash_wait_limit: Arc<Semaphore>,
    /// How long a request that has already spent its abuse budget waits for a
    /// `hash_limit` permit before the server answers 503 `unavailable`.
    pub hash_permit_wait: Duration,
    pub mfa_cipher: Option<Arc<MfaCipher>>,
    pub mfa_enrollment_enabled: bool,
    /// Dormant owner routes for SMS line activation; off by default.
    pub sms_line_activation_enabled: bool,
}

impl preauth::OwnerAuthState for AuthHttpState {
    fn database_url(&self) -> &str {
        &self.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }
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
            hash_limit: Arc::new(Semaphore::new(HASH_PERMITS)),
            hash_wait_limit: Arc::new(Semaphore::new(HASH_WAIT_SLOTS)),
            hash_permit_wait: HASH_PERMIT_WAIT,
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
        .route("/seats", get(seats_http::list))
        .route("/seats/{user_id}", delete(seats_http::remove))
        .route("/seats/invitations", post(seats_http::create))
        .route(
            "/seats/invitations/{invitation_id}",
            delete(seats_http::cancel),
        )
        .route("/seats/accept", post(seats_http::accept))
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
        .route("/sms-lines", get(sms_lines::list))
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
    Conflict,
    SmsOwnerKeyActive,
    NotFound,
    TooManyRequests,
    Unavailable,
    /// Every password-hash permit stayed busy for the whole wait. This is
    /// server load, not a spent abuse budget, so it is 503 with Retry-After.
    Busy,
    Internal,
}

impl IntoResponse for AuthHttpError {
    fn into_response(self) -> Response {
        let retry_after = matches!(self, Self::Busy);
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::SmsOwnerKeyActive => (StatusCode::CONFLICT, "revoke_sms_owner_key_first"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable | Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let mut response = (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(ErrorBody { code }),
        )
            .into_response();
        if retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

impl AuthHttpState {
    /// Wait up to `hash_permit_wait` for one of the process's password-hash
    /// permits. Callers must spend their abuse budget first, so only admitted
    /// requests queue here. Every waiter holds a request-pool connection, so
    /// the queue itself is bounded: a request that cannot take one of the
    /// `hash_wait_limit` slots is refused immediately with the same `Busy`
    /// answer a full wait produces, and cannot pin further request
    /// connections.
    async fn hash_permit(&self) -> Result<OwnedSemaphorePermit, AuthHttpError> {
        // Held only while this call queues; dropped on success, timeout, or
        // a closed gate, so waiter slots always recycle.
        let _waiter = self
            .hash_wait_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthHttpError::Busy)?;
        let acquire = self.hash_limit.clone().acquire_owned();
        match tokio::time::timeout(self.hash_permit_wait, acquire).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(AuthHttpError::Busy),
        }
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
        AuthError::Conflict => AuthHttpError::Conflict,
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

/// The database-free first step of [`require_owner`]. Owner handlers call it
/// before taking a pooled connection, so a request without a session cookie is
/// rejected with the same 401 without competing for request capacity.
pub fn require_session_cookie(headers: &HeaderMap) -> Result<(), AuthHttpError> {
    cookie(headers, SESSION_COOKIE)
        .map(|_| ())
        .ok_or(AuthHttpError::Unauthorized)
}

/// Shared by account and enrollment HTTP handlers. `mutation=true` enforces
/// the exact Origin and CSRF header/cookie, in addition to the session cookie.
/// The caller must hold the owner role; an observer session fails closed with
/// the same 401 as an absent session so owner routes leak no role signal.
pub async fn require_owner(
    client: &Client,
    hasher: &TokenHasher,
    canonical_origin: &str,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<SessionPrincipal, AuthHttpError> {
    let principal = require_member(client, hasher, canonical_origin, headers, mutation).await?;
    if principal.role != Role::Owner {
        return Err(AuthHttpError::Unauthorized);
    }
    Ok(principal)
}

/// Any live membership role (owner or observer). Gates only self-service
/// authentication routes and read-only status scoped to the caller's own
/// account; every owner-authority route must use [`require_owner`] instead.
pub async fn require_member(
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

/// The CSRF cookie and `x-zrotext-csrf` header, present and equal. The hash
/// binding to the session is checked later by
/// [`SessionPrincipal::require_csrf_token`].
fn csrf_double_submit(headers: &HeaderMap) -> Result<(&str, &str), AuthHttpError> {
    let csrf_cookie = cookie(headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    if csrf_cookie.len() != csrf_header.len()
        || !bool::from(csrf_cookie.as_bytes().ct_eq(csrf_header.as_bytes()))
    {
        return Err(AuthHttpError::Forbidden);
    }
    Ok((csrf_cookie, csrf_header))
}

/// The database-free first step of [`require_owner_read`]. Content-bearing
/// owner GETs call it in place of [`require_session_cookie`], so a request
/// without a session cookie gets 401, and a cookie-only request without the
/// matching CSRF header gets 403, before either takes a pooled connection.
pub fn require_owner_read_headers(headers: &HeaderMap) -> Result<(), AuthHttpError> {
    require_session_cookie(headers)?;
    csrf_double_submit(headers).map(|_| ())
}

/// Owner session plus CSRF header proof for GETs that return account content
/// (messages, export, webhooks, review queues, devices). Browsers omit Origin
/// on same-origin GETs, so unlike a mutation this does not require it. The
/// custom header keeps these reads from relying only on same-origin response
/// isolation: a cross-origin page cannot set it without a CORS preflight, and
/// cannot learn the CSRF cookie value. Session metadata the page needs before
/// it reads the CSRF cookie (`/v1/auth/session`) stays cookie-only.
pub async fn require_owner_read(
    client: &Client,
    hasher: &TokenHasher,
    headers: &HeaderMap,
) -> Result<SessionPrincipal, AuthHttpError> {
    let principal = require_member_read(client, hasher, headers).await?;
    if principal.role != Role::Owner {
        return Err(AuthHttpError::Unauthorized);
    }
    Ok(principal)
}

/// Any live membership role for content-bearing GETs scoped to the caller's
/// own account: observer device status and the observer's own session
/// inventory. The CSRF proof is identical to [`require_owner_read`].
pub async fn require_member_read(
    client: &Client,
    hasher: &TokenHasher,
    headers: &HeaderMap,
) -> Result<SessionPrincipal, AuthHttpError> {
    let token = cookie(headers, SESSION_COOKIE).ok_or(AuthHttpError::Unauthorized)?;
    let (csrf_cookie, csrf_header) = csrf_double_submit(headers)?;
    let principal = auth::authenticate_session(client, hasher, token)
        .await
        .map_err(map_auth)?;
    principal
        .require_csrf_token(hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
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
    ApiJson(body): ApiJson<RegisterBody>,
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
    let _permit = state.hash_permit().await?;
    match auth::register(&mut client, &state.hasher, &body.email, &body.password).await {
        Ok(_) => {}
        // Avoid leaking whether this address is already registered. A pending
        // owner that still holds the address keeps its record, but its mailed
        // code stops working: that code was issued for the earlier
        // registrant's password, and this later registrant (or the recipient
        // of the mail) must not be able to verify the address with it.
        Err(AuthError::Database(ref error))
            if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) =>
        {
            drop(_permit);
            auth::cancel_pending_verification(&mut client, &body.email)
                .await
                .map_err(map_auth)?;
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
    ApiJson(body): ApiJson<ResendBody>,
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
    let _permit = state.hash_permit().await?;
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
    // Release the worker socket for the SMTP send: a slow mail server must
    // not hold one of the worker slots. The claim's five-minute lease keeps
    // the mail owned while no socket is held.
    drop(client);
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        state.dispatcher.dispatch(&mail.email, &mail.token),
    )
    .await;
    let delivered = matches!(&result, Ok(Ok(())));
    let client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
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
    // Release the worker socket across the SMTP send; the leased claim keeps
    // the code owned while no socket is held.
    drop(client);
    let delivered = tokio::time::timeout(
        Duration::from_secs(30),
        state
            .dispatcher
            .dispatch_password_reset(&mail.email, &mail.token),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
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
    // Release the worker socket across the SMTP send; the leased claim keeps
    // the notice owned while no socket is held.
    drop(client);
    let delivered = tokio::time::timeout(
        Duration::from_secs(30),
        state
            .dispatcher
            .dispatch_password_reset_notice(&notice.email),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let client = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let _ = account::ack_reset_notice(&client, &notice, delivered)
        .await
        .map_err(map_auth)?;
    Ok(delivered)
}

#[derive(Deserialize)]
struct VerifyBody {
    token: String,
    password: String,
}

/// A code verifies an address only together with the password that
/// registered it. Without that binding, a third party could register the
/// address with its own password and the recipient of the mail would
/// activate the foreign account by pasting the code. A missing password is a
/// malformed body and fails at the JSON extractor before any database work;
/// a wrong password, an unknown code and a consumed code share one response.
async fn verify_email(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<VerifyBody>,
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
    let _permit = state.hash_permit().await?;
    if auth::verify_email_with_password(&mut client, &state.hasher, &body.token, &body.password)
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
    ApiJson(body): ApiJson<LoginBody>,
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
    let _permit = state.hash_permit().await?;
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
    ApiJson(body): ApiJson<MfaLoginBody>,
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
    role: &'static str,
}

async fn session(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    require_session_cookie(&headers)?;
    let client = connect(&state.database_url).await?;
    let member = require_member(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let mut response = Json(SessionBody {
        account_id: member.tenant.account_id(),
        user_id: member.user_id,
        session_id: member.session_id,
        role: member.role.as_str(),
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
    require_session_cookie(&headers)?;
    let client = connect(&state.database_url).await?;
    let member = require_member(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let sessions = account::list_sessions(&client, &member)
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
    /// Defaults to false: signing out other sessions keeps the owner's API
    /// keys working, because integrations use them independently of any
    /// session. Pass `true` to revoke every unrevoked key as well.
    #[serde(default)]
    revoke_api_keys: bool,
}

async fn revoke_other_sessions(
    State(state): State<Arc<AuthHttpState>>,
    MemberMutation(member, _slot): MemberMutation,
    ApiJson(body): ApiJson<RevokeOtherSessionsBody>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::SessionsRevokeOthers,
        Some(&member.user_id.to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state.hash_permit().await?;
    match account::revoke_other_sessions(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &member,
        &body.current_password,
        body.code.as_deref(),
        body.revoke_api_keys,
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
    MemberMutation(member, _slot): MemberMutation,
    ApiJson(body): ApiJson<ChangePasswordBody>,
) -> Result<Response, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    let subject = member.user_id.to_string();
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
    let _permit = state.hash_permit().await?;
    match account::change_password(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &member,
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
    ApiJson(body): ApiJson<ResetRequestBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_origin(&headers, &state.canonical_origin)?;
    if !state.dispatcher.password_reset_ready() {
        return Err(AuthHttpError::Unavailable);
    }
    let mut client = connect(&state.database_url).await?;
    let subject = auth::normalize_email(&body.email).ok();
    let admitted = match subject.as_deref() {
        Some(subject) => admit_password_reset_request(&client, &state.hasher, subject).await,
        None => {
            abuse_limits::consume(&client, &state.hasher, Limit::PasswordResetRequest, None).await
        }
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

/// Window of the verified reset lane's per-address budget. It matches the
/// one-code-per-15-minutes throttle in [`account::request_password_reset`],
/// which is the real cadence for a known address.
const VERIFIED_RESET_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The subject the verified lane charges for a live owner address. Anyone can
/// spend the anonymous per-address counter by naming the address, so the lane
/// must not share it: this subject is distinct, and it rolls over with the
/// code throttle, so anonymous requests can hold back the owner's next code by
/// at most one throttle window instead of a day. The verified route ceiling
/// still bounds the lane as a whole.
fn verified_reset_subject(subject: &str, now: SystemTime) -> String {
    let window = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        / VERIFIED_RESET_WINDOW.as_secs();
    format!("{subject}\0verified\0{window}")
}

/// Spend the anonymous per-address budget first. When it refuses, a live
/// verified owner address is charged the verified lane's own subject rather
/// than the anonymous counter a stranger may have spent, and then the lane's
/// daily per-address cap (`Limit::PasswordResetVerifiedDaily`, 12 per day),
/// both before the reset transaction. An unknown address charges the refused
/// anonymous counter once more and reads its daily budget instead, and a
/// verified request refused by its window subject also reads the daily budget,
/// so every outcome runs the probe and two further counter statements before
/// the uniform 202. The unknown-address charge admits at most what the
/// anonymous lane would have.
async fn admit_password_reset_request(
    client: &Client,
    hasher: &TokenHasher,
    subject: &str,
) -> Result<bool, tokio_postgres::Error> {
    admit_reset_request_with(
        &ClientResetBudgets { client, hasher },
        subject,
        SystemTime::now(),
    )
    .await
}

/// The database statements a reset-request admission can run. Each method is
/// one statement, so tests can check that every outcome runs the same kinds
/// and number of statements whether or not the address exists.
trait ResetBudgets {
    /// Charge the anonymous per-address counter.
    async fn charge_anonymous(&self, subject: &str) -> Result<bool, tokio_postgres::Error>;
    /// Whether the address belongs to a verified owner of an enabled account.
    async fn owner_is_live(&self, subject: &str) -> Result<bool, tokio_postgres::Error>;
    /// Charge the verified lane's throttle-window subject.
    async fn charge_window(&self, window_subject: &str) -> Result<bool, tokio_postgres::Error>;
    /// Charge the verified lane's daily per-address cap.
    async fn charge_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error>;
    /// Read the daily per-address cap without charging it.
    async fn read_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error>;
}

struct ClientResetBudgets<'a> {
    client: &'a Client,
    hasher: &'a TokenHasher,
}

impl ResetBudgets for ClientResetBudgets<'_> {
    async fn charge_anonymous(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        let limit = Limit::PasswordResetRequest;
        abuse_limits::consume(self.client, self.hasher, limit, Some(subject)).await
    }

    async fn owner_is_live(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        Ok(self
            .client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE m.role='owner' AND u.email=$1 AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL)",
                &[&subject],
            )
            .await?
            .get::<_, bool>(0))
    }

    async fn charge_window(&self, window_subject: &str) -> Result<bool, tokio_postgres::Error> {
        let limit = Limit::PasswordResetRequest;
        abuse_limits::consume_verified(self.client, self.hasher, limit, window_subject).await
    }

    async fn charge_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        let limit = Limit::PasswordResetVerifiedDaily;
        abuse_limits::consume_verified(self.client, self.hasher, limit, subject).await
    }

    async fn read_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        // The daily cap is only ever charged in the verified lane, so read
        // that lane's counter row.
        let limit = Limit::PasswordResetVerifiedDaily;
        let lane = abuse_limits::Lane::Verified;
        abuse_limits::subject_budget_open(self.client, self.hasher, limit, subject, lane).await
    }
}

async fn admit_reset_request_with(
    budgets: &impl ResetBudgets,
    subject: &str,
    now: SystemTime,
) -> Result<bool, tokio_postgres::Error> {
    if budgets.charge_anonymous(subject).await? {
        return Ok(true);
    }
    if budgets.owner_is_live(subject).await? {
        if budgets
            .charge_window(&verified_reset_subject(subject, now))
            .await?
        {
            // Charged only after the window subject admits, so requests the
            // window already refuses do not spend the owner's daily cap.
            return budgets.charge_daily(subject).await;
        }
        budgets.read_daily(subject).await?;
        Ok(false)
    } else {
        let admitted = budgets.charge_anonymous(subject).await?;
        budgets.read_daily(subject).await?;
        Ok(admitted)
    }
}

#[derive(Deserialize)]
struct ResetConfirmBody {
    token: String,
    new_password: String,
}

async fn confirm_password_reset(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ResetConfirmBody>,
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
    let _permit = state.hash_permit().await?;
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
    require_session_cookie(&headers)?;
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

/// Keeps disabled MFA enrollment a 404 (and a missing cipher a 503) ahead of
/// owner authentication, as before authentication moved ahead of the body.
struct MfaEnrollmentGate;

impl axum::extract::FromRequestParts<Arc<AuthHttpState>> for MfaEnrollmentGate {
    type Rejection = AuthHttpError;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &Arc<AuthHttpState>,
    ) -> Result<Self, AuthHttpError> {
        if !state.mfa_enrollment_enabled {
            return Err(AuthHttpError::NotFound);
        }
        state
            .mfa_cipher
            .as_ref()
            .ok_or(AuthHttpError::Unavailable)?;
        Ok(Self)
    }
}

async fn begin_mfa_enrollment(
    State(state): State<Arc<AuthHttpState>>,
    _gate: MfaEnrollmentGate,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<MfaEnrollBody>,
) -> Result<Response, AuthHttpError> {
    if !state.mfa_enrollment_enabled {
        return Err(AuthHttpError::NotFound);
    }
    let cipher = state
        .mfa_cipher
        .as_ref()
        .ok_or(AuthHttpError::Unavailable)?;
    let mut client = connect(&state.database_url).await?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let _permit = state.hash_permit().await?;
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
    _gate: MfaEnrollmentGate,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<MfaCodeBody>,
) -> Result<Response, AuthHttpError> {
    if !state.mfa_enrollment_enabled {
        return Err(AuthHttpError::NotFound);
    }
    let cipher = state
        .mfa_cipher
        .as_ref()
        .ok_or(AuthHttpError::Unavailable)?;
    let mut client = connect(&state.database_url).await?;
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
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<MfaDisableBody>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let _permit = state.hash_permit().await?;
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
    require_session_cookie(&headers)?;
    let client = connect(&state.database_url).await?;
    let member = require_member(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    auth::revoke_session(&client, &member, member.session_id)
        .await
        .map_err(map_auth)?;
    cleared_session_response()
}

#[derive(Deserialize)]
struct CreateKeyBody {
    scopes: Vec<String>,
    bound_device_id: Option<Uuid>,
    /// Omitted: the 365-day default. `null`: the discouraged never-expire
    /// opt-in. Integer: that many days.
    #[serde(default)]
    lifetime_days: ApiKeyLifetime,
    current_password: String,
    code: Option<String>,
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
    last_used_at_ms: Option<i64>,
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
    require_session_cookie(&headers)?;
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
                    last_used_at_ms: key.last_used_at_ms,
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
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<CreateKeyBody>,
) -> Result<Response, AuthHttpError> {
    let scopes = body
        .scopes
        .iter()
        .map(|name| parse_scope(name).ok_or(AuthHttpError::BadRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let mut client = connect(&state.database_url).await?;
    // Charge the account, not its session or live key count: logging in again
    // and revoking issued keys must not reset the database growth budget.
    // The same 20-per-day budget is spent before the password is hashed, so
    // it also bounds password guesses made through this route more tightly
    // than the password-change budget would.
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
    let _permit = state.hash_permit().await?;
    let key = match account::create_api_key_with_proof(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        &body.current_password,
        body.code.as_deref(),
        account::ApiKeyRequest {
            scopes: &scopes,
            bound_device_id: body.bound_device_id,
            lifetime: body.lifetime_days,
        },
    )
    .await
    {
        Ok(key) => key,
        Err(AuthError::InvalidCredentials) => return Err(AuthHttpError::BadRequest),
        Err(error) => return Err(map_auth(error)),
    };
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
    require_session_cookie(&headers)?;
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
