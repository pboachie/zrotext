// SPDX-License-Identifier: AGPL-3.0-only
//! Browser-facing account routes. All cookie-authenticated writes require an
//! exact, configured HTTPS Origin and the double-submit CSRF token.

use crate::auth::{
    self, AuthError, Scope, SessionPrincipal, TokenHasher,
    abuse_limits::{self, Limit},
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
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use uuid::Uuid;

const SESSION_COOKIE: &str = "__Host-zrotext_session";
const CSRF_COOKIE: &str = "__Host-zrotext_csrf";
const CSRF_HEADER: &str = "x-zrotext-csrf";

/// A deployment supplies a reviewed mail transport here. The default server
/// deliberately keeps registration closed until that transport is configured.
/// Implementations must not log the token or place it in a URL.
pub trait VerificationDispatcher: Send + Sync {
    fn ready(&self) -> bool;
    fn dispatch<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>>;
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
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async { Err(()) })
    }
}

/// TLS-only SMTP delivery. Configuration is loaded by the runtime from a
/// secret store or environment; values are never included in errors or logs.
pub struct SmtpVerificationDispatcher {
    from: lettre::message::Mailbox,
    reply_to: Option<lettre::message::Mailbox>,
    transport: AsyncSmtpTransport<Tokio1Executor>,
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
}

impl VerificationDispatcher for SmtpVerificationDispatcher {
    fn ready(&self) -> bool {
        true
    }

    fn dispatch<'a>(
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
                .subject("Verify your ZROtext email")
                .body(format!(
                    "Your ZROtext email verification code is:\n\n{token}\n\nEnter this code in the ZROtext verification form. It expires in 24 hours.\n"
                ))
                .map_err(|_| ())?;
            self.transport.send(message).await.map_err(|_| ())?;
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct AuthHttpState {
    pub database_url: String,
    pub hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    pub dispatcher: Arc<dyn VerificationDispatcher>,
    pub hash_limit: Arc<Semaphore>,
    pub mfa_cipher: Option<Arc<MfaCipher>>,
    pub mfa_enrollment_enabled: bool,
}

impl AuthHttpState {
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        canonical_origin: String,
        dispatcher: Arc<dyn VerificationDispatcher>,
    ) -> Result<Self, &'static str> {
        if !valid_canonical_origin(&canonical_origin) {
            return Err("AUTH_ORIGIN must be a canonical HTTPS origin");
        }
        Ok(Self {
            database_url,
            hasher,
            canonical_origin,
            dispatcher,
            // Argon2id uses 64 MiB per operation. Limit concurrent hashes.
            hash_limit: Arc::new(Semaphore::new(2)),
            mfa_cipher: None,
            mfa_enrollment_enabled: false,
        })
    }

    pub fn with_mfa_cipher(mut self, cipher: Arc<MfaCipher>) -> Self {
        self.mfa_cipher = Some(cipher);
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
        .route("/mfa", get(mfa_status))
        .route("/mfa/enroll", post(begin_mfa_enrollment))
        .route("/mfa/confirm", post(confirm_mfa_enrollment))
        .route("/mfa/disable", post(disable_mfa))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/{key_id}", delete(revoke_api_key))
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
        AuthError::Database(_) => AuthHttpError::Unavailable,
        AuthError::Password => AuthHttpError::Internal,
        AuthError::Crypto => AuthHttpError::Unavailable,
        AuthError::RateLimited => AuthHttpError::TooManyRequests,
    }
}

async fn connect(database_url: &str) -> Result<Client, AuthHttpError> {
    let (client, connection) = crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    tokio::spawn(async move {
        // Connection errors contain deployment details; do not log them here.
        let _ = connection.await;
    });
    Ok(client)
}

fn valid_canonical_origin(origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && !host.contains('/')
        && !host.contains('?')
        && !host.contains('#')
        && !host.contains('@')
        && !host.chars().any(char::is_whitespace)
        && !host.ends_with(':')
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
    if !state.dispatcher.ready() {
        return Err(AuthHttpError::Unavailable);
    }
    let mut client = connect(&state.database_url).await?;
    let subject = auth::normalize_email(&body.email).ok();
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::Registration,
        subject.as_deref(),
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
    if !state.dispatcher.ready() {
        return Ok(false);
    }
    let (mut client, connection) = crate::runtime_db::connect_worker(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let Some(mail) = auth::claim_verification_mail(&mut client, &state.hasher)
        .await
        .map_err(map_auth)?
    else {
        return Ok(false);
    };
    let delivered = tokio::time::timeout(
        Duration::from_secs(30),
        state.dispatcher.dispatch(&mail.email, &mail.token),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let _ = auth::ack_verification_mail(&client, &mail, delivered)
        .await
        .map_err(map_auth)?;
    Ok(true)
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
    if !abuse_limits::consume(&client, &state.hasher, Limit::Login, subject.as_deref())
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
    let credentials = match auth::login(&client, &state.hasher, &body.email, &body.password).await {
        Ok(credentials) => credentials,
        Err(AuthError::MfaRequired {
            account_id,
            user_id,
        }) => {
            let challenge_token =
                mfa::begin_login_challenge(&client, &state.hasher, account_id, user_id)
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
    session_response(&credentials)
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
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::MfaChallenge,
        Some(&body.challenge_token),
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
    session_response(&credentials)
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
    let client = connect(&state.database_url).await?;
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
        &client,
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
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct CaptureVerification(Mutex<Option<String>>);

    impl VerificationDispatcher for CaptureVerification {
        fn ready(&self) -> bool {
            true
        }

        fn dispatch<'a>(
            &'a self,
            _email: &'a str,
            token: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
            *self.0.lock().unwrap() = Some(token.to_owned());
            Box::pin(async { Ok(()) })
        }
    }

    fn json_post(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn owner_post(uri: &str, body: serde_json::Value, cookies: &str, csrf: &str) -> Request<Body> {
        let mut request = json_post(uri, body);
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookies).unwrap());
        request
            .headers_mut()
            .insert(CSRF_HEADER, HeaderValue::from_str(csrf).unwrap());
        request
    }

    #[tokio::test]
    async fn mfa_enrollment_is_off_by_default() {
        let state = AuthHttpState::new(
            "postgres://unused".to_owned(),
            Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let app = router(state);
        for (path, body) in [
            ("/mfa/enroll", serde_json::json!({"password":"unused"})),
            ("/mfa/confirm", serde_json::json!({"code":"000000"})),
        ] {
            let response = app.clone().oneshot(json_post(path, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    fn key_list_request(
        cookie_header: Option<&str>,
        csrf: Option<&str>,
        uri: &str,
    ) -> Request<Body> {
        let mut request = Request::builder().uri(uri);
        if let Some(cookies) = cookie_header {
            request = request.header(header::COOKIE, cookies);
        }
        if let Some(csrf) = csrf {
            request = request.header(CSRF_HEADER, csrf);
        }
        request.body(Body::empty()).unwrap()
    }

    #[test]
    fn canonical_origin_and_cookie_parsing_are_strict() {
        assert!(valid_canonical_origin("https://zrotext.example"));
        assert!(!valid_canonical_origin("http://zrotext.example"));
        assert!(!valid_canonical_origin("https://zrotext.example/path"));
        assert!(!valid_canonical_origin("https://a@zrotext.example"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; __Host-zrotext_session=zts_abc"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE), Some("zts_abc"));
        assert_eq!(cookie(&headers, CSRF_COOKIE), None);
    }

    #[test]
    fn unauthenticated_writes_require_exact_origin() {
        let mut headers = HeaderMap::new();
        assert!(require_origin(&headers, "https://zrotext.example").is_err());
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(require_origin(&headers, "https://zrotext.example").is_err());
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://zrotext.example"),
        );
        assert!(require_origin(&headers, "https://zrotext.example").is_ok());
    }

    #[test]
    fn smtp_configuration_preserves_sender_identity_without_connecting() {
        let sender = SmtpVerificationDispatcher::new(
            "smtp.example.test",
            465,
            "user".to_owned(),
            "test-only-password".to_owned(),
            "notice@example.test",
            Some("ZROtext"),
            Some("support@example.test"),
        )
        .unwrap();
        assert_eq!(sender.from.name.as_deref(), Some("ZROtext"));
        assert_eq!(
            sender.reply_to.unwrap().email.to_string(),
            "support@example.test"
        );
        assert!(
            SmtpVerificationDispatcher::new(
                "smtp.example.test",
                587,
                "user".to_owned(),
                "test-only-password".to_owned(),
                "notice@example.test",
                Some("bad\nname"),
                None,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn registration_fails_closed_without_delivery_and_never_returns_token() {
        let state = AuthHttpState::new(
            "postgres://unused".to_owned(),
            Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"email":"owner@example.test","password":"correct horse 123"}"#,
            ))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("ztv_"));
    }

    #[tokio::test]
    async fn login_rejects_cross_origin_before_password_work() {
        let state = AuthHttpState::new(
            "postgres://unused".to_owned(),
            Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::ORIGIN, "https://evil.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"email":"owner@example.test","password":"correct horse 123"}"#,
            ))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn postgres_http_account_lifecycle_enforces_csrf_and_revocation() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_auth_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (test_client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/002_auth.sql"
            ))
            .await
            .unwrap();
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/005_verification_outbox.sql"
            ))
            .await
            .unwrap();
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"
            ))
            .await
            .unwrap();
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/013_owner_mfa.sql"
            ))
            .await
            .unwrap();
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
            ))
            .await
            .unwrap();
        test_client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"
            ))
            .await
            .unwrap();
        let capture = Arc::new(CaptureVerification(Mutex::new(None)));
        let state = AuthHttpState::new(
            url,
            Arc::new(TokenHasher::new(crate::test_keys::key(42)).unwrap()),
            "https://zrotext.example".to_owned(),
            capture.clone(),
        )
        .unwrap();
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(json_post(
                "/register",
                serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        for (email, password) in [
            ("unknown@example.test", "correct horse 123"),
            ("owner@example.test", "wrong password"),
            ("owner@example.test", "correct horse 123"),
        ] {
            let response = app
                .clone()
                .oneshot(json_post(
                    "/resend-verification",
                    serde_json::json!({"email":email,"password":password}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }
        assert!(dispatch_one_verification(&state).await.unwrap());
        let token = capture.0.lock().unwrap().take().unwrap();
        let response = app
            .clone()
            .oneshot(json_post(
                "/verify-email",
                serde_json::json!({"token":token}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        let cookie_header = cookies.join("; ");
        let csrf = cookies[1].split_once('=').unwrap().1;
        let session_request = Request::builder()
            .uri("/session")
            .header(header::COOKIE, &cookie_header)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(session_request).await.unwrap().status(),
            StatusCode::OK
        );
        let body = serde_json::json!({"scopes":["messages:read"],"lifetime_days":30});
        let mut request = json_post("/api-keys", body.clone());
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_header).unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut request = json_post("/api-keys", body);
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_header).unwrap(),
        );
        request
            .headers_mut()
            .insert(CSRF_HEADER, HeaderValue::from_str(csrf).unwrap());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let key: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key_id = key["id"].as_str().unwrap();
        assert!(key["token"].as_str().unwrap().starts_with("ztk_"));
        let response = app
            .clone()
            .oneshot(key_list_request(None, None, "/api-keys"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let response = app
            .clone()
            .oneshot(key_list_request(Some(&cookie_header), None, "/api-keys"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some("wrong"),
                "/api-keys",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                "/api-keys",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let listed = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&listed).contains("ztk_"));
        assert!(!String::from_utf8_lossy(&listed).contains("token_hash"));
        let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
        assert_eq!(listed["keys"][0]["id"], key["id"]);
        assert_eq!(listed["keys"][0]["status"], "active");
        assert_eq!(
            listed["keys"][0]["scopes"],
            serde_json::json!(["messages:read"])
        );
        assert!(listed["keys"][0].get("token").is_none());
        test_client
            .execute(
                "UPDATE api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
                &[&Uuid::parse_str(key_id).unwrap()],
            )
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                "/api-keys",
            ))
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(listed["keys"][0]["status"], "expired");
        let (mut outsider, connection) = tokio_postgres::connect(&state.database_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let foreign_password = Uuid::new_v4().to_string();
        let foreign = auth::register(
            &mut outsider,
            &state.hasher,
            "foreign@example.test",
            &foreign_password,
        )
        .await
        .unwrap();
        auth::verify_email(&mut outsider, &state.hasher, &foreign.verification_token)
            .await
            .unwrap();
        let foreign_session = auth::login(
            &outsider,
            &state.hasher,
            "foreign@example.test",
            &foreign_password,
        )
        .await
        .unwrap();
        let foreign_owner =
            auth::authenticate_session(&outsider, &state.hasher, &foreign_session.token)
                .await
                .unwrap();
        let foreign_key = auth::create_api_key(
            &outsider,
            &state.hasher,
            &foreign_owner,
            &[Scope::MessagesRead],
            None,
            Some(30),
        )
        .await
        .unwrap();
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                "/api-keys",
            ))
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
        assert_ne!(listed["keys"][0]["id"], foreign_key.id.to_string());
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                &format!("/api-keys?before={}", foreign_key.id),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api-keys/{key_id}"))
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::COOKIE, &cookie_header)
            .header(CSRF_HEADER, csrf)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                "/api-keys",
            ))
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(listed["keys"][0]["status"], "revoked");
        let owner = auth::authenticate_session(
            &test_client,
            &state.hasher,
            cookies[0].split_once('=').unwrap().1,
        )
        .await
        .unwrap();
        for i in 0..52u8 {
            let test_hash = rand::random::<[u8; 32]>();
            test_client
                .execute(
                    "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,$6)",
                    &[
                        &Uuid::new_v4(),
                        &owner.tenant.account_id(),
                        &owner.user_id,
                        &format!("paging{i:06}"),
                        &&test_hash[..],
                        &vec!["messages:read".to_owned()],
                    ],
                )
                .await
                .unwrap();
        }
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                "/api-keys",
            ))
            .await
            .unwrap();
        let first: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 32 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["keys"].as_array().unwrap().len(), 50);
        let cursor = first["next_cursor"].as_str().unwrap();
        let response = app
            .clone()
            .oneshot(key_list_request(
                Some(&cookie_header),
                Some(csrf),
                &format!("/api-keys?before={cursor}"),
            ))
            .await
            .unwrap();
        let second: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second["keys"].as_array().unwrap().len(), 3);
        assert_eq!(second["next_cursor"], serde_json::Value::Null);
        assert!(!first["keys"].as_array().unwrap().iter().any(|key| {
            second["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|other| other["id"] == key["id"])
        }));
        let request = Request::builder()
            .method("POST")
            .uri("/logout")
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::COOKIE, &cookie_header)
            .header(CSRF_HEADER, csrf)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        let request = Request::builder()
            .uri("/session")
            .header(header::COOKIE, &cookie_header)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        for _ in 0..11 {
            assert!(
                auth::abuse_limits::consume(
                    &test_client,
                    &state.hasher,
                    Limit::Login,
                    Some("owner@example.test"),
                )
                .await
                .unwrap()
            );
        }
        let response = router(state)
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"OWNER@example.test","password":"correct horse 123"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn api_key_issuance_budget_survives_concurrency_revocation_and_new_sessions() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("key_budget_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(vec![42; 32]).unwrap());
        let password = format!("synthetic-{}", Uuid::new_v4());
        let mut sessions = Vec::new();
        for email in ["owner@example.test", "other@example.test"] {
            let signup = auth::register(&mut client, &hasher, email, &password)
                .await
                .unwrap();
            auth::verify_email(&mut client, &hasher, &signup.verification_token)
                .await
                .unwrap();
            sessions.push(
                auth::login(&client, &hasher, email, &password)
                    .await
                    .unwrap(),
            );
        }
        let state = AuthHttpState::new(
            url,
            hasher.clone(),
            "https://zrotext.example".into(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let apps = [router(state.clone()), router(state)];
        let request_for = |session: &auth::SessionCredentials| {
            owner_post(
                "/api-keys",
                serde_json::json!({"scopes":["messages:read"]}),
                &format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    session.token, session.csrf_token
                ),
                &session.csrf_token,
            )
        };
        let mut tasks = Vec::new();
        for index in 0..32 {
            let app = apps[index % 2].clone();
            let request = request_for(&sessions[0]);
            tasks.push(tokio::spawn(async move {
                app.oneshot(request).await.unwrap().status()
            }));
        }
        let mut created = 0;
        for task in tasks {
            match task.await.unwrap() {
                StatusCode::CREATED => created += 1,
                StatusCode::TOO_MANY_REQUESTS => {}
                status => panic!("unexpected status {status}"),
            }
        }
        assert_eq!(created, 20);
        let count: i64 = client
            .query_one("SELECT count(*) FROM api_keys", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 20);
        client
            .execute("UPDATE api_keys SET revoked_at=now()", &[])
            .await
            .unwrap();
        let fresh = auth::login(&client, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        assert_eq!(
            apps[0]
                .clone()
                .oneshot(request_for(&fresh))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            apps[1]
                .clone()
                .oneshot(request_for(&sessions[1]))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        // Cleanup must retain a daily subject budget beyond the generic two-minute window.
        client
            .execute(
                "UPDATE auth_abuse_counters SET updated_at=now()-interval '3 minutes'",
                &[],
            )
            .await
            .unwrap();
        abuse_limits::prune(&client).await.unwrap();
        assert_eq!(
            apps[0]
                .clone()
                .oneshot(request_for(&fresh))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        client.batch_execute("DROP FUNCTION auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)").await.unwrap();
        assert_eq!(
            apps[1]
                .clone()
                .oneshot(request_for(&sessions[1]))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn valid_verification_survives_anonymous_invalid_code_exhaustion() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_verify_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let test_password = Uuid::new_v4().to_string();
        let signup = auth::register(
            &mut client,
            &hasher,
            "verify-cap@example.test",
            &test_password,
        )
        .await
        .unwrap();
        let state = AuthHttpState::new(
            url.clone(),
            hasher,
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let a = router(state.clone());
        let b = router(state.clone());
        for _ in 0..120 {
            let response = a
                .clone()
                .oneshot(json_post(
                    "/verify-email",
                    serde_json::json!({"token":"invalid"}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let mut wrong_code = signup.verification_token.clone();
        let last = wrong_code.pop().unwrap();
        wrong_code.push(if last == 'A' { 'Q' } else { 'A' });
        assert!(
            !auth::verification_token_is_live(&client, &state.hasher, &wrong_code)
                .await
                .unwrap()
        );
        let invalid = b
            .clone()
            .oneshot(json_post(
                "/verify-email",
                serde_json::json!({"token":wrong_code}),
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::TOO_MANY_REQUESTS);
        let mut wrong_origin = json_post(
            "/verify-email",
            serde_json::json!({"token":signup.verification_token}),
        );
        wrong_origin.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            b.clone().oneshot(wrong_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let valid = b
            .clone()
            .oneshot(json_post(
                "/verify-email",
                serde_json::json!({"token":signup.verification_token}),
            ))
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::NO_CONTENT);
        let replay = a
            .oneshot(json_post(
                "/verify-email",
                serde_json::json!({"token":signup.verification_token}),
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::TOO_MANY_REQUESTS);
        let row = client
            .query_one(
                "SELECT u.email_verified_at IS NOT NULL,
                        (SELECT count(*) FROM email_verifications v
                         WHERE v.user_id=u.id AND v.used_at IS NOT NULL)
                 FROM users u WHERE u.id=$1",
                &[&signup.user_id],
            )
            .await
            .unwrap();
        assert!(row.get::<_, bool>(0));
        assert_eq!(row.get::<_, i64>(1), 1);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn postgres_http_mfa_never_sets_session_before_factor_and_limits_replay() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_mfa_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let password = Uuid::new_v4().to_string();
        let wrong_password = Uuid::new_v4().to_string();
        let signup = auth::register(&mut client, &hasher, "mfa@example.test", &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut client, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let key = rand::random::<[u8; 32]>().to_vec();
        let state = AuthHttpState::new(
            url.clone(),
            hasher.clone(),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap()
        .with_mfa_cipher(Arc::new(MfaCipher::new(key).unwrap()))
        .with_mfa_enrollment_enabled();
        let app = router(state);
        let response = app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        let cookie_header = cookies.join("; ");
        let csrf = cookies[1].split_once('=').unwrap().1;
        let response = app
            .clone()
            .oneshot(json_post(
                "/mfa/enroll",
                serde_json::json!({"password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(owner_post(
                "/mfa/enroll",
                serde_json::json!({"password":wrong_password.as_str()}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(owner_post(
                "/mfa/enroll",
                serde_json::json!({"password":password.as_str()}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let secret =
            totp_rs::Secret::try_from_base32(body["secret_base32"].as_str().unwrap()).unwrap();
        let code = totp_rs::Builder::new()
            .with_secret(secret)
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let response = app
            .clone()
            .oneshot(owner_post(
                "/mfa/confirm",
                serde_json::json!({"code":code}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let recovery = body["recovery_codes"][0].as_str().unwrap();
        let recovery_next = body["recovery_codes"][1].as_str().unwrap().to_owned();
        let recovery_disable = body["recovery_codes"][2].as_str().unwrap().to_owned();
        let status_request = Request::builder()
            .method("GET")
            .uri("/mfa")
            .header(header::COOKIE, &cookie_header)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(status_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let response = app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let challenge = body["challenge_token"].as_str().unwrap();
        let count: i64 = client
            .query_one(
                "SELECT count(*) FROM sessions WHERE account_id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        let response = app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":challenge,"code":recovery}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        let response = app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":challenge,"code":recovery}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let count: i64 = client
            .query_one(
                "SELECT count(*) FROM sessions WHERE account_id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 2);
        let response = app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let second_challenge = body["challenge_token"].as_str().unwrap();
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(json_post(
                    "/login/mfa",
                    serde_json::json!({"challenge_token":second_challenge,"code":"invalid"}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":second_challenge,"code":recovery_next}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let fresh_challenge = body["challenge_token"].as_str().unwrap();
        let response = app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":fresh_challenge,"code":recovery_next}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = app
            .clone()
            .oneshot(owner_post(
                "/mfa/disable",
                serde_json::json!({"password":password.as_str(),"code":recovery_disable}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        client
            .execute(
                "UPDATE owner_mfa SET failed_window_started_at=now()-interval '16 minutes' WHERE account_id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap();
        let no_key_app = router(
            AuthHttpState::new(
                url,
                hasher,
                "https://zrotext.example".to_owned(),
                Arc::new(DisabledVerificationDispatcher),
            )
            .unwrap(),
        );
        let response = no_key_app
            .clone()
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let challenge = body["challenge_token"].as_str().unwrap();
        let response = no_key_app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":challenge,"code":recovery_next}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        let cookie_header = cookies.join("; ");
        let csrf = cookies[1].split_once('=').unwrap().1;
        let response = no_key_app
            .clone()
            .oneshot(owner_post(
                "/mfa/disable",
                serde_json::json!({"password":password.as_str(),"code":"zrc_AAAAAAAAAAAAAAAAAAAAAA"}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let failures: i32 = client
            .query_one(
                "SELECT failed_attempts FROM owner_mfa WHERE account_id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(failures, 1);
        let response = no_key_app
            .clone()
            .oneshot(owner_post(
                "/mfa/disable",
                serde_json::json!({"password":password.as_str(),"code":recovery_disable}),
                &cookie_header,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = no_key_app
            .oneshot(json_post(
                "/login",
                serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
