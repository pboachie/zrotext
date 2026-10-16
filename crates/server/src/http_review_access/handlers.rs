// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    cookies::{self, Cookies},
    dto::*,
};
use crate::{
    api_json::ApiJson,
    auth::review_access::{
        AccessError,
        current::{Credentials, LocatorPhase},
        frames::{Browser, LocatorSelector, Preparation},
        roots::{Completion, Material, RootPreparation},
        storage::{self, ReviewAccess},
    },
};
use axum::{
    Json, Router,
    extract::Request,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio_postgres::Row;
use uuid::Uuid;

type Answer = std::result::Result<Response, Failure>;
pub(super) struct Failure(AccessError);
impl From<AccessError> for Failure {
    fn from(value: AccessError) -> Self {
        Self(value)
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, code) = match self.0 {
            AccessError::Rejected => (StatusCode::BAD_REQUEST, "invalid_request"),
            AccessError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AccessError::BusyUnknown => (StatusCode::CONFLICT, "busy_unknown"),
            AccessError::Unavailable => (StatusCode::CONFLICT, "unavailable"),
            AccessError::Database(_) => (StatusCode::SERVICE_UNAVAILABLE, "busy_unknown"),
        };
        (status, Json(serde_json::json!({"code":code}))).into_response()
    }
}
pub(super) fn router(access: Arc<ReviewAccess>) -> Router {
    Router::new()
        .route(
            "/review/root",
            get(|| async {
                static_response(
                    "text/html; charset=utf-8",
                    include_str!("../../../../web/review/root.html"),
                )
            }),
        )
        .route(
            "/review/root.mjs",
            get(|| async {
                static_response(
                    "text/javascript; charset=utf-8",
                    include_str!("../../../../web/review/root.mjs"),
                )
            }),
        )
        .route(
            "/review/root-material.mjs",
            get(|| async {
                static_response(
                    "text/javascript; charset=utf-8",
                    include_str!("../../../../web/review/root-material.mjs"),
                )
            }),
        )
        .route(
            "/review/single-flight.mjs",
            get(|| async {
                static_response(
                    "text/javascript; charset=utf-8",
                    include_str!("../../../../web/review/single-flight.mjs"),
                )
            }),
        )
        .route(
            "/review/root.css",
            get(|| async {
                static_response(
                    "text/css; charset=utf-8",
                    include_str!("../../../../web/review/root.css"),
                )
            }),
        )
        .route("/v1/review/browser/prepare", post(browser_prepare))
        .route("/v1/review/browser/confirm", post(browser_confirm))
        .route("/v1/review/preparations", post(prepare))
        .route("/v1/review/preparations/confirm", post(confirm))
        .route("/v1/review/preparations/cancel", post(cancel))
        .route("/v1/review/preparations/status", post(preparation_status))
        .route("/v1/review/login/bootstrap", post(login_bootstrap))
        .route("/v1/review/login/resume", post(login_resume))
        .route("/v1/review/login/status", post(login_status))
        .route("/v1/review/workspace/status", post(workspace_status))
        .route("/v1/review/session/context", post(session_context))
        .route("/v1/review/session/confirm", post(session_confirm))
        .route("/v1/review/locator/context", post(locator_context))
        .route(
            "/v1/review/locator/retention-confirm",
            post(locator_confirm),
        )
        .route("/v1/review/locator/retention-status", post(locator_status))
        .route("/v1/review/root/issue", post(root_issue))
        .route("/v1/review/root/issue-status", post(root_issue_status))
        .route("/v1/review/root/complete", post(root_complete))
        .route("/v1/review/root/result", post(root_result))
        .route("/v1/review/root/custody-export", post(root_export))
        .layer(DefaultBodyLimit::max(16_384))
        .layer(middleware::from_fn_with_state(
            access.clone(),
            headers_first,
        ))
        .layer(middleware::from_fn(response_headers))
        .with_state(access)
}
fn static_response(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}
async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
async fn headers_first(
    State(access): State<Arc<ReviewAccess>>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path().starts_with("/v1/review/")
        && let Err(error) = cookies::require_origin(request.headers(), &access.scope)
            .and_then(|_| Cookies::parse(request.headers()).map(|_| ()))
    {
        return Failure(error).into_response();
    }
    let slot = if request.uri().path().starts_with("/v1/review/root/")
        || request.uri().path().starts_with("/v1/review/session/")
        || request.uri().path().starts_with("/v1/review/locator/")
    {
        let headers = request.headers().clone();
        let checked = async {
            let cookies = Cookies::parse(&headers)?;
            let credentials = active_credentials(&access, &cookies, &headers)?;
            let (browser, _) = browser_now(&access, &cookies).await?;
            // All DB locks/clients leave this observational check before the
            // body extractor runs. Business handlers reacquire real witnesses.
            let context = access
                .context(&browser, &credentials, Uuid::new_v4())
                .await?;
            crate::http_auth::preauth::AccountSlot::try_acquire(context.account)
                .ok_or(AccessError::RateLimited)
        }
        .await;
        match checked {
            Ok(slot) => Some(slot),
            Err(error) => return Failure(error).into_response(),
        }
    } else {
        None
    };
    let response = next.run(request).await;
    drop(slot);
    response
}
async fn browser_now(
    access: &ReviewAccess,
    cookies: &Cookies,
) -> std::result::Result<(Browser, u64), AccessError> {
    let client = access.connect().await?;
    let now = storage::clock(&*client, 0).await?;
    Ok((cookies.browser(&access.key, &access.scope, now)?, now))
}
fn state(raw: &str) -> std::result::Result<OperationState, AccessError> {
    match raw {
        "prepared" => Ok(OperationState::Prepared),
        "confirmed" => Ok(OperationState::Confirmed),
        "checking" => Ok(OperationState::BusyUnknown),
        "committed" => Ok(OperationState::CommittedKnown),
        "cancelled_no_effect" => Ok(OperationState::CancelledNoEffect),
        "rejected_no_effect" => Ok(OperationState::RejectedNoEffect),
        _ => Err(AccessError::Unavailable),
    }
}
fn operation(prep: &Preparation, state: OperationState, now: u64) -> OperationResponse {
    OperationResponse {
        version: Version1,
        request_id: prep.request,
        preparation_id: prep.id,
        generation: Decimal(prep.generation),
        state,
        create_deadline_ms: Decimal(prep.create_deadline),
        delivery_deadline_ms: Decimal(prep.delivery_deadline),
        server_now_ms: Decimal(now),
    }
}
fn row_operation(
    row: &Row,
    now: u64,
) -> std::result::Result<Option<OperationResponse>, AccessError> {
    if row.get::<_, String>("state") == "empty" {
        return Ok(None);
    }
    Ok(Some(OperationResponse {
        version: Version1,
        request_id: row.get("request_id"),
        preparation_id: row.get("preparation_id"),
        generation: Decimal(row.get::<_, i64>("generation") as u64),
        state: state(&row.get::<_, String>("state"))?,
        create_deadline_ms: Decimal(row.get::<_, i64>("create_deadline_ms") as u64),
        delivery_deadline_ms: Decimal(row.get::<_, i64>("delivery_deadline_ms") as u64),
        server_now_ms: Decimal(now),
    }))
}
async fn browser_response(
    access: &ReviewAccess,
    browser: &Browser,
    request: Uuid,
    now: u64,
) -> std::result::Result<BrowserContext, AccessError> {
    let row = access.browser_view(browser).await?;
    Ok(BrowserContext {
        version: Version1,
        request_id: request,
        browser_context_commitment_b64: STANDARD.encode(browser.digest(&access.key, &access.scope)),
        issued_ms: Decimal(browser.issued),
        expires_ms: Decimal(browser.expires),
        server_now_ms: Decimal(now),
        outstanding: if row.get::<_, bool>("delivered") {
            None
        } else {
            row_operation(&row, now)?
        },
        owner_session_issued: row.get::<_, i64>("active_owner_generation") > 0,
    })
}
fn browser_csrf(
    headers: &HeaderMap,
    access: &ReviewAccess,
    browser: &Browser,
) -> std::result::Result<(), AccessError> {
    let expected = STANDARD.encode(browser.digest(&access.key, &access.scope));
    let supplied = cookies::one_header(headers, cookies::PREPARED_HEADER)?;
    if supplied.len() != expected.len()
        || !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
    {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
async fn browser_prepare(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RequestIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    if cookies.get(cookies::BROWSER).is_none() {
        cookies.no_staging()?;
        if [
            cookies::BROKER,
            cookies::OWNER,
            cookies::BROKER_CSRF,
            cookies::OWNER_CSRF,
        ]
        .iter()
        .any(|name| cookies.get(name).is_some())
        {
            // Lost browser continuity with retained credentials is unavailable,
            // never evidence that a fresh independent workspace is intended.
            return Err(AccessError::Unavailable.into());
        }
    }
    let (browser, now, fresh) = access
        .browser_prepare(cookies.get(cookies::BROWSER))
        .await?;
    let body = browser_response(&access, &browser, body.request_id.0, now).await?;
    let mut response = Json(body).into_response();
    if fresh {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookies::set(
                cookies::BROWSER,
                &browser.seal(&access.key, &access.scope),
                now,
                browser.expires,
                true,
            )?,
        );
    }
    Ok(response)
}
async fn browser_confirm(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<BrowserConfirmRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    browser_csrf(&headers, &access, &browser)?;
    if body.browser_context_commitment_b64
        != STANDARD.encode(browser.digest(&access.key, &access.scope))
    {
        return Err(AccessError::Rejected.into());
    }
    let now = access.browser_confirm(&browser).await?;
    Ok(Json(browser_response(&access, &browser, body.request_id.0, now).await?).into_response())
}
async fn prepare(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PrepareRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    cookies.no_staging()?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    browser_csrf(&headers, &access, &browser)?;
    let prep = match body.operation {
        PrepareOperation::InitialBootstrap { alias } => {
            access
                .prepare_login(&browser, body.request_id.0, alias, false)
                .await?
        }
        PrepareOperation::BrokerForResume { alias } => {
            access
                .prepare_login(&browser, body.request_id.0, alias, true)
                .await?
        }
        PrepareOperation::RootIssue {
            root_pin_b64,
            independently_compared_fingerprint_b64,
            encrypted_backup_b64,
            public_card_b64,
        } => {
            let c = active_credentials(&access, &cookies, &headers)?;
            let material = material(
                &root_pin_b64,
                &independently_compared_fingerprint_b64,
                &encrypted_backup_b64,
                &public_card_b64,
            )?;
            access
                .prepare_root(
                    &browser,
                    &c,
                    body.request_id.0,
                    RootPreparation::Issue(&material),
                )
                .await?
        }
        PrepareOperation::RootComplete {
            root_challenge_id,
            reauth_challenge_id,
            reauth_nonce_b64,
            unsigned_enrollment_b64,
            enrollment_signature_b64,
            custody_signature_b64,
            independently_compared_fingerprint_b64,
            encrypted_backup_b64,
            public_card_b64,
        } => {
            let c = active_credentials(&access, &cookies, &headers)?;
            let completion = completion(
                &access,
                &browser,
                &c,
                CompletionFields {
                    root: root_challenge_id.0,
                    reauth: reauth_challenge_id.0,
                    nonce: &reauth_nonce_b64,
                    unsigned: &unsigned_enrollment_b64,
                    enrollment: &enrollment_signature_b64,
                    custody: &custody_signature_b64,
                    compared: &independently_compared_fingerprint_b64,
                    backup: &encrypted_backup_b64,
                    card: &public_card_b64,
                },
            )
            .await?;
            access
                .prepare_root(
                    &browser,
                    &c,
                    body.request_id.0,
                    RootPreparation::Complete(&completion),
                )
                .await?
        }
    };
    let client = access.connect().await?;
    let now = storage::clock(&*client, prep.prepared).await?;
    drop(client);
    let mut response = Json(operation(&prep, OperationState::Prepared, now)).into_response();
    for (name, value, http_only) in [
        (
            format!("__Host-ztrw-p-{}", prep.id.simple()),
            prep.seal(&access.key, &access.scope),
            true,
        ),
        (
            format!("__Host-ztrw-c-{}", prep.id.simple()),
            URL_SAFE_NO_PAD.encode(prep.candidates.csrf.as_ref()),
            false,
        ),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookies::set(&name, &value, now, prep.delivery_deadline, http_only)?,
        );
    }
    if prep.operation == crate::auth::review_access::frames::Operation::InitialBootstrap {
        let selector =
            LocatorSelector::from_initial(&prep, &browser, &access.key, &access.scope, now)?;
        response.headers_mut().append(
            header::SET_COOKIE,
            cookies::set(
                &format!("__Host-ztrw-l-{}", prep.id.simple()),
                &selector.seal(&access.key, &access.scope, now)?,
                now,
                browser.expires,
                true,
            )?,
        );
    }
    Ok(response)
}
fn identity(prep: &Preparation, body: &PreparedIdentity) -> std::result::Result<(), AccessError> {
    if prep.request != body.request_id.0
        || prep.id != body.preparation_id.0
        || prep.generation != body.generation.0
    {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
async fn confirm(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, true)?;
    identity(&prep, &body)?;
    let result = if matches!(
        prep.operation,
        crate::auth::review_access::frames::Operation::RootIssue
            | crate::auth::review_access::frames::Operation::RootComplete
    ) {
        let c = active_credentials(&access, &cookies, &headers)?;
        access
            .transition_root(&browser, &c, &prep, "confirm")
            .await?
    } else {
        access.transition(&prep, "confirm").await?
    };
    Ok(Json(operation(&prep, state(&result)?, now)).into_response())
}
async fn cancel(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
    identity(&prep, &body)?;
    let result = if matches!(
        prep.operation,
        crate::auth::review_access::frames::Operation::RootIssue
            | crate::auth::review_access::frames::Operation::RootComplete
    ) {
        let c = active_credentials(&access, &cookies, &headers)?;
        access
            .transition_root(&browser, &c, &prep, "cancel")
            .await?
    } else {
        access.transition(&prep, "cancel").await?
    };
    let terminal = matches!(
        result.as_str(),
        "cancelled_no_effect" | "rejected_no_effect"
    );
    let mut response = Json(operation(&prep, state(&result)?, now)).into_response();
    if terminal {
        for (prefix, http_only) in [("p", true), ("c", false)] {
            response.headers_mut().append(
                header::SET_COOKIE,
                cookies::clear(
                    &format!("__Host-ztrw-{prefix}-{}", prep.id.simple()),
                    http_only,
                )?,
            );
        }
        if prep.operation == crate::auth::review_access::frames::Operation::InitialBootstrap {
            let name = format!("__Host-ztrw-l-{}", prep.id.simple());
            if let Some(supplied) = cookies.get(&name) {
                // Only an authenticated, unused prospective selector belonging
                // to this positively terminal original request is disposable.
                let expected = zeroize::Zeroizing::new(
                    LocatorSelector::from_initial(
                        &prep,
                        &browser,
                        &access.key,
                        &access.scope,
                        now,
                    )?
                    .seal(&access.key, &access.scope, now)?,
                );
                if supplied.len() != expected.len()
                    || !bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
                {
                    return Err(AccessError::Rejected.into());
                }
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, cookies::clear(&name, true)?);
            }
        }
    }
    Ok(response)
}
async fn preparation_status(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparationStatusRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    if cookies.staged("__Host-ztrw-p-").is_some() {
        let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
        match body {
            PreparationStatusRequest::Exact(body) => identity(&prep, &body)?,
            PreparationStatusRequest::HeldStaging(body) => {
                if body.request_id.0 != prep.request {
                    return Err(AccessError::Rejected.into());
                }
            }
        }
        let result = if matches!(
            prep.operation,
            crate::auth::review_access::frames::Operation::RootIssue
                | crate::auth::review_access::frames::Operation::RootComplete
        ) {
            let c = active_credentials(&access, &cookies, &headers)?;
            access
                .transition_root(&browser, &c, &prep, "inspect")
                .await?
        } else {
            access.transition(&prep, "inspect").await?
        };
        return Ok(Json(operation(&prep, state(&result)?, now)).into_response());
    }
    let PreparationStatusRequest::Exact(body) = body else {
        return Err(AccessError::Unavailable.into());
    };
    let row = access.browser_view(&browser).await?;
    let result = row_operation(&row, now)?.ok_or(AccessError::Unavailable)?;
    if result.request_id != body.request_id.0
        || result.preparation_id != body.preparation_id.0
        || result.generation.0 != body.generation.0
        || !matches!(row.get::<_, i16>("operation"), 1 | 2 | 4 | 5)
        || !matches!(
            row.get::<_, String>("state").as_str(),
            "cancelled_no_effect" | "rejected_no_effect"
        )
    {
        return Err(AccessError::Unavailable.into());
    }
    if matches!(row.get::<_, i16>("operation"), 4 | 5) {
        let c = active_credentials(&access, &cookies, &headers)?;
        access.context(&browser, &c, body.request_id.0).await?;
    }
    let held = cookies::decode_secret(cookies::one_header(&headers, cookies::PREPARED_HEADER)?)?;
    let digest: [u8; 32] = Sha256::digest(held.as_ref()).into();
    let expected: Vec<u8> = row.get("prepared_csrf_digest");
    if !bool::from(digest.as_slice().ct_eq(&expected)) {
        return Err(AccessError::Rejected.into());
    }
    Ok(Json(result).into_response())
}
async fn login_bootstrap(
    state: State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    body: ApiJson<LoginRequest>,
) -> Answer {
    login(state, headers, body, false).await
}
async fn login_resume(
    state: State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    body: ApiJson<LoginRequest>,
) -> Answer {
    login(state, headers, body, true).await
}
async fn login(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LoginRequest>,
    resume: bool,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, true)?;
    if prep.request != body.request_id.0
        || prep.id != body.preparation_id.0
        || prep.generation != body.generation.0
        || prep.alias != body.alias
        || prep.operation
            != if resume {
                crate::auth::review_access::frames::Operation::BrokerForResume
            } else {
                crate::auth::review_access::frames::Operation::InitialBootstrap
            }
    {
        return Err(AccessError::Rejected.into());
    }
    access.login(&prep, &body.password.0).await?;
    let client = access.connect().await?;
    let now = storage::clock(&*client, prep.prepared).await?;
    Ok(Json(operation(&prep, OperationState::CommittedKnown, now)).into_response())
}

fn active_credentials(
    access: &ReviewAccess,
    cookies: &Cookies,
    headers: &HeaderMap,
) -> std::result::Result<Credentials, AccessError> {
    let broker = cookies::ActiveCredential::parse(
        cookies
            .get(cookies::BROKER)
            .ok_or(AccessError::Unavailable)?,
    )?;
    let owner = cookies::ActiveCredential::parse(
        cookies
            .get(cookies::OWNER)
            .ok_or(AccessError::Unavailable)?,
    )?;
    let broker_csrf = cookies.csrf(headers, cookies::BROKER_CSRF, "x-ztrw-broker-csrf")?;
    let owner_csrf = cookies.csrf(headers, cookies::OWNER_CSRF, "x-ztrw-owner-csrf")?;
    access.credentials(
        broker.session,
        &broker.candidate,
        &broker_csrf,
        owner.session,
        &owner.candidate,
        &owner_csrf,
    )
}
async fn login_status(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
    identity(&prep, &body)?;
    if !matches!(
        prep.operation,
        crate::auth::review_access::frames::Operation::InitialBootstrap
            | crate::auth::review_access::frames::Operation::BrokerForResume
    ) {
        return Err(AccessError::Rejected.into());
    }
    let result = access.login_status(&prep).await?;
    let client = access.connect().await?;
    let now = storage::clock(&*client, prep.prepared).await?;
    let deadline = result.get::<_, i64>("delivery_deadline_ms") as u64;
    let mut response = Json(operation(&prep, OperationState::CommittedKnown, now)).into_response();
    for (name, value, http_only) in [
        (
            cookies::BROKER,
            cookies::active_value(prep.identities.broker_session, &prep.candidates.broker)?,
            true,
        ),
        (
            cookies::BROKER_CSRF,
            zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(prep.candidates.broker_csrf.as_ref())),
            false,
        ),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookies::set(name, &value, now, deadline, http_only)?,
        );
    }
    Ok(response)
}
async fn workspace_status(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
    identity(&prep, &body)?;
    if prep.operation != crate::auth::review_access::frames::Operation::InitialBootstrap {
        return Err(AccessError::Rejected.into());
    }
    let broker = cookies::ActiveCredential::parse(
        cookies
            .get(cookies::BROKER)
            .ok_or(AccessError::Unavailable)?,
    )?;
    let csrf = cookies.csrf(&headers, cookies::BROKER_CSRF, "x-ztrw-broker-csrf")?;
    let credentials = access.credentials(
        broker.session,
        &broker.candidate,
        &csrf,
        prep.identities.owner_session,
        &prep.candidates.owner,
        &prep.candidates.owner_csrf,
    )?;
    let context = access
        .context(&browser, &credentials, body.request_id.0)
        .await?;
    if context.account != prep.identities.account
        || context.owner_user != prep.identities.user
        || context.review_owner_session != prep.identities.owner_session
    {
        return Err(AccessError::Unavailable.into());
    }
    let now = context.server_now_ms.0;
    let deadline = context.idle_deadline_ms.0.min(context.absolute_expiry_ms.0);
    let mut response = Json(operation(&prep, OperationState::CommittedKnown, now)).into_response();
    for (name, value, http_only) in [
        (
            cookies::OWNER,
            cookies::active_value(prep.identities.owner_session, &prep.candidates.owner)?,
            true,
        ),
        (
            cookies::OWNER_CSRF,
            zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(prep.candidates.owner_csrf.as_ref())),
            false,
        ),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookies::set(name, &value, now, deadline, http_only)?,
        );
    }
    Ok(response)
}
async fn session_context(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RequestIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    let credentials = active_credentials(&access, &cookies, &headers)?;
    Ok(Json(
        access
            .context(&browser, &credentials, body.request_id.0)
            .await?,
    )
    .into_response())
}
async fn session_confirm(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let credentials = active_credentials(&access, &cookies, &headers)?;
    let csrf = if cookies.staged("__Host-ztrw-p-").is_some() {
        let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
        identity(&prep, &body)?;
        zeroize::Zeroizing::new(*prep.candidates.csrf)
    } else {
        cookies::decode_secret(cookies::one_header(&headers, cookies::PREPARED_HEADER)?)?
    };
    access
        .acknowledge(
            &browser,
            &credentials,
            body.preparation_id.0,
            body.request_id.0,
            body.generation.0,
            &csrf,
        )
        .await?;
    let row = access.browser_view(&browser).await?;
    let result = row_operation(&row, now)?.ok_or(AccessError::Unavailable)?;
    let mut response = Json(result).into_response();
    for (prefix, http_only) in [("p", true), ("c", false)] {
        let name = format!("__Host-ztrw-{prefix}-{}", body.preparation_id.0.simple());
        if cookies.get(&name).is_some() {
            response
                .headers_mut()
                .append(header::SET_COOKIE, cookies::clear(&name, http_only)?);
        }
    }
    Ok(response)
}
async fn locator_context(
    state: State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    body: ApiJson<LocatorRetentionRequest>,
) -> Answer {
    locator(state, headers, body, LocatorPhase::Context).await
}
async fn locator_confirm(
    state: State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    body: ApiJson<LocatorRetentionRequest>,
) -> Answer {
    locator(state, headers, body, LocatorPhase::Confirm).await
}
async fn locator_status(
    state: State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    body: ApiJson<LocatorRetentionRequest>,
) -> Answer {
    locator(state, headers, body, LocatorPhase::Status).await
}
async fn locator(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LocatorRetentionRequest>,
    phase: LocatorPhase,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    let credentials = active_credentials(&access, &cookies, &headers)?;
    let digest = canonical_bytes::<32>(&body.selector_cookie_sha256_b64)?;
    let name = format!("__Host-ztrw-l-{}", body.preparation_id.0.simple());
    if cookies
        .staged("__Host-ztrw-l-")
        .is_some_and(|(actual, _)| actual != name)
    {
        return Err(AccessError::Rejected.into());
    }
    let readonly = matches!(phase, LocatorPhase::Context);
    let retained = access
        .locator_retention(
            &browser,
            &credentials,
            crate::auth::review_access::current::LocatorObservation {
                phase,
                preparation: body.preparation_id.0,
                request: body.request_id.0,
                selector_hash: &digest,
                selector_value: cookies.get(&name),
            },
        )
        .await?;
    let mut response = Json(LocatorRetentionResponse {
        version: Version1,
        request_id: body.request_id.0,
        preparation_id: body.preparation_id.0,
        selector_cookie_sha256_b64: body.selector_cookie_sha256_b64,
        retained,
    })
    .into_response();
    if !readonly && retained && cookies.get(&name).is_some() {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookies::clear(&name, true)?);
    }
    Ok(response)
}
pub(super) fn canonical_bytes<const N: usize>(
    raw: &str,
) -> std::result::Result<[u8; N], AccessError> {
    if raw.len() != N.div_ceil(3) * 4 {
        return Err(AccessError::Rejected);
    }
    let bytes = STANDARD.decode(raw).map_err(|_| AccessError::Rejected)?;
    if bytes.len() != N || STANDARD.encode(&bytes) != raw {
        return Err(AccessError::Rejected);
    }
    bytes.try_into().map_err(|_| AccessError::Rejected)
}
fn bounded_bytes(raw: &str, maximum: usize) -> std::result::Result<Vec<u8>, AccessError> {
    if raw.len() > maximum.div_ceil(3) * 4 {
        return Err(AccessError::Rejected);
    }
    let bytes = STANDARD.decode(raw).map_err(|_| AccessError::Rejected)?;
    if bytes.is_empty() || bytes.len() > maximum || STANDARD.encode(&bytes) != raw {
        return Err(AccessError::Rejected);
    }
    Ok(bytes)
}
fn material(
    pin: &str,
    compared: &str,
    backup: &str,
    card: &str,
) -> std::result::Result<Material, AccessError> {
    Ok(Material {
        pin: canonical_bytes(pin)?,
        compared: canonical_bytes(compared)?,
        backup: bounded_bytes(backup, crate::sealed_root_custody::MAX_BACKUP)?,
        card: bounded_bytes(card, crate::sealed_root_custody::MAX_CARD)?,
    })
}
struct CompletionFields<'a> {
    root: Uuid,
    reauth: Uuid,
    nonce: &'a str,
    unsigned: &'a str,
    enrollment: &'a str,
    custody: &'a str,
    compared: &'a str,
    backup: &'a str,
    card: &'a str,
}
async fn completion(
    access: &ReviewAccess,
    browser: &Browser,
    c: &Credentials,
    fields: CompletionFields<'_>,
) -> std::result::Result<Completion, AccessError> {
    Ok(Completion {
        root: fields.root,
        reauth: fields.reauth,
        nonce: canonical_bytes(fields.nonce)?,
        unsigned: bounded_bytes(fields.unsigned, 663)?,
        enrollment_signature: canonical_bytes(fields.enrollment)?,
        custody_signature: canonical_bytes(fields.custody)?,
        material: Material {
            pin: access.completion_pin(browser, c, fields.reauth).await?,
            compared: canonical_bytes(fields.compared)?,
            backup: bounded_bytes(fields.backup, crate::sealed_root_custody::MAX_BACKUP)?,
            card: bounded_bytes(fields.card, crate::sealed_root_custody::MAX_CARD)?,
        },
    })
}
async fn root_issue(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RootIssueRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let c = active_credentials(&access, &cookies, &headers)?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, true)?;
    identity(
        &prep,
        &PreparedIdentity {
            version: Version1,
            request_id: body.request_id,
            preparation_id: body.preparation_id,
            generation: body.generation,
        },
    )?;
    let material = material(
        &body.root_pin_b64,
        &body.independently_compared_fingerprint_b64,
        &body.encrypted_backup_b64,
        &body.public_card_b64,
    )?;
    Ok(Json(access.issue_root(&browser, &c, &prep, &material).await?).into_response())
}
async fn root_issue_status(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PreparedIdentity>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let c = active_credentials(&access, &cookies, &headers)?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, false)?;
    identity(&prep, &body)?;
    Ok(Json(access.root_issue_status(&browser, &c, &prep).await?).into_response())
}
async fn root_complete(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RootCompleteRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, now) = browser_now(&access, &cookies).await?;
    let c = active_credentials(&access, &cookies, &headers)?;
    let prep = cookies.prepared(&headers, &access.key, &access.scope, &browser, now, true)?;
    identity(
        &prep,
        &PreparedIdentity {
            version: Version1,
            request_id: body.request_id,
            preparation_id: body.preparation_id,
            generation: body.generation,
        },
    )?;
    let completion = completion(
        &access,
        &browser,
        &c,
        CompletionFields {
            root: body.root_challenge_id.0,
            reauth: body.reauth_challenge_id.0,
            nonce: &body.reauth_nonce_b64,
            unsigned: &body.unsigned_enrollment_b64,
            enrollment: &body.enrollment_signature_b64,
            custody: &body.custody_signature_b64,
            compared: &body.independently_compared_fingerprint_b64,
            backup: &body.encrypted_backup_b64,
            card: &body.public_card_b64,
        },
    )
    .await?;
    Ok(Json(
        access
            .complete_root(&browser, &c, &prep, &completion, &body.password.0)
            .await?,
    )
    .into_response())
}
async fn root_result(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RootReadRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    let c = active_credentials(&access, &cookies, &headers)?;
    let (receipt, _) = access
        .read_root(
            &browser,
            &c,
            body.request_id.0,
            &canonical_bytes(&body.independently_compared_fingerprint_b64)?,
        )
        .await?;
    Ok(Json(receipt).into_response())
}
async fn root_export(
    State(access): State<Arc<ReviewAccess>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RootReadRequest>,
) -> Answer {
    let cookies = Cookies::parse(&headers)?;
    let (browser, _) = browser_now(&access, &cookies).await?;
    let c = active_credentials(&access, &cookies, &headers)?;
    let (_, export) = access
        .read_root(
            &browser,
            &c,
            body.request_id.0,
            &canonical_bytes(&body.independently_compared_fingerprint_b64)?,
        )
        .await?;
    Ok(Json(export).into_response())
}
