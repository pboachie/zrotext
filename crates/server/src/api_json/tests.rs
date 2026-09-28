use super::*;
use crate::{
    alpha_policy::AlphaPolicy,
    auth::TokenHasher,
    enrollment::EnrollmentHasher,
    http_auth::{self, AuthHttpState, DisabledVerificationDispatcher},
    http_enrollment::{self, EnrollmentHttpState},
    http_messages::{self, MessagesHttpState},
    http_owner_review::{self, OwnerReviewState},
    http_webhooks::{self, WebhookHttpState},
    webhook_worker::WebhookSecretVault,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::DefaultBodyLimit,
    routing::post,
};
use serde::Deserialize;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Never connected: every case here is rejected before a handler runs.
const UNUSED_DATABASE: &str = "postgresql://unused.invalid/unused";
const ORIGIN: &str = "https://zrotext.example";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    #[allow(dead_code)]
    count: u8,
}

async fn probe(ApiJson(_): ApiJson<Probe>) -> StatusCode {
    StatusCode::NO_CONTENT
}

fn request(uri: &str, content_type: Option<&str>, body: &str) -> Request {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::ORIGIN, ORIGIN);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

/// Syntax, media type, unknown member, missing member and type errors.
fn bad_bodies() -> [(Option<&'static str>, &'static str); 7] {
    [
        (Some("application/json"), "{"),
        (Some("application/json"), "[]"),
        (
            Some("application/json"),
            r#"{"count":1,"unexpected_field":true}"#,
        ),
        (Some("application/json"), "{}"),
        (Some("application/json"), r#"{"count":"one"}"#),
        (Some("text/plain"), r#"{"count":1}"#),
        (None, r#"{"count":1}"#),
    ]
}

async fn assert_envelope(app: &Router, uri: &str, content_type: Option<&str>, body: &str) {
    let response = app
        .clone()
        .oneshot(request(uri, content_type, body))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "{uri} {content_type:?} {body}"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // No serde text, field names or axum detail leaves the server.
    assert_eq!(value, serde_json::json!({"code": "invalid_request"}));
}

async fn assert_router_envelope(app: Router, uri: &str) {
    for (content_type, body) in bad_bodies() {
        assert_envelope(&app, uri, content_type, body).await;
    }
}

#[tokio::test]
async fn every_json_rejection_becomes_the_invalid_request_envelope() {
    let app = Router::new()
        .route("/probe", post(probe))
        .layer(DefaultBodyLimit::max(64));
    assert_router_envelope(app.clone(), "/probe").await;

    let accepted = app
        .clone()
        .oneshot(request(
            "/probe",
            Some("application/json"),
            r#"{"count":1}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

    // An unreadable body keeps its own status rather than claiming bad JSON.
    let oversized = app
        .oneshot(request(
            "/probe",
            Some("application/json"),
            &format!(r#"{{"count":1,"pad":"{}"}}"#, "a".repeat(128)),
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(oversized.headers()[header::CACHE_CONTROL], "no-store");
}

fn hasher() -> Arc<TokenHasher> {
    Arc::new(TokenHasher::new(vec![7; 32]).unwrap())
}

/// Body-carrying owner and API routes authenticate from headers before the
/// body extractor runs, so a request without credentials gets the route's
/// JSON error envelope for `status`/`code` whatever its body, and malformed
/// bodies are only parsed for callers that authenticated.
async fn assert_rejected_before_body(app: Router, uri: &str, status: StatusCode, code: &str) {
    for (content_type, body) in bad_bodies() {
        let response = app
            .clone()
            .oneshot(request(uri, content_type, body))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{uri} {content_type:?} {body}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, serde_json::json!({ "code": code }), "{uri}");
    }
}

#[tokio::test]
async fn auth_router_rejects_malformed_json_with_its_envelope() {
    let mut state = AuthHttpState::new(
        UNUSED_DATABASE.into(),
        hasher(),
        ORIGIN.into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    state.sms_line_activation_enabled = true;
    let app = http_auth::router(state);
    assert_router_envelope(app.clone(), "/login").await;
    for uri in [
        "/sms-line-owner-keys/challenge".to_owned(),
        format!("/sms-lines/{}/activations", Uuid::new_v4()),
        "/password".to_owned(),
        "/api-keys".to_owned(),
    ] {
        assert_rejected_before_body(app.clone(), &uri, StatusCode::UNAUTHORIZED, "unauthorized")
            .await;
    }
}

#[tokio::test]
async fn messages_router_rejects_malformed_json_with_its_envelope() {
    // Disabled alpha stays a 404 before any credential or body check.
    let disabled = AlphaPolicy::parse(None, None, None).unwrap();
    let state = MessagesHttpState::new(UNUSED_DATABASE.into(), hasher(), Arc::new(disabled), false)
        .unwrap();
    assert_rejected_before_body(
        http_messages::router(state),
        "/messages",
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let enabled = AlphaPolicy::parse(
        Some("true"),
        Some(&Uuid::new_v4().to_string()),
        Some("+15555550101"),
    )
    .unwrap();
    let state =
        MessagesHttpState::new(UNUSED_DATABASE.into(), hasher(), Arc::new(enabled), false).unwrap();
    assert_rejected_before_body(
        http_messages::router(state),
        "/messages",
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

#[tokio::test]
async fn enrollment_router_rejects_malformed_json_with_its_envelope() {
    let state = EnrollmentHttpState::new(
        UNUSED_DATABASE.into(),
        hasher(),
        Arc::new(EnrollmentHasher::new(vec![9; 32]).unwrap()),
        ORIGIN.into(),
    );
    let app = http_enrollment::router(state);
    assert_router_envelope(app.clone(), &format!("/pairings/{}/claim", Uuid::new_v4())).await;
    assert_rejected_before_body(app, "/pairings", StatusCode::UNAUTHORIZED, "unauthorized").await;
}

#[tokio::test]
async fn webhook_router_rejects_malformed_json_with_its_envelope() {
    let state = WebhookHttpState {
        database_url: UNUSED_DATABASE.into(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.into(),
        vault: Arc::new(WebhookSecretVault::new(1, Zeroizing::new(vec![5; 32])).unwrap()),
    };
    assert_rejected_before_body(
        http_webhooks::router(state),
        "/v1/webhooks",
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

#[tokio::test]
async fn owner_review_router_rejects_malformed_json_with_its_envelope() {
    let state = OwnerReviewState {
        database_url: UNUSED_DATABASE.into(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.into(),
    };
    let app = http_owner_review::router(state);
    for uri in [
        "/v1/owner/opt-out-holds",
        "/v1/owner/opt-out-review/decisions",
    ] {
        assert_rejected_before_body(app.clone(), uri, StatusCode::UNAUTHORIZED, "unauthorized")
            .await;
    }
}
