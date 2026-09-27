// SPDX-License-Identifier: AGPL-3.0-only
//! Owner GETs that return account content (messages, export, webhooks,
//! review queues, devices, pairings) need the `x-zrotext-csrf` header as well
//! as the session cookie. Every router here gets an unparsable database URL,
//! so any request that reached the connection pool answers 503: a 401 or 403
//! proves the handler refused it before touching the database.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;
use zrotext_server::{
    auth::TokenHasher, enrollment::EnrollmentHasher, http_enrollment, http_owner_export,
    http_owner_messages, http_owner_review, http_webhooks, webhook_worker::WebhookSecretVault,
};

const NO_DATABASE: &str = "not a database url";
const ORIGIN: &str = "https://zrotext.example";
const SESSION: &str = "__Host-zrotext_session=zts_fixture";
const CSRF_VALUE: &str = "ztc_fixture";

fn hasher() -> Arc<TokenHasher> {
    Arc::new(TokenHasher::new(vec![7; 32]).unwrap())
}

/// Each content-bearing GET, with the router that serves it.
fn content_reads() -> Vec<(&'static str, Router, String)> {
    let id = Uuid::new_v4();
    let export = http_owner_export::router(http_owner_export::OwnerExportState {
        database_url: NO_DATABASE.to_owned(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.to_owned(),
    });
    let messages = http_owner_messages::router(http_owner_messages::OwnerMessagesState {
        database_url: NO_DATABASE.to_owned(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.to_owned(),
    });
    let review = http_owner_review::router(http_owner_review::OwnerReviewState {
        database_url: NO_DATABASE.to_owned(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.to_owned(),
    });
    let webhooks = http_webhooks::router(http_webhooks::WebhookHttpState {
        database_url: NO_DATABASE.to_owned(),
        auth_hasher: hasher(),
        canonical_origin: ORIGIN.to_owned(),
        vault: Arc::new(WebhookSecretVault::new(1, Zeroizing::new(vec![9; 32])).unwrap()),
    });
    let enrollment = Router::new().nest(
        "/v1/enrollment",
        http_enrollment::router(http_enrollment::EnrollmentHttpState::new(
            NO_DATABASE.to_owned(),
            hasher(),
            Arc::new(EnrollmentHasher::new(vec![11; 32]).unwrap()),
            ORIGIN.to_owned(),
        )),
    );
    vec![
        ("export", export, "/v1/owner/export".to_owned()),
        ("messages", messages, "/v1/owner/messages".to_owned()),
        (
            "opt-out review",
            review.clone(),
            "/v1/owner/opt-out-review".to_owned(),
        ),
        (
            "opt-out holds",
            review,
            "/v1/owner/opt-out-holds".to_owned(),
        ),
        ("webhook list", webhooks.clone(), "/v1/webhooks".to_owned()),
        (
            "webhook deliveries",
            webhooks.clone(),
            format!("/v1/webhooks/{id}/deliveries"),
        ),
        (
            "inbound events",
            webhooks,
            format!("/v1/inbound/messages/{id}/events"),
        ),
        (
            "devices",
            enrollment.clone(),
            "/v1/enrollment/devices".to_owned(),
        ),
        (
            "pairing view",
            enrollment,
            format!("/v1/enrollment/pairings/{id}"),
        ),
    ]
}

async fn status(app: Router, uri: &str, cookie: Option<String>, csrf: Option<&str>) -> StatusCode {
    // Origin is present and correct throughout: the header, not Origin, is
    // what these reads check.
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::ORIGIN, ORIGIN);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-zrotext-csrf", csrf);
    }
    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn content_reads_without_a_session_cookie_are_unauthorized_before_database() {
    for (name, app, uri) in content_reads() {
        assert_eq!(
            status(
                app,
                &uri,
                Some(format!("__Host-zrotext_csrf={CSRF_VALUE}")),
                Some(CSRF_VALUE)
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
    }
}

#[tokio::test]
async fn cookie_only_content_reads_are_forbidden_before_database() {
    for (name, app, uri) in content_reads() {
        // Session cookie alone: what a cross-site page's credentialed GET
        // carries, since it can neither read the CSRF cookie nor set the
        // custom header without a CORS preflight.
        assert_eq!(
            status(app.clone(), &uri, Some(SESSION.to_owned()), None).await,
            StatusCode::FORBIDDEN,
            "{name}: session cookie only"
        );
        assert_eq!(
            status(
                app.clone(),
                &uri,
                Some(format!("{SESSION}; __Host-zrotext_csrf={CSRF_VALUE}")),
                None
            )
            .await,
            StatusCode::FORBIDDEN,
            "{name}: CSRF cookie without header"
        );
        assert_eq!(
            status(
                app.clone(),
                &uri,
                Some(SESSION.to_owned()),
                Some(CSRF_VALUE)
            )
            .await,
            StatusCode::FORBIDDEN,
            "{name}: header without CSRF cookie"
        );
        assert_eq!(
            status(
                app.clone(),
                &uri,
                Some(format!("{SESSION}; __Host-zrotext_csrf={CSRF_VALUE}")),
                Some("ztc_other00")
            )
            .await,
            StatusCode::FORBIDDEN,
            "{name}: mismatched header"
        );
        // A matching pair passes the database-free step and then needs the
        // database to bind the token to the session.
        assert_eq!(
            status(
                app,
                &uri,
                Some(format!("{SESSION}; __Host-zrotext_csrf={CSRF_VALUE}")),
                Some(CSRF_VALUE)
            )
            .await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name}: matching pair"
        );
    }
}
