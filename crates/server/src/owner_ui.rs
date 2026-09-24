// SPDX-License-Identifier: AGPL-3.0-only
//! Small same-origin owner surface for the existing enrollment API.

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};

const PAGE: &str = include_str!("../../../web/owner/devices.html");
const SCRIPT: &str = include_str!("../../../web/owner/devices.js");
const STYLE: &str = include_str!("../../../web/owner/devices.css");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub fn router() -> Router {
    Router::new()
        .route("/owner/devices", get(page))
        .route("/owner/devices.js", get(script))
        .route("/owner/devices.css", get(style))
}

fn secure_response(mut response: Response, content_type: &'static str) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

async fn page() -> Response {
    secure_response(Html(PAGE).into_response(), "text/html; charset=utf-8")
}

async fn script() -> Response {
    secure_response(
        (StatusCode::OK, SCRIPT).into_response(),
        "text/javascript; charset=utf-8",
    )
}

async fn style() -> Response {
    secure_response(
        (StatusCode::OK, STYLE).into_response(),
        "text/css; charset=utf-8",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn credential_forms_fail_closed_without_javascript() {
        use crate::{
            auth::TokenHasher,
            http_auth::{self, AuthHttpState, DisabledVerificationDispatcher},
        };
        use std::sync::Arc;

        let state = AuthHttpState::new(
            "postgres://unused".into(),
            Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
            "https://zrotext.example".into(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let app = router().nest("/v1/auth", http_auth::router(state));
        for (id, endpoint, body) in [
            (
                "login-form",
                "/v1/auth/login",
                "email=owner%40example.test&password=synthetic-password",
            ),
            (
                "mfa-form",
                "/v1/auth/login/mfa",
                "code=synthetic-recovery-code",
            ),
        ] {
            // Without the submit listener, native HTML forms must not put
            // credentials in the URL. Their URL-encoded POST fails closed at
            // the JSON-only endpoint, before any database or password work.
            let start = PAGE.find(&format!("<form id=\"{id}\"")).unwrap();
            let tag = PAGE[start..].split('>').next().unwrap();
            assert!(tag.contains("method=\"post\""));
            assert!(tag.contains(&format!("action=\"{endpoint}\"")));
            let request = Request::builder()
                .method("POST")
                .uri(endpoint)
                .header(header::ORIGIN, "https://zrotext.example")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            assert!(request.uri().query().is_none());
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(!response.headers().contains_key(header::LOCATION));
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn owner_assets_are_same_origin_and_never_cached() {
        for (path, content_type) in [
            ("/owner/devices", "text/html; charset=utf-8"),
            ("/owner/devices.js", "text/javascript; charset=utf-8"),
            ("/owner/devices.css", "text/css; charset=utf-8"),
        ] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("connect-src 'self'")
            );
        }
    }
}
