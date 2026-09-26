// SPDX-License-Identifier: AGPL-3.0-only
//! Small same-origin owner surface for the existing enrollment API.

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};

const PAGE: &str = include_str!("../../../web/owner/devices.html");
const SCRIPT: &str = include_str!("../../../web/owner/devices.js");
const STYLE: &str = include_str!("../../../web/owner/devices.css");
const ACCOUNT_PAGE: &str = include_str!("../../../web/owner/account.html");
const ACCOUNT_SCRIPT: &str = include_str!("../../../web/owner/account.js");
const SMS_LINES_PAGE: &str = include_str!("../../../web/owner/sms-lines.html");
const SMS_LINES_SCRIPT: &str = include_str!("../../../web/owner/sms-lines.js");
const SMS_LINE_SIGNING_SCRIPT: &str = include_str!("../../../web/owner/sms-line-signing.js");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub fn router() -> Router {
    Router::new()
        .route("/owner/devices", get(page))
        .route("/owner/devices.js", get(script))
        .route("/owner/devices.css", get(style))
        .route("/owner/account", get(account_page))
        .route("/owner/account.js", get(account_script))
        .route("/owner/sms-lines", get(sms_lines_page))
        .route("/owner/sms-lines.js", get(sms_lines_script))
        .route("/owner/sms-line-signing.js", get(sms_line_signing_script))
}

pub fn source_router<S>(source_url: String) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        "/source",
        get(move || {
            let url = source_url.clone();
            async move { Redirect::temporary(&url) }
        }),
    )
}

pub fn source_destination(
    configured: Option<&str>,
    commit: Option<&str>,
) -> Result<String, &'static str> {
    let url = match configured {
        Some(value) => value.to_owned(),
        None => match commit
            .filter(|value| value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            Some(value) => format!("https://github.com/pboachie/zrotext/tree/{value}"),
            None => "https://github.com/pboachie/zrotext".to_owned(),
        },
    };
    let parsed = reqwest::Url::parse(&url).map_err(|_| "SOURCE_URL must be a valid HTTPS URL")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("SOURCE_URL must be an HTTPS URL without credentials or fragment");
    }
    Ok(url)
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
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
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

async fn account_page() -> Response {
    secure_response(
        Html(ACCOUNT_PAGE).into_response(),
        "text/html; charset=utf-8",
    )
}

async fn account_script() -> Response {
    secure_response(
        (StatusCode::OK, ACCOUNT_SCRIPT).into_response(),
        "text/javascript; charset=utf-8",
    )
}

async fn sms_lines_page() -> Response {
    secure_response(
        Html(SMS_LINES_PAGE).into_response(),
        "text/html; charset=utf-8",
    )
}

async fn sms_lines_script() -> Response {
    secure_response(
        (StatusCode::OK, SMS_LINES_SCRIPT).into_response(),
        "text/javascript; charset=utf-8",
    )
}

async fn sms_line_signing_script() -> Response {
    secure_response(
        (StatusCode::OK, SMS_LINE_SIGNING_SCRIPT).into_response(),
        "text/javascript; charset=utf-8",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn source_route_uses_configured_corresponding_source() {
        assert!(PAGE.contains("href=\"/source\""));
        assert!(include_str!("../static/billing-dashboard.html").contains("href=\"/source\""));
        let url = source_destination(Some("https://example.org/fork/source"), None).unwrap();
        let response = source_router::<()>(url)
            .oneshot(
                Request::builder()
                    .uri("/source")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://example.org/fork/source"
        );
        assert!(source_destination(Some("javascript:alert(1)"), None).is_err());
    }

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
            (
                "register-form",
                "/v1/auth/register",
                "email=owner%40example.test",
            ),
            (
                "verify-form",
                "/v1/auth/verify-email",
                "token=synthetic-code",
            ),
            (
                "resend-form",
                "/v1/auth/resend-verification",
                "email=owner%40example.test",
            ),
            (
                "mfa-enroll-form",
                "/v1/auth/mfa/enroll",
                "password=synthetic-password",
            ),
            ("mfa-confirm-form", "/v1/auth/mfa/confirm", "code=000000"),
            (
                "mfa-disable-form",
                "/v1/auth/mfa/disable",
                "code=synthetic-code",
            ),
            ("key-form", "/v1/auth/sms-line-owner-keys", "mfa=000000"),
        ] {
            // Without the submit listener, native HTML forms must not put
            // credentials in the URL. Their URL-encoded POST fails closed at
            // the JSON-only endpoint, before any database or password work.
            let document = [PAGE, ACCOUNT_PAGE, SMS_LINES_PAGE]
                .into_iter()
                .find(|page| page.contains(&format!("<form id=\"{id}\"")))
                .unwrap();
            let start = document.find(&format!("<form id=\"{id}\"")).unwrap();
            let tag = document[start..].split('>').next().unwrap();
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
        assert!(PAGE.contains("href=\"/owner/account\""));
        assert!(PAGE.contains("href=\"/owner/sms-lines\""));
        // The activation form never submits natively to a URL with parameters.
        assert!(
            SMS_LINES_PAGE.contains(
                "<form id=\"activation-form\" method=\"post\" action=\"/owner/sms-lines\">"
            )
        );
        assert!(ACCOUNT_PAGE.contains("id=\"verify\""));
        for (path, content_type) in [
            ("/owner/devices", "text/html; charset=utf-8"),
            ("/owner/devices.js", "text/javascript; charset=utf-8"),
            ("/owner/devices.css", "text/css; charset=utf-8"),
            ("/owner/account", "text/html; charset=utf-8"),
            ("/owner/account.js", "text/javascript; charset=utf-8"),
            ("/owner/sms-lines", "text/html; charset=utf-8"),
            ("/owner/sms-lines.js", "text/javascript; charset=utf-8"),
            (
                "/owner/sms-line-signing.js",
                "text/javascript; charset=utf-8",
            ),
        ] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(
                response.headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=63072000; includeSubDomains"
            );
            assert!(
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("connect-src 'self'")
            );
        }
    }
}
