// SPDX-License-Identifier: AGPL-3.0-only
//! Small same-origin owner surface for the existing enrollment API.

use axum::{
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
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
const TEMPLATE_PAGE: &str = include_str!("../../../web/owner/template-preview.html");
const TEMPLATE_SCRIPT: &str = include_str!("../../../web/owner/template-preview.js");
const TEMPLATE_CORE: &str = include_str!("../../../web/owner/template-preview-core.js");
const TEMPLATE_STYLE: &str = include_str!("../../../web/owner/template-preview.css");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Strong validator for a compile-time-constant asset, computed once.
fn asset_etag(body: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(body.as_bytes());
    let mut etag = String::with_capacity(digest.len() * 2 + 2);
    etag.push('"');
    for byte in digest {
        etag.push_str(&format!("{byte:02x}"));
    }
    etag.push('"');
    etag
}

fn if_none_match_matches(if_none_match: Option<&HeaderValue>, etag: &str) -> bool {
    let Some(value) = if_none_match.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == etag || candidate == format!("W/{etag}")
    })
}

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
        .route("/owner/template-preview", get(template_page))
        .route("/owner/template-preview.js", get(template_script))
        .route("/owner/template-preview-core.js", get(template_core))
        .route("/owner/template-preview.css", get(template_style))
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

fn secure_headers(mut response: Response, content_type: &'static str) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
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
    response
}

/// Rendered HTML stays uncacheable.
fn secure_response(response: Response, content_type: &'static str) -> Response {
    let mut response = secure_headers(response, content_type);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Compile-time-constant JS/CSS assets revalidate with a strong ETag:
/// `no-cache` keeps every load checked, and a matching `If-None-Match`
/// answers `304` with no body. The assets contain no account data.
fn cached_asset(
    body: &'static str,
    content_type: &'static str,
    etag: &str,
    if_none_match: Option<&HeaderValue>,
) -> Response {
    if if_none_match_matches(if_none_match, etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(
            header::ETAG,
            HeaderValue::from_str(etag).expect("quoted hex etag"),
        );
        return response;
    }
    let mut response = secure_headers((StatusCode::OK, body).into_response(), content_type);
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("quoted hex etag"),
    );
    response
}

async fn page() -> Response {
    secure_response(Html(PAGE).into_response(), "text/html; charset=utf-8")
}

async fn script(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| asset_etag(SCRIPT));
    cached_asset(
        SCRIPT,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn style(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| asset_etag(STYLE));
    cached_asset(
        STYLE,
        "text/css; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn account_page() -> Response {
    secure_response(
        Html(ACCOUNT_PAGE).into_response(),
        "text/html; charset=utf-8",
    )
}

async fn account_script(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(ACCOUNT_SCRIPT));
    cached_asset(
        ACCOUNT_SCRIPT,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn sms_lines_page() -> Response {
    secure_response(
        Html(SMS_LINES_PAGE).into_response(),
        "text/html; charset=utf-8",
    )
}

async fn sms_lines_script(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(SMS_LINES_SCRIPT));
    cached_asset(
        SMS_LINES_SCRIPT,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn sms_line_signing_script(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(SMS_LINE_SIGNING_SCRIPT));
    cached_asset(
        SMS_LINE_SIGNING_SCRIPT,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn template_page() -> Response {
    let mut response = secure_response(
        Html(TEMPLATE_PAGE).into_response(),
        "text/html; charset=utf-8",
    );
    // A local-only editor must never gain a native form submission fallback.
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"));
    response
}

async fn template_script(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(TEMPLATE_SCRIPT));
    cached_asset(
        TEMPLATE_SCRIPT,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn template_core(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(TEMPLATE_CORE));
    cached_asset(
        TEMPLATE_CORE,
        "text/javascript; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

async fn template_style(headers: HeaderMap) -> Response {
    static ETAG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| asset_etag(TEMPLATE_STYLE));
    cached_asset(
        TEMPLATE_STYLE,
        "text/css; charset=utf-8",
        &ETAG,
        headers.get(header::IF_NONE_MATCH),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn template_preview_has_no_submission_fallback_or_reflection() {
        assert!(ACCOUNT_PAGE.contains("href=\"/owner/template-preview\""));
        assert!(TEMPLATE_PAGE.contains("<fieldset id=\"editor\" disabled>"));
        assert!(!TEMPLATE_PAGE.contains("<form"));
        assert!(!TEMPLATE_PAGE.contains("type=\"submit\""));
        for method in ["GET", "POST"] {
            let response = router()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/owner/template-preview?template=synthetic-sentinel")
                        .body(Body::from("synthetic-sentinel"))
                        .unwrap(),
                )
                .await
                .unwrap();
            if method == "POST" {
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap();
                for directive in [
                    "default-src 'none'",
                    "script-src 'self'",
                    "form-action 'none'",
                    "frame-ancestors 'none'",
                ] {
                    assert!(csp.contains(directive));
                }
                assert!(!csp.contains("unsafe-inline"));
                assert!(!csp.contains("unsafe-eval"));
            }
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-sentinel"));
        }
    }

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
                "token=synthetic-code&password=synthetic-password",
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
            // Anonymous forms reach the JSON-only extractor, which answers with
            // the API error envelope. Owner forms are rejected from headers
            // alone before their body is read: 401 without a session, and the
            // disabled-by-default MFA enrollment routes stay 404.
            let expected = if endpoint.starts_with("/v1/auth/login")
                || [
                    "/v1/auth/register",
                    "/v1/auth/verify-email",
                    "/v1/auth/resend-verification",
                ]
                .contains(&endpoint)
            {
                StatusCode::BAD_REQUEST
            } else if ["/v1/auth/mfa/enroll", "/v1/auth/mfa/confirm"].contains(&endpoint) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(response.status(), expected, "{id}");
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(!response.headers().contains_key(header::LOCATION));
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn owner_html_is_never_cached_and_assets_revalidate_with_etags() {
        assert!(PAGE.contains("href=\"/owner/account\""));
        assert!(PAGE.contains("href=\"/owner/sms-lines\""));
        // The activation form never submits natively to a URL with parameters.
        assert!(
            SMS_LINES_PAGE.contains(
                "<form id=\"activation-form\" method=\"post\" action=\"/owner/sms-lines\">"
            )
        );
        assert!(ACCOUNT_PAGE.contains("id=\"verify\""));
        for (path, content_type, cache_control) in [
            ("/owner/devices", "text/html; charset=utf-8", "no-store"),
            (
                "/owner/devices.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            ("/owner/devices.css", "text/css; charset=utf-8", "no-cache"),
            ("/owner/account", "text/html; charset=utf-8", "no-store"),
            (
                "/owner/account.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/template-preview",
                "text/html; charset=utf-8",
                "no-store",
            ),
            (
                "/owner/template-preview.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/template-preview-core.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/template-preview.css",
                "text/css; charset=utf-8",
                "no-cache",
            ),
            ("/owner/sms-lines", "text/html; charset=utf-8", "no-store"),
            (
                "/owner/sms-lines.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/sms-line-signing.js",
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
        ] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers()[header::CACHE_CONTROL], cache_control);
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
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
            if cache_control == "no-cache" {
                let etag = response.headers()[header::ETAG].to_str().unwrap();
                assert!(etag.starts_with('"') && etag.ends_with('"') && etag.len() == 66);
                // A matching If-None-Match revalidates to 304 with no body.
                let revalidated = router()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header(header::IF_NONE_MATCH, etag)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(revalidated.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(revalidated.headers()[header::ETAG], etag);
                assert_eq!(revalidated.headers()[header::CACHE_CONTROL], "no-cache");
                let bytes = axum::body::to_bytes(revalidated.into_body(), 1)
                    .await
                    .unwrap();
                assert!(bytes.is_empty());
                // A stale validator still returns the full asset.
                let stale = router()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header(header::IF_NONE_MATCH, "\"stale\"")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(stale.status(), StatusCode::OK);
            } else {
                // Rendered HTML keeps no validator: it always re-renders in full.
                assert!(!response.headers().contains_key(header::ETAG));
            }
        }
    }

    #[test]
    fn if_none_match_parsing_accepts_lists_and_weak_validators() {
        let etag = asset_etag("synthetic-asset");
        let header = HeaderValue::from_str(&format!("\"other\", W/{etag}")).unwrap();
        assert!(if_none_match_matches(Some(&header), &etag));
        assert!(!if_none_match_matches(
            Some(&HeaderValue::from_static("\"stale\"")),
            &etag
        ));
        assert!(!if_none_match_matches(None, &etag));
    }
}
