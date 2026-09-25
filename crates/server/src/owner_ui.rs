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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

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
