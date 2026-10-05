// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

const ASSETS: [(&str, &str, &str); 2] = [
    (
        "/owner/workflow-exceptions",
        "text/html; charset=utf-8",
        EXCEPTIONS_PAGE,
    ),
    (
        "/owner/workflow-exceptions.js",
        "text/javascript; charset=utf-8",
        EXCEPTIONS_SCRIPT,
    ),
];
const SENTINEL: &str = "synthetic-request-sentinel";

struct Snapshot {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn request(app: Router, method: &str, path: &str, validator: Option<&str>) -> Snapshot {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-synthetic-sentinel", SENTINEL)
        .header("x-customer-routines-enabled", "true");
    if let Some(validator) = validator {
        request = request.header(header::IF_NONE_MATCH, validator);
    }
    let response = app
        .oneshot(request.body(Body::from(SENTINEL)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    // The existing devices script exceeds the exceptions response budget.
    // Only this static regression fixture uses its known compiled byte length.
    let body_limit = if path == "/owner/devices.js" {
        SCRIPT.len()
    } else {
        65536
    };
    let body = axum::body::to_bytes(response.into_body(), body_limit)
        .await
        .unwrap()
        .to_vec();
    Snapshot {
        status,
        headers,
        body,
    }
}

fn assert_secure_uncacheable(response: &Snapshot, content_type: &str) {
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CONTENT_TYPE], content_type);
    assert_eq!(response.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers[header::CONTENT_SECURITY_POLICY], CSP);
    assert_eq!(response.headers["x-content-type-options"], "nosniff");
    assert_eq!(response.headers["referrer-policy"], "no-referrer");
    assert_eq!(
        response.headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=63072000; includeSubDomains"
    );
    for name in [header::ETAG, header::SET_COOKIE, header::LOCATION] {
        assert!(!response.headers.contains_key(name));
    }
}

#[tokio::test]
async fn default_and_disabled_exceptions_routes_cannot_be_enabled_by_requests() {
    for app in [router(), router_with_customer_routines(false)] {
        for (path, _, _) in ASSETS {
            for method in ["GET", "HEAD", "POST"] {
                let uri = format!("{path}?customer_routines_enabled=true&account={SENTINEL}");
                let response = request(app.clone(), method, &uri, None).await;
                assert_eq!(response.status, StatusCode::NOT_FOUND, "{method} {path}");
                assert!(!String::from_utf8_lossy(&response.body).contains(SENTINEL));
                assert!(!response.headers.contains_key(header::LOCATION));
                assert!(!response.headers.contains_key(header::SET_COOKIE));
            }
        }
    }
}

#[tokio::test]
async fn enabled_exceptions_assets_return_exact_sources_without_request_reflection() {
    for (path, content_type, source) in ASSETS {
        let uri = format!("{path}?account={SENTINEL}&context={SENTINEL}&cursor={SENTINEL}");
        let response = request(router_with_customer_routines(true), "GET", &uri, None).await;
        assert_secure_uncacheable(&response, content_type);
        assert_eq!(response.body, source.as_bytes());
        assert!(!String::from_utf8_lossy(&response.body).contains(SENTINEL));
    }
}

#[tokio::test]
async fn enabled_exceptions_head_preserves_headers_and_has_no_body() {
    for (path, content_type, _) in ASSETS {
        let response = request(router_with_customer_routines(true), "HEAD", path, None).await;
        assert_secure_uncacheable(&response, content_type);
        assert!(response.body.is_empty());
    }
}

#[tokio::test]
async fn enabled_exceptions_assets_never_revalidate_to_not_modified() {
    for (path, content_type, source) in ASSETS {
        let matching = asset_etag(source);
        for validator in ["\"stale\"", "*", matching.as_str()] {
            let response = request(
                router_with_customer_routines(true),
                "GET",
                path,
                Some(validator),
            )
            .await;
            assert_secure_uncacheable(&response, content_type);
            assert_eq!(response.body, source.as_bytes());
        }
    }
}

#[tokio::test]
async fn enabled_exceptions_assets_refuse_mutation_methods() {
    for (path, _, _) in ASSETS {
        for method in ["POST", "PUT", "DELETE"] {
            let response = request(router_with_customer_routines(true), method, path, None).await;
            assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
            assert!(!String::from_utf8_lossy(&response.body).contains(SENTINEL));
            assert!(!response.headers.contains_key(header::SET_COOKIE));
            assert!(!response.headers.contains_key(header::LOCATION));
        }
    }
}

#[tokio::test]
async fn exceptions_gate_keeps_unknown_paths_and_data_apis_absent() {
    for enabled in [false, true] {
        for path in [
            "/owner/workflow-exceptions/",
            "/owner/workflow-exceptions.js/",
            "/owner/workflow-exceptions-unknown",
            "/v1/owner/workflow/contexts/synthetic-context/exceptions",
            "/owner/conversation",
            "/owner/conversation-line-setup.js",
        ] {
            let response = request(router_with_customer_routines(enabled), "GET", path, None).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{enabled} {path}");
        }
    }
}

#[tokio::test]
async fn devices_navigation_uses_one_hidden_owner_link_only_when_enabled() {
    assert_eq!(
        PAGE.matches("<!-- workflow-exceptions-navigation -->").count(),
        1
    );
    for enabled in [false, true] {
        let uri = format!("/owner/devices?customer_routines_enabled=true&account={SENTINEL}");
        let response = request(router_with_customer_routines(enabled), "GET", &uri, None).await;
        assert_secure_uncacheable(&response, "text/html; charset=utf-8");
        let html = String::from_utf8(response.body).unwrap();
        assert!(!html.contains(SENTINEL));
        assert!(!html.contains("<!-- workflow-exceptions-navigation -->"));
        assert!(html.contains("href=\"/owner/account\""));
        assert!(html.contains("id=\"owner-main\""));
        assert!(html.contains("src=\"/owner/owner-shell.js\""));
        if enabled {
            let link = "<a href=\"/owner/workflow-exceptions\" data-owner-only hidden>Workflow exceptions</a>";
            assert_eq!(html.matches(link).count(), 1);
            assert_eq!(html.matches("/owner/workflow-exceptions").count(), 1);
            let nav = html.split("<nav class=\"owner-nav\"").nth(1).unwrap();
            assert!(nav.split("</nav>").next().unwrap().contains(link));
        } else {
            assert!(!html.contains("workflow-exceptions"));
            assert!(!html.contains("Workflow exceptions"));
        }
    }
}

#[tokio::test]
async fn default_devices_navigation_and_head_remain_closed() {
    let response = request(router(), "GET", "/owner/devices", None).await;
    assert_secure_uncacheable(&response, "text/html; charset=utf-8");
    assert!(!String::from_utf8_lossy(&response.body).contains("workflow-exceptions"));
    for enabled in [false, true] {
        let response = request(
            router_with_customer_routines(enabled),
            "HEAD",
            "/owner/devices",
            None,
        )
        .await;
        assert_secure_uncacheable(&response, "text/html; charset=utf-8");
        assert!(response.body.is_empty());
    }
}

#[test]
fn exceptions_page_preserves_manual_selection_and_closed_visit_copy() {
    for id in ["exceptions-account", "exceptions-context"] {
        let marker = format!("id=\"{id}\"");
        let input = EXCEPTIONS_PAGE.split(marker.as_str()).nth(1).unwrap();
        assert!(!input.split('>').next().unwrap().contains("value="));
    }
    assert!(EXCEPTIONS_PAGE.contains("id=\"exceptions-ack\" type=\"checkbox\""));
    assert!(EXCEPTIONS_PAGE.contains("Independently intended account"));
    assert!(EXCEPTIONS_PAGE.contains("Known context"));
    assert!(EXCEPTIONS_PAGE.contains("Clearing or leaving closes this visit."));
    assert!(EXCEPTIONS_PAGE.contains("No metadata is stored by this page."));
    assert!(EXCEPTIONS_PAGE.contains("They do not approve work, send messages"));
    assert!(
        EXCEPTIONS_PAGE
            .contains("Reading is unavailable if this server does not provide that response.")
    );
    assert!(EXCEPTIONS_PAGE.contains("src=\"workflow-exceptions.js\""));
    assert!(!EXCEPTIONS_PAGE.contains("<form"));
    assert!(!EXCEPTIONS_PAGE.contains("type=\"submit\""));
}

#[tokio::test]
async fn routines_gate_preserves_existing_static_sources_and_cache_policy() {
    for enabled in [false, true] {
        for (path, source, content_type, cache) in [
            (
                "/owner/account",
                ACCOUNT_PAGE,
                "text/html; charset=utf-8",
                "no-store",
            ),
            (
                "/owner/devices.js",
                SCRIPT,
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/owner-shell.js",
                SHELL_SCRIPT,
                "text/javascript; charset=utf-8",
                "no-cache",
            ),
            (
                "/owner/devices.css",
                STYLE,
                "text/css; charset=utf-8",
                "no-cache",
            ),
        ] {
            let app = router_with_customer_routines(enabled);
            let response = request(app.clone(), "GET", path, None).await;
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.headers[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers[header::CACHE_CONTROL], cache);
            assert_eq!(response.body, source.as_bytes());
            if cache == "no-cache" {
                let etag = response.headers[header::ETAG].to_str().unwrap();
                let response = request(app, "GET", path, Some(etag)).await;
                assert_eq!(response.status, StatusCode::NOT_MODIFIED);
                assert_eq!(response.headers[header::CACHE_CONTROL], "no-cache");
                assert_eq!(response.headers[header::ETAG], etag);
                assert!(response.body.is_empty());
            } else {
                assert_secure_uncacheable(&response, content_type);
            }
        }
    }
}

#[tokio::test]
async fn existing_ingress_wrapper_preserves_static_gate_and_method_refusals() {
    for enabled in [false, true] {
        for (method, expected) in [
            ("GET", StatusCode::OK),
            ("HEAD", StatusCode::OK),
            ("POST", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let app = crate::ingress::protect(router_with_customer_routines(enabled));
            let response = request(app, method, "/owner/workflow-exceptions", None).await;
            assert_eq!(
                response.status,
                if enabled {
                    expected
                } else {
                    StatusCode::NOT_FOUND
                }
            );
            assert!(!String::from_utf8_lossy(&response.body).contains(SENTINEL));
            if enabled && method != "POST" {
                assert_secure_uncacheable(&response, "text/html; charset=utf-8");
                if method == "HEAD" {
                    assert!(response.body.is_empty());
                }
            }
        }
    }
}
