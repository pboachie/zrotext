// SPDX-License-Identifier: AGPL-3.0-only
//! HTTP wire mapping controls. The actual authenticated PG ceremony is tested
//! separately; these do not claim a mounted browser/server integration.
use super::*;
use axum::body::Body as HttpBody;
use tower::ServiceExt;

async fn request(app: Router) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/proof")
                .body(HttpBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn pending_proof_is_a_repeatable_closed_not_found_refusal() {
    // A missing genuine retained device proof maps through the SAME response
    // function as the handler, so the strict owner client can keep its original
    // opening. It is not a malformed/ambiguous empty HTTP failure.
    let app = Router::new().route(
        "/proof",
        post(|| async { wire_response(Err(StatusCode::NOT_FOUND)) }),
    );
    for _ in 0..2 {
        let (status, value) = request(app.clone()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value, serde_json::json!({"error":"not_found"}));
    }
    let failed = Router::new().route(
        "/proof",
        post(|| async { wire_response(Err(StatusCode::INTERNAL_SERVER_ERROR)) }),
    );
    let (status, value) = request(failed).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        value,
        serde_json::json!({"error":"temporarily_unavailable"})
    );
}
#[tokio::test]
async fn body_media_timeout_and_bounds_share_frozen_invalid_request_shape() {
    for internal in [
        StatusCode::BAD_REQUEST,
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    ] {
        let app = Router::new().route(
            "/proof",
            post(move || async move { wire_response(Err(internal)) }),
        );
        let (status, value) = request(app).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value, serde_json::json!({"error":"invalid_request"}));
    }
    assert_eq!(
        mapped(live::Error::Unsupported),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
