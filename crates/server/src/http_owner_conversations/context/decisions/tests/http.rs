// SPDX-License-Identifier: AGPL-3.0-only
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use tower::ServiceExt;
#[tokio::test]
async fn owner_decisions_reject_anonymous_bearer_and_oversized_requests_before_database_access() {
    for path in [
        "actions",
        "actions/status",
        "actions/decide",
        "actions/edit",
        "actions/bind",
        "responses/correlate",
        "takeover",
    ] {
        for bearer in [false, true] {
            let state = crate::http_owner_conversations::OwnerConversationsState {
                database_url: "postgres://unused".into(),
                auth_hasher: std::sync::Arc::new(
                    crate::http_owner_conversations::TokenHasher::new(crate::test_keys::key(83))
                        .unwrap(),
                ),
                canonical_origin: "https://zrotext.example".into(),
            };
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("/v1/owner/workflow/{path}"));
            if bearer {
                request = request.header(header::AUTHORIZATION, "Bearer synthetic");
            }
            let response = super::super::http::router(state)
                .oneshot(request.body(Body::from(vec![0; 8193])).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{path} bearer={bearer}"
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }
}
