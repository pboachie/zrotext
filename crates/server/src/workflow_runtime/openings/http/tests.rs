// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

mod database;
mod genuine_pair;

fn disconnected() -> OwnerConversationsState {
    OwnerConversationsState {
        database_url: "postgres://unused".into(),
        auth_hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: "https://zrotext.example".into(),
    }
}

fn protected(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}

#[tokio::test]
async fn anonymous_and_bearer_openings_refuse_before_body_or_database() {
    for path in [
        "/v1/owner/workflow/openings",
        "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status",
    ] {
        for bearer in [false, true] {
            let mut request = Request::builder().method("POST").uri(path);
            if bearer {
                request = request.header(header::AUTHORIZATION, "Bearer synthetic");
            }
            let response = router(disconnected())
                .oneshot(request.body(Body::from(vec![0; 8193])).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            protected(&response);
        }
    }
}

#[tokio::test]
async fn status_is_post_only_and_disabled_composition_has_no_opening_routes() {
    let path = "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status";
    let response = router(disconnected())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    protected(&response);
    for enabled_original in [false, true] {
        let app = crate::workflow_runtime::routines::http::owner_router_with_original(
            disconnected(),
            false,
            enabled_original,
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/owner/workflow/openings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
