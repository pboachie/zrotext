// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn workflow() -> WorkflowHttpState {
    WorkflowHttpState {
        database_url: "unreachable-fixture-database".into(),
        hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    }
}
fn owner() -> OwnerConversationsState {
    OwnerConversationsState {
        database_url: "unreachable-fixture-database".into(),
        auth_hasher: workflow().hasher,
        canonical_origin: "https://example.invalid".into(),
    }
}
fn request(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn original_operations_are_closed_before_database_authentication_when_gate_is_off() {
    for operation in ["admit_original", "current_original"] {
        let response = router(workflow(), true)
            .oneshot(request(
                "/v1/workflow/routines",
                serde_json::json!({"operation":operation,"params":{}}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = router(workflow(), true)
        .oneshot(request(
            "/v1/workflow/routines",
            serde_json::json!({"operation":"current","params":{}}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router_with_original(workflow(), true, true)
        .oneshot(request(
            "/v1/workflow/routines",
            serde_json::json!({"operation":"current_original","params":{}}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn original_policy_and_supplemental_headers_are_closed_before_owner_extractors() {
    let response = owner_router(owner(), true)
        .oneshot(request(
            "/v1/owner/workflow/routines/policy",
            serde_json::json!({"original_input":{"grant_id":"example"}}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let mut req = request("/v1/owner/workflow/routines/output", serde_json::json!({}));
    req.headers_mut()
        .insert("x-zrotext-original-reader", "example".parse().unwrap());
    let response = owner_router(owner(), true).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
