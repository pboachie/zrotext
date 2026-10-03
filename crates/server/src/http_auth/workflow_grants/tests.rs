// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

fn body() -> serde_json::Value {
    serde_json::json!({"current_password":"synthetic-password", "code":"123456", "connector_id":Uuid::new_v4(),
        "context_id":Uuid::new_v4(),"contact_id":Uuid::new_v4(),"purpose":"operational",
        "permissions":["context_metadata"],"expires_at_ms":1})
}

#[test]
fn published_grant_setup_vector_uses_the_actual_closed_owner_dto() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/workflow-grant-setup-01.json"
    ))
    .unwrap();
    let request = vector["request"].clone();
    assert!(
        serde_json::from_value::<CreateBody>(request.clone())
            .unwrap()
            .grant()
            .is_ok()
    );
    for name in vector["forbidden_fields"].as_array().unwrap() {
        let mut changed = request.clone();
        changed[name.as_str().unwrap()] = serde_json::json!(true);
        assert!(serde_json::from_value::<CreateBody>(changed).is_err());
    }
    for permissions in vector["invalid_permissions"].as_array().unwrap() {
        let mut changed = request.clone();
        changed["permissions"] = permissions.clone();
        assert!(
            serde_json::from_value::<CreateBody>(changed)
                .map(|request| request.grant().is_err())
                .unwrap_or(true)
        );
    }
}

#[test]
fn grant_setup_rejects_duplicate_permissions_credential_fields_and_noncanonical_bindings() {
    let valid: CreateBody = serde_json::from_value(body()).unwrap();
    assert!(valid.grant().is_ok());
    for extra in ["token", "approved", "verified", "account_id", "device_id"] {
        let mut value = body();
        value[extra] = serde_json::json!(true);
        assert!(serde_json::from_value::<CreateBody>(value).is_err());
    }
    for permissions in [
        serde_json::json!([]),
        serde_json::json!(["send", "send"]),
        serde_json::json!(["owner"]),
    ] {
        let mut value = body();
        value["permissions"] = permissions;
        assert!(
            serde_json::from_value::<CreateBody>(value)
                .map(|value| value.grant().is_err())
                .unwrap_or(true)
        );
    }
    for value in ["AA==", "not-a-key", ""] {
        let mut input = body();
        input["signer_key_id"] = serde_json::json!(value);
        assert!(
            serde_json::from_value::<CreateBody>(input)
                .unwrap()
                .grant()
                .is_err()
        );
    }
}

#[tokio::test]
async fn default_off_owner_grant_setup_and_revoke_do_not_connect_to_database() {
    let state = AuthHttpState::new(
        "unavailable".into(),
        Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        "https://owner.example.test".into(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap();
    for (method, path) in [
        ("POST", "/workflow-grants".to_string()),
        ("DELETE", format!("/workflow-grants/{}", Uuid::new_v4())),
    ] {
        let response = super::super::router(state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
