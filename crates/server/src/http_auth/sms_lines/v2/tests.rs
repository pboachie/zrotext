// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::TokenHasher,
    http_auth::{self, DisabledVerificationDispatcher},
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

#[test]
fn raw_owner_objects_reject_arrays_duplicates_nulls_and_type_confusion() {
    let valid = r#"{"device_id":"aabbccdd-1122-3344-5566-778899aabbcc","opening_id":"11223344-5566-7788-99aa-bbccddeeff00"}"#;
    assert!(serde_json::from_str::<OpenBody>(valid).is_ok());
    // Every positional element has the correct type; only object shape differs.
    assert!(
        serde_json::from_str::<OpenBody>(
            r#"["aabbccdd-1122-3344-5566-778899aabbcc","11223344-5566-7788-99aa-bbccddeeff00"]"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<ApproveBody>(r#"["synthetic"]"#).is_err());
    assert!(
        serde_json::from_str::<ApproveBody>(r#"{"owner_signature_der_b64url":"synthetic"}"#)
            .is_ok()
    );
    for raw in [
        r#"{"device_id":"first","device_id":"second","opening_id":"third"}"#,
        r#"{"device_id":"first","\u0064evice_id":"second","opening_id":"third"}"#,
        r#"{"device_id":"first","opening_id":"second","opening_id":"third"}"#,
        r#"{"device_id":"first"}"#,
        r#"{"device_id":"first","opening_id":"second","v":2}"#,
    ] {
        assert!(serde_json::from_str::<OpenBody>(raw).is_err(), "{raw}");
    }
    for value in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(2),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        for field in ["device_id", "opening_id"] {
            let mut body: serde_json::Value = serde_json::from_str(valid).unwrap();
            body[field] = value.clone();
            assert!(serde_json::from_str::<OpenBody>(&body.to_string()).is_err());
        }
        assert!(
            serde_json::from_str::<ApproveBody>(
                &serde_json::json!({"owner_signature_der_b64url":value}).to_string()
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_str::<ApproveBody>(
            r#"{"owner_signature_der_b64url":"first","\u006fwner_signature_der_b64url":"second"}"#
        )
        .is_err()
    );
}

#[test]
fn owner_bodies_reject_caller_account_version_and_noncanonical_identifiers() {
    let good = serde_json::json!({"device_id":Uuid::new_v4(),"opening_id":Uuid::new_v4()});
    assert!(serde_json::from_value::<OpenBody>(good.clone()).is_ok());
    for key in ["account_id", "protocol_version", "trusted", "nonce"] {
        let mut bad = good.clone();
        bad[key] = serde_json::json!(true);
        assert!(serde_json::from_value::<OpenBody>(bad).is_err());
    }
    assert!(id(&Uuid::nil().to_string()).is_err());
    assert!(id("AABBCCDD-1122-3344-5566-778899AABBCC").is_err());
    assert!(id("aabbccdd112233445566778899aabbcc").is_err());
    assert!(signature("AA==").is_err());
    assert!(signature("AAAAAAAAAAA").is_err());
}
#[tokio::test]
async fn opt_out_and_owner_cookie_precede_pending_body_and_database_connection() {
    for enabled in [false, true] {
        let mut state = http_auth::AuthHttpState::new(
            "invalid".into(),
            Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
            "https://owner.example.test".into(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        if enabled {
            state = state.with_sms_line_activation_enabled();
        }
        let line = Uuid::new_v4();
        let challenge = Uuid::new_v4();
        for (method, path) in [
            ("POST", format!("/sms-lines/{line}/activations-v2")),
            (
                "GET",
                format!("/sms-lines/{line}/activations-v2/{challenge}"),
            ),
            (
                "POST",
                format!("/sms-lines/{line}/activations-v2/{challenge}/approve"),
            ),
        ] {
            let body = Body::from_stream(futures_util::stream::pending::<
                std::result::Result<axum::body::Bytes, std::io::Error>,
            >());
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                http_auth::router(state.clone()).oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(body)
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
    }
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; genuine auth/MFA/owner key and enrollment"]
async fn actual_owner_routes_keep_opening_identity_and_refuse_wrong_origin_and_csrf() {
    use crate::sealed_inbound::line_activation::v2_runtime::db_tests::SmsCase;
    let c = SmsCase::new().await;
    c.seed_lease(2).await;
    let app = c.app();
    let path = format!("/sms-lines/{}/activations-v2", c.line);
    let body = serde_json::json!({"device_id":c.device,"opening_id":Uuid::new_v4()});
    for header in ["origin", "x-zrotext-csrf"] {
        let mut request = c.request("POST", &path, body.clone());
        request.headers_mut().insert(
            header,
            if header == "origin" {
                "https://other.example"
            } else {
                "ztc_wrong"
            }
            .parse()
            .unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    for raw in [
        r#"["device","opening"]"#,
        r#"{"device_id":"a","opening_id":"b","\u0064evice_id":"c"}"#,
        r#"{"device_id":null,"opening_id":"b"}"#,
        r#"{"device_id":"a","opening_id":2}"#,
        r#"{"device_id":"a","opening_id":"b","protocol_version":2}"#,
    ] {
        let mut request = c.request("POST", &path, body.clone());
        *request.body_mut() = Body::from(raw);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        c.database
            .owner
            .query_one("SELECT count(*) FROM line_activation_v2_pending", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    for header in ["origin", "x-zrotext-csrf"] {
        let mut request = c.request("POST", &path, body.clone());
        request
            .headers_mut()
            .insert(header, "invalid".parse().unwrap());
        *request.body_mut() = Body::from_stream(futures_util::stream::pending::<
            std::result::Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.clone().oneshot(request),
        )
        .await
        .expect("authenticated refusal before pending body")
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let mut previous = None;
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(c.request("POST", &path, body.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert!(value["generation"].is_string());
        assert!(value["expires_at_ms"].is_i64());
        assert!(value.get("nonce").is_none());
        if let Some(previous) = previous {
            assert_eq!(previous, value);
        }
        previous = Some(value);
    }
    c.cleanup().await;
}
