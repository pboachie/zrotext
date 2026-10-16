// SPDX-License-Identifier: AGPL-3.0-only
use super::db_tests::{ORIGIN, SmsCase};
use super::*;
use crate::{auth, http_auth};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; original-session v2 ceremony and genuine enrollment"]
async fn setup_resume_is_account_fenced_and_reports_original_line_session_without_restoring_secrets()
 {
    let c = SmsCase::new().await;
    let mut db = c.connect().await;
    c.seed_lease(2).await;
    let opening = Uuid::new_v4();
    let challenge = open(
        &mut db,
        &c.principal,
        c.line,
        c.device,
        Purpose::Sms,
        opening,
        None,
    )
    .await
    .unwrap();
    let state = http_auth::AuthHttpState::new(
        c.url.clone(),
        c.hasher.clone(),
        ORIGIN.into(),
        Arc::new(http_auth::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_sms_line_activation_enabled();
    let app = http_auth::setup::router(state);
    let response = app
        .clone()
        .oneshot(c.request("GET", "/setup", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let first: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        first["account_id"],
        c.principal.tenant.account_id().to_string()
    );
    assert_eq!(first["devices"][0]["device_id"], c.device.to_string());
    assert_eq!(first["devices"][0]["line_activation_version"], 2);
    assert_eq!(first["devices"][0]["setup_line_id"], c.line.to_string());
    assert_eq!(
        first["line_activations"][0]["challenge_id"],
        challenge.tuple.id.to_string()
    );
    assert_eq!(
        first["line_activations"][0]["opening_id"],
        opening.to_string()
    );
    assert_eq!(first["line_activations"][0]["same_session"], true);
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    for secret in [
        "token",
        "nonce",
        "signature",
        "statement",
        &c.credentials.token,
        &c.credentials.csrf_token,
    ] {
        assert!(!text.contains(secret));
    }
    let req = |token: &str, csrf: &str| {
        Request::builder()
            .uri("/setup")
            .header(
                "cookie",
                format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
            )
            .header("x-zrotext-csrf", csrf)
            .body(Body::empty())
            .unwrap()
    };
    // This second session was issued by the real MFA-required fixture login.
    let response = app
        .clone()
        .oneshot(req(
            &c.second_credentials.token,
            &c.second_credentials.csrf_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let changed: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(changed["line_activations"][0]["same_session"], false);
    assert_eq!(changed["line_activations"][0]["status"], "session_changed");
    assert_ne!(first["session_id"], changed["session_id"]);
    assert_eq!(
        first["devices"][0]["setup_line_id"],
        changed["devices"][0]["setup_line_id"]
    );
    assert_ne!(
        first["devices"][0]["setup_opening_id"],
        changed["devices"][0]["setup_opening_id"]
    );
    let password = crate::test_keys::password(9);
    let other = auth::register(&mut db, &c.hasher, "setup-second@example.test", &password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &c.hasher, &other.verification_token)
        .await
        .unwrap();
    let credentials = auth::login(&db, &c.hasher, "setup-second@example.test", &password)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(req(&credentials.token, &credentials.csrf_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let other_view: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(other_view["devices"].as_array().unwrap().is_empty());
    assert!(
        other_view["line_activations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Seed a distinct observer row; membership roles are immutable.
    let observer = Uuid::new_v4();
    db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'setup-observer@example.test',password_hash,clock_timestamp() FROM users WHERE id=$2",&[&observer,&other.user_id]).await.unwrap();
    db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
        &[&c.principal.tenant.account_id(), &observer],
    )
    .await
    .unwrap();
    let observer = auth::login(&db, &c.hasher, "setup-observer@example.test", &password)
        .await
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(req(&observer.token, &observer.csrf_token))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // A reconnect preserves enrollment but invalidates the old unapproved
    // declaration's original phone lease.
    c.seed_lease(2).await;
    let response = app
        .clone()
        .oneshot(c.request("GET", "/setup", serde_json::json!({})))
        .await
        .unwrap();
    let reconnected: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        reconnected["line_activations"][0]["status"],
        "connection_changed"
    );
    assert_eq!(reconnected["devices"][0]["device_id"], c.device.to_string());
    let disabled = http_auth::setup::router(
        http_auth::AuthHttpState::new(
            c.url.clone(),
            c.hasher.clone(),
            ORIGIN.into(),
            Arc::new(http_auth::DisabledVerificationDispatcher),
        )
        .unwrap(),
    );
    let response = disabled
        .oneshot(c.request("GET", "/setup", serde_json::json!({})))
        .await
        .unwrap();
    let disabled: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(disabled["sms_line_activation_available"], false);
    assert!(disabled["line_activations"].as_array().unwrap().is_empty());
    assert!(disabled["devices"][0]["line_activation_version"].is_null());
    // A historical approval without its current key is not current authority.
    db.execute("DELETE FROM device_keys WHERE device_id=$1", &[&c.device])
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(c.request("GET", "/setup", serde_json::json!({})))
        .await
        .unwrap();
    let missing: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(missing["pairings"][0]["status"], "revoked");
    assert!(missing["pairings"][0]["approved_device_id"].is_null());
    assert!(missing["devices"].as_array().unwrap().is_empty());
    let cookie_only = Request::builder()
        .uri("/setup")
        .header(
            "cookie",
            format!("__Host-zrotext_session={}", c.credentials.token),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(cookie_only).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&c.principal.session_id],
    )
    .await
    .unwrap();
    assert_eq!(
        app.oneshot(c.request("GET", "/setup", serde_json::json!({})))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    c.cleanup().await;
}
