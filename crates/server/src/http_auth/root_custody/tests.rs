// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[test]
fn custody_transport_refuses_noncanonical_oversized_and_secret_fields() {
    assert!(decode("AA==", 1).is_ok());
    assert!(decode("AA", 1).is_err());
    assert!(decode("AAA=", 1).is_err());
    assert!(fixed::<32>("AA==").is_err());
    assert!(serde_json::from_value::<CompleteBody>(serde_json::json!({
        "unsigned_enrollment_b64":"", "enrollment_signature_b64":"", "custody_signature_b64":"",
        "independently_compared_fingerprint_b64":"", "encrypted_backup_b64":"", "public_card_b64":"",
        "mfa_code":"", "recovery_token":"synthetic_canary"
    })).is_err());
}

#[tokio::test]
async fn standard_auth_router_does_not_expose_root_custody() {
    let state = AuthHttpState::new(
        "not-a-database".into(),
        Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(91)).unwrap()),
        "https://owner.example.test".into(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap();
    assert!(!state.root_custody_enabled);
    for path in ["/sealed-root", "/sealed-root/challenge"] {
        let response = super::super::router(state.clone())
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

fn opt_in_state() -> AuthHttpState {
    AuthHttpState::new(
        "not-a-database".into(),
        Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(91)).unwrap()),
        "https://owner.example.test".into(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap()
}

#[test]
fn operator_root_custody_opt_in_requires_the_mfa_cipher() {
    assert!(
        opt_in_state()
            .with_root_custody_opt_in(true, false)
            .is_err()
    );
    let disabled = opt_in_state()
        .with_root_custody_opt_in(false, false)
        .unwrap();
    assert!(!disabled.root_custody_enabled);
    let cipher = Arc::new(crate::auth::mfa::MfaCipher::new(crate::test_keys::key(92)).unwrap());
    let enabled = opt_in_state()
        .with_mfa_cipher(cipher)
        .with_root_custody_opt_in(true, false)
        .unwrap();
    assert!(enabled.root_custody_enabled);
    assert!(
        enabled
            .clone()
            .with_root_custody_opt_in(true, true)
            .is_err()
    );
    assert!(
        !enabled
            .clone()
            .with_root_custody_opt_in(false, true)
            .unwrap()
            .root_custody_enabled
    );
    assert!(
        !enabled
            .with_root_custody_opt_in(false, false)
            .unwrap()
            .root_custody_enabled
    );
}

#[tokio::test]
async fn operator_root_custody_opt_in_mounts_only_the_existing_ceremony() {
    let cipher = Arc::new(crate::auth::mfa::MfaCipher::new(crate::test_keys::key(92)).unwrap());
    let state = opt_in_state()
        .with_mfa_cipher(cipher)
        .with_root_custody_opt_in(true, false)
        .unwrap();
    let response = super::super::router(state)
        .oneshot(
            Request::builder()
                .uri("/sealed-root/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The challenge exists, but GET cannot perform enrollment or touch the DB.
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL and DATABASE_ALLOW_PLAINTEXT=true; disposable PostgreSQL custody HTTP test"]
async fn authenticated_http_custody_requires_csrf_and_exports_same_independently_compared_pin() {
    use crate::sealed_root_ceremony::tests::Owner;
    use crate::sealed_root_custody::tests::{bundle, sign};
    use axum::body::to_bytes;
    use sha2::{Digest, Sha256};
    let o = Owner::new().await;
    o.f.db
        .batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/069_sealed_root_custody.sql"
        ))
        .await
        .unwrap();
    let (backup, card, compared) = bundle(&o.root, &o.pin, o.principal.tenant.account_id());
    let mut url = url::Url::parse(&o.f.url).unwrap();
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={}", o.f.schema));
    let state = AuthHttpState::new(
        url.to_string(),
        Arc::new(o.hasher),
        "https://owner.example.test".into(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_mfa_cipher(Arc::new(o.cipher))
    .with_root_custody_opt_in(true, false)
    .unwrap();
    let app = super::super::router(state);
    let cookie = format!(
        "{}={}; {}={}",
        super::super::SESSION_COOKIE,
        o.token,
        super::super::CSRF_COOKIE,
        o.csrf
    );
    let headers = |method: &str, path: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", &cookie)
            .header("origin", "https://owner.example.test")
            .header("x-zrotext-csrf", &o.csrf)
            .header("content-type", "application/json")
    };
    let payload = serde_json::json!({"root_pin_b64":STANDARD.encode(o.pin),
        "independently_compared_fingerprint_b64":STANDARD.encode(compared),
        "encrypted_backup_b64":STANDARD.encode(&backup),"public_card_b64":STANDARD.encode(&card)});
    let missing_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sealed-root/challenge")
                .header("cookie", &cookie)
                .header("origin", "https://owner.example.test")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(
            headers("POST", "/sealed-root/challenge")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    let unsigned = STANDARD
        .decode(response["unsigned_enrollment_b64"].as_str().unwrap())
        .unwrap();
    let message = [
        b"ZTSE/root-custody/v1\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        &unsigned,
        &Sha256::digest(&backup),
        &Sha256::digest(&card),
        &compared,
    ]
    .concat();
    assert_eq!(STANDARD.encode(&message), response["custody_statement_b64"]);
    let enrollment = [
        b"ZTSE/root-enroll/v1\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        &unsigned,
    ]
    .concat();
    let completion = serde_json::json!({"unsigned_enrollment_b64":STANDARD.encode(&unsigned),
        "enrollment_signature_b64":STANDARD.encode(sign(&o.root,&enrollment)),"custody_signature_b64":STANDARD.encode(sign(&o.root,&message)),
        "independently_compared_fingerprint_b64":STANDARD.encode(compared),"encrypted_backup_b64":STANDARD.encode(&backup),
        "public_card_b64":STANDARD.encode(&card),"mfa_code":o.recovery});
    let response = app
        .clone()
        .oneshot(
            headers("POST", "/sealed-root")
                .body(Body::from(completion.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(
            headers("GET", "/sealed-root")
                .header("x-zrotext-root-fingerprint", STANDARD.encode(compared))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let exported: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(exported["root_pin_b64"], STANDARD.encode(o.pin));
    assert_eq!(exported["encrypted_backup_b64"], STANDARD.encode(backup));
    assert_eq!(exported["public_card_b64"], STANDARD.encode(card));
    assert!(exported.get("recovery_token").is_none());
    o.f.cleanup().await;
}
