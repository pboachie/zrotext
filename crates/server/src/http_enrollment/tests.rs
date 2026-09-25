use super::*;
use crate::{
    auth::{TokenHasher, login, register, verify_email},
    enrollment::{device_challenge_bytes, enrollment_challenge_bytes},
};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use p256::elliptic_curve::Generate;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn request(method: Method, uri: &str, body: Value, session: Option<(&str, &str)>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some((token, csrf)) = session {
        builder = builder
            .header(
                header::COOKIE,
                format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
            )
            .header(header::ORIGIN, "https://test.example")
            .header("x-zrotext-csrf", csrf);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json_response(response: Response) -> Value {
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn apply_migrations(admin: &Client) {
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
    ] {
        admin.batch_execute(sql).await.unwrap();
    }
}

#[test]
fn binary_fields_have_strict_bounds() {
    assert!(decode_nonce(&URL_SAFE_NO_PAD.encode([0u8; 32])).is_ok());
    assert!(decode_nonce(&URL_SAFE_NO_PAD.encode([0u8; 31])).is_err());
    assert!(decode_nonce(&format!("{}=", URL_SAFE_NO_PAD.encode([0u8; 32]))).is_err());
    assert!(decode_bounded(&"A".repeat(215), 214, 80, 160).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn http_pairing_requires_csrf_proves_key_and_revokes_device() {
    let root_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    assert!(root_url.starts_with("postgres://") || root_url.starts_with("postgresql://"));
    let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_enroll_test_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_migrations(&admin).await;
    let auth_hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let enrollment_hasher =
        Arc::new(EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let a = register(
        &mut admin,
        &auth_hasher,
        "http-a@example.test",
        "correct horse 123",
    )
    .await
    .unwrap();
    let b = register(
        &mut admin,
        &auth_hasher,
        "http-b@example.test",
        "correct horse 456",
    )
    .await
    .unwrap();
    verify_email(&mut admin, &auth_hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(&mut admin, &auth_hasher, &b.verification_token)
        .await
        .unwrap();
    let sa = login(
        &admin,
        &auth_hasher,
        "http-a@example.test",
        "correct horse 123",
    )
    .await
    .unwrap();
    let sb = login(
        &admin,
        &auth_hasher,
        "http-b@example.test",
        "correct horse 456",
    )
    .await
    .unwrap();
    let separator = if root_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
    let app = router(EnrollmentHttpState::new(
        scoped_url,
        auth_hasher.clone(),
        enrollment_hasher,
        "https://test.example".into(),
    ));

    let unauthenticated_list = app
        .clone()
        .oneshot(request(Method::GET, "/devices", json!({}), None))
        .await
        .unwrap();
    assert_eq!(unauthenticated_list.status(), StatusCode::UNAUTHORIZED);
    let empty_list = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(empty_list.status(), StatusCode::OK);
    assert_eq!(
        json_response(empty_list).await,
        json!({"devices":[],"next_cursor":null})
    );

    let oversized = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/pairings/{}/claim", Uuid::new_v4()),
            json!({"token":"A".repeat(MAX_BODY_BYTES)}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let forged = Request::builder()
        .method(Method::POST)
        .uri("/pairings")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("__Host-zrotext_session={}", sa.token),
        )
        .body(Body::from(r#"{"display_name":"Phone"}"#))
        .unwrap();
    let response = app.clone().oneshot(forged).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/pairings",
            json!({"display_name":"Phone"}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let created = json_response(response).await;
    let pairing_id: Uuid = created["pairing_id"].as_str().unwrap().parse().unwrap();
    let token = created["token"].as_str().unwrap();

    let signing = SigningKey::generate_from_rng(&mut rng());
    let spki = signing.verifying_key().to_public_key_der().unwrap();
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/pairings/{pairing_id}/claim"),
            json!({"token":token,"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let claim = json_response(response).await;
    assert_eq!(claim["account_id"], a.account_id.to_string());
    let nonce = decode_nonce(claim["challenge_nonce"].as_str().unwrap()).unwrap();
    let fingerprint: [u8; 32] =
        Sha256::digest(signing.verifying_key().to_sec1_point(false).as_bytes()).into();
    let payload = enrollment_challenge_bytes(a.account_id, pairing_id, &fingerprint, &nonce);
    let signature: Signature = signing.sign(&payload);
    let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/prove"),
                json!({"challenge_nonce":claim["challenge_nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}),
                None,
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_response(response).await["proof_verified"], true);

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/pairings/{pairing_id}"),
            json!({}),
            Some((&sb.token, &sb.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/approve"),
                json!({"comparison_code":claim["comparison_code"],"key_fingerprint":claim["key_fingerprint"]}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let device_id: Uuid = json_response(response).await["device_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let owner_devices = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(owner_devices.headers()[header::CACHE_CONTROL], "no-store");
    let owner_devices = json_response(owner_devices).await;
    assert_eq!(owner_devices["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        owner_devices["devices"][0]["device_id"],
        device_id.to_string()
    );
    assert_eq!(owner_devices["devices"][0]["display_name"], "Phone");
    assert_eq!(owner_devices["devices"][0]["revoked"], false);
    assert_eq!(owner_devices["devices"][0]["active_socket_lease"], false);
    assert_eq!(owner_devices["next_cursor"], Value::Null);
    // A lease is written only after device proof. Its owner view follows
    // the writer's site and deployment fences, without asserting radio.
    admin
        .batch_execute("INSERT INTO sites(site_id) VALUES('hub-a'),('hub-b')")
        .await
        .unwrap();
    admin.execute(
            "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,'hub-a','instance-a',1,now()+interval '90 seconds',1)",
            &[&device_id, &a.account_id],
        ).await.unwrap();
    let status =
        |token: &str, csrf: &str| request(Method::GET, "/devices", json!({}), Some((token, csrf)));
    let active = json_response(
        app.clone()
            .oneshot(status(&sa.token, &sa.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(active["devices"][0]["active_socket_lease"], true);
    for readiness in ["sms_ready", "sim_ready", "radio_ready"] {
        assert!(active["devices"][0].get(readiness).is_none());
    }
    let other_tenant_active = json_response(
        app.clone()
            .oneshot(status(&sb.token, &sb.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        other_tenant_active,
        json!({"devices":[],"next_cursor":null})
    );
    admin
        .execute(
            "UPDATE device_sessions SET lease_until=now()-interval '1 second' WHERE device_id=$1",
            &[&device_id],
        )
        .await
        .unwrap();
    let expired = json_response(
        app.clone()
            .oneshot(status(&sa.token, &sa.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(expired["devices"][0]["active_socket_lease"], false);
    admin.execute("UPDATE device_sessions SET site_id='hub-b',instance_id='instance-b',connection_epoch=2,lease_until=now()+interval '90 seconds' WHERE device_id=$1", &[&device_id]).await.unwrap();
    let reconnected = json_response(
        app.clone()
            .oneshot(status(&sa.token, &sa.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(reconnected["devices"][0]["active_socket_lease"], true);
    admin
        .batch_execute("UPDATE deployment_authority SET epoch=2")
        .await
        .unwrap();
    let stale_epoch = json_response(
        app.clone()
            .oneshot(status(&sa.token, &sa.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(stale_epoch["devices"][0]["active_socket_lease"], false);
    admin.batch_execute("UPDATE deployment_authority SET epoch=1; UPDATE sites SET draining=TRUE WHERE site_id='hub-b'").await.unwrap();
    let draining = json_response(
        app.clone()
            .oneshot(status(&sa.token, &sa.csrf_token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(draining["devices"][0]["active_socket_lease"], false);
    admin
        .batch_execute("UPDATE sites SET draining=FALSE WHERE site_id='hub-b'")
        .await
        .unwrap();
    let other_tenant_devices = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&sb.token, &sb.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(
        json_response(other_tenant_devices).await,
        json!({"devices":[],"next_cursor":null})
    );

    let forbidden_revoke = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/devices/{device_id}"),
            json!({}),
            Some((&sb.token, &sb.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(forbidden_revoke.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/devices/{device_id}/challenge"),
            json!({}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    let device_challenge = DeviceChallenge {
        id: challenge["challenge_id"].as_str().unwrap().parse().unwrap(),
        account_id: a.account_id,
        device_id,
        nonce: decode_nonce(challenge["nonce"].as_str().unwrap()).unwrap(),
    };
    let signature: Signature = signing.sign(&device_challenge_bytes(&device_challenge));
    let auth_body = json!({
        "challenge_id":device_challenge.id,
        "account_id":device_challenge.account_id,
        "device_id":device_challenge.device_id,
        "nonce":challenge["nonce"],
        "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    });
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/devices/authenticate",
            auth_body.clone(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/devices/authenticate",
            auth_body,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/devices/{device_id}"),
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let revoked_list = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    let revoked_device = json_response(revoked_list).await;
    assert_eq!(revoked_device["devices"][0]["revoked"], true);
    assert_eq!(revoked_device["devices"][0]["active_socket_lease"], false);

    // Listing stays bounded and the cursor cannot cross tenant scope.
    let sec1 = signing.verifying_key().to_sec1_point(false);
    for index in 0..51 {
        let extra_id = Uuid::new_v4();
        admin
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,$3)",
                &[&extra_id, &a.account_id, &format!("Extra {index}")],
            )
            .await
            .unwrap();
        admin
                .execute(
                    "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
                    &[&extra_id, &a.account_id, &sec1.as_bytes(), &&fingerprint[..]],
                )
                .await
                .unwrap();
    }
    let first_page = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    let first_page = json_response(first_page).await;
    assert_eq!(first_page["devices"].as_array().unwrap().len(), 50);
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/devices?before={cursor}"),
            json!({}),
            Some((&sa.token, &sa.csrf_token)),
        ))
        .await
        .unwrap();
    let second_page = json_response(second_page).await;
    assert_eq!(second_page["devices"].as_array().unwrap().len(), 2);
    assert_eq!(second_page["next_cursor"], Value::Null);
    let tenant_b_cursor = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/devices?before={cursor}"),
            json!({}),
            Some((&sb.token, &sb.csrf_token)),
        ))
        .await
        .unwrap();
    assert_eq!(json_response(tenant_b_cursor).await["devices"], json!([]));
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/devices/{device_id}/challenge"),
            json!({}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let gate_hasher = auth_hasher.clone();
    for _ in 0..19 {
        assert!(
            abuse_limits::consume(
                &admin,
                &gate_hasher,
                Limit::PairClaim,
                Some(&pairing_id.to_string()),
            )
            .await
            .unwrap()
        );
    }
    let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/claim"),
                json!({"token":"x".repeat(47),"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
                None,
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let other_pairing = Uuid::new_v4();
    let response = app
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{other_pairing}/claim"),
                json!({"token":"x".repeat(47),"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
                None,
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    admin
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn phones_pair_and_reconnect_after_anonymous_budgets_are_spent() {
    let root_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_enroll_budget_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_migrations(&admin).await;
    let auth_hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let enrollment_hasher =
        Arc::new(EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let owner = register(
        &mut admin,
        &auth_hasher,
        "budget-owner@example.test",
        &password,
    )
    .await
    .unwrap();
    verify_email(&mut admin, &auth_hasher, &owner.verification_token)
        .await
        .unwrap();
    let session = login(&admin, &auth_hasher, "budget-owner@example.test", &password)
        .await
        .unwrap();
    let separator = if root_url.contains('?') { '&' } else { '?' };
    let app = router(EnrollmentHttpState::new(
        format!("{root_url}{separator}options=-csearch_path%3D{schema}"),
        auth_hasher.clone(),
        enrollment_hasher,
        "https://test.example".into(),
    ));
    let owner_session = Some((session.token.as_str(), session.csrf_token.as_str()));
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/pairings",
            json!({"display_name":"Phone"}),
            owner_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_response(response).await;
    let pairing_id: Uuid = created["pairing_id"].as_str().unwrap().parse().unwrap();
    let token = created["token"].as_str().unwrap().to_owned();

    // One anonymous source spends every public enrollment route budget
    // with made-up pairing and device IDs; the last few go over HTTP.
    let signing = SigningKey::generate_from_rng(&mut rng());
    let spki = URL_SAFE_NO_PAD.encode(
        signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    let zero = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let junk_signature = URL_SAFE_NO_PAD.encode([0u8; 16]);
    let junk = |route: usize| {
        let id = Uuid::new_v4();
        match route {
            0 => request(
                Method::POST,
                &format!("/pairings/{id}/claim"),
                json!({"token":format!("ztp_{zero}"),"public_key_spki":spki}),
                None,
            ),
            1 => request(
                Method::POST,
                &format!("/pairings/{id}/prove"),
                json!({"challenge_nonce":zero,"signature_der":junk_signature}),
                None,
            ),
            2 => request(
                Method::POST,
                &format!("/devices/{id}/challenge"),
                json!({}),
                None,
            ),
            _ => request(
                Method::POST,
                "/devices/authenticate",
                json!({"challenge_id":Uuid::new_v4(),"account_id":owner.account_id,"device_id":id,"nonce":zero,"signature_der":junk_signature}),
                None,
            ),
        }
    };
    let limits = [
        Limit::PairClaim,
        Limit::PairProof,
        Limit::DeviceChallenge,
        Limit::DeviceAuthenticate,
    ];
    for (route, limit) in limits.into_iter().enumerate() {
        for _ in 0..298 {
            assert!(
                abuse_limits::consume(
                    &admin,
                    &auth_hasher,
                    limit,
                    Some(&Uuid::new_v4().to_string()),
                )
                .await
                .unwrap()
            );
        }
        for _ in 0..2 {
            let status = app.clone().oneshot(junk(route)).await.unwrap().status();
            assert!(status == StatusCode::NOT_FOUND || status == StatusCode::OK);
        }
        assert_eq!(
            app.clone().oneshot(junk(route)).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    // Knowing the pairing ID is not enough; its one-use token is.
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/pairings/{pairing_id}/claim"),
            json!({"token":format!("ztp_{zero}"),"public_key_spki":spki}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // The real phone still pairs.
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/pairings/{pairing_id}/claim"),
            json!({"token":token,"public_key_spki":spki}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let claim = json_response(response).await;
    let nonce = decode_nonce(claim["challenge_nonce"].as_str().unwrap()).unwrap();
    let fingerprint: [u8; 32] =
        Sha256::digest(signing.verifying_key().to_sec1_point(false).as_bytes()).into();
    let payload = enrollment_challenge_bytes(owner.account_id, pairing_id, &fingerprint, &nonce);
    let signature: Signature = signing.sign(&payload);
    let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/prove"),
                json!({"challenge_nonce":claim["challenge_nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}),
                None,
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_response(response).await["proof_verified"], true);
    let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/approve"),
                json!({"comparison_code":claim["comparison_code"],"key_fingerprint":claim["key_fingerprint"]}),
                owner_session,
            ))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let device_id: Uuid = json_response(response).await["device_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // The enrolled phone still reconnects.
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/devices/{device_id}/challenge"),
            json!({}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    let device_challenge = DeviceChallenge {
        id: challenge["challenge_id"].as_str().unwrap().parse().unwrap(),
        account_id: owner.account_id,
        device_id,
        nonce: decode_nonce(challenge["nonce"].as_str().unwrap()).unwrap(),
    };
    // A stale nonce for the real device does not pass the probe.
    let stale = json!({
        "challenge_id":device_challenge.id,
        "account_id":owner.account_id,
        "device_id":device_id,
        "nonce":zero,
        "signature_der":junk_signature,
    });
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/devices/authenticate", stale, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let signature: Signature = signing.sign(&device_challenge_bytes(&device_challenge));
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/devices/authenticate",
            json!({
                "challenge_id":device_challenge.id,
                "account_id":owner.account_id,
                "device_id":device_id,
                "nonce":challenge["nonce"],
                "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Junk is still refused and left no rows behind.
    for route in 0..4 {
        assert_eq!(
            app.clone().oneshot(junk(route)).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let rows: i64 = admin
        .query_one("SELECT count(*) FROM auth_abuse_counters", &[])
        .await
        .unwrap()
        .get(0);
    // Per route: the anonymous budget row and 300 admitted junk subjects,
    // plus a verified ceiling and the one real pairing or device subject.
    assert_eq!(rows, 4 * (1 + 300) + 4 * 2);
    admin
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}
