// SPDX-License-Identifier: AGPL-3.0-only
use super::tests::{apply_migrations, json_response, request};
use super::*;
use crate::auth::{self, login, register, verify_email};
use axum::http::Method;
use enrollment::binding::{BindingChallenge, challenge_bytes};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[test]
fn binding_requests_are_closed_objects_and_canonical_ids() {
    for invalid in [
        r#"["AA"]"#,
        r#"{"key_fingerprint":"AA","extra":true}"#,
        r#"{"key_fingerprint":"AA","key_fingerprint":"AA"}"#,
    ] {
        assert!(serde_json::from_str::<binding::ChallengeBody>(invalid).is_err());
    }
    assert!(serde_json::from_str::<binding::ReadBody>(r#"["a","b","c","d"]"#).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated synthetic PostgreSQL fixture"]
async fn binding_recovers_lost_claim_proof_approval_and_pruned_receipt_but_refuses_revocation() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("binding_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    apply_migrations(&db).await;
    let ah = Arc::new(TokenHasher::new(crate::test_keys::key(1)).unwrap());
    let eh = Arc::new(EnrollmentHasher::new(crate::test_keys::key(2)).unwrap());
    let password = crate::test_keys::password(3);
    let signup = register(&mut db, &ah, "binding@example.test", &password)
        .await
        .unwrap();
    verify_email(&mut db, &ah, &signup.verification_token)
        .await
        .unwrap();
    let login = login(&db, &ah, "binding@example.test", &password)
        .await
        .unwrap();
    let owner = auth::authenticate_session(&db, &ah, &login.token)
        .await
        .unwrap();
    let sep = if url.contains('?') { '&' } else { '?' };
    let app = router(EnrollmentHttpState::new(
        format!("{url}{sep}options=-csearch_path%3D{schema}"),
        ah.clone(),
        eh.clone(),
        "https://test.example".into(),
    ));
    let key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let fp: [u8; 32] = Sha256::digest(key.verifying_key().to_sec1_point(false).as_bytes()).into();
    let fp_text: String = fp.iter().map(|b| format!("{b:02X}")).collect();
    let ticket = enrollment::create_pairing(&db, &eh, &owner, "Synthetic phone")
        .await
        .unwrap();
    let claim = enrollment::claim_pairing(&mut db, &eh, ticket.id, &ticket.token, spki.as_bytes())
        .await
        .unwrap();
    let path = format!("/pairings/{}/binding", ticket.id);
    // A public locator is not a credential. Wrong fingerprints cannot spend
    // a private share belonging to the real phone, even past the old60 bound.
    for _ in 0..65 {
        assert_eq!(
            app.clone()
                .oneshot(request(
                    Method::POST,
                    &format!("{path}/challenge"),
                    json!({"key_fingerprint":"00".repeat(32)}),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let rows: i64 = db
        .query_one(
            "SELECT count(*) FROM auth_abuse_counters WHERE scope='pair_binding'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        rows, 1,
        "anonymous binding requests create only the shared route counter"
    );
    let unclaimed = enrollment::create_pairing(&db, &eh, &owner, "Unclaimed interrupted phone")
        .await
        .unwrap();
    let unclaimed_path = format!("/pairings/{}/binding/challenge", unclaimed.id);
    let challenge_body = json!({"key_fingerprint":fp_text});
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &unclaimed_path,
                challenge_body.clone(),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        enrollment::cancel_pairing(&db, &owner, unclaimed.id)
            .await
            .unwrap()
    );
    let terminal = app
        .clone()
        .oneshot(request(
            Method::POST,
            &unclaimed_path,
            challenge_body.clone(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(terminal.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_response(terminal).await,
        json!({"code":"pairing_cancelled"})
    );
    let expired = enrollment::create_pairing(&db, &eh, &owner, "Unclaimed expired phone")
        .await
        .unwrap();
    db.execute("UPDATE pairing_requests SET created_at=now()-interval '2 days',expires_at=now()-interval '25 hours' WHERE id=$1",&[&expired.id]).await.unwrap();
    let expired_path = format!("/pairings/{}/binding/challenge", expired.id);
    let terminal = app
        .clone()
        .oneshot(request(
            Method::POST,
            &expired_path,
            challenge_body.clone(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(terminal.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_response(terminal).await,
        json!({"code":"pairing_expired"})
    );
    assert_eq!(enrollment::prune_expired(&db).await.unwrap(), 1);
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &expired_path,
                challenge_body.clone(),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let challenge_response = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("{path}/challenge"),
            json!({"key_fingerprint":fp_text}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(challenge_response.status(), StatusCode::OK);
    assert_eq!(
        challenge_response.headers()[header::CACHE_CONTROL],
        "no-store"
    );
    let c = json_response(challenge_response).await;
    let challenge = BindingChallenge {
        account_id: signup.account_id,
        pairing_id: ticket.id,
        challenge_id: c["challenge_id"].as_str().unwrap().parse().unwrap(),
        nonce: decode_nonce(c["challenge_nonce"].as_str().unwrap()).unwrap(),
        fingerprint: fp,
    };
    let signature: Signature = key.sign(&challenge_bytes(&challenge));
    let body = json!({"account_id":signup.account_id,"challenge_id":challenge.challenge_id,"challenge_nonce":c["challenge_nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())});
    let read = app
        .clone()
        .oneshot(request(Method::POST, &path, body.clone(), None))
        .await
        .unwrap();
    assert_eq!(json_response(read).await["status"], "awaiting_proof");
    let original_signature: Signature = key.sign(&enrollment::enrollment_challenge_bytes(
        signup.account_id,
        ticket.id,
        &fp,
        &claim.challenge_nonce,
    ));
    let mut replay = body.clone();
    replay["signature_der"] = URL_SAFE_NO_PAD
        .encode(original_signature.to_der().as_bytes())
        .into();
    assert_eq!(
        app.clone()
            .oneshot(request(Method::POST, &path, replay, None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        enrollment::prove_pairing_key(
            &mut db,
            &eh,
            ticket.id,
            &claim.challenge_nonce,
            original_signature.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    let read = app
        .clone()
        .oneshot(request(Method::POST, &path, body.clone(), None))
        .await
        .unwrap();
    let pending = json_response(read).await;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["comparison_code"], claim.comparison_code);
    assert!(pending["device_id"].is_null());
    let mut rebound = body.clone();
    rebound["account_id"] = Uuid::new_v4().to_string().into();
    assert_eq!(
        app.clone()
            .oneshot(request(Method::POST, &path, rebound, None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let device = enrollment::approve_pairing(
        &mut db,
        &owner,
        ticket.id,
        &claim.comparison_code,
        &claim.key_fingerprint,
    )
    .await
    .unwrap();
    let read = app
        .clone()
        .oneshot(request(Method::POST, &path, body.clone(), None))
        .await
        .unwrap();
    let approved = json_response(read).await;
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["device_id"], device.to_string());
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &format!("{path}/challenge"),
                json!({"key_fingerprint":"00".repeat(32)}),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    // Failures repeat only the affected ceremony; the enrolled binding above
    // remains separately recoverable with its original key.
    for expected in ["cancelled", "expired", "proof_rejected"] {
        let extra = enrollment::create_pairing(&db, &eh, &owner, "Interrupted phone")
            .await
            .unwrap();
        let claimed =
            enrollment::claim_pairing(&mut db, &eh, extra.id, &extra.token, spki.as_bytes())
                .await
                .unwrap();
        match expected {
            "cancelled" => {
                assert!(
                    enrollment::cancel_pairing(&db, &owner, extra.id)
                        .await
                        .unwrap()
                );
            }
            "expired" => {
                db.execute("UPDATE pairing_requests SET created_at=now()-interval '10 minutes',expires_at=now()-interval '1 minute' WHERE id=$1",&[&extra.id]).await.unwrap();
            }
            _ => {
                assert!(
                    !enrollment::prove_pairing_key(
                        &mut db,
                        &eh,
                        extra.id,
                        &claimed.challenge_nonce,
                        signature.to_der().as_bytes()
                    )
                    .await
                    .unwrap()
                );
            }
        }
        let now = 1_800_000_000_000;
        let c = enrollment::binding::issue(&db, &eh, extra.id, fp, now)
            .await
            .unwrap();
        let sig: Signature = key.sign(&challenge_bytes(&c));
        let failed = enrollment::binding::read(&db, &eh, c, sig.to_der().as_bytes(), now)
            .await
            .unwrap();
        assert_eq!(failed.status, expected);
        assert!(failed.device_id.is_none());
        assert!(failed.comparison_code.is_none());
        assert_eq!(
            app.clone()
                .oneshot(request(
                    Method::POST,
                    &format!("/pairings/{}/binding/challenge", extra.id),
                    json!({"key_fingerprint":"00".repeat(32)}),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    // Neither the wrong key nor a disabled account is an approved handoff.
    assert!(
        enrollment::binding::issue(&db, &eh, ticket.id, [0; 32], 1_800_000_000_000)
            .await
            .is_err()
    );
    db.execute(
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        &[&signup.account_id],
    )
    .await
    .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(Method::POST, &path, body.clone(), None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &unclaimed_path,
                challenge_body.clone(),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    db.execute(
        "UPDATE accounts SET disabled_at=NULL WHERE id=$1",
        &[&signup.account_id],
    )
    .await
    .unwrap();
    db.execute("UPDATE pairing_requests SET created_at=now()-interval '2 days',expires_at=now()-interval '25 hours' WHERE id=$1",&[&ticket.id]).await.unwrap();
    assert_eq!(enrollment::prune_expired(&db).await.unwrap(), 1);
    let read = app
        .clone()
        .oneshot(request(Method::POST, &path, body.clone(), None))
        .await
        .unwrap();
    let recovered = json_response(read).await;
    assert_eq!(recovered["device_id"], device.to_string());
    assert!(recovered["comparison_code"].is_null());
    db.execute(
        "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
        &[&device],
    )
    .await
    .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(Method::POST, &path, body.clone(), None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &format!("{path}/challenge"),
                challenge_body,
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        db.execute(
            "UPDATE device_keys SET source_pairing_id=$2 WHERE device_id=$1",
            &[&device, &Uuid::new_v4()]
        )
        .await
        .is_err()
    );
    assert!(
        enrollment::revoke_device(&mut db, &owner, device)
            .await
            .unwrap()
    );
    assert_eq!(
        app.oneshot(request(Method::POST, &path, body, None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
