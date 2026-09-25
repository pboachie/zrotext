// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;

macro_rules! migration {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/migrations/",
            $name
        ))
    };
}

// The ceremony runs on the complete schema. SQL is embedded at build time so
// the test never executes files discovered at runtime.
const TEST_MIGRATIONS: [(&str, &str); 36] = [
    ("001_foundation.sql", migration!("001_foundation.sql")),
    ("002_auth.sql", migration!("002_auth.sql")),
    ("003_delivery.sql", migration!("003_delivery.sql")),
    ("004_enrollment.sql", migration!("004_enrollment.sql")),
    (
        "005_verification_outbox.sql",
        migration!("005_verification_outbox.sql"),
    ),
    (
        "006_usage_metering.sql",
        migration!("006_usage_metering.sql"),
    ),
    (
        "007_inbound_webhook_foundation.sql",
        migration!("007_inbound_webhook_foundation.sql"),
    ),
    (
        "008_stripe_billing_foundation.sql",
        migration!("008_stripe_billing_foundation.sql"),
    ),
    (
        "009_webhook_manual_replay.sql",
        migration!("009_webhook_manual_replay.sql"),
    ),
    (
        "010_billing_test_entitlement.sql",
        migration!("010_billing_test_entitlement.sql"),
    ),
    (
        "011_billing_payment_holds.sql",
        migration!("011_billing_payment_holds.sql"),
    ),
    (
        "012_auth_abuse_limits.sql",
        migration!("012_auth_abuse_limits.sql"),
    ),
    ("013_owner_mfa.sql", migration!("013_owner_mfa.sql")),
    (
        "014_owner_mfa_failure_budget.sql",
        migration!("014_owner_mfa_failure_budget.sql"),
    ),
    (
        "015_webhook_kek_commitments.sql",
        migration!("015_webhook_kek_commitments.sql"),
    ),
    (
        "016_auth_abuse_atomic.sql",
        migration!("016_auth_abuse_atomic.sql"),
    ),
    (
        "017_billing_device_caps.sql",
        migration!("017_billing_device_caps.sql"),
    ),
    (
        "018_sealed_inbound_identity.sql",
        migration!("018_sealed_inbound_identity.sql"),
    ),
    (
        "019_line_activation_contract.sql",
        migration!("019_line_activation_contract.sql"),
    ),
    (
        "020_enrollment_retention_indexes.sql",
        migration!("020_enrollment_retention_indexes.sql"),
    ),
    (
        "021_billing_payment_grace.sql",
        migration!("021_billing_payment_grace.sql"),
    ),
    (
        "022_pending_owner_expiry.sql",
        migration!("022_pending_owner_expiry.sql"),
    ),
    (
        "023_billing_py_charge_and_unsupported.sql",
        migration!("023_billing_py_charge_and_unsupported.sql"),
    ),
    (
        "024_billing_risk_operator_review.sql",
        migration!("024_billing_risk_operator_review.sql"),
    ),
    (
        "025_account_recovery.sql",
        migration!("025_account_recovery.sql"),
    ),
    (
        "026_data_retention.sql",
        migration!("026_data_retention.sql"),
    ),
    (
        "027_billing_test_config.sql",
        migration!("027_billing_test_config.sql"),
    ),
    (
        "028_billing_provider_failures.sql",
        migration!("028_billing_provider_failures.sql"),
    ),
    (
        "029_webhook_dispatch_fairness.sql",
        migration!("029_webhook_dispatch_fairness.sql"),
    ),
    (
        "030_terminal_dispatch_jobs.sql",
        migration!("030_terminal_dispatch_jobs.sql"),
    ),
    (
        "031_recipient_suppression.sql",
        migration!("031_recipient_suppression.sql"),
    ),
    (
        "032_line_opt_out_events.sql",
        migration!("032_line_opt_out_events.sql"),
    ),
    (
        "033_sms_line_binding_scope.sql",
        migration!("033_sms_line_binding_scope.sql"),
    ),
    (
        "034_delivery_sweep_index.sql",
        migration!("034_delivery_sweep_index.sql"),
    ),
    (
        "035_sms_owner_key_ceremony.sql",
        migration!("035_sms_owner_key_ceremony.sql"),
    ),
    (
        "036_owner_opt_out_holds.sql",
        migration!("036_owner_opt_out_holds.sql"),
    ),
];

#[test]
fn ceremony_fixture_tracks_numbered_migrations() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut discovered = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    discovered.sort();
    let embedded = TEST_MIGRATIONS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(discovered, embedded, "update the embedded migration list");
}

#[test]
fn possession_statement_is_bound_to_account_session_nonce_and_key() {
    let account = Uuid::new_v4();
    let user = Uuid::new_v4();
    let session = Uuid::new_v4();
    let challenge = Uuid::new_v4();
    let nonce: [u8; 32] = rand::random();
    let key = SigningKey::generate_from_rng(&mut rng());
    let sec1 = key.verifying_key().to_sec1_point(false);
    let fingerprint = sha256(sec1.as_bytes());
    let statement = possession_statement(account, user, session, challenge, &nonce, &fingerprint);
    assert_eq!(statement.len(), DOMAIN.len() + 16 * 4 + 64);
    assert!(statement.starts_with(DOMAIN));
    let signature: Signature = key.sign(&statement);
    key.verifying_key().verify(&statement, &signature).unwrap();
    for altered in [
        possession_statement(
            Uuid::new_v4(),
            user,
            session,
            challenge,
            &nonce,
            &fingerprint,
        ),
        possession_statement(
            account,
            user,
            Uuid::new_v4(),
            challenge,
            &nonce,
            &fingerprint,
        ),
        possession_statement(
            account,
            user,
            session,
            challenge,
            &rand::random(),
            &fingerprint,
        ),
        possession_statement(account, user, session, challenge, &nonce, &rand::random()),
    ] {
        assert!(key.verifying_key().verify(&altered, &signature).is_err());
    }
}

#[test]
fn key_encoding_requires_canonical_uncompressed_p256() {
    let key = SigningKey::generate_from_rng(&mut rng());
    let point = key.verifying_key().to_sec1_point(false);
    let encoded = STANDARD.encode(point.as_bytes());
    assert!(key_bytes(&encoded).is_ok());
    assert!(
        key_bytes(&STANDARD.encode(key.verifying_key().to_sec1_point(true).as_bytes())).is_err()
    );
    assert!(key_bytes(&format!("{encoded}=")).is_err());
    assert!(key_bytes(&STANDARD.encode([4u8; 65])).is_err());
}

#[test]
fn registration_statement_matches_public_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/sms-owner-key-registration.vector.json"
    ))
    .unwrap();
    let id = |field: &str| vector[field].as_str().unwrap().parse::<Uuid>().unwrap();
    let sec1 = key_bytes(vector["signing_key_sec1_b64"].as_str().unwrap()).unwrap();
    let fingerprint = sha256(&sec1);
    assert_eq!(
        fingerprint_string(&fingerprint),
        vector["fingerprint_b64url"]
    );
    let nonce = decode_canonical::<32>(vector["nonce_b64"].as_str().unwrap()).unwrap();
    let statement = possession_statement(
        id("account_id"),
        id("user_id"),
        id("session_id"),
        id("challenge_id"),
        &nonce,
        &fingerprint,
    );
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex(&statement), vector["statement_hex"]);
    assert_eq!(hex(&sha256(&statement)), vector["statement_sha256_hex"]);
}

#[test]
fn owner_key_requests_reject_private_key_fields() {
    assert!(
        serde_json::from_value::<ChallengeBody>(serde_json::json!({
            "signing_key_sec1_b64":"unused", "private_key":"never accepted"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<RegisterBody>(serde_json::json!({
            "challenge_id":Uuid::new_v4(), "nonce_b64":"unused", "signature_der_b64":"unused",
            "mfa_code":"unused", "private_key":"never accepted"
        }))
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_owner_key_ceremony_requires_possession_mfa_and_revokes_only_sms_scope() {
    use crate::{
        auth::{self, TokenHasher, mfa::MfaCipher},
        http_auth::{self, DisabledVerificationDispatcher},
        inbound::InboundSession,
        sealed_inbound::sms_line_binding_ready,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use std::sync::Arc;
    use tokio_postgres::NoTls;
    use tower::ServiceExt;

    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("set test database URL");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("sms_owner_key_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let sep = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{sep}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in TEST_MIGRATIONS {
        if name == "034_delivery_sweep_index.sql" {
            // Mirror the migrator's autocommit preparation before the
            // numbered, checksummed validation file.
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                 ON messages(updated_at,id) \
                 WHERE state IN ('claimed','submitting','submitted')",
            )
            .await
            .unwrap();
        }
        db.batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = &format!("owner-{}", Uuid::new_v4().simple());
    let signup = auth::register(&mut db, &hasher, "sms-owner@example.test", password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let credentials = auth::login(&db, &hasher, "sms-owner@example.test", password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
        .await
        .unwrap();
    let cipher = Arc::new(MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let enrollment = auth::mfa::begin_enrollment(&mut db, &cipher, &principal, password)
        .await
        .unwrap();
    let secret = totp_rs::Secret::try_from_base32(&enrollment.secret_base32).unwrap();
    let code = totp_rs::Builder::new()
        .with_secret(secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let recovery = auth::mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
        .await
        .unwrap()
        .codes;
    let app = http_auth::router(
        http_auth::AuthHttpState::new(
            url.clone(),
            hasher.clone(),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap()
        .with_mfa_cipher(cipher),
    );
    let cookies = format!(
        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
        credentials.token, credentials.csrf_token
    );
    let owner_request = |method: &str, path: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::COOKIE, &cookies)
            .header("x-zrotext-csrf", &credentials.csrf_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let sealed_alias = SigningKey::generate_from_rng(&mut rng())
        .verifying_key()
        .to_sec1_point(false);
    db.execute(
        "INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)",
        &[&signup.account_id, &&sha256(sealed_alias.as_bytes())[..], &sealed_alias.as_bytes()],
    ).await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":STANDARD.encode(sealed_alias.as_bytes())})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let alias_device = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'alias-device')",
        &[&alias_device, &signup.account_id],
    )
    .await
    .unwrap();
    let device_alias = SigningKey::generate_from_rng(&mut rng())
        .verifying_key()
        .to_sec1_point(false);
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&alias_device,&signup.account_id,&device_alias.as_bytes(),&&sha256(device_alias.as_bytes())[..]]).await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":STANDARD.encode(device_alias.as_bytes())})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let key = SigningKey::generate_from_rng(&mut rng());
    let sec1 = key.verifying_key().to_sec1_point(false);
    let key_b64 = STANDARD.encode(sec1.as_bytes());
    let no_cipher_app = http_auth::router(
        http_auth::AuthHttpState::new(
            url.clone(),
            hasher.clone(),
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap(),
    );
    assert_eq!(
        no_cipher_app
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":key_b64})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    db.execute(
        "UPDATE users SET mfa_enabled=false WHERE id=$1",
        &[&signup.user_id],
    )
    .await
    .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":key_b64})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    db.execute(
        "UPDATE users SET mfa_enabled=true WHERE id=$1",
        &[&signup.user_id],
    )
    .await
    .unwrap();
    let mut wrong_origin = owner_request(
        "POST",
        "/sms-line-owner-keys/challenge",
        serde_json::json!({"signing_key_sec1_b64":key_b64}),
    );
    wrong_origin
        .headers_mut()
        .insert(header::ORIGIN, "https://other.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(wrong_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let response = app
        .clone()
        .oneshot(owner_request(
            "POST",
            "/sms-line-owner-keys/challenge",
            serde_json::json!({"signing_key_sec1_b64":key_b64}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    let challenge_id: Uuid = challenge_body["challenge_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let nonce: [u8; 32] = decode_canonical(challenge_body["nonce_b64"].as_str().unwrap()).unwrap();
    let fingerprint = sha256(sec1.as_bytes());
    let statement = possession_statement(
        signup.account_id,
        signup.user_id,
        credentials.id,
        challenge_id,
        &nonce,
        &fingerprint,
    );
    let signature: Signature = key.sign(&statement);
    let good_body = serde_json::json!({
        "challenge_id": challenge_id,
        "nonce_b64": STANDARD.encode(nonce),
        "signature_der_b64": STANDARD.encode(signature.to_der().as_bytes()),
        "mfa_code": recovery[0],
    });
    let mut forged = good_body.clone();
    let forged_signature: Signature = SigningKey::generate_from_rng(&mut rng()).sign(&statement);
    forged["signature_der_b64"] =
        serde_json::json!(STANDARD.encode(forged_signature.to_der().as_bytes()));
    assert_eq!(
        app.clone()
            .oneshot(owner_request("POST", "/sms-line-owner-keys", forged))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut wrong_factor = good_body.clone();
    wrong_factor["mfa_code"] = serde_json::json!("000000");
    assert_eq!(
        app.clone()
            .oneshot(owner_request("POST", "/sms-line-owner-keys", wrong_factor))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let failed: i32 = db
        .query_one(
            "SELECT failed_attempts FROM owner_mfa WHERE account_id=$1",
            &[&signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failed, 1);
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys",
                good_body.clone()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request("POST", "/sms-line-owner-keys", good_body))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "GET",
                "/sms-line-owner-keys",
                serde_json::json!({})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let no_csrf_list = Request::builder()
        .uri("/sms-line-owner-keys")
        .header(header::COOKIE, &cookies)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_csrf_list).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let future_alias_device = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'future-alias')",
        &[&future_alias_device, &signup.account_id],
    )
    .await
    .unwrap();
    assert!(db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&future_alias_device,&signup.account_id,&sec1.as_bytes(),&&fingerprint[..]]).await.is_err());
    // The test deliberately exercises more management requests than one
    // production abuse window permits. Age only this disposable fixture budget.
    db.execute("UPDATE auth_abuse_counters SET window_started_at=clock_timestamp()-interval '16 minutes' WHERE scope='mfa_manage'", &[]).await.unwrap();
    let path = format!("/sms-line-owner-keys/{}", fingerprint_string(&fingerprint));
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "DELETE",
                &path,
                serde_json::json!({"mfa_code":recovery[0]})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mfa_disable = serde_json::json!({"password":password,"code":recovery[2]});
    let blocked_disable = app
        .clone()
        .oneshot(owner_request("POST", "/mfa/disable", mfa_disable.clone()))
        .await
        .unwrap();
    assert_eq!(blocked_disable.status(), StatusCode::CONFLICT);
    let blocked_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(blocked_disable.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(blocked_body["code"], "revoke_sms_owner_key_first");
    // Synthetic active SMS binding and sealed binding share one device but
    // have separate line identities. Revocation must fence only SMS scope.
    let device = Uuid::new_v4();
    let sms_line = Uuid::new_v4();
    let sealed_line = Uuid::new_v4();
    db.execute("INSERT INTO sites(site_id) VALUES('synthetic-site')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic-device')",
        &[&device, &signup.account_id],
    )
    .await
    .unwrap();
    let device_key = SigningKey::generate_from_rng(&mut rng())
        .verifying_key()
        .to_sec1_point(false);
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device,&signup.account_id,&device_key.as_bytes(),&&sha256(device_key.as_bytes())[..]]).await.unwrap();
    db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,'synthetic-site','synthetic-instance',1,clock_timestamp()+interval '1 hour',1)", &[&device,&signup.account_id]).await.unwrap();
    for (line, purpose) in [(sms_line, "sms"), (sealed_line, "sealed")] {
        db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'active',clock_timestamp(),1,1)", &[&line,&signup.account_id]).await.unwrap();
        db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) VALUES($1,$2,$3,1,'active',$4,$4,clock_timestamp(),$5)", &[&signup.account_id,&line,&device,&&[1u8;32][..],&purpose]).await.unwrap();
    }
    let inbound = InboundSession {
        account_id: signup.account_id,
        device_id: device,
        site_id: "synthetic-site",
        instance_id: "synthetic-instance",
        connection_epoch: 1,
        deployment_epoch: 1,
    };
    assert!(
        sms_line_binding_ready(&db, inbound, sms_line, 1)
            .await
            .unwrap()
    );
    assert!(
        sms_line_binding_ready(&db, inbound, sealed_line, 1)
            .await
            .unwrap()
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "DELETE",
                &path,
                serde_json::json!({"mfa_code":"000000"})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        sms_line_binding_ready(&db, inbound, sms_line, 1)
            .await
            .unwrap()
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "DELETE",
                &path,
                serde_json::json!({"mfa_code":recovery[1]})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        !sms_line_binding_ready(&db, inbound, sms_line, 1)
            .await
            .unwrap()
    );
    assert!(
        sms_line_binding_ready(&db, inbound, sealed_line, 1)
            .await
            .unwrap()
    );
    let states = db.query("SELECT l.state,b.state,b.purpose FROM phone_lines l JOIN device_line_bindings b ON b.line_id=l.id WHERE l.account_id=$1", &[&signup.account_id]).await.unwrap();
    assert!(states.iter().any(|row| row.get::<_, String>(2) == "sms"
        && row.get::<_, String>(0) == "revoked"
        && row.get::<_, String>(1) == "revoked"));
    assert!(states.iter().any(|row| row.get::<_, String>(2) == "sealed"
        && row.get::<_, String>(0) == "active"
        && row.get::<_, String>(1) == "active"));
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":key_b64})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "DELETE",
                &path,
                serde_json::json!({"mfa_code":recovery[2]})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let audit: i64 = db
        .query_one(
            "SELECT count(*) FROM sms_owner_key_audit WHERE account_id=$1",
            &[&signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit, 2);
    assert_eq!(
        app.oneshot(owner_request("POST", "/mfa/disable", mfa_disable))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
