// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{self, TokenHasher},
    http_auth::{self, DisabledVerificationDispatcher},
    sealed_inbound::sms_line_binding_ready,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;
use std::sync::Arc;
use tokio_postgres::NoTls;
use tower::ServiceExt;

macro_rules! migration {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/compose/migrations/",
                $name
            )),
        )
    };
}

// Complete reviewed schema, embedded at build time.
const TEST_MIGRATIONS: [(&str, &str); 39] = [
    migration!("001_foundation.sql"),
    migration!("002_auth.sql"),
    migration!("003_delivery.sql"),
    migration!("004_enrollment.sql"),
    migration!("005_verification_outbox.sql"),
    migration!("006_usage_metering.sql"),
    migration!("007_inbound_webhook_foundation.sql"),
    migration!("008_stripe_billing_foundation.sql"),
    migration!("009_webhook_manual_replay.sql"),
    migration!("010_billing_test_entitlement.sql"),
    migration!("011_billing_payment_holds.sql"),
    migration!("012_auth_abuse_limits.sql"),
    migration!("013_owner_mfa.sql"),
    migration!("014_owner_mfa_failure_budget.sql"),
    migration!("015_webhook_kek_commitments.sql"),
    migration!("016_auth_abuse_atomic.sql"),
    migration!("017_billing_device_caps.sql"),
    migration!("018_sealed_inbound_identity.sql"),
    migration!("019_line_activation_contract.sql"),
    migration!("020_enrollment_retention_indexes.sql"),
    migration!("021_billing_payment_grace.sql"),
    migration!("022_pending_owner_expiry.sql"),
    migration!("023_billing_py_charge_and_unsupported.sql"),
    migration!("024_billing_risk_operator_review.sql"),
    migration!("025_account_recovery.sql"),
    migration!("026_data_retention.sql"),
    migration!("027_billing_test_config.sql"),
    migration!("028_billing_provider_failures.sql"),
    migration!("029_webhook_dispatch_fairness.sql"),
    migration!("030_terminal_dispatch_jobs.sql"),
    migration!("031_recipient_suppression.sql"),
    migration!("032_line_opt_out_events.sql"),
    migration!("033_sms_line_binding_scope.sql"),
    migration!("034_delivery_sweep_index.sql"),
    migration!("035_sms_owner_key_ceremony.sql"),
    migration!("036_owner_opt_out_holds.sql"),
    migration!("037_sms_line_activation_exchange.sql"),
    migration!("038_owner_opt_out_hold_guards.sql"),
    migration!("039_inbound_device_clock_offset.sql"),
];

#[test]
fn exchange_fixture_tracks_numbered_migrations() {
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

const ORIGIN: &str = "https://zrotext.example";

struct Owner {
    account_id: Uuid,
    cookies: String,
    csrf: String,
}

async fn owner(db: &mut Client, hasher: &TokenHasher, email: &str) -> Owner {
    let password = format!("owner-{}", Uuid::new_v4().simple());
    let signup = auth::register(db, hasher, email, &password).await.unwrap();
    auth::verify_email(db, hasher, &signup.verification_token)
        .await
        .unwrap();
    let credentials = auth::login(db, hasher, email, &password).await.unwrap();
    Owner {
        account_id: signup.account_id,
        cookies: format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            credentials.token, credentials.csrf_token
        ),
        csrf: credentials.csrf_token,
    }
}

fn request(
    owner: &Owner,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &owner.cookies)
        .header("x-zrotext-csrf", &owner.csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

fn der(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_sms_line_activation_exchange_binds_owner_device_and_live_session() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("set test database URL");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("sms_line_exchange_test_{}", Uuid::new_v4().simple());
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
            // Mirror the migrator's autocommit preparation.
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
    db.execute("INSERT INTO sites(site_id) VALUES('virtual-sms-hub')", &[])
        .await
        .unwrap();
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let owner = owner(&mut db, &hasher, "sms-line-exchange@example.test").await;
    let other = owner_for_other_account(&mut db, &hasher).await;

    let device = Uuid::new_v4();
    let device_key = SigningKey::generate_from_rng(&mut rng());
    let owner_key = SigningKey::generate_from_rng(&mut rng());
    let wrong_key = SigningKey::generate_from_rng(&mut rng());
    let device_sec1 = device_key.verifying_key().to_sec1_point(false);
    let owner_sec1 = owner_key.verifying_key().to_sec1_point(false);
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual sms device')",
        &[&device, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device, &owner.account_id, &device_sec1.as_bytes(), &&digest(device_sec1.as_bytes())[..]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO sms_line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)",
        &[&owner.account_id, &&digest(owner_sec1.as_bytes())[..], &owner_sec1.as_bytes()],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id, \
         connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'virtual-sms-hub','virtual-hub',1,now()+interval '10 minutes',1)",
        &[&device, &owner.account_id],
    )
    .await
    .unwrap();
    let session = InboundSession {
        account_id: owner.account_id,
        device_id: device,
        site_id: "virtual-sms-hub",
        instance_id: "virtual-hub",
        connection_epoch: 1,
        deployment_epoch: 1,
    };

    let state = || {
        http_auth::AuthHttpState::new(
            url.clone(),
            hasher.clone(),
            ORIGIN.to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap()
    };
    let line = Uuid::new_v4();
    let open_path = format!("/sms-lines/{line}/activations");
    let open_body = serde_json::json!({ "device_id": device });

    // Dormant by default.
    let disabled = http_auth::router(state());
    assert_eq!(
        disabled
            .oneshot(request(&owner, "POST", &open_path, Some(open_body.clone())))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let app = http_auth::router(state().with_sms_line_activation_enabled());

    // A mutation needs the exact Origin; a stray private-key field is refused.
    let mut foreign = request(&owner, "POST", &open_path, Some(open_body.clone()));
    foreign
        .headers_mut()
        .insert(header::ORIGIN, "https://other.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let with_private = serde_json::json!({ "device_id": device, "private_key": "x" });
    assert!(
        app.clone()
            .oneshot(request(&owner, "POST", &open_path, Some(with_private)))
            .await
            .unwrap()
            .status()
            .is_client_error()
    );

    let opened = app
        .clone()
        .oneshot(request(&owner, "POST", &open_path, Some(open_body.clone())))
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::CREATED);
    let opened = json(opened).await;
    let challenge_id = Uuid::parse_str(opened["challenge_id"].as_str().unwrap()).unwrap();
    let generation = opened["generation"].as_i64().unwrap();
    let view_path = format!("/sms-lines/{line}/activations/{challenge_id}");
    let approve_path = format!("{view_path}/approve");
    let view = |who: &Owner| request(who, "GET", &view_path, None);

    let status = json(app.clone().oneshot(view(&owner)).await.unwrap()).await;
    assert_eq!(status["status"], "awaiting_device");
    assert!(status.get("owner_statement_b64").is_none());
    // Another account cannot see the challenge.
    assert_eq!(
        app.clone().oneshot(view(&other)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    // The device stream pushes it once per connection.
    let pushed = next_challenge(&db, session).await.unwrap().unwrap();
    assert_eq!(
        (
            pushed.challenge_id,
            pushed.line_id,
            pushed.device_id,
            pushed.generation
        ),
        (challenge_id, line, device, generation)
    );
    mark_challenge_pushed(&db, session, challenge_id)
        .await
        .unwrap();
    assert!(next_challenge(&db, session).await.unwrap().is_none());
    let reconnected = InboundSession {
        connection_epoch: 2,
        ..session
    };
    assert!(next_challenge(&db, reconnected).await.unwrap().is_some());

    let observation = SimObservation {
        android_api_level: 29,
        active_subscription_count: 1,
        selected_subscription_id: 3,
    };
    let challenge = LineChallenge {
        id: pushed.challenge_id,
        account_id: pushed.account_id,
        line_id: pushed.line_id,
        device_id: pushed.device_id,
        generation: pushed.generation,
        nonce: pushed.nonce,
    };
    let statement = sms_device_line_statement(&challenge, observation).unwrap();
    let device_der = der(&device_key, &statement);
    let proof = |signature_der, observation| DeviceProof {
        challenge_id,
        observation,
        signature_der,
    };

    // Wrong key, changed declaration, stale connection and ambiguous SIM fail.
    let wrong_der = der(&wrong_key, &statement);
    assert!(
        !record_device_proof(&mut db, session, proof(&wrong_der, observation))
            .await
            .unwrap()
    );
    let changed = SimObservation {
        selected_subscription_id: 4,
        ..observation
    };
    assert!(
        !record_device_proof(&mut db, session, proof(&device_der, changed))
            .await
            .unwrap()
    );
    let two_sims = SimObservation {
        active_subscription_count: 2,
        ..observation
    };
    assert!(
        !record_device_proof(&mut db, session, proof(&device_der, two_sims))
            .await
            .unwrap()
    );
    assert!(
        !record_device_proof(&mut db, reconnected, proof(&device_der, observation))
            .await
            .unwrap()
    );
    assert_eq!(
        json(app.clone().oneshot(view(&owner)).await.unwrap()).await["status"],
        "awaiting_device"
    );

    assert!(
        record_device_proof(&mut db, session, proof(&device_der, observation))
            .await
            .unwrap()
    );
    // Exact replay is idempotent; a different signature cannot replace it.
    assert!(
        record_device_proof(&mut db, session, proof(&device_der, observation))
            .await
            .unwrap()
    );
    assert!(
        !record_device_proof(&mut db, session, proof(&wrong_der, observation))
            .await
            .unwrap()
    );
    assert!(next_challenge(&db, reconnected).await.unwrap().is_none());
    assert!(next_ack(&db, session, &[]).await.unwrap().is_none());

    let status = json(app.clone().oneshot(view(&owner)).await.unwrap()).await;
    assert_eq!(status["status"], "awaiting_owner");
    assert_eq!(status["android_api_level"], 29);
    assert_eq!(status["selected_subscription_id"], 3);
    let owner_statement = STANDARD
        .decode(status["owner_statement_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        owner_statement,
        sms_owner_line_statement(&statement, &device_der)
    );
    assert_eq!(
        STANDARD
            .decode(status["device_statement_b64"].as_str().unwrap())
            .unwrap(),
        statement
    );

    let approve = |who: &Owner, signature: &[u8]| {
        request(
            who,
            "POST",
            &approve_path,
            Some(serde_json::json!({ "owner_signature_der_b64": STANDARD.encode(signature) })),
        )
    };
    let malformed = request(
        &owner,
        "POST",
        &approve_path,
        Some(serde_json::json!({ "owner_signature_der_b64": "not base64!" })),
    );
    assert_eq!(
        app.clone().oneshot(malformed).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(approve(&owner, &der(&wrong_key, &owner_statement)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let owner_der = der(&owner_key, &owner_statement);
    assert_eq!(
        app.clone()
            .oneshot(approve(&other, &owner_der))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        !sms_line_binding_ready(&db, session, line, generation)
            .await
            .unwrap()
    );

    assert_eq!(
        app.clone()
            .oneshot(approve(&owner, &owner_der))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        sms_line_binding_ready(&db, session, line, generation)
            .await
            .unwrap()
    );
    // Replay after activation is refused.
    assert_eq!(
        app.clone()
            .oneshot(approve(&owner, &owner_der))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let status = json(app.clone().oneshot(view(&owner)).await.unwrap()).await;
    assert_eq!(status["status"], "activated");
    assert!(status.get("owner_statement_b64").is_none());

    // Each connection learns of the activation, bound to its exact proof.
    let ack = next_ack(&db, reconnected, &[]).await.unwrap().unwrap();
    assert_eq!(
        ack,
        ActivationAck {
            challenge_id,
            account_id: owner.account_id,
            line_id: line,
            device_id: device,
            generation,
            device_statement_sha256: digest(&statement),
            device_signature_sha256: digest(&device_der),
        }
    );
    assert!(
        next_ack(&db, reconnected, &[challenge_id])
            .await
            .unwrap()
            .is_none()
    );
    // A dropped connection does not lose it: the next one is told again.
    assert_eq!(next_ack(&db, session, &[]).await.unwrap(), Some(ack));
    assert_eq!(retire(&db, session, ACK_RESEND_SECONDS).await.unwrap(), 0);
    assert_eq!(retire(&db, session, 0).await.unwrap(), 1);
    assert!(next_ack(&db, session, &[]).await.unwrap().is_none());
    assert_eq!(
        json(app.clone().oneshot(view(&owner)).await.unwrap()).await["status"],
        "activated"
    );
    let cleared: Option<Vec<u8>> = db
        .query_one(
            "SELECT nonce FROM sms_line_activation_exchanges WHERE challenge_id=$1",
            &[&challenge_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(cleared.is_none());
    // The stored proof, acknowledgement and cleared nonce are write-once.
    for statement in [
        "UPDATE sms_line_activation_exchanges SET nonce=$2 WHERE challenge_id=$1",
        "UPDATE sms_line_activation_exchanges SET device_signature_der=$2 WHERE challenge_id=$1",
    ] {
        assert!(
            db.execute(statement, &[&challenge_id, &vec![7u8; 32]])
                .await
                .is_err()
        );
    }
    assert!(
        db.execute(
            "UPDATE sms_line_activation_exchanges SET ack_sent_at=NULL WHERE challenge_id=$1",
            &[&challenge_id],
        )
        .await
        .is_err()
    );
    assert!(
        db.execute(
            "DELETE FROM sms_line_activation_exchanges WHERE challenge_id=$1",
            &[&challenge_id],
        )
        .await
        .is_err()
    );

    // Approval needs the connection that delivered the proof to still be live.
    let second_line = Uuid::new_v4();
    let opened = json(
        app.clone()
            .oneshot(request(
                &owner,
                "POST",
                &format!("/sms-lines/{second_line}/activations"),
                Some(open_body),
            ))
            .await
            .unwrap(),
    )
    .await;
    let second_id = Uuid::parse_str(opened["challenge_id"].as_str().unwrap()).unwrap();
    let pushed = next_challenge(&db, session).await.unwrap().unwrap();
    assert_eq!(pushed.challenge_id, second_id);
    let second = LineChallenge {
        id: pushed.challenge_id,
        account_id: pushed.account_id,
        line_id: pushed.line_id,
        device_id: pushed.device_id,
        generation: pushed.generation,
        nonce: pushed.nonce,
    };
    let second_statement = sms_device_line_statement(&second, observation).unwrap();
    let second_device_der = der(&device_key, &second_statement);
    assert!(
        record_device_proof(
            &mut db,
            session,
            DeviceProof {
                challenge_id: second_id,
                observation,
                signature_der: &second_device_der,
            },
        )
        .await
        .unwrap()
    );
    db.execute(
        "UPDATE device_sessions SET connection_epoch=2 WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    let second_owner_der = der(
        &owner_key,
        &sms_owner_line_statement(&second_statement, &second_device_der),
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                &owner,
                "POST",
                &format!("/sms-lines/{second_line}/activations/{second_id}/approve"),
                Some(serde_json::json!({
                    "owner_signature_der_b64": STANDARD.encode(&second_owner_der)
                })),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(next_ack(&db, reconnected, &[]).await.unwrap().is_none());
    // The owner is told the stored proof can no longer be approved.
    let second_view = format!("/sms-lines/{second_line}/activations/{second_id}");
    assert_eq!(
        json(
            app.clone()
                .oneshot(request(&owner, "GET", &second_view, None))
                .await
                .unwrap()
        )
        .await["status"],
        "closed"
    );
    // A superseded exchange loses its nonce without recording an acknowledgement.
    let third = json(
        app.clone()
            .oneshot(request(
                &owner,
                "POST",
                &format!("/sms-lines/{second_line}/activations"),
                Some(serde_json::json!({ "device_id": device })),
            ))
            .await
            .unwrap(),
    )
    .await;
    let third_id = Uuid::parse_str(third["challenge_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        retire(&db, reconnected, ACK_RESEND_SECONDS).await.unwrap(),
        1
    );
    let rows = db
        .query(
            "SELECT challenge_id,nonce IS NULL,ack_sent_at IS NULL \
             FROM sms_line_activation_exchanges WHERE challenge_id = ANY($1)",
            &[&vec![second_id, third_id]],
        )
        .await
        .unwrap();
    for row in rows {
        let id: Uuid = row.get(0);
        assert_eq!(
            row.get::<_, bool>(1),
            id == second_id,
            "nonce cleared only when superseded"
        );
        assert!(row.get::<_, bool>(2));
    }

    // The owner lists their lines with the phone of each active binding.
    let listed = app
        .clone()
        .oneshot(request(&owner, "GET", "/sms-lines", None))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json(listed).await;
    let lines = listed["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(listed["next_cursor"].is_null());
    // Newest first: the second line has no active binding yet.
    assert_eq!(lines[0]["line_id"], serde_json::json!(second_line));
    assert_eq!(lines[0]["state"], "pending");
    assert!(lines[0].get("device_id").is_none());
    assert_eq!(lines[1]["line_id"], serde_json::json!(line));
    assert_eq!(lines[1]["state"], "active");
    assert_eq!(lines[1]["generation"], serde_json::json!(generation));
    assert_eq!(lines[1]["purpose"], "sms");
    assert_eq!(lines[1]["device_id"], serde_json::json!(device));
    assert_eq!(lines[1]["device_name"], "virtual sms device");
    assert!(lines[1]["approved_at_ms"].is_i64());
    // Cursor paging stays in the account and ends after the oldest line.
    let page_two = json(
        app.clone()
            .oneshot(request(
                &owner,
                "GET",
                &format!("/sms-lines?before={second_line}"),
                None,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(page_two["lines"].as_array().unwrap().len(), 1);
    assert_eq!(
        app.clone()
            .oneshot(request(
                &other,
                "GET",
                &format!("/sms-lines?before={line}"),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let others = json(
        app.clone()
            .oneshot(request(&other, "GET", "/sms-lines", None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(others["lines"].as_array().unwrap().len(), 0);
    // A listing needs the CSRF header, and the route is dormant by default.
    let mut without_csrf = request(&owner, "GET", "/sms-lines", None);
    without_csrf.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        app.clone().oneshot(without_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http_auth::router(state())
            .oneshot(request(&owner, "GET", "/sms-lines", None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

async fn owner_for_other_account(db: &mut Client, hasher: &TokenHasher) -> Owner {
    owner(db, hasher, "sms-line-exchange-other@example.test").await
}
