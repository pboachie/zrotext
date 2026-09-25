// SPDX-License-Identifier: AGPL-3.0-only
//! SMS line activation over the real authenticated WebSocket route against
//! disposable SQL. No Android radio, SIM, carrier, or SMS is involved.

use super::*;
use crate::{
    auth,
    enrollment::{DeviceChallenge, device_challenge_bytes},
    sealed_inbound::{
        line_activation::{LineChallenge, sms_device_line_statement, sms_owner_line_statement},
        sms_line_binding_ready,
    },
};
use futures_util::{SinkExt, StreamExt};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

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

const TEST_MIGRATIONS: [(&str, &str); 37] = [
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
];

async fn send_json(socket: &mut TestSocket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

/// Next text frame of the given type, skipping heartbeat traffic.
async fn receive_type(socket: &mut TestSocket, kind: &str) -> Value {
    loop {
        let message = timeout(Duration::from_secs(10), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(text) = message else {
            panic!("expected {kind}, got {message:?}")
        };
        let frame: Value = serde_json::from_str(text.as_str()).unwrap();
        if frame["type"] == kind {
            return frame;
        }
    }
}

async fn receive_close_code(socket: &mut TestSocket) -> u16 {
    let message = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Close(Some(frame)) = message else {
        panic!("expected WebSocket close, got {message:?}")
    };
    u16::from(frame.code)
}

async fn open_socket(
    address: std::net::SocketAddr,
    account: Uuid,
    device: Uuid,
    key: &SigningKey,
) -> (TestSocket, i64) {
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device}),
    )
    .await;
    let challenge_json = receive_type(&mut socket, "challenge").await;
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id: account,
        device_id: device,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = key.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account,
            "device_id":device,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session = receive_type(&mut socket, "session").await;
    (socket, session["connection_epoch"].as_i64().unwrap())
}

fn der(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}

fn proof_frame(epoch: i64, challenge_id: Uuid, signature: &[u8]) -> Value {
    json!({
        "v":1,"type":"sms_line_proof","connection_epoch":epoch,"challenge_id":challenge_id,
        "android_api_level":29,"active_subscription_count":1,"selected_subscription_id":3,
        "signature_der":URL_SAFE_NO_PAD.encode(signature)
    })
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn sms_line_activation_frames_are_gated_bound_to_the_connection_and_resent() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("sms_line_socket_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in TEST_MIGRATIONS {
        if name == "034_delivery_sweep_index.sql" {
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
    db.execute("INSERT INTO sites(site_id) VALUES('sms-line-socket')", &[])
        .await
        .unwrap();

    let hasher = TokenHasher::new(crate::test_keys::key(10)).unwrap();
    let password = format!("owner-{}", Uuid::new_v4().simple());
    let signup = auth::register(&mut db, &hasher, "sms-line-socket@example.test", &password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let login = auth::login(&db, &hasher, "sms-line-socket@example.test", &password)
        .await
        .unwrap();
    let owner = auth::authenticate_session(&db, &hasher, &login.token)
        .await
        .unwrap();
    let account = signup.account_id;
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let device_key = SigningKey::generate_from_rng(&mut rng());
    let owner_key = SigningKey::generate_from_rng(&mut rng());
    let device_sec1 = device_key.verifying_key().to_sec1_point(false);
    let owner_sec1 = owner_key.verifying_key().to_sec1_point(false);
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual device')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device, &account, &device_sec1.as_bytes(), &&Sha256::digest(device_sec1.as_bytes())[..]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO sms_line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)",
        &[&account, &&Sha256::digest(owner_sec1.as_bytes())[..], &owner_sec1.as_bytes()],
    )
    .await
    .unwrap();

    let enabled = DeviceSocketState {
        database_url: schema_url.clone(),
        site_id: "sms-line-socket".into(),
        instance_id: "virtual-hub".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: true,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let disabled = DeviceSocketState {
        sms_line_activation_enabled: false,
        ..enabled.clone()
    };
    let serve = |state: DeviceSocketState| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        (address, server)
    };
    let (disabled_address, disabled_server) = serve(disabled).await;
    let (address, enabled_server) = serve(enabled).await;

    // A dormant hub refuses the frame outright.
    let (mut socket, epoch) = open_socket(disabled_address, account, device, &device_key).await;
    send_json(&mut socket, proof_frame(epoch, Uuid::new_v4(), &[2; 8])).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    // An enabled hub refuses a proof for another connection epoch.
    let (mut socket, epoch) = open_socket(address, account, device, &device_key).await;
    send_json(&mut socket, proof_frame(epoch + 1, Uuid::new_v4(), &[2; 8])).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    // The owner opens a challenge; the device's own stream receives it.
    let (mut socket, epoch) = open_socket(address, account, device, &device_key).await;
    let (opened, _) = exchange::open(&mut db, &owner, line, device).await.unwrap();
    let pushed = receive_type(&mut socket, "sms_line_challenge").await;
    assert_eq!(pushed["challenge_id"], json!(opened.id));
    assert_eq!(pushed["line_id"], json!(line));
    let challenge = LineChallenge {
        id: opened.id,
        account_id: account,
        line_id: line,
        device_id: device,
        generation: pushed["generation"].as_i64().unwrap(),
        nonce: URL_SAFE_NO_PAD
            .decode(pushed["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let observation = SimObservation {
        android_api_level: 29,
        active_subscription_count: 1,
        selected_subscription_id: 3,
    };
    let statement = sms_device_line_statement(&challenge, observation).unwrap();
    let device_der = der(&device_key, &statement);

    // A forged proof is refused without closing the stream; the real one is kept.
    send_json(
        &mut socket,
        proof_frame(epoch, opened.id, &der(&owner_key, &statement)),
    )
    .await;
    assert_eq!(
        receive_type(&mut socket, "sms_line_proof_ack").await,
        json!({"v":1,"type":"sms_line_proof_ack","challenge_id":opened.id,"accepted":false})
    );
    send_json(&mut socket, proof_frame(epoch, opened.id, &device_der)).await;
    assert_eq!(
        receive_type(&mut socket, "sms_line_proof_ack").await,
        json!({"v":1,"type":"sms_line_proof_ack","challenge_id":opened.id,"accepted":true})
    );

    let owner_der = der(
        &owner_key,
        &sms_owner_line_statement(&statement, &device_der),
    );
    exchange::approve(&mut db, &owner, line, opened.id, &owner_der)
        .await
        .unwrap();
    let expected = json!({
        "v":1,"type":"sms_line_activated","challenge_id":opened.id,"account_id":account,
        "line_id":line,"device_id":device,"generation":challenge.generation,
        "device_statement_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(&statement)),
        "device_signature_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(&device_der))
    });
    assert_eq!(
        receive_type(&mut socket, "sms_line_activated").await,
        expected
    );
    let session = crate::inbound::InboundSession {
        account_id: account,
        device_id: device,
        site_id: "sms-line-socket",
        instance_id: "virtual-hub",
        connection_epoch: epoch,
        deployment_epoch: 1,
    };
    assert!(
        sms_line_binding_ready(&db, session, line, challenge.generation)
            .await
            .unwrap()
    );

    // The acknowledgement survives a dropped connection.
    drop(socket);
    let (mut socket, _) = open_socket(address, account, device, &device_key).await;
    assert_eq!(
        receive_type(&mut socket, "sms_line_activated").await,
        expected
    );
    drop(socket);

    enabled_server.abort();
    disabled_server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
