// SPDX-License-Identifier: AGPL-3.0-only
//! A localhost device speaks the real socket protocol against disposable SQL.
//! No Android radio, SMS, DNS lookup, or external webhook request is involved.

use super::*;
use crate::{
    enrollment::{DeviceChallenge, device_challenge_bytes},
    webhook_egress::{DeliveryResponse, EgressError},
    webhook_worker::{WebhookSecretVault, dispatch_one_with},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use zeroize::Zeroizing;

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn receive_json(socket: &mut TestSocket) -> Value {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("socket response timed out")
        .expect("socket closed")
        .expect("socket read failed");
    serde_json::from_str(frame.to_text().expect("expected a text frame"))
        .expect("invalid server JSON")
}

async fn send_json(socket: &mut TestSocket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .expect("socket send failed");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn authenticated_inbound_replay_retries_one_webhook_delivery() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_socket_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let endpoint_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    db.execute("INSERT INTO sites(site_id) VALUES('socket-test')", &[])
        .await
        .unwrap();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual device')",
        &[&device_id, &account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device_id, &account_id, &public_key.as_bytes(), &&fingerprint[..]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15555550101',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message_id, &account_id, &device_id, &vec![2u8; 32], &b"fixture".as_slice(), &vec![3u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'submitted')",
        &[&attempt_id, &account_id, &message_id, &device_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[&Uuid::new_v4(), &account_id, &message_id, &attempt_id, &vec![4u8; 32]],
    )
    .await
    .unwrap();
    let vault = WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(7))).unwrap();
    let secret = vault
        .seal(account_id, endpoint_id, &crate::test_keys::key(8))
        .unwrap();
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) \
         VALUES($1,$2,'https://hooks.example.org/inbound',$3,1,true)",
        &[&endpoint_id, &account_id, &secret],
    )
    .await
    .unwrap();

    let state = DeviceSocketState {
        database_url: schema_url,
        site_id: "socket-test".into(),
        instance_id: "virtual-server".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: true,
        line_opt_out_enabled: false,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let challenge_json = receive_json(&mut socket).await;
    assert_eq!(challenge_json["type"], "challenge");
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id,
        device_id,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = signing.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account_id,
            "device_id":device_id,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session_json = receive_json(&mut socket).await;
    assert_eq!(session_json["type"], "session");
    let connection_epoch = session_json["connection_epoch"].as_i64().unwrap();
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let inbound_session = InboundSession {
        account_id,
        device_id,
        site_id: "socket-test",
        instance_id: "virtual-server",
        connection_epoch,
        deployment_epoch: 1,
    };
    let event = InboundEvent {
        event_id,
        sequence: 1,
        message_id,
        attempt_id,
        classification: inbound::Classification::CapturedLocal,
        observed_at_ms,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let signature: Signature = signing.sign(&inbound::signed_event_bytes(inbound_session, &event));
    let frame = json!({
        "v":1,"type":"inbound_event","connection_epoch":connection_epoch,
        "event_id":event_id,"sequence":1,"message_id":message_id,
        "attempt_id":attempt_id,"classification":"captured_local",
        "observed_at_ms":observed_at_ms,"part_count":1,
        "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    });
    send_json(&mut socket, frame.clone()).await;
    let ack = receive_json(&mut socket).await;
    assert_eq!(
        ack,
        json!({"v":1,"type":"inbound_event_ack","event_id":event_id,"created":true,"queued_deliveries":1})
    );
    send_json(&mut socket, frame).await;
    let replay_ack = receive_json(&mut socket).await;
    assert_eq!(
        replay_ack,
        json!({"v":1,"type":"inbound_event_ack","event_id":event_id,"created":false,"queued_deliveries":0})
    );
    let row = db
        .query_one(
            "SELECT (SELECT count(*) FROM inbound_events WHERE id=$1), \
                    (SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2)",
            &[&event_id, &endpoint_id],
        )
        .await
        .unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 1));

    // The socket replay above must still leave one logical event and delivery.
    // Drive that delivery through the real claim, payload, and retry code while
    // a local receiver stub checks the stable body and decrypted signing key.
    let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    for (attempt, expected_outcome) in ["http_error", "network_error", "ack"]
        .into_iter()
        .enumerate()
    {
        let received = received.clone();
        assert!(
            dispatch_one_with(
                &mut db,
                &vault,
                "virtual-receiver",
                move |url, body, secret| async move {
                    assert_eq!(url, "https://hooks.example.org/inbound");
                    assert_eq!(secret.as_slice(), crate::test_keys::key(8).as_slice());
                    let parsed: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(parsed["event_id"], event_id.to_string());
                    assert_eq!(parsed["message_id"], message_id.to_string());
                    assert_eq!(parsed["content_kind"], "metadata_only");
                    assert!(parsed.get("sender_e164").is_none());
                    assert!(parsed.get("body").is_none());
                    let timestamp = 1_750_000_000_u64;
                    let header =
                        crate::webhook_egress::signature_header(&secret, timestamp, &body).unwrap();
                    let digest = header.strip_prefix("v1=").unwrap();
                    let digest = digest
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let mut verifier =
                        <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&secret).unwrap();
                    verifier.update(timestamp.to_string().as_bytes());
                    verifier.update(b".");
                    verifier.update(&body);
                    verifier.verify_slice(&digest).unwrap();
                    received.lock().unwrap().push(body);
                    match attempt {
                        0 => Ok(DeliveryResponse {
                            status: 500,
                            acknowledged: false,
                        }),
                        1 => Err(EgressError::Transport),
                        _ => Ok(DeliveryResponse {
                            status: 204,
                            acknowledged: true,
                        }),
                    }
                }
            )
            .await
            .unwrap()
        );
        let outcome: String = db
            .query_one(
                "SELECT outcome FROM webhook_attempts a JOIN webhook_deliveries d ON d.id=a.delivery_id \
                 WHERE d.event_id=$1 AND d.endpoint_id=$2 AND a.attempt_number=$3",
                &[&event_id, &endpoint_id, &((attempt + 1) as i16)],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(outcome, expected_outcome);
        if attempt < 2 {
            assert!(
                !dispatch_one_with(&mut db, &vault, "early-retry", |_, _, _| async {
                    unreachable!("retry must observe backoff")
                })
                .await
                .unwrap()
            );
            assert_eq!(
                db.execute(
                    "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' \
                     WHERE event_id=$1 AND endpoint_id=$2 AND status='pending'",
                    &[&event_id, &endpoint_id],
                )
                .await
                .unwrap(),
                1
            );
        }
    }
    {
        let bodies = received.lock().unwrap();
        assert_eq!(bodies.len(), 3);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
    }
    let row = db
        .query_one(
            "SELECT (SELECT count(*) FROM inbound_events WHERE id=$1), \
                    (SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2), \
                    (SELECT status FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2), \
                    (SELECT attempt_count FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2)",
            &[&event_id, &endpoint_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, String>(2), "succeeded");
    assert_eq!(row.get::<_, i16>(3), 3);
    assert!(
        !dispatch_one_with(&mut db, &vault, "virtual-receiver", |_, _, _| async {
            unreachable!("a completed delivery must not be sent again")
        })
        .await
        .unwrap()
    );

    // Revoking a key must close an already-authenticated connection on its
    // next heartbeat, even though its original challenge succeeded.
    db.execute(
        "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
        &[&device_id],
    )
    .await
    .unwrap();
    send_json(&mut socket, json!({"type":"heartbeat", "v":1})).await;
    let closed = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(matches!(closed, Some(Ok(Message::Close(_))) | None));
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn socket_handshakes_share_http_enrollment_budgets() {
    use crate::http_enrollment::{self, EnrollmentHttpState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("socket_budget_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'budget fixture')",
        &[&device_id, &account_id],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device_id,&account_id,&public_key.as_bytes(),&&fingerprint[..]]).await.unwrap();
    let auth_hasher = Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap());
    let enrollment_hasher = Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap());
    let state = DeviceSocketState {
        database_url: schema_url.clone(),
        site_id: "fixture".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: enrollment_hasher.clone(),
        auth_hasher: auth_hasher.clone(),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let http = http_enrollment::router(EnrollmentHttpState::new(
        schema_url,
        auth_hasher.clone(),
        enrollment_hasher,
        "https://zrotext.example".into(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let path = format!("/devices/{device_id}/challenge");
    let request = || {
        Request::builder()
            .method("POST")
            .uri(&path)
            .body(Body::empty())
            .unwrap()
    };
    // Spend 29 attempts on HTTP, then the last attempt on a fresh socket.
    for _ in 0..29 {
        assert_eq!(
            http.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let challenge = receive_json(&mut socket).await;
    assert_eq!(challenge["type"], "challenge");
    assert_eq!(
        http.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A reconnect must not create the 31st persistent challenge.
    let (mut denied, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut denied,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(5), denied.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_)))
    ));
    let count: i64 = db
        .query_one("SELECT count(*) FROM device_auth_challenges", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 30);
    // A valid signature must still be rejected when the shared proof budget is spent.
    for _ in 0..30 {
        assert!(
            abuse_limits::consume(
                &db,
                &auth_hasher,
                Limit::DeviceAuthenticate,
                Some(&device_id.to_string())
            )
            .await
            .unwrap()
        );
    }
    let typed = DeviceChallenge {
        id: Uuid::parse_str(challenge["challenge_id"].as_str().unwrap()).unwrap(),
        account_id,
        device_id,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let signature: Signature = signing.sign(&device_challenge_bytes(&typed));
    send_json(&mut socket, json!({"v":1,"type":"proof","challenge_id":typed.id,"account_id":account_id,"device_id":device_id,"nonce":challenge["nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())})).await;
    assert!(matches!(
        timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_)))
    ));
    let used: bool = db
        .query_one(
            "SELECT used_at IS NOT NULL FROM device_auth_challenges WHERE id=$1",
            &[&typed.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !used,
        "rate-limited proof must not reach signature verification"
    );
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn enrolled_phone_reconnects_after_junk_spends_handshake_budgets() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("socket_junk_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    db.execute("INSERT INTO sites(site_id) VALUES('fixture')", &[])
        .await
        .unwrap();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'reconnect fixture')",
        &[&device_id, &account_id],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device_id,&account_id,&public_key.as_bytes(),&&fingerprint[..]]).await.unwrap();
    let auth_hasher = Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap());
    let state = DeviceSocketState {
        database_url: schema_url,
        site_id: "fixture".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: auth_hasher.clone(),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    // One anonymous source spends both shared handshake budgets with
    // made-up device IDs, as rapid hello/close cycles would.
    for limit in [Limit::DeviceChallenge, Limit::DeviceAuthenticate] {
        for _ in 0..300 {
            assert!(
                abuse_limits::consume(&db, &auth_hasher, limit, Some(&Uuid::new_v4().to_string()))
                    .await
                    .unwrap()
            );
        }
    }
    let (mut junk, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut junk,
        json!({"v":1,"type":"hello","device_id":Uuid::new_v4()}),
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(5), junk.next()).await.unwrap(),
        Some(Ok(Message::Close(Some(frame)))) if u16::from(frame.code) == RETRY_LATER
    ));
    // The enrolled phone still completes its handshake.
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let challenge_json = receive_json(&mut socket).await;
    assert_eq!(challenge_json["type"], "challenge");
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id,
        device_id,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = signing.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account_id,
            "device_id":device_id,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session_json = receive_json(&mut socket).await;
    assert_eq!(session_json["type"], "session");
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
