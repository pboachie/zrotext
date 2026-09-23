// SPDX-License-Identifier: AGPL-3.0-only
//! A localhost device speaks the real socket protocol against disposable SQL.
//! No Android radio, SMS, DNS lookup, or webhook request is involved.

use super::*;
use crate::{
    enrollment::{DeviceChallenge, device_challenge_bytes},
    webhook_worker::WebhookSecretVault,
};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
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
async fn authenticated_inbound_frame_commits_one_webhook_delivery() {
    let Ok(url) = std::env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL to run virtual inbound socket test");
        return;
    };
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_socket_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let endpoint_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let signing = SigningKey::random(&mut OsRng);
    let public_key = signing.verifying_key().to_encoded_point(false);
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
    let vault = WebhookSecretVault::new(1, Zeroizing::new(vec![7; 32])).unwrap();
    let secret = vault.seal(account_id, endpoint_id, &[8; 32]).unwrap();
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
        enrollment_hasher: Arc::new(EnrollmentHasher::new(vec![9; 32]).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: true,
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

    socket.close(None).await.unwrap();
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
