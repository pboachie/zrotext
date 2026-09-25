// SPDX-License-Identifier: AGPL-3.0-only
//! Handshake admission: sockets that never authenticate expire on a hard
//! deadline, release their handshake slot, and never hold session capacity.
//!
//! These tests drive real localhost sockets, so they use short configured
//! bounds instead of a paused clock: auto-advance would fire the deadlines
//! while the runtime waits on socket I/O.

use super::*;
use crate::enrollment::{DeviceChallenge, device_challenge_bytes};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio_postgres::NoTls;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{self, Message as WsMessage},
};

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn socket_state(database_url: String, site_id: &str) -> DeviceSocketState {
    DeviceSocketState {
        database_url,
        site_id: site_id.into(),
        instance_id: "admission-hub".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(61)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(62)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    }
}

async fn serve(
    state: DeviceSocketState,
    admission: SocketAdmission,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router_with_admission(state, admission))
            .await
            .unwrap();
    });
    (address, server)
}

async fn open(address: SocketAddr) -> TestSocket {
    connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .expect("handshake slot should be available")
        .0
}

async fn expect_refused(address: SocketAddr) {
    match connect_async(format!("ws://{address}/v1/device-stream")).await {
        Err(tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(other) => panic!("expected 503 refusal, got {other}"),
        Ok(_) => panic!("expected 503 refusal, socket was admitted"),
    }
}

async fn expect_close(socket: &mut TestSocket) -> u16 {
    loop {
        let frame = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("pending socket was not closed")
            .expect("socket ended without close frame")
            .expect("socket read failed");
        match frame {
            WsMessage::Close(Some(frame)) => return u16::from(frame.code),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            other => panic!("expected close frame, got {other:?}"),
        }
    }
}

async fn send_json(socket: &mut TestSocket, value: Value) {
    socket
        .send(WsMessage::Text(value.to_string().into()))
        .await
        .unwrap();
}

async fn receive_json(socket: &mut TestSocket) -> Value {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("socket response timed out")
        .expect("socket closed")
        .expect("socket read failed");
    serde_json::from_str(frame.to_text().expect("expected a text frame")).unwrap()
}

#[tokio::test]
async fn idle_handshakes_expire_at_deadline_and_release_their_slots() {
    let admission = SocketAdmission::new(2, 4, AUTH_TIMEOUT, Duration::from_millis(300));
    let (address, server) = serve(
        socket_state(
            "host=127.0.0.1 port=1 connect_timeout=1 user=invalid".into(),
            "site-a",
        ),
        admission.clone(),
    )
    .await;

    // Two sockets upgrade and then say nothing, saturating the handshake budget.
    let mut idle_a = open(address).await;
    let mut idle_b = open(address).await;
    expect_refused(address).await;
    assert_eq!(admission.handshaking.available_permits(), 0);
    assert_eq!(
        admission.established.available_permits(),
        4,
        "unauthenticated sockets must not hold session capacity"
    );

    // Neither socket reaches the 10 second hello timeout: the hard handshake
    // deadline closes both, and the slots are free once the close is observed.
    let started = Instant::now();
    assert_eq!(expect_close(&mut idle_a).await, RETRY_LATER);
    assert_eq!(expect_close(&mut idle_b).await, RETRY_LATER);
    assert!(started.elapsed() < AUTH_TIMEOUT);
    assert_eq!(admission.handshaking.available_permits(), 2);

    // A new device is admitted into the handshake again. Storage is offline
    // here, so a hello proceeds past admission and is refused with 1013.
    let mut device = open(address).await;
    send_json(
        &mut device,
        json!({"v":1,"type":"hello","device_id":Uuid::new_v4()}),
    )
    .await;
    assert_eq!(expect_close(&mut device).await, RETRY_LATER);
    assert_eq!(admission.handshaking.available_permits(), 2);
    server.abort();
}

#[tokio::test]
async fn silent_socket_is_closed_by_hello_step_timeout() {
    let admission = SocketAdmission::new(1, 1, Duration::from_millis(200), HANDSHAKE_DEADLINE);
    let (address, server) = serve(
        socket_state(
            "host=127.0.0.1 port=1 connect_timeout=1 user=invalid".into(),
            "site-a",
        ),
        admission.clone(),
    )
    .await;
    let mut idle = open(address).await;
    expect_refused(address).await;
    assert_eq!(expect_close(&mut idle).await, close_code::POLICY);
    assert_eq!(admission.handshaking.available_permits(), 1);
    assert_eq!(admission.established.available_permits(), 1);
    drop(open(address).await);
    server.abort();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn saturated_handshake_budget_does_not_lock_out_enrolled_device() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("socket_admission_{}", Uuid::new_v4().simple());
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
    db.execute("INSERT INTO sites(site_id) VALUES('admission-test')", &[])
        .await
        .unwrap();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'admission phone')",
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

    let admission = SocketAdmission::new(1, 2, AUTH_TIMEOUT, Duration::from_secs(2));
    let (address, server) = serve(
        socket_state(schema_url, "admission-test"),
        admission.clone(),
    )
    .await;

    // An idle socket fills the whole handshake budget; the phone is refused
    // only until the deadline reclaims that slot.
    let mut idle = open(address).await;
    expect_refused(address).await;
    assert_eq!(expect_close(&mut idle).await, RETRY_LATER);

    let mut phone = open(address).await;
    send_json(
        &mut phone,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let challenge_json = receive_json(&mut phone).await;
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
        &mut phone,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account_id,
            "device_id":device_id,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session_json = receive_json(&mut phone).await;
    assert_eq!(session_json["type"], "session");
    let connection_epoch = session_json["connection_epoch"].as_i64().unwrap();
    // The authenticated phone moved from the handshake budget to a session slot.
    assert_eq!(admission.handshaking.available_permits(), 1);
    assert_eq!(admission.established.available_permits(), 1);

    // Saturating the handshake budget again cannot displace the session.
    let mut idle = open(address).await;
    expect_refused(address).await;
    send_json(&mut phone, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(
        receive_json(&mut phone).await,
        json!({"v":1,"type":"heartbeat_ack","connection_epoch":connection_epoch})
    );
    assert_eq!(expect_close(&mut idle).await, RETRY_LATER);
    assert_eq!(admission.handshaking.available_permits(), 1);
    send_json(&mut phone, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(
        receive_json(&mut phone).await,
        json!({"v":1,"type":"heartbeat_ack","connection_epoch":connection_epoch})
    );

    let _ = phone.close(None).await;
    drop(phone);
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
