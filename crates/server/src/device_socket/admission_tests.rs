// SPDX-License-Identifier: AGPL-3.0-only
//! Handshake admission: sockets that never authenticate expire on a hard
//! deadline, release their handshake slot, and never hold session capacity.
//!
//! These tests drive real localhost sockets, so they use short configured
//! bounds instead of a paused clock: auto-advance would fire the deadlines
//! while the runtime waits on socket I/O.

#[path = "database_capacity_tests.rs"]
mod database_capacity_tests;
#[path = "preconditions_lock_tests.rs"]
mod preconditions_lock_tests;
#[path = "preconditions_tests.rs"]
mod preconditions_tests;

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
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: std::sync::Arc::new(super::mms_spike_policy::MmsSpikePolicy::disabled()),
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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

#[test]
fn one_account_at_its_share_leaves_session_slots_for_other_accounts() {
    let admission =
        SocketAdmission::new(4, 4, AUTH_TIMEOUT, HANDSHAKE_DEADLINE).with_account_limit(2);
    let (busy, other) = (Uuid::new_v4(), Uuid::new_v4());
    let first = admission.admit_session(busy, Uuid::new_v4()).unwrap();
    let _second = admission.admit_session(busy, Uuid::new_v4()).unwrap();
    assert!(
        admission.admit_session(busy, Uuid::new_v4()).is_none(),
        "a third device must not exceed the account's share"
    );
    assert_eq!(admission.established.available_permits(), 2);

    let _other = admission
        .admit_session(other, Uuid::new_v4())
        .expect("another account still connects while one holds its maximum");
    assert_eq!(admission.established.available_permits(), 1);

    // The share is released with the socket's slot on every exit path.
    drop(first);
    assert_eq!(admission.established.available_permits(), 2);
    assert!(admission.admit_session(busy, Uuid::new_v4()).is_some());
}

#[test]
fn account_share_never_exceeds_process_capacity() {
    let admission = SocketAdmission::new(2, 2, AUTH_TIMEOUT, HANDSHAKE_DEADLINE);
    let _a = admission
        .admit_session(Uuid::new_v4(), Uuid::new_v4())
        .unwrap();
    let _b = admission
        .admit_session(Uuid::new_v4(), Uuid::new_v4())
        .unwrap();
    assert!(
        admission
            .admit_session(Uuid::new_v4(), Uuid::new_v4())
            .is_none()
    );
}

#[tokio::test]
async fn reconnect_takes_over_its_device_slot_and_signals_the_older_socket() {
    // One process slot and one per account: a reconnect needs neither a
    // second process slot nor a second share of the account's budget.
    let admission =
        SocketAdmission::new(1, 1, AUTH_TIMEOUT, HANDSHAKE_DEADLINE).with_account_limit(1);
    let (account, device) = (Uuid::new_v4(), Uuid::new_v4());
    let older = admission.admit_session(account, device).unwrap();
    assert_eq!(admission.established.available_permits(), 0);

    let newer = admission
        .admit_session(account, device)
        .expect("a reconnecting device must not wait for its older socket's slot");
    assert_eq!(admission.established.available_permits(), 0);
    timeout(Duration::from_secs(1), older.superseded.notified())
        .await
        .expect("the superseded socket is told to close within a second");

    // The older socket exiting later must not free the newer socket's slot.
    drop(older);
    assert_eq!(admission.established.available_permits(), 0);
    assert!(
        admission.admit_session(account, Uuid::new_v4()).is_none(),
        "the device still counts once against its account"
    );
    assert!(
        timeout(Duration::from_millis(50), newer.superseded.notified())
            .await
            .is_err(),
        "the current socket is not signalled"
    );
    drop(newer);
    assert_eq!(admission.established.available_permits(), 1);
    assert!(admission.admit_session(account, Uuid::new_v4()).is_some());
}

async fn expect_closed_within(socket: &mut TestSocket, limit: Duration) {
    timeout(limit, async {
        while let Some(frame) = socket.next().await {
            match frame {
                Ok(WsMessage::Close(_)) | Err(_) => return,
                Ok(_) => continue,
            }
        }
    })
    .await
    .expect("superseded socket stayed open");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn account_share_and_reconnect_takeover_on_real_sockets() {
    use database_capacity_tests::{Fixture, prove};
    let fixture = Fixture::new().await;
    let admission =
        SocketAdmission::new(8, 4, AUTH_TIMEOUT, HANDSHAKE_DEADLINE).with_account_limit(1);
    let (address, server) = serve(
        socket_state(fixture.url.clone(), "capacity-test"),
        admission.clone(),
    )
    .await;
    let connect = |device: Uuid, signing: SigningKey| async move {
        let mut socket = open(address).await;
        send_json(
            &mut socket,
            json!({"v":1,"type":"hello","device_id":device}),
        )
        .await;
        let challenge = receive_json(&mut socket).await;
        assert_eq!(challenge["type"], "challenge");
        (socket, challenge, signing)
    };

    // The first account holds its whole share with one phone.
    let (phone, signing) = fixture.device().await;
    let (mut held, challenge, signing) = connect(phone, signing).await;
    let held_epoch = prove(&mut held, challenge, &signing).await;
    assert_eq!(admission.established.available_permits(), 3);

    // A second device of the same account is refused after its proof.
    let (extra, extra_signing) = fixture.device().await;
    let (mut refused, challenge, extra_signing) = connect(extra, extra_signing).await;
    let frame = &challenge;
    let proof_challenge = DeviceChallenge {
        id: Uuid::parse_str(frame["challenge_id"].as_str().unwrap()).unwrap(),
        account_id: fixture.account_id,
        device_id: extra,
        nonce: URL_SAFE_NO_PAD
            .decode(frame["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = extra_signing.sign(&device_challenge_bytes(&proof_challenge));
    send_json(
        &mut refused,
        json!({
            "v":1,"type":"proof","challenge_id":proof_challenge.id,"account_id":fixture.account_id,
            "device_id":extra,"nonce":frame["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    assert_eq!(expect_close(&mut refused).await, RETRY_LATER);
    assert_eq!(admission.established.available_permits(), 3);

    // Another account is still admitted while the first holds its maximum.
    let other_account = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let other_signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = other_signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    fixture
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&other_account])
        .await
        .unwrap();
    fixture
        .db
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'other phone')",
            &[&other_device, &other_account],
        )
        .await
        .unwrap();
    fixture.db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&other_device, &other_account, &public_key.as_bytes(), &&fingerprint[..]],
    ).await.unwrap();
    let (mut other, challenge, other_signing) = connect(other_device, other_signing).await;
    prove(&mut other, challenge, &other_signing).await;
    assert_eq!(admission.established.available_permits(), 2);

    // The same phone reconnecting takes over its slot; the older socket is
    // closed well before the 10 second session check would notice.
    let (mut replacement, challenge, signing) = connect(phone, signing).await;
    let epoch = prove(&mut replacement, challenge, &signing).await;
    assert!(epoch > held_epoch);
    expect_closed_within(&mut held, Duration::from_secs(1)).await;
    assert_eq!(admission.established.available_permits(), 2);
    send_json(&mut replacement, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(
        receive_json(&mut replacement).await,
        json!({"v":1,"type":"heartbeat_ack","connection_epoch":epoch})
    );

    drop((replacement, other, held));
    server.abort();
    fixture.finish().await;
}
