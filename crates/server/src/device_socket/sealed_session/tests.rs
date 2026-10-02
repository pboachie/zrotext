// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::device_socket::*;
use crate::enrollment::{DeviceChallenge, device_challenge_bytes};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message as WsMessage, client::IntoClientRequest},
};

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Fixture {
    db: tokio_postgres::Client,
    url: String,
    schema: String,
    account: Uuid,
    device: Uuid,
    signing: SigningKey,
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        let base = std::env::var("ZT_INBOUND_TEST_DATABASE_URL").unwrap();
        let (db, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("sealed_socket_time_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        crate::auth::test_schema::apply(&db).await;
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let signing = SigningKey::generate_from_rng(&mut rand::rng());
        let public = signing.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(public.as_bytes()).into();
        db.batch_execute("INSERT INTO sites(site_id) VALUES('sealed-time-test')")
            .await
            .unwrap();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual sealed phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device,&account,&public.as_bytes(),&&fingerprint[..]]).await.unwrap();
        let state = DeviceSocketState {
            database_url: url.clone(),
            site_id: "sealed-time-test".into(),
            instance_id: "sealed-time-server".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(77)).unwrap()),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(78)).unwrap()),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: true,
            sealed_dispatch_enabled: true,
            inbound_pilot_enabled: false,
            line_opt_out_enabled: false,
            sms_line_activation_enabled: false,
            mms_spike_policy: Arc::new(MmsSpikePolicy::disabled()),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        Self {
            db,
            url,
            schema,
            account,
            device,
            signing,
            address,
            server,
        }
    }
    async fn phone(&self, protocol: &str) -> (TestSocket, i64) {
        let mut request = format!("ws://{}/v1/device-stream", self.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("sec-websocket-protocol", protocol.parse().unwrap());
        let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.headers()["sec-websocket-protocol"], protocol);
        send(
            &mut socket,
            json!({"v":1,"type":"hello","device_id":self.device}),
        )
        .await;
        let frame = receive(&mut socket).await;
        assert_eq!(frame["type"], "challenge");
        let challenge = DeviceChallenge {
            id: Uuid::parse_str(frame["challenge_id"].as_str().unwrap()).unwrap(),
            account_id: self.account,
            device_id: self.device,
            nonce: URL_SAFE_NO_PAD
                .decode(frame["nonce"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let signature: Signature = self.signing.sign(&device_challenge_bytes(&challenge));
        send(&mut socket,json!({"v":1,"type":"proof","challenge_id":challenge.id,"account_id":self.account,"device_id":self.device,
            "nonce":frame["nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())})).await;
        let session = receive(&mut socket).await;
        assert_eq!(session["type"], "session");
        (socket, session["connection_epoch"].as_i64().unwrap())
    }
    async fn cleanup(self) {
        self.server.abort();
        let _ = self.server.await;
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}
async fn send(socket: &mut TestSocket, frame: Value) {
    socket
        .send(WsMessage::Text(frame.to_string().into()))
        .await
        .unwrap();
}
async fn receive(socket: &mut TestSocket) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(frame.to_text().expect("expected JSON response")).unwrap()
}
async fn refused(socket: &mut TestSocket, expected_code: Option<u16>, context: &str) {
    let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .unwrap()
        .unwrap()
        .expect(context);
    let WsMessage::Close(frame) = frame else {
        panic!("expected refusal close, got {frame:?}")
    };
    assert_eq!(
        frame.map(|frame| u16::from(frame.code)),
        expected_code,
        "{context}"
    );
    socket
        .flush()
        .await
        .expect("acknowledge the server close before dropping the fixture socket");
}
fn request(epoch: i64, challenge: Uuid) -> Value {
    json!({"v":1,"type":"sealed_session_request","connection_epoch":epoch,"challenge":challenge})
}

fn readiness(epoch: i64) -> Value {
    json!({"v":1,"type":"sealed_ready","grant_version":1,"connection_epoch":epoch,
        "line_id":Uuid::new_v4(),"binding_generation":1,"reader_key_id":URL_SAFE_NO_PAD.encode([1u8;32])})
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; v2 readiness never rearms, no radio"]
async fn resampling_time_cannot_rearm_one_use_sealed_readiness() {
    let fixture = Fixture::new().await;
    let (mut phone, epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    send(&mut phone, request(epoch, Uuid::new_v4())).await;
    assert_eq!(receive(&mut phone).await["type"], "sealed_session");
    send(&mut phone, readiness(epoch)).await;
    send(&mut phone, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(
        receive(&mut phone).await,
        json!({"v":1,"type":"heartbeat_ack","connection_epoch":epoch})
    );
    tokio::time::sleep(Duration::from_secs(5)).await;
    send(&mut phone, request(epoch, Uuid::new_v4())).await;
    assert_eq!(receive(&mut phone).await["type"], "sealed_session");
    send(&mut phone, readiness(epoch)).await;
    refused(
        &mut phone,
        None,
        "resampling cannot renew one-use readiness",
    )
    .await;
    assert_eq!(
        fixture
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(phone);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real authenticated v2 socket, no radio"]
async fn authenticated_time_sample_uses_fresh_database_time_after_wait_and_refuses_nonce_replay() {
    let fixture = Fixture::new().await;
    let (mut phone, epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    let (mut blocker, connection) = tokio_postgres::connect(&fixture.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let tx = blocker.transaction().await.unwrap();
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    tx.batch_execute("LOCK TABLE device_sessions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let challenge = Uuid::new_v4();
    send(&mut phone, request(epoch, challenge)).await;
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let blocked:bool=fixture.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",&[&pid]).await.unwrap().get(0);
            if blocked {break}
            tokio::task::yield_now().await;
        }
    }).await.expect("time sample must actually wait for current-session verification");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let lower: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    tx.commit().await.unwrap();
    let first = receive(&mut phone).await;
    assert_eq!(first["type"], "sealed_session");
    assert_eq!(first["challenge"], challenge.to_string());
    assert_eq!(first["account_id"], fixture.account.to_string());
    assert_eq!(first["device_id"], fixture.device.to_string());
    assert_eq!(first["connection_epoch"], epoch);
    assert_eq!(first["deployment_epoch"], 1);
    assert_ne!(first["session_id"], Uuid::nil().to_string());
    assert!(first["server_time_ms"].as_i64().unwrap() >= lower);
    tokio::time::sleep(Duration::from_secs(5)).await;
    let next = Uuid::new_v4();
    send(&mut phone, request(epoch, next)).await;
    let second = receive(&mut phone).await;
    assert_eq!(second["challenge"], next.to_string());
    assert_eq!(second["session_id"], first["session_id"]);
    assert!(
        second["server_time_ms"].as_i64().unwrap() >= first["server_time_ms"].as_i64().unwrap()
    );
    let row=fixture.db.query_one("SELECT (SELECT count(*) FROM message_attempts),dispatch_enabled FROM deployment_authority WHERE singleton=TRUE",&[]).await.unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        0,
        "time samples must never create grants"
    );
    assert!(
        !row.get::<_, bool>(1),
        "time samples must never enable dispatch"
    );
    tokio::time::sleep(Duration::from_secs(5)).await;
    send(&mut phone, request(epoch, challenge)).await;
    refused(&mut phone, Some(1008), "replayed nonce").await;
    drop(phone);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real authenticated socket authority refusals"]
async fn v2_time_cannot_bypass_protocol_initial_sample_or_replaced_device_session() {
    let fixture = Fixture::new().await;
    let (mut v1, epoch) = fixture.phone(crate::sealed_dispatch::wire::PROTOCOL).await;
    send(&mut v1, request(epoch, Uuid::new_v4())).await;
    refused(&mut v1, None, "v1 cannot sample time").await;
    drop(v1);
    let (mut early, epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    send(&mut early, readiness(epoch)).await;
    refused(&mut early, None, "v2 readiness needs an initial sample").await;
    drop(early);
    let (mut wrong, epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    send(&mut wrong, request(epoch + 1, Uuid::new_v4())).await;
    refused(&mut wrong, Some(1008), "foreign connection epoch").await;
    drop(wrong);
    let (mut old, epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    // Replace SQL authority without the separate local admission kick. This
    // keeps the old transport live so the sample's current-session check runs.
    fixture.db.execute("UPDATE device_sessions SET connection_epoch=connection_epoch+1 WHERE account_id=$1 AND device_id=$2", &[&fixture.account,&fixture.device]).await.unwrap();
    send(&mut old, request(epoch, Uuid::new_v4())).await;
    refused(&mut old, Some(1008), "replaced session").await;
    drop(old);
    let (mut current, next_epoch) = fixture
        .phone(crate::sealed_dispatch::wire::PROTOCOL_V2)
        .await;
    assert!(next_epoch > epoch);
    fixture
        .db
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&fixture.account],
        )
        .await
        .unwrap();
    send(&mut current, request(next_epoch, Uuid::new_v4())).await;
    refused(&mut current, Some(1008), "disabled account").await;
    drop(current);
    fixture.cleanup().await;
}
#[test]
fn request_parser_rejects_unknown_authority_fields_and_missing_challenge() {
    let base = serde_json::json!({"v":1,"type":"sealed_session_request","connection_epoch":1,"challenge":Uuid::new_v4()});
    assert!(matches!(
        serde_json::from_value::<super::super::ClientFrame>(base.clone()),
        Ok(super::super::ClientFrame::SealedSessionRequest { v: 1, .. })
    ));
    let mut extra = base.clone();
    extra["authorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<super::super::ClientFrame>(extra).is_err());
    let mut missing = base;
    missing.as_object_mut().unwrap().remove("challenge");
    assert!(serde_json::from_value::<super::super::ClientFrame>(missing).is_err());
}
#[test]
fn replay_rate_and_lifetime_budget_fail_closed_without_evicting_nonces() {
    let mut samples = Samples::new();
    let start = Instant::now();
    let first = Uuid::new_v4();
    let session = samples.session_id();
    assert!(!samples.is_sampled());
    assert!(!samples.admit(Uuid::nil(), start));
    assert!(samples.admit(first, start));
    assert!(!samples.admit(Uuid::new_v4(), start + Duration::from_secs(4)));
    assert!(!samples.admit(first, start + Duration::from_secs(5)));
    samples.sampled();
    for index in 1..64 {
        assert!(samples.admit(Uuid::new_v4(), start + Duration::from_secs(index * 5)));
    }
    assert!(!samples.admit(Uuid::new_v4(), start + Duration::from_secs(320)));
    assert!(!samples.admit(first, start + Duration::from_secs(325)));
    assert_eq!(samples.session_id(), session);
    assert!(samples.is_sampled());
    assert_ne!(Samples::new().session_id(), session);
}
