// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_inbound::line_activation::v2_runtime::db_tests::SmsCase;
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, signature::Signer};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message as WireMessage, client::IntoClientRequest},
};
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
async fn frame(socket: &mut Socket, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            if let Some(Ok(WireMessage::Text(text))) = socket.next().await {
                let v: Value = serde_json::from_str(&text).unwrap();
                if v["type"] == kind {
                    return v;
                }
            } else {
                panic!("socket closed before {kind}");
            }
        }
    })
    .await
    .expect("bounded actual frame wait")
}
fn state(c: &SmsCase) -> DeviceSocketState {
    DeviceSocketState {
        database_url: c.url.clone(),
        site_id: "v2-test".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: c.hasher.clone(),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: true,
        mms_spike_policy: Arc::new(MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    }
}
async fn authenticate(c: &SmsCase, url: &str, token: &str) -> (Socket, i64) {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", token.parse().unwrap());
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], token);
    socket
        .send(WireMessage::Text(
            serde_json::json!({"v":1,"type":"hello","device_id":c.device})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let challenge = frame(&mut socket, "challenge").await;
    let id = Uuid::parse_str(challenge["challenge_id"].as_str().unwrap()).unwrap();
    let nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature: Signature = c.paired.sign(&crate::enrollment::device_challenge_bytes(
        &crate::enrollment::DeviceChallenge {
            id,
            account_id: c.principal.tenant.account_id(),
            device_id: c.device,
            nonce,
        },
    ));
    socket.send(WireMessage::Text(serde_json::json!({"v":1,"type":"proof","challenge_id":id,"account_id":c.principal.tenant.account_id(),"device_id":c.device,"nonce":challenge["nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}).to_string().into())).await.unwrap();
    let session = frame(&mut socket, "session").await;
    assert_eq!(session["v"], 1);
    assert!(session.get("line_activation_version").is_none());
    let epoch = session["connection_epoch"].as_i64().unwrap();
    (socket, epoch)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; production socket and genuine owner/device enrollment"]
async fn actual_composite_handshake_and_legacy_reconnect_store_different_versions() {
    let c = SmsCase::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = tokio::sync::oneshot::channel();
    let (stop_sender, stop_receiver) = stop;
    let app = router(state(&c));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_receiver.await;
            })
            .await
            .unwrap();
    });
    let url = format!("ws://{address}/v1/device-stream");
    let (mut socket, epoch) = authenticate(&c, &url, PROTOCOL).await;
    assert_eq!(
        c.db.query_one(
            "SELECT line_activation_version FROM device_sessions WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        2
    );
    let mut db = c.connect().await;
    let opened = runtime::open(
        &mut db,
        &c.principal,
        c.line,
        c.device,
        Purpose::Sms,
        Uuid::new_v4(),
        None,
    )
    .await
    .unwrap();
    let incoming = frame(&mut socket, "sms_line_challenge_v2").await;
    assert_eq!(incoming["challenge_id"], opened.tuple.id.to_string());
    let mut raw = [0u8; 121];
    raw[0..2].copy_from_slice(&35u16.to_be_bytes());
    raw[2..4].copy_from_slice(&2u16.to_be_bytes());
    raw[4..8].copy_from_slice(&7i32.to_be_bytes());
    raw[8] = 2;
    for offset in [9, 25, 49, 73] {
        raw[offset..offset + 16].copy_from_slice(Uuid::new_v4().as_bytes());
    }
    raw[65..73].copy_from_slice(&1i64.to_be_bytes());
    raw[89..121].fill(7);
    let observation =
        crate::sealed_inbound::line_activation::v2::ObservationV2::decode(&raw).unwrap();
    let statement = crate::sealed_inbound::line_activation::v2::device_statement(
        crate::sealed_inbound::line_activation::v2::PurposeV2::Sms,
        &opened.tuple,
        &observation,
    )
    .unwrap();
    let proof: Signature = c.paired.sign(&statement.bytes());
    socket.send(WireMessage::Text(serde_json::json!({"v":2,"type":"sms_line_proof_v2","connection_epoch":epoch.to_string(),"challenge_id":opened.tuple.id,"observation_b64url":URL_SAFE_NO_PAD.encode(raw),"signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())}).to_string().into())).await.unwrap();
    assert_eq!(
        frame(&mut socket, "sms_line_proof_ack_v2").await["accepted"],
        true
    );
    let view = runtime::view(&mut db, &c.principal, c.line, opened.tuple.id, Purpose::Sms)
        .await
        .unwrap();
    let approval: Signature = c.approval.sign(&view.owner_statement.unwrap());
    runtime::approve(
        &mut db,
        &c.principal,
        c.line,
        opened.tuple.id,
        Purpose::Sms,
        approval.to_der().as_bytes(),
    )
    .await
    .unwrap();
    wake_sms_line_activation();
    let final_ack = frame(&mut socket, "sms_line_activated_v2").await;
    assert_eq!(
        final_ack["device_signature_sha256"],
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(proof.to_der().as_bytes()))
    );
    let (mut legacy, next) = authenticate(&c, &url, preconditions::PROTOCOL_V2).await;
    assert!(next > epoch);
    assert_eq!(
        c.db.query_one(
            "SELECT line_activation_version FROM device_sessions WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );
    assert!(runtime::current(&mut db, c.session(epoch)).await.is_err());
    assert!(runtime::current(&mut db, c.session(next)).await.is_err());
    legacy.close(None).await.unwrap();
    let _ = socket.close(None).await;
    drop(legacy);
    drop(socket);
    drop(db);
    stop_sender.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completed before guarded cleanup")
        .unwrap();
    c.cleanup().await;
}
