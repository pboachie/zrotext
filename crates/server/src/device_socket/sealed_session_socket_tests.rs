// SPDX-License-Identifier: AGPL-3.0-only
//! Actual authenticated socket time exchange; no radio or carrier effects.
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

async fn authenticate_offered(
    address: std::net::SocketAddr,
    fixture: &Fixture,
    key: &SigningKey,
    protocol: &str,
) -> (TestSocket, i64) {
    let mut request = format!("ws://{address}/v1/device-stream")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", protocol.parse().unwrap());
    let (mut socket, response) = connect_async(request).await.unwrap();
    if protocol == crate::sealed_dispatch::wire::PROTOCOL_V2 {
        // Dormant routers intentionally do not select the offered protocol.
        if let Some(selected) = response.headers().get("Sec-WebSocket-Protocol") {
            assert_eq!(selected.to_str().unwrap(), protocol);
        }
    }
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":fixture.device}),
    )
    .await;
    let challenge_json = receive_type(&mut socket, "challenge").await;
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id: fixture.account,
        device_id: fixture.device,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = key.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({"v":1,"type":"proof","challenge_id":challenge.id,
        "account_id":fixture.account,"device_id":fixture.device,"nonce":challenge_json["nonce"],
        "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())}),
    )
    .await;
    let session = receive_type(&mut socket, "session").await;
    (socket, session["connection_epoch"].as_i64().unwrap())
}

async fn closed_without_sample(socket: &mut TestSocket, policy: bool) {
    loop {
        let frame = timeout(Duration::from_secs(10), socket.next())
            .await
            .unwrap();
        match frame {
            Some(Ok(Message::Close(reason))) => {
                if policy {
                    assert_eq!(u16::from(reason.unwrap().code), close_code::POLICY);
                }
                return;
            }
            Some(Ok(Message::Text(text))) => {
                let value: Value = serde_json::from_str(&text).unwrap();
                assert_ne!(
                    value["type"], "sealed_session",
                    "refused socket returned a clock sample"
                );
            }
            None | Some(Err(_)) if !policy => return,
            other => panic!("expected refused socket close, got {other:?}"),
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run documented PostgreSQL test command"]
async fn dormant_clock_gates_and_replacement_cleanup_preserve_live_session() {
    let fixture = Fixture::new().await;
    let key = SigningKey::generate_from_rng(&mut rng());
    let point = key.verifying_key().to_sec1_point(false);
    fixture.db.execute("UPDATE device_keys SET signing_key_sec1=$1,fingerprint=$2 WHERE account_id=$3 AND device_id=$4",
        &[&point.as_bytes(),&&Sha256::digest(point.as_bytes())[..],&fixture.account,&fixture.device]).await.unwrap();
    let separator = if fixture.url.contains('?') { '&' } else { '?' };
    let state = DeviceSocketState {
        database_url: format!(
            "{}{separator}options=-csearch_path%3D{}",
            fixture.url, fixture.schema
        ),
        site_id: "manifest-test".into(),
        instance_id: "sealed-time-socket".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: true,
        sealed_dispatch_enabled: true,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(super::super::mms_spike_policy::MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let serve = |state: DeviceSocketState| async move {
        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        (address, server)
    };
    let (address, server) = serve(state.clone()).await;
    let v2 = crate::sealed_dispatch::wire::PROTOCOL_V2;
    for dormant in [
        DeviceSocketState {
            sealed_dispatch_enabled: false,
            ..state.clone()
        },
        DeviceSocketState {
            dispatch_runtime_enabled: false,
            ..state.clone()
        },
    ] {
        let (address, dormant_server) = serve(dormant).await;
        let (mut socket, epoch) = authenticate_offered(address, &fixture, &key, v2).await;
        send_json(&mut socket,json!({"v":1,"type":"sealed_session_request","connection_epoch":epoch,"challenge":Uuid::new_v4()})).await;
        closed_without_sample(&mut socket, true).await;
        drop(socket);
        dormant_server.abort();
        let _ = dormant_server.await;
    }
    let (mut old, old_epoch) = authenticate_offered(address, &fixture, &key, v2).await;
    let (mut replacement, new_epoch) = authenticate_offered(address, &fixture, &key, v2).await;
    assert!(new_epoch > old_epoch);
    closed_without_sample(&mut old, false).await;
    drop(old);
    let held: i64 = fixture
        .db
        .query_one(
            "SELECT connection_epoch FROM device_sessions WHERE account_id=$1 AND device_id=$2",
            &[&fixture.account, &fixture.device],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        held, new_epoch,
        "old socket cleanup must preserve the replacement session"
    );
    send_json(&mut replacement,json!({"v":1,"type":"sealed_session_request","connection_epoch":old_epoch,"challenge":Uuid::new_v4()})).await;
    closed_without_sample(&mut replacement, true).await;
    drop(replacement);
    server.abort();
    let _ = server.await;
    fixture.cleanup().await;
}
