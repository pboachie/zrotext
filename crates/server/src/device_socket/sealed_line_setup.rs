// SPDX-License-Identifier: AGPL-3.0-only
//! SEALED activation transport, distinct from SMS activation and content consent.
use super::*;
use crate::sealed_inbound::line_activation::sealed_exchange;

pub(super) fn canonical_bytes<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == value)
        .then_some(bytes)?
        .try_into()
        .ok()
}

pub(super) fn canonical_signature(value: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    ((8..=80).contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(&bytes) == value).then_some(bytes)
}

async fn send(socket: &mut WebSocket, value: serde_json::Value) -> bool {
    let text = value.to_string();
    text.len() <= MAX_FRAME_BYTES && socket.send(Message::Text(text.into())).await.is_ok()
}

/// No acknowledgement is retired by merely writing to the socket. The exact
/// phone installation receipt is required, so dropped frames repeat safely.
pub(super) async fn push(
    socket: &mut WebSocket,
    database_url: &str,
    session: InboundSession<'_>,
) -> Option<bool> {
    let mut client = runtime_db::connect_device(database_url).await.ok()?;
    let challenge = sealed_exchange::next_challenge(&mut client, session)
        .await
        .ok()?;
    let ack = sealed_exchange::next_ack(&mut client, session, &[])
        .await
        .ok()?;
    drop(client);
    let mut pushed = false;
    if let Some(c) = challenge {
        if !send(socket, serde_json::json!({
            "v":1,"type":"sealed_line_challenge","connection_epoch":session.connection_epoch,
            "challenge_id":c.challenge_id,"account_id":c.account_id,"line_id":c.line_id,
            "device_id":c.device_id,"generation":c.generation,"nonce":URL_SAFE_NO_PAD.encode(c.nonce),
            "expires_at_ms":c.expires_at_ms
        })).await { return None; }
        pushed = true;
    }
    if let Some(a) = ack {
        if !send(
            socket,
            serde_json::json!({
                "v":1,"type":"sealed_line_activated","connection_epoch":session.connection_epoch,
                "challenge_id":a.challenge_id,"account_id":a.account_id,"line_id":a.line_id,
                "device_id":a.device_id,"generation":a.generation,
                "device_statement_sha256":URL_SAFE_NO_PAD.encode(a.device_statement_sha256),
                "device_signature_sha256":URL_SAFE_NO_PAD.encode(a.device_signature_sha256)
            }),
        )
        .await
        {
            return None;
        }
        pushed = true;
    }
    Some(pushed)
}

pub(super) async fn receipt(
    socket: &mut WebSocket,
    kind: &str,
    connection_epoch: i64,
    challenge_id: Uuid,
    accepted: bool,
) -> bool {
    send(
        socket,
        serde_json::json!({"v":1,"type":kind,
        "connection_epoch":connection_epoch,"challenge_id":challenge_id,"accepted":accepted}),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_owner_conversations::sealed_line_setup::tests::Case;
    use futures_util::{SinkExt, StreamExt};
    use p256::ecdsa::{Signature, signature::Signer};
    use tokio_tungstenite::{connect_async, tungstenite::Message as WireMessage};
    type Socket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn frame(socket: &mut Socket, kind: &str) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(35), async {
            loop {
                let WireMessage::Text(text) = socket.next().await.unwrap().unwrap() else {
                    continue;
                };
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if value["type"] == kind {
                    return value;
                }
            }
        })
        .await
        .expect("expected authenticated stream frame")
    }
    async fn write(socket: &mut Socket, value: serde_json::Value) {
        socket
            .send(WireMessage::Text(value.to_string().into()))
            .await
            .unwrap();
    }
    async fn connect(address: std::net::SocketAddr, c: &Case) -> (Socket, i64) {
        let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
            .await
            .unwrap();
        write(
            &mut socket,
            serde_json::json!({"v":1,"type":"hello","device_id":c.device}),
        )
        .await;
        let wire = frame(&mut socket, "challenge").await;
        let challenge = crate::enrollment::DeviceChallenge {
            id: serde_json::from_value(wire["challenge_id"].clone()).unwrap(),
            account_id: c.owner.principal.tenant.account_id(),
            device_id: c.device,
            nonce: canonical_bytes::<32>(wire["nonce"].as_str().unwrap()).unwrap(),
        };
        let signature: Signature = c
            .paired
            .sign(&crate::enrollment::device_challenge_bytes(&challenge));
        write(
            &mut socket,
            serde_json::json!({"v":1,"type":"proof","challenge_id":challenge.id,
            "account_id":challenge.account_id,"device_id":c.device,"nonce":wire["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}),
        )
        .await;
        let epoch = frame(&mut socket, "session").await["connection_epoch"]
            .as_i64()
            .unwrap();
        (socket, epoch)
    }
    fn state(c: &Case) -> DeviceSocketState {
        DeviceSocketState {
            database_url: c.state().owner.database_url,
            site_id: "manifest-test".into(),
            instance_id: "fixture".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            sealed_dispatch_enabled: false,
            inbound_pilot_enabled: false,
            line_opt_out_enabled: false,
            sms_line_activation_enabled: false,
            mms_spike_policy: Arc::new(MmsSpikePolicy::disabled()),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        }
    }
    async fn serve(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (
            address,
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }),
        )
    }

    #[tokio::test]
    #[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema; no radio"]
    async fn real_socket_requires_opt_in_and_exact_installation_receipt() {
        let c = Case::new().await;
        let (address, server) =
            serve(router_with_conversations(state(&c), "wss://example.test").unwrap()).await;
        let (mut socket, epoch) = connect(address, &c).await;
        write(
            &mut socket,
            serde_json::json!({"v":1,"type":"sealed_line_proof","connection_epoch":epoch,
            "challenge_id":Uuid::new_v4(),"android_api_level":31,"active_subscription_count":1,
            "selected_subscription_id":3,"signature_der":URL_SAFE_NO_PAD.encode([7;8])}),
        )
        .await;
        let close = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(close,WireMessage::Close(Some(ref close)) if u16::from(close.code)==close_code::POLICY)
        );
        server.abort();
        let (address, server) =
            serve(router_with_sealed_line_setup(state(&c), "wss://example.test", 8).unwrap()).await;
        let (mut socket, epoch) = connect(address, &c).await;
        let registration = c.register(1).await;
        let (challenge, _) = sealed_exchange::open(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            c.device,
            registration,
        )
        .await
        .unwrap();
        let pushed = frame(&mut socket, "sealed_line_challenge").await;
        assert_eq!(pushed["challenge_id"], challenge.id.to_string());
        assert_eq!(pushed["connection_epoch"], epoch);
        let observation = SimObservation {
            android_api_level: 31,
            active_subscription_count: 1,
            selected_subscription_id: 3,
        };
        let statement =
            crate::sealed_inbound::line_activation::device_line_statement(&challenge, observation)
                .unwrap();
        let signature: Signature = c.paired.sign(&statement);
        write(&mut socket,serde_json::json!({"v":1,"type":"sealed_line_proof","connection_epoch":epoch,
            "challenge_id":challenge.id,"android_api_level":31,"active_subscription_count":1,
            "selected_subscription_id":3,"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())})).await;
        assert_eq!(
            frame(&mut socket, "sealed_line_proof_ack").await["accepted"],
            true
        );
        let view = sealed_exchange::view(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            challenge.id,
        )
        .await
        .unwrap();
        assert!(!view.phone_acknowledged);
        let signature: Signature = c.approval.sign(&view.owner_statement.unwrap());
        sealed_exchange::approve(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            challenge.id,
            signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        let ack = frame(&mut socket, "sealed_line_activated").await;
        let mut receipt = ack.clone();
        receipt["type"] = "sealed_line_installed".into();
        let digest = receipt["device_statement_sha256"].clone();
        receipt["device_statement_sha256"] = URL_SAFE_NO_PAD.encode([0; 32]).into();
        write(&mut socket, receipt.clone()).await;
        assert_eq!(
            frame(&mut socket, "sealed_line_install_ack").await["accepted"],
            false
        );
        assert!(
            !sealed_exchange::view(
                &mut c.owner.f.connect().await,
                &c.owner.principal,
                c.line,
                challenge.id
            )
            .await
            .unwrap()
            .phone_acknowledged
        );
        receipt["device_statement_sha256"] = digest;
        write(&mut socket, receipt.clone()).await;
        assert_eq!(
            frame(&mut socket, "sealed_line_install_ack").await["accepted"],
            true
        );
        write(&mut socket, receipt).await;
        assert_eq!(
            frame(&mut socket, "sealed_line_install_ack").await["accepted"],
            true
        );
        assert!(
            sealed_exchange::view(
                &mut c.owner.f.connect().await,
                &c.owner.principal,
                c.line,
                challenge.id
            )
            .await
            .unwrap()
            .phone_acknowledged
        );
        socket.close(None).await.unwrap();
        server.abort();
        c.cleanup().await;
    }
    #[test]
    fn wire_bytes_reject_padding_wrong_length_and_oversized_signatures() {
        let encoded = URL_SAFE_NO_PAD.encode([7; 32]);
        assert_eq!(canonical_bytes::<32>(&encoded), Some([7; 32]));
        assert!(canonical_bytes::<32>(&(encoded + "=")).is_none());
        assert!(canonical_bytes::<32>(&URL_SAFE_NO_PAD.encode([7; 31])).is_none());
        assert!(canonical_signature(&URL_SAFE_NO_PAD.encode([7; 81])).is_none());
        assert!(canonical_signature(&URL_SAFE_NO_PAD.encode([7; 7])).is_none());
    }
    #[test]
    fn ordinary_conversation_policy_does_not_enable_sealed_setup() {
        assert!(
            !conversation::Policy::new("wss://example.test")
                .unwrap()
                .sealed_line_setup
        );
    }
}
