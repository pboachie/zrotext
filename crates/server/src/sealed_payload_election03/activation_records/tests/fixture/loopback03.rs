// SPDX-License-Identifier: AGPL-3.0-only
//! Real socket claim and IO on one disposable manual ordinary-runtime fixture.
use crate::{auth, device_socket, enrollment, runtime_db};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest},
};
use uuid::Uuid;

const OWNER_ORIGIN: &str = "https://activation.example";
const PROFILE_PROTOCOL: &str = "zrotext-device-status-v2+sealed-dispatch-v3";
const ORDINARY_PROTOCOL: &str = "zrotext-device-status-v2";
const IO_BOUND: Duration = Duration::from_secs(5);
// Current profile readiness traverses the full writer graph. This is a bounded
// test observation budget, never a server/grant lifetime or a renewed permit.
const PROFILE_RESPONSE_BOUND: Duration = Duration::from_secs(60);
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Peer {
    socket: Socket,
    epoch: i64,
    pending: VecDeque<Value>,
}
impl Peer {
    async fn send(&mut self, raw: &Value) {
        let bytes = serde_json::to_string(raw).unwrap();
        assert!(bytes.len() <= 4096);
        timeout(IO_BOUND, self.socket.send(Message::Text(bytes.into())))
            .await
            .unwrap()
            .unwrap();
    }
    async fn receive(&mut self, kind: &str) -> Value {
        if let Some(index) = self.pending.iter().position(|v| v["type"] == kind) {
            return self.pending.remove(index).unwrap();
        }
        let bound = match kind {
            "sealed_execution_grant" | "payload_profile_submit_ack03" => PROFILE_RESPONSE_BOUND,
            _ => IO_BOUND,
        };
        let deadline = tokio::time::Instant::now() + bound;
        for _ in 0..64 {
            let frame = tokio::time::timeout_at(deadline, self.socket.next())
                .await
                .expect("bounded socket response")
                .expect("socket remained open")
                .unwrap();
            let raw = match frame {
                Message::Text(raw) => raw,
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => panic!("expected bounded text response"),
            };
            assert!(raw.len() <= 192 * 1024);
            let value: Value = serde_json::from_str(&raw).unwrap();
            let tag = value["type"].as_str().expect("typed response");
            if tag == kind {
                return value;
            }
            assert!(matches!(
                tag,
                "sealed_line_challenge_v2"
                    | "sealed_line_activated_v2"
                    | "payload_profile_challenge03"
                    | "payload_profile_selection_challenge03"
                    | "conversation_interval_challenge03"
            ));
            assert!(self.pending.len() < 16, "bounded retained side frames");
            self.pending.push_back(value);
        }
        panic!("bounded response frame count");
    }
    async fn connect(
        address: SocketAddr,
        account: Uuid,
        device: Uuid,
        key: &SigningKey,
        profile: bool,
    ) -> Self {
        let mut request = format!("ws://{address}/v1/device-stream")
            .into_client_request()
            .unwrap();
        let protocol = if profile {
            PROFILE_PROTOCOL
        } else {
            ORDINARY_PROTOCOL
        };
        request
            .headers_mut()
            .insert("sec-websocket-protocol", protocol.parse().unwrap());
        let (socket, response) = timeout(IO_BOUND, tokio_tungstenite::connect_async(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.headers()["sec-websocket-protocol"], protocol);
        let mut peer = Self {
            socket,
            epoch: 0,
            pending: VecDeque::new(),
        };
        peer.send(&json!({"v":1,"type":"hello","device_id":device}))
            .await;
        let challenge = peer.receive("challenge").await;
        assert_eq!(challenge.as_object().unwrap().len(), 6);
        assert_eq!(challenge["account_id"], account.to_string());
        assert_eq!(challenge["device_id"], device.to_string());
        let transcript = enrollment::DeviceChallenge {
            id: Uuid::parse_str(challenge["challenge_id"].as_str().unwrap()).unwrap(),
            account_id: account,
            device_id: device,
            nonce: B
                .decode(challenge["nonce"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let signature: Signature = key.sign(&enrollment::device_challenge_bytes(&transcript));
        peer.send(&json!({"v":1,"type":"proof","challenge_id":transcript.id,
            "account_id":account,"device_id":device,"nonce":challenge["nonce"],
            "signature_der":B.encode(signature.to_der().as_bytes())}))
            .await;
        let session = peer.receive("session").await;
        assert_eq!(session.as_object().unwrap().len(), 4);
        assert_eq!(session["v"], 1);
        peer.epoch = session["connection_epoch"]
            .as_i64()
            .filter(|n| *n > 0)
            .unwrap();
        peer
    }
}

struct OwnedServer {
    state: device_socket::DeviceSocketState,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl OwnedServer {
    async fn stop(&mut self) {
        self.state
            .draining
            .store(true, std::sync::atomic::Ordering::Release);
        self.state.drain_notify.notify_waiters();
        let _ = self.shutdown.take().unwrap().send(());
        let mut task = self.task.take().unwrap();
        match timeout(IO_BOUND, &mut task).await {
            Ok(result) => result.unwrap(),
            Err(error) => {
                task.abort();
                let _ = timeout(IO_BOUND, task).await;
                panic!("owned server shutdown: {error}");
            }
        }
    }
}
impl Drop for OwnedServer {
    fn drop(&mut self) {
        self.state
            .draining
            .store(true, std::sync::atomic::Ordering::Release);
        self.state.drain_notify.notify_waiters();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
pub(crate) struct Loopback03 {
    server: OwnedServer,
    address: SocketAddr,
    account: Uuid,
    device: Uuid,
    io: Mutex<Peer>,
}
impl Loopback03 {
    pub(super) async fn start(
        db: &crate::sealed_payload_election03::test_database::Fixture,
        hasher: Arc<auth::TokenHasher>,
        enrollment_hasher: enrollment::EnrollmentHasher,
        account: Uuid,
        device: Uuid,
        key: &SigningKey,
    ) -> Self {
        use runtime_db::NativeConnection;
        let url = db.runtime_socket_url();
        let actual = runtime_db::fixture_connection(&url).await.unwrap();
        assert!(actual.native_candidate().is_none(), "manual fixture only");
        drop(actual);
        let state = device_socket::DeviceSocketState {
            database_url: url.clone(),
            site_id: "activation-test".into(),
            instance_id: "fixture".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(enrollment_hasher),
            auth_hasher: hasher.clone(),
            alpha_policy: Arc::new(
                crate::alpha_policy::AlphaPolicy::parse(None, None, None).unwrap(),
            ),
            dispatch_runtime_enabled: true,
            sealed_dispatch_enabled: true,
            inbound_pilot_enabled: false,
            line_opt_out_enabled: false,
            sms_line_activation_enabled: false,
            line_readiness_enabled: false,
            mms_spike_policy: Arc::new(device_socket::MmsSpikePolicy::disabled()),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
        };
        let fetch = crate::conversation_grant03::http::FetchState03::new(
            url,
            state.site_id.clone(),
            1,
            OWNER_ORIGIN.into(),
            hasher,
        )
        .unwrap();
        let router = device_socket::router_with_profile03(
            state.clone(),
            "wss://activation.example",
            OWNER_ORIGIN,
            2,
        )
        .unwrap()
        .merge(
            crate::conversation_grant03::http::router(fetch)
                .await
                .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        // Own cleanup before the first peer await, including handshake failure.
        let server = OwnedServer {
            state,
            shutdown: Some(shutdown),
            task: Some(server),
        };
        let peer = Peer::connect(address, account, device, key, true).await;
        let result = Self {
            server,
            address,
            account,
            device,
            io: Mutex::new(peer),
        };
        result.assert_claim(&db.reader, key, 2).await;
        result
    }
    pub(crate) async fn epoch(&self) -> i64 {
        self.io.lock().await.epoch
    }
    pub(crate) async fn assert_claim(
        &self,
        reader: &tokio_postgres::Client,
        key: &SigningKey,
        expected_line_activation_version: i16,
    ) {
        let epoch = self.epoch().await;
        let row = reader.query_one(
            "SELECT s.connection_epoch,s.line_activation_version,k.signing_key_sec1,s.lease_until>clock_timestamp() FROM public.device_sessions s JOIN public.device_keys k ON(k.account_id,k.device_id)=(s.account_id,s.device_id) WHERE s.account_id=$1 AND s.device_id=$2 AND k.revoked_at IS NULL",
            &[&self.account,&self.device],
        ).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), epoch);
        assert_eq!(row.get::<_, i16>(1), expected_line_activation_version);
        assert_eq!(
            row.get::<_, Vec<u8>>(2),
            key.verifying_key().to_sec1_point(false).as_bytes()
        );
        assert!(row.get::<_, bool>(3));
    }
    pub(crate) async fn exchange(&self, request: &Value, kind: &str) -> Value {
        let mut peer = self.io.lock().await;
        peer.send(request).await;
        peer.receive(kind).await
    }
    pub(crate) async fn heartbeat(&self) {
        let ack = self
            .exchange(&json!({"v":1,"type":"heartbeat"}), "heartbeat_ack")
            .await;
        assert_eq!(ack["connection_epoch"], self.epoch().await);
    }
    pub(crate) async fn sample_profile(&self) {
        let nonce = Uuid::new_v4();
        let reply = self
            .exchange(
                &json!({"v":1,"type":"payload_profile_session03_request",
            "connection_epoch":self.epoch().await,"challenge":nonce}),
                "payload_profile_session03",
            )
            .await;
        assert_eq!(reply["challenge"], nonce.to_string());
        assert_eq!(reply["account_id"], self.account.to_string());
        assert_eq!(reply["device_id"], self.device.to_string());
        assert_eq!(reply["connection_epoch"], self.epoch().await);
    }
    pub(crate) async fn grant(
        &self,
        ready: &crate::sealed_dispatch::wire03::ReadyFrame03,
    ) -> crate::sealed_dispatch::wire03::GrantFrame03 {
        // This manual peer must perform the real same-epoch heartbeat between
        // long positive phases, just as a live peer does. No expired lease or
        // immutable grant is renewed by this assertion-preserving exchange.
        self.heartbeat().await;
        let raw: Value = serde_json::from_slice(&ready.to_json().unwrap()).unwrap();
        let response = self.exchange(&raw, "sealed_execution_grant").await;
        crate::sealed_dispatch::wire03::GrantFrame03::parse(&serde_json::to_vec(&response).unwrap())
            .unwrap()
    }
    pub(crate) async fn fetch(
        &self,
        grant: &crate::sealed_dispatch::wire03::GrantFrame03,
        key: &SigningKey,
    ) -> Value {
        // grant() keeps the socket live before issuing the immutable grant.
        // Start HTTP directly, like the device client, rather than waiting for
        // an unrelated socket ACK inside the original grant window.
        let signature: Signature = key.sign(&grant.fetch_transcript());
        let body = json!({"grant":serde_json::from_slice::<Value>(&grant.to_json().unwrap()).unwrap(),
            "signature_der":B.encode(signature.normalize_s().to_der().as_bytes())});
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(IO_BOUND)
            .timeout(PROFILE_RESPONSE_BOUND)
            .build()
            .unwrap();
        let response = client
            .post(format!(
                "http://{}/v1/sealed/dispatch/envelope03",
                self.address
            ))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = response.bytes().await.unwrap();
        assert!(bytes.len() <= 192 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }
    pub(crate) async fn reconnect_ordinary(&self, key: &SigningKey) {
        let mut peer = self.io.lock().await;
        let previous = peer.epoch;
        timeout(IO_BOUND, peer.socket.close(None))
            .await
            .unwrap()
            .unwrap();
        let next = Peer::connect(self.address, self.account, self.device, key, false).await;
        assert!(next.epoch > previous);
        *peer = next;
    }
    pub(super) async fn finish(mut self) {
        // Peer close is best effort. Mandatory server drain/stop follows even
        // on timeout/close error; Case then observes all pool sockets drained.
        let _ = timeout(IO_BOUND, self.io.get_mut().socket.close(None)).await;
        self.server.stop().await;
    }
}
