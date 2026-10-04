// SPDX-License-Identifier: AGPL-3.0-only
//! Explicitly selected test-only loopback bridge. Never compiled into server binaries.
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::SinkExt;
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{Signature, signature::Signer};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, watch};
use tower::ServiceExt;

struct Simulator {
    fixture: Mutex<Fixture>,
    owner: SessionPrincipal,
    statement: Statement,
    done: Arc<Notify>,
    sockets: SocketTasks,
    token: String,
    phone_session: Uuid,
    origin_hash: [u8; 32],
    queue_router: Router,
    owner_token: String,
    owner_csrf: String,
}

// Axum's upgraded callbacks outlive HTTP graceful shutdown. A receiver registers ownership
// before upgrade dispatch, including an upgrade that fails before invoking its callback.
#[derive(Clone)]
struct SocketTasks {
    shutdown: watch::Sender<bool>,
    active: watch::Sender<()>,
}

impl SocketTasks {
    fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        let (active, _) = watch::channel(());
        Self { shutdown, active }
    }

    fn register<T, R>(&self, state: Arc<T>, resource: R) -> Option<SocketTask<T, R>> {
        if *self.shutdown.borrow() {
            return None;
        }
        Some(SocketTask {
            resource,
            state,
            _active: self.active.subscribe(),
        })
    }

    fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    async fn wait(&self) {
        self.active.closed().await;
    }
}

struct SocketTask<T, R> {
    // Rust drops fields in declaration order, also on cancellation/unwind: release the
    // scoped connection and state before the final receiver permits fixture cleanup.
    resource: R,
    state: Arc<T>,
    _active: watch::Receiver<()>,
}

impl<T, R> SocketTask<T, R> {
    fn state(&self) -> &T {
        &self.state
    }

    fn parts(&mut self) -> (&T, &mut R) {
        (&self.state, &mut self.resource)
    }
}

async fn socket_shutdown(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn finish_server(
    server: &mut tokio::task::JoinHandle<()>,
    sockets: &SocketTasks,
    deadline: tokio::time::Instant,
) -> Result<Result<(), tokio::task::JoinError>, tokio::time::error::Elapsed> {
    let joined = match tokio::time::timeout_at(deadline, &mut *server).await {
        Ok(joined) => joined,
        Err(error) => {
            sockets.stop();
            server.abort();
            let _ = server.await;
            return Err(error);
        }
    };
    // The HTTP join is consumed. Drain under its same deadline without polling it again.
    if let Err(error) = tokio::time::timeout_at(deadline, sockets.wait()).await {
        sockets.stop();
        return Err(error);
    }
    Ok(joined)
}

mod lifecycle_tests;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    token: String,
    op: String,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    challenge: Option<Uuid>,
    #[serde(default)]
    event: Option<Uuid>,
    #[serde(default)]
    confirmation: Option<String>,
}

async fn phone_channel(
    State(state): State<Arc<Simulator>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if headers
        .get("x-zrotext-fixture-token")
        .and_then(|v| v.to_str().ok())
        != Some(state.token.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Complete cold scoped PG setup before the authenticated socket opens. It must not inflate
    // only the bootstrap clock's RTT relative to a later independent runtime clock sample.
    let client = {
        let f = state.fixture.lock().await;
        f.connect().await
    };
    let Some(mut task) = state.sockets.register(state.clone(), client) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .on_upgrade(move |mut socket| async move {
            let mut shutdown = task.state().sockets.shutdown.subscribe();
            // Every frame still holds the fixture lock and enters the unchanged transaction.
            loop {
                let received = tokio::select! {
                    biased;
                    _ = socket_shutdown(&mut shutdown) => {
                        let _ = socket.close().await;
                        break;
                    }
                    received = socket.recv() => received,
                };
                let Some(Ok(Message::Binary(bytes))) = received else {
                    break;
                };
                let (state, client) = task.parts();
                let f = state.fixture.lock().await;
                let result = super::super::channel::handle(
                    client,
                    &super::super::channel::AuthenticatedChannelSession {
                        device: f.session(),
                        phone_session: state.phone_session,
                        origin_hash: state.origin_hash,
                    },
                    &bytes,
                )
                .await;
                match result {
                    Ok(reply) => {
                        if socket.send(Message::Binary(reply.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = socket.close().await;
                        break;
                    }
                }
            }
            drop(task);
        })
        .into_response()
}

async fn command(
    State(state): State<Arc<Simulator>>,
    Json(c): Json<Command>,
) -> (StatusCode, Json<Value>) {
    if c.token != state.token {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok":false})));
    }
    let mut f = state.fixture.lock().await;
    let mut client = f.connect().await;
    let session = f.session();
    let s = &state.statement;
    let result:Result<Value,ConversationError>=match c.op.as_str() {
        "channel"=>match c.data.and_then(|v|STANDARD.decode(v).ok()) {
            Some(bytes)=>super::super::channel::handle(&mut client,&super::super::channel::AuthenticatedChannelSession {
                device:session,phone_session:state.phone_session,origin_hash:state.origin_hash,
            },&bytes).await.map(|reply|json!({"ok":true,"frame":STANDARD.encode(reply)})),
            None=>Err(ConversationError::Invalid),
        },
        "approve"|"installed"=>{
            let data=c.data.and_then(|v|STANDARD.decode(v).ok());
            let signature=c.signature.and_then(|v|STANDARD.decode(v).ok());
            match (data,signature) {
                (Some(data),Some(signature))=>{
                    let r=if c.op=="approve" {approve(&mut client,session,&data,&signature).await} else {installed(&mut client,session,&data,&signature).await};
                    r.map(|()|json!({"ok":true}))
                },_=>Err(ConversationError::Invalid),
            }
        },
        "lease"=>match c.challenge {
            Some(challenge)=>active_lease(&mut client,session,s.interval,challenge).await.map(|lease|{
                let bytes=[b"zrotext/fixture/active/v1\0".as_slice(),s.digest().unwrap().as_slice(),challenge.as_bytes(),&lease.valid_for_ms.to_be_bytes()].concat();
                let signature:Signature=f.root.sign(&bytes);
                json!({"ok":true,"duration":lease.valid_for_ms,"proof":STANDARD.encode(bytes),"signature":STANDARD.encode(signature.normalize_s().to_bytes())})
            }),None=>Err(ConversationError::Invalid),
        },
        "capture"=>match c.data.and_then(|v|STANDARD.decode(v).ok()) {
            Some(bytes)=>crate::sealed_inbound::ingest::ingest_conversation(&mut client,session,f.line,1,&f.bytes,&bytes,CaptureInterval {interval:s.interval,activation_digest:s.activation_digest}).await
                .map(|r|json!({"ok":true,"created":r.created,"event":r.event_id})).map_err(|_|ConversationError::Forbidden),
            None=>Err(ConversationError::Invalid),
        },
        "history"=>match c.event {
            Some(event)=>match read_history(&mut client,&state.owner,event).await {
                Ok(bytes)=>{
                    // Scoped real PG identities, never a fixture-side or echoed success counter.
                    let row=client.query_one("SELECT device_sequence FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",&[&s.account,&event]).await.unwrap();
                    let ids:Vec<Uuid>=client.query("SELECT id FROM sealed_event_deliveries WHERE account_id=$1 AND event_id=$2 AND interval_id=$3 ORDER BY id LIMIT 6",&[&s.account,&event,&s.interval]).await.unwrap().iter().map(|r|r.get(0)).collect();
                    assert!(ids.len()<=5);
                    let counts=client.query_one("SELECT (SELECT count(*) FROM conversation_inbound_provenance WHERE account_id=$1 AND interval_id=$2), (SELECT count(*) FROM sealed_event_deliveries WHERE account_id=$1 AND interval_id=$2)",&[&s.account,&s.interval]).await.unwrap();
                    Ok(json!({"ok":true,"envelope":STANDARD.encode(bytes),"event":event,"sequence":row.get::<_,i64>(0),"deliveryIds":ids,"intervalEvents":counts.get::<_,i64>(0),"intervalDeliveries":counts.get::<_,i64>(1)}))
                },Err(error)=>Err(error),
            },None=>Err(ConversationError::Invalid),
        },
        "browser_authority"=>active_lease(&mut client,session,s.interval,Uuid::new_v4()).await.map(|lease| json!({"ok":true,"phase":"active","validForMs":lease.valid_for_ms,"manifest":STANDARD.encode(&f.bytes),
            "scope":{"account":s.account,"session":s.originating_session,"interval":s.interval,"device":s.device,"line":s.line,"generation":s.generation.to_string(),"peer":s.peer,"reader":STANDARD.encode(s.reader),"manifest":STANDARD.encode(Sha256::digest(&f.bytes[..f.bytes.len()-64]))}})),
        "send"=>submit_confirmed(&state, &f, &c).await,
        "send_expiry_wait"=>{
            match c.confirmation.as_ref().and_then(|v|STANDARD.decode(v).ok()) {
                Some(proof)=>{
                    let confirmed=super::super::send::Confirmation::decode(&proof).unwrap();
                    let mut blocker=f.connect().await;
                    let hold=blocker.transaction().await.unwrap();
                    hold.query_one("SELECT id FROM accounts WHERE id=$1 FOR UPDATE",&[&s.account]).await.unwrap();
                    assert!(confirmed.expires_ms-now(&hold).await.unwrap()<=1500);
                    let mut pending=Box::pin(submit_confirmed(&state,&f,&c));
                    assert!(tokio::time::timeout(std::time::Duration::from_millis(25),&mut pending).await.is_err(),"actual HTTP admission must wait for account lock");
                    while now(&hold).await.unwrap()<confirmed.expires_ms {tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
                    hold.commit().await.unwrap();
                    assert!(matches!(pending.await,Err(ConversationError::Forbidden)),"confirmation expiry after lock wait must fail closed");
                    assert_eq!(durable_counts(&f,confirmed.message).await,(0,0,0,0));
                    Ok(json!({"ok":true,"rejected":true}))
                },_=>Err(ConversationError::Invalid),
            }
        },
        "renew"=>{
            f.advance();
            let tx=client.transaction().await.unwrap();
            let mut admitted=sealed_manifest_store::admit(&tx,session,f.line,1,&f.bytes).await.unwrap();
            admitted.context(&f.wanted()).await.unwrap();drop(admitted);tx.commit().await.unwrap();
            Ok(json!({"ok":true,"manifest":STANDARD.encode(&f.bytes)}))
        },
        "pause"|"withdraw"=>close(&mut client,&state.owner,s.interval,c.op=="withdraw").await.map(|()|json!({"ok":true})),
        "logout"=>{
            let r=close(&mut client,&state.owner,s.interval,false).await;
            if r.is_ok() {f.db.execute("UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",&[&state.owner.session_id]).await.unwrap();}
            r.map(|()|json!({"ok":true}))
        },
        "finish"=>{state.sockets.stop();state.done.notify_one();Ok(json!({"ok":true}))},
        _=>Err(ConversationError::Invalid),
    };
    match result {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(_) => (StatusCode::FORBIDDEN, Json(json!({"ok":false}))),
    }
}

// The fixture bridge posts through the real dormant cookie/CSRF HTTP adapter.
// Returning an envelope requires committed queue and proof rows, never a map.
async fn submit_confirmed(
    state: &Simulator,
    f: &Fixture,
    c: &Command,
) -> Result<Value, ConversationError> {
    let (Some(envelope), Some(confirmation), Some(signature)) =
        (&c.data, &c.confirmation, &c.signature)
    else {
        return Err(ConversationError::Invalid);
    };
    let request = axum::http::Request::post("/v1/owner/conversation/send")
        .header("content-type", "application/json")
        .header("origin", "https://test.example")
        .header(
            "cookie",
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                state.owner_token, state.owner_csrf
            ),
        )
        .header("x-zrotext-csrf", &state.owner_csrf)
        .body(axum::body::Body::from(
            json!({"envelope":envelope,"confirmation":confirmation,"signature":signature})
                .to_string(),
        ))
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(28),
        state.queue_router.clone().oneshot(request),
    )
    .await
    .expect("fixture HTTP queue admission exceeded bounded deadline")
    .unwrap();
    if response.status() != StatusCode::ACCEPTED {
        return Err(match response.status() {
            StatusCode::FORBIDDEN => ConversationError::Forbidden,
            StatusCode::CONFLICT => ConversationError::Conflict,
            StatusCode::BAD_REQUEST => ConversationError::Invalid,
            _ => ConversationError::Unavailable,
        });
    }
    let result: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["state"], "queued");
    let message: Uuid = result["message_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(durable_counts(f, message).await, (1, 1, 1, 1));
    let row =
        f.db.query_one(
            "SELECT transport_payload FROM messages WHERE account_id=$1 AND id=$2",
            &[&f.account, &message],
        )
        .await
        .unwrap();
    let queued: Vec<u8> = row.get(0);
    assert_eq!(STANDARD.encode(&queued), *envelope);
    Ok(json!({"ok":true,"created":result["created"],"envelope":STANDARD.encode(queued)}))
}

async fn durable_counts(f: &Fixture, message: Uuid) -> (i64, i64, i64, i64) {
    let row=f.db.query_one("SELECT (SELECT count(*) FROM messages WHERE account_id=$1 AND id=$2), \
        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1 AND message_id=$2), \
        (SELECT count(*) FROM conversation_confirmation_records WHERE account_id=$1 AND message_id=$2), \
        (SELECT count(*) FROM usage_ledger WHERE account_id=$1 AND message_id=$2 AND entry_kind='reserve')",&[&f.account,&message]).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

fn queue_router(f: &Fixture) -> Router {
    let sep = if f.url.contains('?') { '&' } else { '?' };
    let url = format!("{}{sep}options=-csearch_path%3D{}", f.url, f.schema);
    let hasher = Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let owner = super::super::OwnerConversationsState {
        database_url: url.clone(),
        auth_hasher: hasher.clone(),
        canonical_origin: "https://test.example".into(),
    };
    let phone = f.session();
    let socket = crate::device_socket::DeviceSocketState {
        database_url: url,
        site_id: phone.site_id.into(),
        instance_id: phone.instance_id.into(),
        deployment_epoch: phone.deployment_epoch,
        enrollment_hasher: Arc::new(
            crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(77)).unwrap(),
        ),
        auth_hasher: hasher,
        alpha_policy: Arc::new(crate::alpha_policy::AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(
            crate::device_socket::MmsSpikePolicy::parse(None, None, None).unwrap(),
        ),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    super::super::confirmed_http::router(owner, socket, true)
}

async fn owner_credentials(f: &Fixture, owner: &SessionPrincipal) -> (String, String) {
    let random = |prefix: &str| {
        format!(
            "{prefix}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        )
    };
    let token = random("zts_");
    let csrf = random("ztc_");
    let hash = |domain: &[u8], value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
        mac.update(domain);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    f.db.execute(
        "UPDATE sessions SET token_hash=$1,csrf_hash=$2 WHERE id=$3",
        &[
            &hash(b"session-v1\0", &token),
            &hash(b"csrf-v1\0", &csrf),
            &owner.session_id,
        ],
    )
    .await
    .unwrap();
    (token, csrf)
}

// Called by the existing compiled simulator entry point, so emulator CI runs these real SQL cases.
async fn assert_capture_ack_replay_authority() {
    let (f, _, statement) = tests::pending().await;
    tests::activate(&f, &statement).await;
    let session = super::super::channel::AuthenticatedChannelSession {
        device: f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [9; 32],
    };
    let event = Uuid::new_v4();
    let bytes = tests::capture(&f, &statement, event, 1, b"+12")
        .await
        .unwrap();
    let request = |envelope: &[u8]| {
        let mut out = b"ZTCW\x01\x0c".to_vec();
        for id in [f.account, f.device, session.phone_session] {
            out.extend(id.as_bytes());
        }
        out.extend(session.device.connection_epoch.to_be_bytes());
        out.extend(session.device.deployment_epoch.to_be_bytes());
        out.extend(session.origin_hash);
        out.extend(Uuid::new_v4().as_bytes());
        out.extend(super::super::channel::scope(&statement).unwrap());
        out.extend((envelope.len() as u32).to_be_bytes());
        out.extend(envelope);
        out
    };
    let reply = super::super::channel::handle(&mut f.connect().await, &session, &request(&bytes))
        .await
        .unwrap();
    assert_eq!(&reply[118..134], event.as_bytes());
    assert_eq!(&reply[134..166], Sha256::digest(&bytes).as_slice());
    assert_eq!(
        reply[166], 0,
        "Current exact protected-content replay receives a committed ACK"
    );
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
        &[&f.account, &event],
    )
    .await
    .unwrap();
    assert!(
        matches!(
            super::super::channel::handle(&mut f.connect().await, &session, &request(&bytes)).await,
            Err(ConversationError::Forbidden)
        ),
        "Erased replay must never receive a capture ACK"
    );
    assert!(
        f.db.query_one(
            "SELECT envelope IS NULL FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&f.account, &event]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let unscoped = Uuid::new_v4();
    let observed =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    let raw = super::super::tests::envelope(&f, unscoped, 2, observed as u64, b"+12");
    crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &raw,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            super::super::channel::handle(&mut f.connect().await, &session, &request(&raw)).await,
            Err(ConversationError::Forbidden)
        ),
        "Unscoped replay cannot acquire provenance or receive a capture ACK"
    );
    assert_eq!(f.db.query_one("SELECT count(*) FROM conversation_inbound_provenance WHERE account_id=$1 AND event_id=$2",&[&f.account,&unscoped]).await.unwrap().get::<_,i64>(0),0);
    assert_eq!(
        f.db.query_one(
            "SELECT envelope FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&f.account, &unscoped]
        )
        .await
        .unwrap()
        .get::<_, Vec<u8>>(0),
        raw
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires explicitly selected conversation simulator runner, SDK and disposable PostgreSQL"]
async fn loopback_journal_bridge() {
    assert!(std::env::var_os("ZT_CONVERSATION_SIM_DIR").is_some());
    assert_capture_ack_replay_authority().await;
    let (mut f, owner) = super::super::tests::prepared().await;
    if !super::super::confirmation_records::installed(&f.db)
        .await
        .unwrap()
    {
        f.db.batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
        ))
        .await
        .unwrap();
    }
    f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
    // Queue one opted-in synthetic endpoint; this fixture starts no dispatcher or network callback.
    let endpoint = Uuid::new_v4();
    let vault = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(125).to_vec()),
    )
    .unwrap();
    let secret = vault
        .seal(f.account, endpoint, &crate::test_keys::key(126))
        .unwrap();
    f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled,sealed_events_enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true,true)",&[&endpoint,&f.account,&secret]).await.unwrap();
    let (owner_token, owner_csrf) = owner_credentials(&f, &owner).await;
    let queue_router = queue_router(&f);
    // Additional roles exist only in this fresh owner-signed synthetic manifest.
    // No production key, root grant or shared signer custody is created.
    let browser_key = SigningKey::generate_from_rng(&mut rand::rng());
    let phone_key = SigningKey::generate_from_rng(&mut rand::rng());
    let mut records: Vec<Vec<u8>> = f.bytes[151..f.bytes.len() - 64]
        .chunks_exact(149)
        .map(|r| r.to_vec())
        .collect();
    records.iter_mut().find(|r| r[0] == 2).unwrap()[130..132].copy_from_slice(&12u16.to_be_bytes());
    for (role, scope, key) in [(1u8, 4u16, &phone_key), (5, 1, &browser_key)] {
        let point = key.verifying_key().to_sec1_point(false);
        let algorithm = if role == 1 { [0u8, 16] } else { [1, 1] };
        let id =
            Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat());
        let mut r = vec![role];
        r.extend(id);
        r.extend(point.as_bytes());
        r.extend(if role == 1 {
            *f.device.as_bytes()
        } else {
            [0; 16]
        });
        r.extend(f.line.as_bytes());
        r.extend(scope.to_be_bytes());
        r.extend(&records[0][132..149]);
        records.push(r);
    }
    records.sort_by_key(|r| r[0]);
    f.bytes.truncate(150);
    f.bytes.push(records.len() as u8);
    for r in records {
        f.bytes.extend(r);
    }
    f.bytes.extend([0; 64]);
    let now: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    f.bytes[45..53].copy_from_slice(&((now + 900_000) as u64).to_be_bytes());
    for i in 0..5 {
        let start = 151 + i * 149 + 140;
        f.bytes[start..start + 8].copy_from_slice(&((now + 900_000) as u64).to_be_bytes());
    }
    f.resign();
    let mut client = f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut admitted = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
        .await
        .unwrap();
    admitted.context(&f.wanted()).await.unwrap();
    drop(admitted);
    tx.commit().await.unwrap();
    let predecessor = f.bytes.clone();
    f.advance();
    let consent = ConversationConsent {
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: super::super::DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    };
    let statement = begin(&mut client, &owner, &consent, &f.bytes)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = STANDARD.encode(rand::random::<[u8; 32]>());
    let phone_session = Uuid::new_v4();
    let origin_hash = [0x77; 32];
    // All private key material here is newly generated synthetic fixture material, never owner credentials.
    let ready = json!({"port":port,"token":token,"channelSession":{"account":f.account,"device":f.device,"session":phone_session,"connectionEpoch":1,"deploymentEpoch":1,"originHash":"77".repeat(32)},"trustGeneration":statement.trust_generation,"statement":STANDARD.encode(statement.encode().unwrap()),
        "pin":STANDARD.encode(&f.pin),"manifest":STANDARD.encode(&f.bytes),"predecessor":STANDARD.encode(predecessor),
        "eventScalar":STANDARD.encode(f.event_signer.to_bytes()),"archiveScalar":STANDARD.encode(f.archive_key.to_bytes()),
        "signerPoint":STANDARD.encode(f.event_signer.verifying_key().to_sec1_point(false).as_bytes()),
        "archivePoint":STANDARD.encode(f.archive_key.verifying_key().to_sec1_point(false).as_bytes()),
        "browserScalar":STANDARD.encode(browser_key.to_bytes()),"browserPoint":STANDARD.encode(browser_key.verifying_key().to_sec1_point(false).as_bytes()),
        "phoneScalar":STANDARD.encode(phone_key.to_bytes()),"phonePoint":STANDARD.encode(phone_key.verifying_key().to_sec1_point(false).as_bytes()),
        "rootPoint":STANDARD.encode(f.root.verifying_key().to_sec1_point(false).as_bytes()),
        "fingerprint":STANDARD.encode(Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(),&f.pin].concat())),
        "sdkTool":std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript/test/conversation-simulator-envelope.mjs"),
        "browserTool":std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript/test/conversation-browser-simulator.mjs")});
    let done = Arc::new(Notify::new());
    let sockets = SocketTasks::new();
    let state = Arc::new(Simulator {
        fixture: Mutex::new(f),
        owner,
        statement,
        done: done.clone(),
        sockets: sockets.clone(),
        token,
        phone_session,
        origin_hash,
        queue_router,
        owner_token,
        owner_csrf,
    });
    let app = Router::new()
        .route("/fixture", post(command))
        .route("/phone-channel", get(phone_channel))
        .layer(axum::extract::DefaultBodyLimit::max(80_000))
        .with_state(state.clone());
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { done.notified().await })
            .await
            .unwrap()
    });
    let readiness = serde_json::to_string(&ready).unwrap();
    assert!(readiness.len() <= 16_384);
    println!("\nZT_CONVERSATION_SIM_READY_V1 {readiness}");
    std::io::stdout().flush().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
    let result = finish_server(&mut server, &sockets, deadline).await;
    // A stuck callback fails closed; do not clean its still-owned fixture or cancel a TX
    // merely to manufacture uniqueness. No additional grace period follows this budget.
    let state = Arc::try_unwrap(state).ok().expect("fixture server stopped");
    state.fixture.into_inner().cleanup().await;
    result
        .expect("fixture client did not finish")
        .expect("fixture server failed");
}
