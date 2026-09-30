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
use p256::ecdsa::{Signature, signature::Signer};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

struct Simulator {
    fixture: Mutex<Fixture>,
    owner: SessionPrincipal,
    statement: Statement,
    done: Arc<Notify>,
    token: String,
    phone_session: Uuid,
    origin_hash: [u8; 32],
    sends: Mutex<std::collections::HashMap<Uuid, super::super::send::Confirmation>>,
}
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
    upgrade
        .on_upgrade(move |mut socket| async move {
            while let Some(Ok(Message::Binary(bytes))) = socket.recv().await {
                let f = state.fixture.lock().await;
                let mut client = f.connect().await;
                let result = super::super::channel::handle(
                    &mut client,
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
        "history"=>match c.event {Some(event)=>read_history(&mut client,&state.owner,event).await.map(|b|json!({"ok":true,"envelope":STANDARD.encode(b)})),None=>Err(ConversationError::Invalid)},
        "browser_authority"=>active_lease(&mut client,session,s.interval,Uuid::new_v4()).await.map(|lease| json!({"ok":true,"phase":"active","validForMs":lease.valid_for_ms,"manifest":STANDARD.encode(&f.bytes),
            "scope":{"account":s.account,"session":s.originating_session,"interval":s.interval,"device":s.device,"line":s.line,"generation":s.generation.to_string(),"peer":s.peer,"reader":STANDARD.encode(s.reader),"manifest":STANDARD.encode(Sha256::digest(&f.bytes[..f.bytes.len()-64]))}})),
        "send"=>{
            match (c.data.and_then(|v|STANDARD.decode(v).ok()),c.confirmation.and_then(|v|STANDARD.decode(v).ok()),c.signature.and_then(|v|STANDARD.decode(v).ok())) {
                (Some(bytes),Some(proof),Some(signature))=>match super::super::send::authorize_confirmed_send(&mut client,&state.owner,session,&bytes,&proof,&signature).await {
                    Ok(confirmed)=>{
                        let mut seen=state.sends.lock().await;
                        if let Some(old)=seen.get(&confirmed.message) {
                            if old!=&confirmed {Err(ConversationError::Conflict)} else {Ok(json!({"ok":true,"created":false,"envelope":STANDARD.encode(bytes)}))}
                        } else {seen.insert(confirmed.message,confirmed);Ok(json!({"ok":true,"created":true,"envelope":STANDARD.encode(bytes)}))}
                    },Err(e)=>Err(e),
                },_=>Err(ConversationError::Invalid),
            }
        },
        "send_expiry_wait"=>{
            match (c.data.and_then(|v|STANDARD.decode(v).ok()),c.confirmation.and_then(|v|STANDARD.decode(v).ok()),c.signature.and_then(|v|STANDARD.decode(v).ok())) {
                (Some(bytes),Some(proof),Some(signature))=>{
                    let confirmed=super::super::send::Confirmation::decode(&proof).unwrap();
                    let mut blocker=f.connect().await;
                    let hold=blocker.transaction().await.unwrap();
                    hold.query_one("SELECT id FROM accounts WHERE id=$1 FOR UPDATE",&[&s.account]).await.unwrap();
                    assert!(confirmed.expires_ms-now(&hold).await.unwrap()<=1500);
                    let mut pending=Box::pin(super::super::send::authorize_confirmed_send(&mut client,&state.owner,session,&bytes,&proof,&signature));
                    assert!(tokio::time::timeout(std::time::Duration::from_millis(25),&mut pending).await.is_err(),"actual account lock must block admission");
                    while now(&hold).await.unwrap()<confirmed.expires_ms {tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
                    hold.commit().await.unwrap();
                    assert!(matches!(pending.await,Err(ConversationError::Forbidden)),"confirmation expiry after lock wait must fail closed");
                    assert!(!state.sends.lock().await.contains_key(&confirmed.message));
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
        "finish"=>{state.done.notify_one();Ok(json!({"ok":true}))},
        _=>Err(ConversationError::Invalid),
    };
    match result {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(_) => (StatusCode::FORBIDDEN, Json(json!({"ok":false}))),
    }
}

#[tokio::test]
#[ignore = "requires explicitly selected conversation simulator runner, SDK and disposable PostgreSQL"]
async fn loopback_journal_bridge() {
    let directory =
        std::env::var_os("ZT_CONVERSATION_SIM_DIR").expect("explicit fixture directory");
    let directory = std::path::PathBuf::from(directory);
    assert!(directory.is_absolute() && directory.is_dir());
    let (mut f, owner) = super::super::tests::prepared().await;
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
    let state = Arc::new(Simulator {
        fixture: Mutex::new(f),
        owner,
        statement,
        done: done.clone(),
        token,
        phone_session,
        origin_hash,
        sends: Mutex::new(std::collections::HashMap::new()),
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
    let path = directory.join("ready.json");
    let temporary = directory.join("ready.tmp");
    std::fs::write(&temporary, serde_json::to_vec(&ready).unwrap()).unwrap();
    std::fs::rename(&temporary, &path).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(240), &mut server).await;
    if result.is_err() {
        server.abort();
        let _ = server.await;
    }
    std::fs::remove_file(&path).unwrap();
    let state = Arc::try_unwrap(state).ok().expect("fixture server stopped");
    state.fixture.into_inner().cleanup().await;
    result
        .expect("fixture client did not finish")
        .expect("fixture server failed");
}
