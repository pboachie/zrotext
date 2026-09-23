// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated, heartbeat-only device stream. No message or radio commands.

use crate::{
    alpha_policy::AlphaPolicy,
    enrollment::{self, AuthenticatedDevice, EnrollmentHasher},
};
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Notify, Semaphore},
    time::{interval, timeout},
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, GrantRecord, RadioEvent, SessionRecord, StoreError};
use zrotext_domain::{Evidence, MessageState};

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_SECONDS: u64 = 30;
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(45);
const SESSION_LEASE_SECONDS: i32 = 90;
const MAX_FRAME_BYTES: usize = 4096;
const MAX_DEVICE_SOCKETS: usize = 128;
const DISPATCH_POLL_SECONDS: u64 = 5;
const MIN_SECONDS_BETWEEN_GRANTS: u64 = 60;
const ALPHA_READY_SECONDS: u64 = 300;
static DEVICE_SOCKET_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_DEVICE_SOCKETS)));

#[derive(Clone)]
pub struct DeviceSocketState {
    pub database_url: String,
    pub site_id: String,
    pub instance_id: String,
    pub deployment_epoch: i64,
    pub enrollment_hasher: Arc<EnrollmentHasher>,
    pub alpha_policy: Arc<AlphaPolicy>,
    pub dispatch_runtime_enabled: bool,
    pub draining: Arc<AtomicBool>,
    pub drain_notify: Arc<Notify>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSession {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub connection_epoch: i64,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ClientFrame {
    #[serde(rename = "hello")]
    Hello { v: u8, device_id: Uuid },
    #[serde(rename = "proof")]
    Proof {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        device_id: Uuid,
        nonce: String,
        signature_der: String,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat { v: u8 },
    #[serde(rename = "alpha_ready")]
    AlphaReady {
        v: u8,
        connection_epoch: i64,
        recipient_digest: String,
    },
    #[serde(rename = "radio_event")]
    RadioEvent {
        v: u8,
        connection_epoch: i64,
        event_id: Uuid,
        message_id: Uuid,
        attempt_id: Uuid,
        evidence: RadioEvidence,
        observed_at_ms: i64,
        #[serde(default)]
        segment_index: Option<i32>,
        #[serde(default)]
        segment_count: Option<i32>,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RadioEvidence {
    DurableSubmitIntent,
    ProvenNoSubmit,
    SentCallbackOk,
    SentCallbackFailed,
    DeliveryCallbackOk,
    DeliveryTimeout,
    CrashWithoutCallback,
    CallbackConflict,
}

impl From<RadioEvidence> for Evidence {
    fn from(value: RadioEvidence) -> Self {
        match value {
            RadioEvidence::DurableSubmitIntent => Self::DurableSubmitIntent,
            RadioEvidence::ProvenNoSubmit => Self::ProvenNoSubmit,
            RadioEvidence::SentCallbackOk => Self::SentCallbackOk,
            RadioEvidence::SentCallbackFailed => Self::SentCallbackFailed,
            RadioEvidence::DeliveryCallbackOk => Self::DeliveryCallbackOk,
            RadioEvidence::DeliveryTimeout => Self::DeliveryTimeout,
            RadioEvidence::CrashWithoutCallback => Self::CrashWithoutCallback,
            RadioEvidence::CallbackConflict => Self::CallbackConflict,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerFrame {
    #[serde(rename = "challenge")]
    Challenge {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        device_id: Uuid,
        nonce: String,
    },
    #[serde(rename = "session")]
    Session {
        v: u8,
        connection_epoch: i64,
        heartbeat_seconds: u64,
    },
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck { v: u8, connection_epoch: i64 },
    #[serde(rename = "synthetic_grant")]
    SyntheticGrant {
        v: u8,
        message_id: Uuid,
        attempt_id: Uuid,
        device_id: Uuid,
        generation: i64,
        connection_epoch: i64,
        deployment_epoch: i64,
        recipient_digest: String,
        expires_at_ms: i64,
        recipient_e164: String,
        body: String,
    },
    #[serde(rename = "radio_event_ack")]
    RadioEventAck {
        v: u8,
        event_id: Uuid,
        state: MessageState,
        submit_permitted: bool,
    },
}

/// Mount at `/v1/device-stream`. Deploy behind TLS/WSS; this route accepts
/// neither a browser Origin nor an identity token in URL or headers.
pub fn router(state: DeviceSocketState) -> Router {
    Router::new()
        .route("/v1/device-stream", get(upgrade))
        .with_state(state)
}

async fn upgrade(
    State(state): State<DeviceSocketState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    if state.draining.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // Native gateway clients have no browser Origin. Reject browser-initiated
    // sockets even though they could not produce the enrolled-key signature.
    if headers.contains_key(axum::http::header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(slot) = DEVICE_SOCKET_SLOTS.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    websocket
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            run_socket(socket, state).await;
        })
        .into_response()
}

async fn connect(database_url: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
    tokio::spawn(async move {
        if connection.await.is_err() {
            eprintln!("device socket database connection closed");
        }
    });
    Ok(client)
}

async fn receive_frame(socket: &mut WebSocket) -> Option<ClientFrame> {
    loop {
        let message = socket.recv().await?.ok()?;
        match message {
            Message::Text(text) => return serde_json::from_str(text.as_str()).ok(),
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => return None,
        }
    }
}

async fn send_frame(socket: &mut WebSocket, frame: ServerFrame) -> bool {
    let Ok(json) = serde_json::to_string(&frame) else {
        return false;
    };
    json.len() <= MAX_FRAME_BYTES && socket.send(Message::Text(json.into())).await.is_ok()
}

async fn run_socket(mut socket: WebSocket, state: DeviceSocketState) {
    let Some(ClientFrame::Hello { v: 1, device_id }) =
        timeout(AUTH_TIMEOUT, receive_frame(&mut socket))
            .await
            .ok()
            .flatten()
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(mut client) = connect(&state.database_url).await else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(challenge) =
        enrollment::issue_device_challenge(&client, &state.enrollment_hasher, device_id).await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if !send_frame(
        &mut socket,
        ServerFrame::Challenge {
            v: 1,
            challenge_id: challenge.id,
            account_id: challenge.account_id,
            device_id: challenge.device_id,
            nonce: URL_SAFE_NO_PAD.encode(challenge.nonce),
        },
    )
    .await
    {
        return;
    }
    let Some(ClientFrame::Proof {
        v: 1,
        challenge_id,
        account_id,
        device_id,
        nonce,
        signature_der,
    }) = timeout(AUTH_TIMEOUT, receive_frame(&mut socket))
        .await
        .ok()
        .flatten()
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(decoded_nonce) = URL_SAFE_NO_PAD.decode(nonce.as_bytes()) else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_der.as_bytes()) else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if challenge_id != challenge.id
        || account_id != challenge.account_id
        || device_id != challenge.device_id
        || decoded_nonce != challenge.nonce
        || signature.len() > 80
    {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let Ok(identity) = enrollment::authenticate_device_challenge(
        &mut client,
        &state.enrollment_hasher,
        &challenge,
        &signature,
    )
    .await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if state.draining.load(Ordering::Acquire) {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let Ok(Some(session)) = claim_session(&mut client, identity, &state).await else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if !send_frame(
        &mut socket,
        ServerFrame::Session {
            v: 1,
            connection_epoch: session.connection_epoch,
            heartbeat_seconds: HEARTBEAT_SECONDS,
        },
    )
    .await
    {
        let _ = release_session(&client, session).await;
        return;
    }
    let mut last_heartbeat = Instant::now();
    let mut checks = interval(Duration::from_secs(10));
    checks.tick().await;
    let mut dispatch_checks = interval(Duration::from_secs(DISPATCH_POLL_SECONDS));
    dispatch_checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    dispatch_checks.tick().await;
    let mut last_grant_at: Option<Instant> = None;
    let mut alpha_ready: Option<([u8; 32], Instant)> = None;
    let mut alpha_ready_used = false;
    // Enabled only for controlled local liveness probes. Emit one content-free
    // marker per authenticated session, never a frame or device identifier.
    let diagnostic = std::env::var("ZT_DEVICE_STREAM_DIAGNOSTIC").is_ok_and(|value| value == "1");
    let mut close_reason = "other_stream_exit";
    loop {
        tokio::select! {
            message = receive_frame(&mut socket) => {
                match message {
                    Some(ClientFrame::Heartbeat { v: 1 }) => {
                        if !renew_session(&client, session, &state).await.unwrap_or(false) {
                            close_reason = "heartbeat_renew_failed_or_fenced";
                            break;
                        }
                        last_heartbeat = Instant::now();
                        if !send_frame(&mut socket, ServerFrame::HeartbeatAck {
                            v: 1, connection_epoch: session.connection_epoch,
                        }).await {
                            close_reason = "heartbeat_ack_write_failed";
                            break;
                        }
                    }
                    Some(ClientFrame::AlphaReady { v: 1, connection_epoch, recipient_digest })
                        if connection_epoch == session.connection_epoch && !alpha_ready_used && state.dispatch_runtime_enabled =>
                    {
                        let Ok(bytes) = URL_SAFE_NO_PAD.decode(recipient_digest.as_bytes()) else { break; };
                        let Ok(digest): Result<[u8; 32], _> = bytes.try_into() else { break; };
                        if URL_SAFE_NO_PAD.encode(digest) != recipient_digest
                            || !state.alpha_policy.allows_recipient_digest(session.account_id, &digest)
                            || !session_current(&client, session, &state).await.unwrap_or(false)
                        { break; }
                        alpha_ready = Some((digest, Instant::now()));
                        alpha_ready_used = true;
                    }
                    Some(ClientFrame::RadioEvent {
                        v: 1, connection_epoch, event_id, message_id, attempt_id,
                        evidence, observed_at_ms, segment_index, segment_count,
                    }) if connection_epoch == session.connection_epoch => {
                        if !session_current(&client, session, &state).await.unwrap_or(false) {
                            break;
                        }
                        if matches!(evidence, RadioEvidence::DurableSubmitIntent)
                            && !grant_still_current(&client, session, message_id, attempt_id, &state)
                                .await
                                .unwrap_or(false)
                            && !previous_submit_intent(&client, session, event_id, message_id, attempt_id)
                                .await
                                .unwrap_or(false)
                        {
                            break;
                        }
                        let event = RadioEvent {
                            event_id,
                            account_id: session.account_id,
                            device_id: session.device_id,
                            message_id,
                            attempt_id,
                            evidence: evidence.into(),
                            observed_at_ms,
                            segment_index,
                            segment_count,
                        };
                        let mut store = DeliveryStore::new(&mut client);
                        let Ok(next) = store.record_radio_event(event).await else {
                            break;
                        };
                        let submit_permitted = matches!(evidence, RadioEvidence::DurableSubmitIntent)
                            && grant_still_current(&client, session, message_id, attempt_id, &state)
                                .await
                                .unwrap_or(false);
                        if !send_frame(&mut socket, ServerFrame::RadioEventAck {
                            v: 1, event_id, state: next, submit_permitted,
                        }).await { break; }
                    }
                    _ => break,
                }
            }
            _ = checks.tick() => {
                if last_heartbeat.elapsed() > HEARTBEAT_DEADLINE {
                    close_reason = "heartbeat_deadline";
                    break;
                }
                if !session_current(&client, session, &state).await.unwrap_or(false) {
                    close_reason = "session_check_failed_or_fenced";
                    break;
                }
            }
            _ = dispatch_checks.tick(), if alpha_ready.is_some() => {
                if !session_current(&client, session, &state).await.unwrap_or(false) {
                    break;
                }
                let Some((recipient_digest, armed_at)) = alpha_ready else { continue; };
                if armed_at.elapsed() > Duration::from_secs(ALPHA_READY_SECONDS) {
                    alpha_ready = None;
                    continue;
                }
                if last_grant_at.is_some_and(|at| at.elapsed() < Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS)) {
                    continue;
                }
                match poll_synthetic_grant(&mut client, session, &state, &recipient_digest).await {
                    Ok(Some(frame)) => {
                        alpha_ready = None;
                        if !send_frame(&mut socket, frame).await { break; }
                        last_grant_at = Some(Instant::now());
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            _ = state.drain_notify.notified() => {
                close_reason = "site_drain";
                break;
            },
        }
    }
    if diagnostic {
        eprintln!(
            "ZTDeviceStream close_reason={close_reason} connection_epoch={} since_heartbeat_ms={}",
            session.connection_epoch,
            last_heartbeat.elapsed().as_millis()
        );
    }
    let _ = release_session(&client, session).await;
    let _ = socket.send(Message::Close(None)).await;
}

fn synthetic_body_is_fixed(body: &str) -> bool {
    let Some(id) = body.strip_prefix("ZROtext synthetic test: ") else {
        return false;
    };
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn store_session(session: DeviceSession, state: &DeviceSocketState) -> SessionRecord {
    SessionRecord {
        account_id: session.account_id,
        device_id: session.device_id,
        site_id: state.site_id.clone(),
        instance_id: state.instance_id.clone(),
        epoch: session.connection_epoch,
        deployment_epoch: state.deployment_epoch,
    }
}

async fn grant_still_current(
    client: &Client,
    session: DeviceSession,
    message_id: Uuid,
    attempt_id: Uuid,
    state: &DeviceSocketState,
) -> Result<bool, tokio_postgres::Error> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM dispatch_fences f JOIN deployment_authority a ON a.singleton=TRUE \
         WHERE f.account_id=$1 AND f.device_id=$2 AND f.message_id=$3 AND f.attempt_id=$4 \
         AND f.session_epoch=$5 AND f.deployment_epoch=$6 AND f.grant_expires_at>now() \
         AND f.outcome IN ('granted','submitting') AND a.epoch=$6 AND a.dispatch_enabled=TRUE",
            &[
                &session.account_id,
                &session.device_id,
                &message_id,
                &attempt_id,
                &session.connection_epoch,
                &state.deployment_epoch,
            ],
        )
        .await?
        .is_some())
}

async fn previous_submit_intent(
    client: &Client,
    session: DeviceSession,
    event_id: Uuid,
    message_id: Uuid,
    attempt_id: Uuid,
) -> Result<bool, tokio_postgres::Error> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM message_events e JOIN message_attempts a ON a.id=e.attempt_id \
         WHERE e.id=$1 AND e.account_id=$2 AND e.message_id=$3 AND e.attempt_id=$4 \
         AND a.device_id=$5 AND e.evidence_code='durable_intent'",
            &[
                &event_id,
                &session.account_id,
                &message_id,
                &attempt_id,
                &session.device_id,
            ],
        )
        .await?
        .is_some())
}

/// Claim only for this authenticated device and issue at most one fenced grant.
/// A failed frame send leaves the grant unresolved; reconnect never retries it.
async fn poll_synthetic_grant(
    client: &mut Client,
    session: DeviceSession,
    state: &DeviceSocketState,
    recipient_digest: &[u8; 32],
) -> Result<Option<ServerFrame>, StoreError> {
    if !state.dispatch_runtime_enabled
        || !state
            .alpha_policy
            .allows_recipient_digest(session.account_id, recipient_digest)
    {
        return Ok(None);
    }
    let enabled = client
        .query_opt(
            "SELECT dispatch_enabled FROM deployment_authority WHERE singleton=TRUE AND epoch=$1",
            &[&state.deployment_epoch],
        )
        .await?
        .is_some_and(|row| row.get::<_, bool>(0));
    if !enabled {
        return Ok(None);
    }
    let active: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM dispatch_fences WHERE account_id=$1 AND device_id=$2 AND outcome IN ('granted','submitting','unknown'))",
            &[&session.account_id, &session.device_id],
        )
        .await?
        .get(0);
    if active {
        return Ok(None);
    }
    let recently_granted: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM message_attempts WHERE account_id=$1 AND device_id=$2 \
             AND created_at>now()-interval '60 seconds')",
            &[&session.account_id, &session.device_id],
        )
        .await?
        .get(0);
    if recently_granted {
        return Ok(None);
    }
    let worker_id = format!(
        "{}:{}:{}",
        state.instance_id, session.device_id, session.connection_epoch
    );
    let Some(claim) = DeliveryStore::new(client)
        .claim_due_for_device_and_recipient(
            &worker_id,
            session.account_id,
            session.device_id,
            recipient_digest,
        )
        .await?
    else {
        return Ok(None);
    };
    let queued = client
        .query_opt(
            "SELECT recipient_e164,transport_payload,transport_mode FROM messages \
             WHERE account_id=$1 AND id=$2 AND device_id=$3 AND state='claimed' AND expires_at>now()",
            &[&claim.account_id, &claim.message_id, &claim.device_id],
        )
        .await?
        .ok_or(StoreError::StaleFence)?;
    let recipient: String = queued.get(0);
    let body_bytes: Vec<u8> = queued.get(1);
    let mode: String = queued.get(2);
    let permitted = mode == "synthetic_alpha"
        && state.alpha_policy.allows(claim.account_id, &recipient)
        && String::from_utf8(body_bytes)
            .as_deref()
            .is_ok_and(synthetic_body_is_fixed);
    if !permitted {
        DeliveryStore::new(client)
            .cancel(claim.account_id, claim.message_id)
            .await?;
        return Ok(None);
    }
    let mut store = DeliveryStore::new(client);
    let record = store_session(session, state);
    let grant = match store.issue_grant(&claim, &record, Uuid::new_v4()).await {
        Ok(grant) => grant,
        Err(StoreError::DeviceBusy | StoreError::DispatchDisabled) => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload = store.synthetic_payload_for_grant(&grant, &record).await?;
    if !state
        .alpha_policy
        .allows(session.account_id, &payload.recipient_e164)
        || grant.recipient_digest.as_slice() != recipient_digest
        || !synthetic_body_is_fixed(&payload.body)
        || grant.expires_at_ms <= now_ms()
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(Some(grant_frame(
        grant,
        payload.recipient_e164,
        payload.body,
    )))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as i64)
}

fn grant_frame(grant: GrantRecord, recipient_e164: String, body: String) -> ServerFrame {
    ServerFrame::SyntheticGrant {
        v: 1,
        message_id: grant.message_id,
        attempt_id: grant.attempt_id,
        device_id: grant.device_id,
        generation: grant.generation,
        connection_epoch: grant.session_epoch,
        deployment_epoch: grant.deployment_epoch,
        recipient_digest: URL_SAFE_NO_PAD.encode(grant.recipient_digest),
        expires_at_ms: grant.expires_at_ms,
        recipient_e164,
        body,
    }
}

/// Compare-and-swap through the writer. A new proof increments the persistent
/// epoch; any older socket immediately loses renewal and all future work rights.
async fn claim_session(
    client: &mut Client,
    identity: AuthenticatedDevice,
    state: &DeviceSocketState,
) -> Result<Option<DeviceSession>, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(None);
    }
    let tx = client.transaction().await?;
    let writer = tx
        .query_one("SELECT NOT pg_is_in_recovery()", &[])
        .await?
        .get::<_, bool>(0);
    if !writer {
        return Ok(None);
    }
    if tx.query_opt(
        "SELECT 1 FROM deployment_authority WHERE singleton=TRUE AND epoch=$1 FOR SHARE",
        &[&state.deployment_epoch],
    ).await?.is_none() || tx.query_opt(
        "SELECT 1 FROM sites WHERE site_id=$1 AND enabled=TRUE AND draining=FALSE FOR SHARE",
        &[&state.site_id],
    ).await?.is_none() {
        return Ok(None);
    }
    let active = tx.query_opt(
        "SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL FOR UPDATE OF d",
        &[&identity.account_id, &identity.device_id],
    ).await?.is_some();
    if !active {
        return Ok(None);
    }
    let row = tx.query_one(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,$3,$4,1,now()+($5::integer * interval '1 second'),$6) ON CONFLICT(device_id) DO UPDATE SET account_id=EXCLUDED.account_id,site_id=EXCLUDED.site_id,instance_id=EXCLUDED.instance_id,connection_epoch=device_sessions.connection_epoch+1,lease_until=EXCLUDED.lease_until,deployment_epoch=EXCLUDED.deployment_epoch RETURNING connection_epoch",
        &[&identity.device_id, &identity.account_id, &state.site_id, &state.instance_id, &SESSION_LEASE_SECONDS, &state.deployment_epoch],
    ).await?;
    tx.commit().await?;
    Ok(Some(DeviceSession {
        account_id: identity.account_id,
        device_id: identity.device_id,
        connection_epoch: row.get(0),
    }))
}

async fn session_current(
    client: &Client,
    session: DeviceSession,
    state: &DeviceSocketState,
) -> Result<bool, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(false);
    }
    Ok(client.query_opt(
        "SELECT 1 FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery()",
        &[&session.account_id, &session.device_id, &state.site_id, &state.instance_id, &session.connection_epoch, &state.deployment_epoch],
    ).await?.is_some())
}

async fn renew_session(
    client: &Client,
    session: DeviceSession,
    state: &DeviceSocketState,
) -> Result<bool, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(false);
    }
    Ok(client.execute(
        "UPDATE device_sessions s SET lease_until=now()+($7::integer * interval '1 second') WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND EXISTS (SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=$3 JOIN deployment_authority p ON p.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery())",
        &[&session.account_id, &session.device_id, &state.site_id, &state.instance_id, &session.connection_epoch, &state.deployment_epoch, &SESSION_LEASE_SECONDS],
    ).await? == 1)
}

async fn release_session(
    client: &Client,
    session: DeviceSession,
) -> Result<(), tokio_postgres::Error> {
    client.execute(
        "UPDATE device_sessions SET lease_until=now() WHERE account_id=$1 AND device_id=$2 AND connection_epoch=$3",
        &[&session.account_id, &session.device_id, &session.connection_epoch],
    ).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::{EnrollmentError, device_challenge_bytes};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use zrotext_delivery_store::NewMessage;

    #[test]
    fn wire_v1_uses_only_documented_fields() {
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let nonce = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let frame = serde_json::to_value(ServerFrame::Challenge {
            v: 1,
            challenge_id,
            account_id,
            device_id,
            nonce: nonce.clone(),
        })
        .unwrap();
        assert_eq!(
            frame,
            serde_json::json!({
                "type":"challenge", "v":1, "challenge_id":challenge_id,
                "account_id":account_id, "device_id":device_id, "nonce":nonce
            })
        );
        let session = serde_json::to_value(ServerFrame::Session {
            v: 1,
            connection_epoch: 7,
            heartbeat_seconds: HEARTBEAT_SECONDS,
        })
        .unwrap();
        assert_eq!(
            session,
            serde_json::json!({
                "type":"session", "v":1, "connection_epoch":7, "heartbeat_seconds":30
            })
        );
        let ack = serde_json::to_value(ServerFrame::HeartbeatAck {
            v: 1,
            connection_epoch: 7,
        })
        .unwrap();
        assert_eq!(
            ack,
            serde_json::json!({
                "type":"heartbeat_ack", "v":1, "connection_epoch":7
            })
        );
        let ready = serde_json::json!({
            "type":"alpha_ready", "v":1, "connection_epoch":7,
            "recipient_digest":URL_SAFE_NO_PAD.encode([8u8; 32])
        });
        assert!(matches!(
            serde_json::from_value::<ClientFrame>(ready.clone()),
            Ok(ClientFrame::AlphaReady {
                v: 1,
                connection_epoch: 7,
                ..
            })
        ));
        let mut extra_ready = ready;
        extra_ready["send_count"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ClientFrame>(extra_ready).is_err());
        let event_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let event = serde_json::json!({
            "type":"radio_event", "v":1, "connection_epoch":7,
            "event_id":event_id, "message_id":message_id,
            "attempt_id":attempt_id, "evidence":"durable_submit_intent",
            "observed_at_ms":1
        });
        assert!(matches!(
            serde_json::from_value::<ClientFrame>(event.clone()),
            Ok(ClientFrame::RadioEvent {
                v: 1,
                connection_epoch: 7,
                evidence: RadioEvidence::DurableSubmitIntent,
                ..
            })
        ));
        let mut extra = event;
        extra["unreviewed_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClientFrame>(extra).is_err());
        assert_eq!(
            serde_json::to_value(ServerFrame::RadioEventAck {
                v: 1,
                event_id,
                state: MessageState::Submitting,
                submit_permitted: true,
            })
            .unwrap(),
            serde_json::json!({
                "type":"radio_event_ack", "v":1, "event_id":event_id,
                "state":"submitting", "submit_permitted":true
            })
        );
    }

    #[tokio::test]
    async fn writer_claim_replay_epoch_and_revocation() {
        let Ok(url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("socket_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let signing = SigningKey::random(&mut OsRng);
        let sec1 = signing.verifying_key().to_encoded_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(sec1.as_bytes()).into();
        client
            .execute("INSERT INTO sites(site_id) VALUES('test-site')", &[])
            .await
            .unwrap();
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Test phone')",
                &[&device_id, &account_id],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
                &[&device_id, &account_id, &sec1.as_bytes(), &&fingerprint[..]],
            )
            .await
            .unwrap();
        let hasher = Arc::new(EnrollmentHasher::new(vec![77; 32]).unwrap());
        let state = DeviceSocketState {
            database_url: url,
            site_id: "test-site".into(),
            instance_id: "test-hub".into(),
            deployment_epoch: 1,
            enrollment_hasher: hasher.clone(),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };

        let bad = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let wrong_signing = SigningKey::random(&mut OsRng);
        let wrong_signature: Signature = wrong_signing.sign(&device_challenge_bytes(&bad));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &bad,
                wrong_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let good_signature: Signature = signing.sign(&device_challenge_bytes(&bad));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &bad,
                good_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let expired = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        client
            .execute(
                "UPDATE device_auth_challenges SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute' WHERE id=$1",
                &[&expired.id],
            )
            .await
            .unwrap();
        let expired_signature: Signature = signing.sign(&device_challenge_bytes(&expired));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &expired,
                expired_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let first = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let cross_tenant = crate::enrollment::DeviceChallenge {
            id: first.id,
            account_id: Uuid::new_v4(),
            device_id: first.device_id,
            nonce: first.nonce,
        };
        let cross_signature: Signature = signing.sign(&device_challenge_bytes(&cross_tenant));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &cross_tenant,
                cross_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let first_signature: Signature = signing.sign(&device_challenge_bytes(&first));
        let first_identity = enrollment::authenticate_device_challenge(
            &mut client,
            &hasher,
            &first,
            first_signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        let first_session = claim_session(&mut client, first_identity, &state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_session.connection_epoch, 1);
        assert!(
            session_current(&client, first_session, &state)
                .await
                .unwrap()
        );
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &first,
                first_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let second = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let second_signature: Signature = signing.sign(&device_challenge_bytes(&second));
        let second_identity = enrollment::authenticate_device_challenge(
            &mut client,
            &hasher,
            &second,
            second_signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        let second_session = claim_session(&mut client, second_identity, &state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_session.connection_epoch, 2);
        assert!(
            !session_current(&client, first_session, &state)
                .await
                .unwrap()
        );
        assert!(!renew_session(&client, first_session, &state).await.unwrap());
        release_session(&client, first_session).await.unwrap();
        assert!(
            session_current(&client, second_session, &state)
                .await
                .unwrap()
        );
        assert!(
            renew_session(&client, second_session, &state)
                .await
                .unwrap()
        );

        let message_id = Uuid::new_v4();
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                account_id,
                client_message_id: message_id,
                device_id,
                idempotency_key: "socket-synthetic-case",
                recipient_e164: "+15555550101",
                synthetic_payload: b"ZROtext synthetic test: socket_case",
                expires_at_ms: now_ms() + 10 * 60 * 1000,
            })
            .await
            .unwrap();
        let approved_digest: [u8; 32] = Sha256::digest(b"+15555550101").into();
        assert!(
            poll_synthetic_grant(&mut client, second_session, &state, &approved_digest)
                .await
                .unwrap()
                .is_none()
        );
        let alpha_state = DeviceSocketState {
            alpha_policy: Arc::new(
                AlphaPolicy::parse(
                    Some("true"),
                    Some(&account_id.to_string()),
                    Some("+15555550101"),
                )
                .unwrap(),
            ),
            dispatch_runtime_enabled: true,
            ..state.clone()
        };
        assert!(
            poll_synthetic_grant(&mut client, second_session, &alpha_state, &approved_digest)
                .await
                .unwrap()
                .is_none()
        );
        client
            .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
            .await
            .unwrap();
        let grant =
            poll_synthetic_grant(&mut client, second_session, &alpha_state, &approved_digest)
                .await
                .unwrap()
                .unwrap();
        let wire = serde_json::to_value(grant).unwrap();
        assert_eq!(wire["type"], "synthetic_grant");
        assert_eq!(wire["message_id"], message_id.to_string());
        assert_eq!(wire["recipient_e164"], "+15555550101");
        assert_eq!(wire["body"], "ZROtext synthetic test: socket_case");
        let attempt_id = Uuid::parse_str(wire["attempt_id"].as_str().unwrap()).unwrap();
        assert!(
            grant_still_current(
                &client,
                second_session,
                message_id,
                attempt_id,
                &alpha_state
            )
            .await
            .unwrap()
        );
        let event_id = Uuid::new_v4();
        let intent = RadioEvent {
            event_id,
            account_id,
            device_id,
            message_id,
            attempt_id,
            evidence: Evidence::DurableSubmitIntent,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        assert_eq!(
            DeliveryStore::new(&mut client)
                .record_radio_event(intent)
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert!(
            grant_still_current(
                &client,
                second_session,
                message_id,
                attempt_id,
                &alpha_state
            )
            .await
            .unwrap()
        );
        client
            .execute(
                "UPDATE dispatch_fences SET grant_expires_at=now()-interval '1 second' WHERE attempt_id=$1",
                &[&attempt_id],
            )
            .await
            .unwrap();
        assert!(
            !grant_still_current(
                &client,
                second_session,
                message_id,
                attempt_id,
                &alpha_state
            )
            .await
            .unwrap()
        );
        assert!(
            previous_submit_intent(&client, second_session, event_id, message_id, attempt_id)
                .await
                .unwrap()
        );
        assert!(
            !previous_submit_intent(
                &client,
                second_session,
                Uuid::new_v4(),
                message_id,
                attempt_id
            )
            .await
            .unwrap()
        );
        assert_eq!(
            DeliveryStore::new(&mut client)
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id,
                    device_id,
                    message_id,
                    attempt_id,
                    evidence: Evidence::SentCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: Some(0),
                    segment_count: Some(1),
                })
                .await
                .unwrap(),
            MessageState::Submitted
        );
        let next_message = Uuid::new_v4();
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                account_id,
                client_message_id: next_message,
                device_id,
                idempotency_key: "socket-synthetic-next-case",
                recipient_e164: "+15555550101",
                synthetic_payload: b"ZROtext synthetic test: next_case",
                expires_at_ms: now_ms() + 10 * 60 * 1000,
            })
            .await
            .unwrap();
        assert!(
            poll_synthetic_grant(&mut client, second_session, &alpha_state, &approved_digest)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            DeliveryStore::new(&mut client)
                .status(account_id, next_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Queued
        );

        // A recipient outside the one-shot phone digest remains queued.
        let other_device = Uuid::new_v4();
        let other_message = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Other phone')",
                &[&other_device, &account_id],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
                &[&other_device, &account_id, &sec1.as_bytes(), &&fingerprint[..]],
            )
            .await
            .unwrap();
        let other_session = claim_session(
            &mut client,
            AuthenticatedDevice {
                account_id,
                device_id: other_device,
            },
            &alpha_state,
        )
        .await
        .unwrap()
        .unwrap();
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                account_id,
                client_message_id: other_message,
                device_id: other_device,
                idempotency_key: "revoked-recipient-case",
                recipient_e164: "+15555550102",
                synthetic_payload: b"ZROtext synthetic test: stale_policy",
                expires_at_ms: now_ms() + 10 * 60 * 1000,
            })
            .await
            .unwrap();
        assert!(
            poll_synthetic_grant(&mut client, other_session, &alpha_state, &approved_digest)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            DeliveryStore::new(&mut client)
                .status(account_id, other_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Queued
        );

        // Two distinct, valid reconnection proofs may race on different hubs.
        // The writer serializes them and leaves only the higher epoch current.
        let mut identities = Vec::new();
        for _ in 0..2 {
            let challenge = enrollment::issue_device_challenge(&client, &hasher, device_id)
                .await
                .unwrap();
            let signature: Signature = signing.sign(&device_challenge_bytes(&challenge));
            identities.push(
                enrollment::authenticate_device_challenge(
                    &mut client,
                    &hasher,
                    &challenge,
                    signature.to_der().as_bytes(),
                )
                .await
                .unwrap(),
            );
        }
        let (mut peer_a, connection_a) = tokio_postgres::connect(&state.database_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection_a.await.unwrap() });
        peer_a
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let (mut peer_b, connection_b) = tokio_postgres::connect(&state.database_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection_b.await.unwrap() });
        peer_b
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            claim_session(&mut peer_a, identities[0], &state),
            claim_session(&mut peer_b, identities[1], &state)
        );
        let left = left.unwrap().unwrap();
        let right = right.unwrap().unwrap();
        assert_eq!(
            [left.connection_epoch, right.connection_epoch]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            [3, 4].into_iter().collect()
        );
        let current_session = if left.connection_epoch > right.connection_epoch {
            left
        } else {
            right
        };
        assert!(
            !session_current(&client, second_session, &state)
                .await
                .unwrap()
        );
        assert!(
            session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        let stale_session = if current_session == left { right } else { left };
        assert!(!renew_session(&client, stale_session, &state).await.unwrap());

        client
            .execute(
                "UPDATE sites SET draining=TRUE WHERE site_id=$1",
                &[&state.site_id],
            )
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        client
            .execute(
                "UPDATE sites SET draining=FALSE WHERE site_id=$1",
                &[&state.site_id],
            )
            .await
            .unwrap();
        client
            .execute("UPDATE deployment_authority SET epoch=2", &[])
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        client
            .execute("UPDATE deployment_authority SET epoch=1", &[])
            .await
            .unwrap();

        client
            .execute(
                "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
                &[&device_id],
            )
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(matches!(
            enrollment::issue_device_challenge(&client, &hasher, device_id).await,
            Err(EnrollmentError::Unauthorized)
        ));
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
