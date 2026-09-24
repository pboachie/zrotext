// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated device stream with heartbeat, opt-in synthetic grants, radio
//! evidence and inbound metadata frames.

use crate::{
    alpha_policy::AlphaPolicy,
    auth::{
        TokenHasher,
        abuse_limits::{self, Limit},
    },
    enrollment::{self, AuthenticatedDevice, EnrollmentError, EnrollmentHasher},
    inbound::{self, Content, InboundEvent, InboundSession},
};
use axum::{
    Router,
    extract::{
        State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code},
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
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{interval, timeout, timeout_at},
};
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, GrantRecord, RadioEvent, SessionRecord, StoreError};
use zrotext_domain::{Evidence, MessageState};

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
// Whole pre-session phase, from the upgrade request through proof verification,
// including storage work. Each of hello and proof still has `AUTH_TIMEOUT`.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);
// A pre-session close is best effort; a peer that stops reading cannot hold it.
const HANDSHAKE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const HEARTBEAT_SECONDS: u64 = 30;
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(45);
const SESSION_LEASE_SECONDS: i32 = 90;
const MAX_FRAME_BYTES: usize = 4096;
const MAX_DEVICE_SOCKETS: usize = 32;
const MAX_HANDSHAKING_DEVICE_SOCKETS: usize = 32;
const DISPATCH_POLL_SECONDS: u64 = 5;
const MIN_SECONDS_BETWEEN_GRANTS: u64 = 60;
const ALPHA_READY_SECONDS: u64 = 300;
static DEVICE_SOCKET_ADMISSION: LazyLock<SocketAdmission> = LazyLock::new(|| {
    SocketAdmission::new(
        MAX_HANDSHAKING_DEVICE_SOCKETS,
        MAX_DEVICE_SOCKETS,
        AUTH_TIMEOUT,
        HANDSHAKE_DEADLINE,
    )
});

/// Per-process device socket capacity. A socket that has not proven an
/// enrolled key draws only from the short-lived handshake budget; the
/// long-lived session slot is reserved after the proof verifies. Sockets that
/// never authenticate therefore expire and cannot occupy enrolled phones'
/// session capacity.
#[derive(Clone)]
struct SocketAdmission {
    handshaking: Arc<Semaphore>,
    established: Arc<Semaphore>,
    step_timeout: Duration,
    handshake_deadline: Duration,
}

impl SocketAdmission {
    fn new(
        handshaking: usize,
        established: usize,
        step_timeout: Duration,
        handshake_deadline: Duration,
    ) -> Self {
        Self {
            handshaking: Arc::new(Semaphore::new(handshaking)),
            established: Arc::new(Semaphore::new(established)),
            step_timeout,
            handshake_deadline,
        }
    }
}

#[derive(Clone)]
struct SocketRoute {
    state: DeviceSocketState,
    admission: SocketAdmission,
}

#[derive(Clone)]
pub struct DeviceSocketState {
    pub database_url: String,
    pub site_id: String,
    pub instance_id: String,
    pub deployment_epoch: i64,
    pub enrollment_hasher: Arc<EnrollmentHasher>,
    pub auth_hasher: Arc<TokenHasher>,
    pub alpha_policy: Arc<AlphaPolicy>,
    pub dispatch_runtime_enabled: bool,
    pub inbound_pilot_enabled: bool,
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
    #[serde(rename = "inbound_event")]
    InboundEvent {
        v: u8,
        connection_epoch: i64,
        event_id: Uuid,
        sequence: i64,
        message_id: Uuid,
        attempt_id: Uuid,
        classification: InboundClassification,
        observed_at_ms: i64,
        part_count: i16,
        signature_der: String,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InboundClassification {
    CapturedLocal,
    SimUnverified,
    SendUnverified,
    EncryptionUnverified,
}

impl From<InboundClassification> for inbound::Classification {
    fn from(value: InboundClassification) -> Self {
        match value {
            InboundClassification::CapturedLocal => Self::CapturedLocal,
            InboundClassification::SimUnverified => Self::SimUnverified,
            InboundClassification::SendUnverified => Self::SendUnverified,
            InboundClassification::EncryptionUnverified => Self::EncryptionUnverified,
        }
    }
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
    #[serde(rename = "inbound_event_ack")]
    InboundEventAck {
        v: u8,
        event_id: Uuid,
        created: bool,
        queued_deliveries: u64,
    },
}

/// Mount at `/v1/device-stream`. Deploy behind TLS/WSS; this route accepts
/// neither a browser Origin nor an identity token in URL or headers.
pub fn router(state: DeviceSocketState) -> Router {
    router_with_admission(state, DEVICE_SOCKET_ADMISSION.clone())
}

fn router_with_admission(state: DeviceSocketState, admission: SocketAdmission) -> Router {
    Router::new()
        .route("/v1/device-stream", get(upgrade))
        .with_state(SocketRoute { state, admission })
}

async fn upgrade(
    State(SocketRoute { state, admission }): State<SocketRoute>,
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
    // Session capacity is reserved only after proof; this early refusal just
    // avoids spending shared handshake budgets when none is left.
    if admission.established.available_permits() == 0 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(handshake_slot) = admission.handshaking.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let deadline = tokio::time::Instant::now() + admission.handshake_deadline;
    websocket
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| run_socket(socket, state, admission, handshake_slot, deadline))
        .into_response()
}

async fn connect(database_url: &str) -> Result<Client, crate::runtime_db::ConnectError> {
    let (client, connection) = crate::runtime_db::connect_device(database_url).await?;
    tokio::spawn(async move {
        if connection.await.is_err() {
            eprintln!("device socket database connection closed");
        }
    });
    Ok(client)
}

// A burst accommodates queued device evidence; the sustained bound includes
// control frames and exact replays, neither of which consumes a daily event cap.
struct FrameBudget {
    tokens: f64,
    updated: Instant,
}
impl FrameBudget {
    fn new(now: Instant) -> Self {
        Self {
            tokens: 256.0,
            updated: now,
        }
    }
    fn admit(&mut self, now: Instant) -> bool {
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * 64.0).min(256.0);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

async fn receive_frame(socket: &mut WebSocket, budget: &mut FrameBudget) -> Option<ClientFrame> {
    loop {
        let message = socket.recv().await?.ok()?;
        if !budget.admit(Instant::now()) {
            return None;
        }
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

const RETRY_LATER: u16 = 1013;

fn enrollment_close_code(error: &EnrollmentError) -> u16 {
    match error {
        EnrollmentError::Unauthorized | EnrollmentError::InvalidInput => close_code::POLICY,
        _ => RETRY_LATER,
    }
}

async fn close_handshake(socket: &mut WebSocket, code: u16) {
    let _ = timeout(
        HANDSHAKE_CLOSE_TIMEOUT,
        socket.send(Message::Close(Some(CloseFrame {
            code,
            reason: "".into(),
        }))),
    )
    .await;
}

/// Pre-session failure: the close code to send, or `None` when the socket
/// already failed and no close frame can be written.
type HandshakeRefusal = Option<u16>;

/// Hello, challenge and proof. Runs under the handshake deadline and returns the
/// device-budget database client together with the verified identity.
async fn authenticate(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    frame_budget: &mut FrameBudget,
    step_timeout: Duration,
) -> Result<(Client, AuthenticatedDevice), HandshakeRefusal> {
    let Some(ClientFrame::Hello { v: 1, device_id }) =
        timeout(step_timeout, receive_frame(socket, frame_budget))
            .await
            .ok()
            .flatten()
    else {
        return Err(Some(close_code::POLICY));
    };
    let Ok(mut client) = connect(&state.database_url).await else {
        return Err(Some(RETRY_LATER));
    };
    // Share the HTTP enrollment budgets across transports and server instances.
    // A concurrent-socket cap alone cannot bound rapid hello/close cycles.
    // Enrolled devices still reconnect after junk IDs exhaust the route budget.
    if !matches!(
        abuse_limits::consume_or_verify(
            &client,
            &state.auth_hasher,
            Limit::DeviceChallenge,
            &device_id.to_string(),
            enrollment::device_is_live(&client, device_id),
        )
        .await,
        Ok(true)
    ) {
        return Err(Some(RETRY_LATER));
    }
    let challenge =
        enrollment::issue_device_challenge(&client, &state.enrollment_hasher, device_id)
            .await
            .map_err(|error| Some(enrollment_close_code(&error)))?;
    if !send_frame(
        socket,
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
        return Err(None);
    }
    let Some(ClientFrame::Proof {
        v: 1,
        challenge_id,
        account_id,
        device_id,
        nonce,
        signature_der,
    }) = timeout(step_timeout, receive_frame(socket, frame_budget))
        .await
        .ok()
        .flatten()
    else {
        return Err(Some(close_code::POLICY));
    };
    let Ok(decoded_nonce) = URL_SAFE_NO_PAD.decode(nonce.as_bytes()) else {
        return Err(Some(close_code::POLICY));
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_der.as_bytes()) else {
        return Err(Some(close_code::POLICY));
    };
    if challenge_id != challenge.id
        || account_id != challenge.account_id
        || device_id != challenge.device_id
        || decoded_nonce != challenge.nonce
        || signature.len() > 80
    {
        return Err(Some(close_code::POLICY));
    }
    if !matches!(
        abuse_limits::consume_or_verify(
            &client,
            &state.auth_hasher,
            Limit::DeviceAuthenticate,
            &device_id.to_string(),
            enrollment::device_challenge_is_live(&client, &state.enrollment_hasher, &challenge),
        )
        .await,
        Ok(true)
    ) {
        return Err(Some(RETRY_LATER));
    }
    let identity = enrollment::authenticate_device_challenge(
        &mut client,
        &state.enrollment_hasher,
        &challenge,
        &signature,
    )
    .await
    .map_err(|error| Some(enrollment_close_code(&error)))?;
    Ok((client, identity))
}

async fn run_socket(
    mut socket: WebSocket,
    state: DeviceSocketState,
    admission: SocketAdmission,
    handshake_slot: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) {
    let mut frame_budget = FrameBudget::new(Instant::now());
    let authenticated = timeout_at(
        deadline,
        authenticate(
            &mut socket,
            &state,
            &mut frame_budget,
            admission.step_timeout,
        ),
    )
    .await
    .unwrap_or(Err(Some(RETRY_LATER)));
    let session_slot = match authenticated {
        Ok(_) => admission.established.clone().try_acquire_owned().ok(),
        Err(_) => None,
    };
    // The handshake budget is released on every path before any close write or
    // steady-state work; only a verified device continues with a session slot.
    drop(handshake_slot);
    let (mut client, identity, _session_slot) = match (authenticated, session_slot) {
        (Ok((client, identity)), Some(slot)) => (client, identity, slot),
        (Ok(_), None) => {
            close_handshake(&mut socket, RETRY_LATER).await;
            return;
        }
        (Err(Some(code)), _) => {
            close_handshake(&mut socket, code).await;
            return;
        }
        (Err(None), _) => return,
    };
    if state.draining.load(Ordering::Acquire) {
        close_handshake(&mut socket, RETRY_LATER).await;
        return;
    }
    let session = match claim_session(&mut client, identity, &state).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            let code = match enrollment::device_still_active(&client, identity).await {
                Ok(false) => close_code::POLICY,
                _ => RETRY_LATER,
            };
            close_handshake(&mut socket, code).await;
            return;
        }
        Err(_) => {
            close_handshake(&mut socket, RETRY_LATER).await;
            return;
        }
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
    // Enabled only for controlled local liveness probes. Emit bounded,
    // content-free timing and exit markers, never frames or device IDs.
    let diagnostic = std::env::var("ZT_DEVICE_STREAM_DIAGNOSTIC").is_ok_and(|value| value == "1");
    let mut diagnostic_heartbeats = 0;
    let mut close_reason = "other_stream_exit";
    loop {
        tokio::select! {
            message = receive_frame(&mut socket, &mut frame_budget) => {
                match message {
                    Some(ClientFrame::Heartbeat { v: 1 }) => {
                        let received_at = Instant::now();
                        let since_prior_accepted_ms = received_at.duration_since(last_heartbeat).as_millis();
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
                        if diagnostic && diagnostic_heartbeats < 256 {
                            eprintln!(
                                "ZTDeviceStream heartbeat_ack connection_epoch={} since_prior_accepted_ms={} handling_ms={}",
                                session.connection_epoch,
                                since_prior_accepted_ms,
                                received_at.elapsed().as_millis()
                            );
                            diagnostic_heartbeats += 1;
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
                    Some(ClientFrame::InboundEvent {
                        v: 1, connection_epoch, event_id, sequence, message_id,
                        attempt_id, classification, observed_at_ms, part_count, signature_der,
                    }) if state.inbound_pilot_enabled && connection_epoch == session.connection_epoch => {
                        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_der.as_bytes()) else { break; };
                        if URL_SAFE_NO_PAD.encode(&signature) != signature_der { break; }
                        let inbound_session = InboundSession {
                            account_id: session.account_id,
                            device_id: session.device_id,
                            site_id: &state.site_id,
                            instance_id: &state.instance_id,
                            connection_epoch: session.connection_epoch,
                            deployment_epoch: state.deployment_epoch,
                        };
                        let event = InboundEvent {
                            event_id, sequence, message_id, attempt_id,
                            classification: classification.into(), observed_at_ms,
                            part_count, content: Content::MetadataOnly,
                            signature_der: &signature,
                        };
                        let Ok(outcome) = inbound::ingest(&mut client, inbound_session, &event).await else { break; };
                        if !send_frame(&mut socket, ServerFrame::InboundEventAck {
                            v: 1, event_id,
                            created: outcome.created,
                            queued_deliveries: outcome.queued_deliveries,
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
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::{EnrollmentError, device_challenge_bytes};
    use futures_util::{SinkExt, StreamExt};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::elliptic_curve::Generate;
    use rand::rng;
    use sha2::{Digest, Sha256};
    use zrotext_delivery_store::NewMessage;

    #[test]
    fn enrollment_rejections_and_storage_failures_have_distinct_close_codes() {
        assert_eq!(
            enrollment_close_code(&EnrollmentError::Unauthorized),
            close_code::POLICY
        );
        assert_eq!(
            enrollment_close_code(&EnrollmentError::AuthorityUnavailable),
            RETRY_LATER
        );
        assert_eq!(
            enrollment_close_code(&EnrollmentError::Unavailable),
            RETRY_LATER
        );
    }

    #[tokio::test]
    async fn handshake_closes_with_retry_code_when_database_is_down() {
        let state = DeviceSocketState {
            database_url: "host=127.0.0.1 port=1 connect_timeout=1 user=invalid".into(),
            site_id: "site-a".into(),
            instance_id: "test-hub".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(77)).unwrap()),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(78)).unwrap()),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            inbound_pilot_enabled: false,
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let (mut socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}/v1/device-stream"))
                .await
                .unwrap();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({"v":1,"type":"hello","device_id":Uuid::new_v4()})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let close = timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let tokio_tungstenite::tungstenite::Message::Close(Some(frame)) = close else {
            panic!("expected close frame");
        };
        assert_eq!(u16::from(frame.code), RETRY_LATER);

        let (mut socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}/v1/device-stream"))
                .await
                .unwrap();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({"v":1,"type":"proof"}).to_string().into(),
            ))
            .await
            .unwrap();
        let close = timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let tokio_tungstenite::tungstenite::Message::Close(Some(frame)) = close else {
            panic!("expected policy close frame");
        };
        assert_eq!(u16::from(frame.code), close_code::POLICY);
        server.abort();
    }

    #[test]
    fn stream_schema_examples_match_serde_frames() {
        let examples: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../protocol/v1/device-stream.examples.json"
        ))
        .unwrap();
        assert_eq!(examples.len(), 12);
        for frame in &examples[..6] {
            let parsed: ClientFrame = serde_json::from_value(frame.clone()).unwrap();
            assert_eq!(frame["v"], 1);
            let variant = match parsed {
                ClientFrame::Hello { .. } => "hello",
                ClientFrame::Proof { .. } => "proof",
                ClientFrame::Heartbeat { .. } => "heartbeat",
                ClientFrame::AlphaReady { .. } => "alpha_ready",
                ClientFrame::RadioEvent { .. } => "radio_event",
                ClientFrame::InboundEvent { .. } => "inbound_event",
            };
            assert_eq!(frame["type"], variant);
        }
        let id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let server_frames = [
            ServerFrame::Challenge {
                v: 1,
                challenge_id: id,
                account_id: id,
                device_id: id,
                nonce: "AQ".into(),
            },
            ServerFrame::Session {
                v: 1,
                connection_epoch: 7,
                heartbeat_seconds: 30,
            },
            ServerFrame::HeartbeatAck {
                v: 1,
                connection_epoch: 7,
            },
            ServerFrame::SyntheticGrant {
                v: 1,
                message_id: id,
                attempt_id: id,
                device_id: id,
                generation: 1,
                connection_epoch: 7,
                deployment_epoch: 1,
                recipient_digest: "AQ".into(),
                expires_at_ms: 1_700_000_000_000,
                recipient_e164: "+15555550101".into(),
                body: "ZROtext synthetic test: case_1".into(),
            },
            ServerFrame::RadioEventAck {
                v: 1,
                event_id: id,
                state: MessageState::Submitting,
                submit_permitted: true,
            },
            ServerFrame::InboundEventAck {
                v: 1,
                event_id: id,
                created: true,
                queued_deliveries: 0,
            },
        ];
        for (actual, documented) in server_frames.into_iter().zip(&examples[6..]) {
            let variant = match &actual {
                ServerFrame::Challenge { .. } => "challenge",
                ServerFrame::Session { .. } => "session",
                ServerFrame::HeartbeatAck { .. } => "heartbeat_ack",
                ServerFrame::SyntheticGrant { .. } => "synthetic_grant",
                ServerFrame::RadioEventAck { .. } => "radio_event_ack",
                ServerFrame::InboundEventAck { .. } => "inbound_event_ack",
            };
            assert_eq!(documented["type"], variant);
            assert_eq!(serde_json::to_value(actual).unwrap(), *documented);
        }
    }

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
        let inbound = serde_json::json!({
            "type":"inbound_event", "v":1, "connection_epoch":7,
            "event_id":event_id, "sequence":1, "message_id":message_id,
            "attempt_id":attempt_id, "classification":"captured_local",
            "observed_at_ms":1, "part_count":1,
            "signature_der":URL_SAFE_NO_PAD.encode([5u8; 70])
        });
        assert!(matches!(
            serde_json::from_value::<ClientFrame>(inbound.clone()),
            Ok(ClientFrame::InboundEvent {
                v: 1,
                connection_epoch: 7,
                classification: InboundClassification::CapturedLocal,
                ..
            })
        ));
        let mut extra_inbound = inbound;
        extra_inbound["sender_e164"] = serde_json::json!("+15551234567");
        assert!(serde_json::from_value::<ClientFrame>(extra_inbound).is_err());
        assert_eq!(
            serde_json::to_value(ServerFrame::InboundEventAck {
                v: 1,
                event_id,
                created: true,
                queued_deliveries: 0,
            })
            .unwrap(),
            serde_json::json!({
                "type":"inbound_event_ack", "v":1, "event_id":event_id,
                "created":true, "queued_deliveries":0
            })
        );
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn lost_intent_ack_across_hubs_needs_no_radio_proof_before_regrant() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("hub_recovery_test_{}", Uuid::new_v4().simple());
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
        let message_id = Uuid::new_v4();
        let recipient = "+15555550101";
        let recipient_digest: [u8; 32] = Sha256::digest(recipient.as_bytes()).into();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let sec1 = signing.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(sec1.as_bytes()).into();
        client
            .batch_execute("INSERT INTO sites(site_id) VALUES('site-a'),('site-b'); UPDATE deployment_authority SET dispatch_enabled=TRUE")
            .await
            .unwrap();
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Virtual phone')",
                &[&device_id, &account_id],
            )
            .await
            .unwrap();
        client.execute(
            "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&device_id, &account_id, &sec1.as_bytes(), &&fingerprint[..]],
        ).await.unwrap();
        let policy = Arc::new(
            AlphaPolicy::parse(Some("true"), Some(&account_id.to_string()), Some(recipient))
                .unwrap(),
        );
        let site_a = DeviceSocketState {
            database_url: url,
            site_id: "site-a".into(),
            instance_id: "hub-a".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(77)).unwrap()),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(78)).unwrap()),
            alpha_policy: policy,
            dispatch_runtime_enabled: true,
            inbound_pilot_enabled: false,
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };
        let site_b = DeviceSocketState {
            site_id: "site-b".into(),
            instance_id: "hub-b".into(),
            ..site_a.clone()
        };
        let identity = AuthenticatedDevice {
            account_id,
            device_id,
        };
        let session_a = claim_session(&mut client, identity, &site_a)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session_a.connection_epoch, 1);
        let expiry = now_ms() + 600_000;
        let input = || NewMessage {
            account_id,
            client_message_id: message_id,
            device_id,
            idempotency_key: "lost-intent-ack",
            recipient_e164: recipient,
            synthetic_payload: b"ZROtext synthetic test: lost_ack",
            expires_at_ms: expiry,
        };
        DeliveryStore::new(&mut client)
            .accept(input())
            .await
            .unwrap();
        let first_grant = poll_synthetic_grant(&mut client, session_a, &site_a, &recipient_digest)
            .await
            .unwrap()
            .unwrap();
        let wire = serde_json::to_value(first_grant).unwrap();
        let first_attempt = Uuid::parse_str(wire["attempt_id"].as_str().unwrap()).unwrap();
        assert_eq!(wire["generation"], 1);

        // The durable intent reached the writer, but its ACK did not reach the
        // phone. A second hub takes the session; silence is still ambiguous.
        let intent = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id,
            device_id,
            message_id,
            attempt_id: first_attempt,
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
        let session_b = claim_session(&mut client, identity, &site_b)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session_b.connection_epoch, 2);
        assert!(!session_current(&client, session_a, &site_a).await.unwrap());
        assert!(session_current(&client, session_b, &site_b).await.unwrap());
        assert!(
            !grant_still_current(&client, session_b, message_id, first_attempt, &site_b)
                .await
                .unwrap()
        );
        client
            .execute(
                "UPDATE message_attempts SET updated_at=now()-interval '3 minutes' WHERE id=$1",
                &[&first_attempt],
            )
            .await
            .unwrap();
        assert_eq!(
            DeliveryStore::new(&mut client)
                .reconcile_silent_attempts(10)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            DeliveryStore::new(&mut client)
                .status(account_id, message_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Unknown
        );
        assert!(
            poll_synthetic_grant(&mut client, session_b, &site_b, &recipient_digest)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !DeliveryStore::new(&mut client)
                .accept(input())
                .await
                .unwrap()
                .created
        );
        let before: (i64, i64) = {
            let row = client.query_one(
                "SELECT (SELECT count(*) FROM message_attempts WHERE message_id=$1), (SELECT count(*) FROM dispatch_fences WHERE message_id=$1)",
                &[&message_id],
            ).await.unwrap();
            (row.get(0), row.get(1))
        };
        assert_eq!(before, (1, 1));

        // The phone can prove the radio never started after the lost ACK.
        // Only that evidence releases the old fence and permits a new attempt.
        let no_radio = RadioEvent {
            event_id: Uuid::new_v4(),
            evidence: Evidence::ProvenNoSubmit,
            ..intent
        };
        assert_eq!(
            DeliveryStore::new(&mut client)
                .record_radio_event(no_radio)
                .await
                .unwrap(),
            MessageState::Queued
        );
        assert_eq!(
            DeliveryStore::new(&mut client)
                .record_radio_event(no_radio)
                .await
                .unwrap(),
            MessageState::Queued
        );
        client
            .execute(
                "UPDATE message_attempts SET created_at=now()-interval '61 seconds' WHERE id=$1",
                &[&first_attempt],
            )
            .await
            .unwrap();
        let second_grant = poll_synthetic_grant(&mut client, session_b, &site_b, &recipient_digest)
            .await
            .unwrap()
            .unwrap();
        let second_wire = serde_json::to_value(second_grant).unwrap();
        assert_ne!(second_wire["attempt_id"], wire["attempt_id"]);
        assert_eq!(second_wire["generation"], 2);
        assert_eq!(second_wire["connection_epoch"], 2);
        let row = client.query_one(
            "SELECT (SELECT count(*) FROM message_attempts WHERE message_id=$1), (SELECT count(*) FROM dispatch_fences WHERE message_id=$1), (SELECT count(*) FROM message_events WHERE message_id=$1 AND evidence_code='proved_no_submit')",
            &[&message_id],
        ).await.unwrap();
        assert_eq!(
            (
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, i64>(2)
            ),
            (2, 1, 1)
        );
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn writer_claim_replay_epoch_and_revocation() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
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
        let signing = SigningKey::generate_from_rng(&mut rng());
        let sec1 = signing.verifying_key().to_sec1_point(false);
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
        let hasher = Arc::new(EnrollmentHasher::new(crate::test_keys::key(77)).unwrap());
        let state = DeviceSocketState {
            database_url: url,
            site_id: "test-site".into(),
            instance_id: "test-hub".into(),
            deployment_epoch: 1,
            enrollment_hasher: hasher.clone(),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(78)).unwrap()),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            inbound_pilot_enabled: false,
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };

        let bad = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let wrong_signing = SigningKey::generate_from_rng(&mut rng());
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

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod virtual_inbound_tests;

#[cfg(test)]
mod frame_budget_tests {
    use super::*;
    #[tokio::test]
    async fn control_frame_flood_closes_real_socket() {
        use futures_util::SinkExt;
        let closed = Arc::new(Notify::new());
        let observed = closed.clone();
        let app = Router::new().route(
            "/",
            get(move |upgrade: WebSocketUpgrade| {
                let closed = closed.clone();
                async move {
                    upgrade.on_upgrade(move |mut socket| async move {
                        let mut budget = FrameBudget::new(Instant::now());
                        assert!(receive_frame(&mut socket, &mut budget).await.is_none());
                        closed.notify_one();
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/"))
            .await
            .unwrap();
        let sender = tokio::spawn(async move {
            for _ in 0..4096 {
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Pong(
                        Vec::new().into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        timeout(Duration::from_secs(2), observed.notified())
            .await
            .unwrap();
        sender.abort();
        server.abort();
    }
    #[test]
    fn replay_burst_is_bounded_and_replenishes_without_unbounded_credit() {
        let now = Instant::now();
        let mut budget = FrameBudget::new(now);
        for _ in 0..256 {
            assert!(budget.admit(now));
        }
        assert!(!budget.admit(now));
        let later = now + Duration::from_secs(1);
        for _ in 0..64 {
            assert!(budget.admit(later));
        }
        assert!(!budget.admit(later));
        let later = later + Duration::from_secs(3600);
        for _ in 0..256 {
            assert!(budget.admit(later));
        }
        assert!(!budget.admit(later));
    }
}
