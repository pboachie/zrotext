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
    inbound::{self, Content, InboundError, InboundEvent, InboundSession},
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
    OptOut,
    OptOutReview,
    OptIn,
}

impl From<InboundClassification> for inbound::Classification {
    fn from(value: InboundClassification) -> Self {
        match value {
            InboundClassification::CapturedLocal => Self::CapturedLocal,
            InboundClassification::SimUnverified => Self::SimUnverified,
            InboundClassification::SendUnverified => Self::SendUnverified,
            InboundClassification::EncryptionUnverified => Self::EncryptionUnverified,
            InboundClassification::OptOut => Self::OptOut,
            InboundClassification::OptOutReview => Self::OptOutReview,
            InboundClassification::OptIn => Self::OptIn,
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
        #[serde(skip_serializing_if = "is_false")]
        suppression_cleared: bool,
    },
}

fn is_false(value: &bool) -> bool {
    !value
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
/// Authenticated upload row cannot be accepted by this writer. The phone must
/// retire the row before opening a new session, then continue heartbeats.
const EVIDENCE_REJECTED: u16 = 4409;

fn radio_evidence_close_code(error: &StoreError, session_still_current: bool) -> u16 {
    match error {
        StoreError::StaleFence if session_still_current => EVIDENCE_REJECTED,
        StoreError::InvalidInput | StoreError::InvalidTransition | StoreError::EventIdConflict => {
            EVIDENCE_REJECTED
        }
        StoreError::Revoked => close_code::POLICY,
        _ => RETRY_LATER,
    }
}

fn inbound_evidence_close_code(error: &InboundError) -> u16 {
    match error {
        InboundError::InvalidInput
        | InboundError::InvalidSignature
        | InboundError::UnknownSource
        | InboundError::EventConflict
        | InboundError::SequenceConflict => EVIDENCE_REJECTED,
        InboundError::Unauthorized => close_code::POLICY,
        InboundError::SourcePending
        | InboundError::StaleLease
        | InboundError::BudgetExhausted
        | InboundError::Database(_) => RETRY_LATER,
    }
}

fn durable_intent_preflight_close_code(
    current_grant: Option<bool>,
    previous_intent: Option<bool>,
) -> Option<u16> {
    match (current_grant, previous_intent) {
        (Some(false), Some(false)) => Some(EVIDENCE_REJECTED),
        (None, _) | (_, None) => Some(RETRY_LATER),
        _ => None,
    }
}

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
    let mut close_with_code = None;
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
                        if matches!(evidence, RadioEvidence::DurableSubmitIntent) {
                            let current_grant = grant_still_current(&client, session,
                                message_id, attempt_id, &state).await;
                            let previous_intent = previous_submit_intent(&client, session,
                                event_id, message_id, attempt_id).await;
                            if let Some(code) = durable_intent_preflight_close_code(
                                current_grant.ok(), previous_intent.ok())
                            {
                                close_with_code = Some(code);
                                break;
                            }
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
                        let next = match store.record_radio_event(event).await {
                            Ok(next) => next,
                            Err(error) => {
                                close_with_code = Some(radio_evidence_close_code(&error,
                                    session_current(&client, session, &state).await.unwrap_or(false)));
                                break;
                            }
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
                        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_der.as_bytes()) else {
                            close_with_code = Some(EVIDENCE_REJECTED);
                            break;
                        };
                        if URL_SAFE_NO_PAD.encode(&signature) != signature_der {
                            close_with_code = Some(EVIDENCE_REJECTED);
                            break;
                        }
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
                        let outcome = match inbound::ingest(&mut client, inbound_session, &event).await {
                            Ok(outcome) => outcome,
                            Err(error) => {
                                close_with_code = Some(inbound_evidence_close_code(&error));
                                break;
                            }
                        };
                        if !send_frame(&mut socket, ServerFrame::InboundEventAck {
                            v: 1, event_id,
                            created: outcome.created,
                            queued_deliveries: outcome.queued_deliveries,
                            suppression_cleared: outcome.suppression_cleared,
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
    let _ = socket
        .send(Message::Close(close_with_code.map(|code| CloseFrame {
            code,
            reason: "".into(),
        })))
        .await;
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
mod tests;

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
