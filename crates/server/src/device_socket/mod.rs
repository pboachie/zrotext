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
    inbound::unsolicited::{self, LineOptOut, LineOptOutError},
    inbound::{self, Content, InboundError, InboundEvent, InboundSession},
    runtime_db,
    sealed_inbound::line_activation::{SimObservation, exchange},
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
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, LazyLock, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{interval, timeout, timeout_at},
};
use tokio_postgres::{Client, types::Type};
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, GrantRecord, RadioEvent, SessionRecord, StoreError};
use zrotext_domain::{Evidence, MessageState};

mod mms_spike_policy;
pub use mms_spike_policy::MmsSpikePolicy;
mod conversation;
mod preconditions;
mod stream_diagnostic;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
// Whole pre-session phase, from the upgrade request through proof verification,
// including storage work. Each of hello and proof still has `AUTH_TIMEOUT`.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);
// A pre-session close is best effort; a peer that stops reading cannot hold it.
const HANDSHAKE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const HEARTBEAT_SECONDS: u64 = 30;
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(45);
// Storage renews a session lease at most this often; earlier heartbeats are
// acknowledged from memory. With the 45 s deadline and the 10 s check cadence,
// renewals stay less than 70 s apart, inside the 90 s lease.
const HEARTBEAT_RENEW_INTERVAL: Duration = Duration::from_secs(HEARTBEAT_SECONDS / 2);
// A phone sends two heartbeats a minute; more than 60 is a client bug or abuse.
const HEARTBEAT_ABUSE_WINDOW: Duration = Duration::from_secs(60);
const MAX_HEARTBEATS_PER_WINDOW: u32 = 60;
const SESSION_LEASE_SECONDS: i32 = 90;
const MAX_FRAME_BYTES: usize = 4096;
// Only the explicitly configured future socket admits bounded sealed content frames.
fn socket_frame_limit(conversation_enabled: bool) -> usize {
    if conversation_enabled {
        48_000
    } else {
        MAX_FRAME_BYTES
    }
}
/// Authenticated device sockets per process, across all accounts.
pub const MAX_DEVICE_SOCKETS: usize = 32;
/// Default share of [`MAX_DEVICE_SOCKETS`] one account may hold.
pub const DEFAULT_DEVICE_SOCKETS_PER_ACCOUNT: usize = 8;
const MAX_HANDSHAKING_DEVICE_SOCKETS: usize = 32;
const DISPATCH_POLL_SECONDS: u64 = 5;
const MIN_SECONDS_BETWEEN_GRANTS: u64 = 60;
const ALPHA_READY_SECONDS: u64 = 300;
const SMS_LINE_POLL_SECONDS: u64 = 3;
/// Idle sockets poll the activation exchange far more slowly: almost no
/// device ever has an open exchange, and a new owner challenge wakes every
/// socket in this process immediately through SMS_LINE_CHALLENGE_WAKE.
const SMS_LINE_IDLE_POLL_SECONDS: u64 = 30;
const SMS_LINE_RETIRE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_SMS_LINE_ACKS_PER_CONNECTION: usize = 64;
/// Process-wide wake for sockets idling between activation polls; the owner
/// side calls wake_sms_line_challenges after opening a challenge. Other hub
/// instances are covered by the idle poll.
static SMS_LINE_CHALLENGE_WAKE: LazyLock<Notify> = LazyLock::new(Notify::new);

/// Poll spacing for the activation loop: fast while the previous poll pushed
/// a frame (an exchange is open), slow while the device has nothing pending.
fn sms_line_poll_delay(pushed: bool) -> Duration {
    if pushed {
        Duration::from_secs(SMS_LINE_POLL_SECONDS)
    } else {
        Duration::from_secs(SMS_LINE_IDLE_POLL_SECONDS)
    }
}

/// Wakes every device socket in this process so a fresh owner challenge or
/// approval is pushed within the active 3 s bound instead of the next idle
/// poll. Called by the activation exchange layer; writes from other hub
/// instances are covered by the idle poll.
pub fn wake_sms_line_activation() {
    SMS_LINE_CHALLENGE_WAKE.notify_waiters();
}
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
/// session capacity. Session slots are held per device: one device holds at
/// most one slot, and one account holds at most `per_account` of them.
#[derive(Clone)]
struct SocketAdmission {
    handshaking: Arc<Semaphore>,
    established: Arc<Semaphore>,
    tenancy: Arc<Mutex<Tenancy>>,
    per_account: usize,
    step_timeout: Duration,
    handshake_deadline: Duration,
}

/// Session slots by device. The map holds at most `established` entries, so a
/// linear per-account count stays small.
#[derive(Default)]
struct Tenancy {
    next_holder: u64,
    devices: HashMap<(Uuid, Uuid), DeviceHold>,
}

struct DeviceHold {
    holder: u64,
    superseded: Arc<Notify>,
    _slot: OwnedSemaphorePermit,
}

/// A verified socket's claim on its device's session slot. Dropping it frees
/// the slot unless a newer socket for the same device has taken it over.
struct SessionSlot {
    tenancy: Arc<Mutex<Tenancy>>,
    key: (Uuid, Uuid),
    holder: u64,
    superseded: Arc<Notify>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        let mut tenancy = self.tenancy.lock().unwrap_or_else(PoisonError::into_inner);
        if tenancy
            .devices
            .get(&self.key)
            .is_some_and(|hold| hold.holder == self.holder)
        {
            tenancy.devices.remove(&self.key);
        }
    }
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
            tenancy: Arc::default(),
            per_account: established,
            step_timeout,
            handshake_deadline,
        }
    }

    fn with_account_limit(mut self, per_account: usize) -> Self {
        self.per_account = per_account;
        self
    }

    /// Reserve the session slot for a verified device. A newer socket for the
    /// same device takes over the older socket's slot and tells it to close,
    /// so a reconnect never counts twice. A new device is refused while its
    /// account already holds its share or the process is full.
    fn admit_session(&self, account_id: Uuid, device_id: Uuid) -> Option<SessionSlot> {
        let key = (account_id, device_id);
        let mut tenancy = self.tenancy.lock().unwrap_or_else(PoisonError::into_inner);
        tenancy.next_holder += 1;
        let holder = tenancy.next_holder;
        let superseded = Arc::new(Notify::new());
        if let Some(hold) = tenancy.devices.get_mut(&key) {
            // notify_one keeps a permit, so an older socket that is busy with
            // other work still sees this at its next loop iteration.
            std::mem::replace(&mut hold.superseded, superseded.clone()).notify_one();
            hold.holder = holder;
        } else {
            let held = tenancy
                .devices
                .keys()
                .filter(|(account, _)| *account == account_id)
                .count();
            if held >= self.per_account {
                return None;
            }
            let slot = self.established.clone().try_acquire_owned().ok()?;
            tenancy.devices.insert(
                key,
                DeviceHold {
                    holder,
                    superseded: superseded.clone(),
                    _slot: slot,
                },
            );
        }
        Some(SessionSlot {
            tenancy: self.tenancy.clone(),
            key,
            holder,
            superseded,
        })
    }
}

#[derive(Clone)]
struct SocketRoute {
    state: DeviceSocketState,
    admission: SocketAdmission,
    conversation: Option<conversation::Policy>,
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
    pub line_opt_out_enabled: bool,
    /// Dormant SMS line activation frames; off unless explicitly configured.
    pub sms_line_activation_enabled: bool,
    /// Founder gating for the outbound MMS spike grant; disabled unless the
    /// one device and recipient allowlist are configured.
    pub mms_spike_policy: Arc<mms_spike_policy::MmsSpikePolicy>,
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
    #[serde(rename = "conversation_ready")]
    ConversationReady {
        v: u8,
        connection_epoch: i64,
        challenge: Uuid,
    },
    #[serde(skip)]
    ConversationBinary(Vec<u8>),
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
    #[serde(rename = "device_status")]
    DeviceStatus {
        v: u8,
        connection_epoch: i64,
        selected_sim: preconditions::SelectedSim,
        sms_permission: preconditions::SmsPermission,
        airplane_mode: preconditions::AirplaneMode,
    },
    #[serde(rename = "device_status_v2")]
    DeviceStatusV2 {
        v: u8,
        connection_epoch: i64,
        selected_sim: preconditions::SelectedSim,
        sms_permission: preconditions::SmsPermission,
        airplane_mode: preconditions::AirplaneMode,
        network_service: preconditions::NetworkService,
    },
    #[serde(rename = "alpha_ready")]
    AlphaReady {
        v: u8,
        connection_epoch: i64,
        recipient_digest: String,
    },
    /// Armed debug-build request for the one MMS spike attempt (#438). The
    /// hub answers with at most one `mms_spike_grant` on this connection;
    /// a client that never sends this frame never receives a grant.
    #[serde(rename = "mms_spike_ready")]
    MmsSpikeReady {
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
        /// Unsigned phone clock at upload; places a START on the hub clock.
        #[serde(default)]
        device_sent_at_ms: Option<i64>,
    },
    #[serde(rename = "line_opt_out")]
    LineOptOut {
        v: u8,
        connection_epoch: i64,
        event_id: Uuid,
        sequence: i64,
        line_id: Uuid,
        binding_generation: i64,
        action: LineOptOutAction,
        recipient_e164: String,
        observed_at_ms: i64,
        signature_der: String,
    },
    #[serde(rename = "sms_line_proof")]
    SmsLineProof {
        v: u8,
        connection_epoch: i64,
        challenge_id: Uuid,
        android_api_level: u16,
        active_subscription_count: u8,
        selected_subscription_id: i32,
        signature_der: String,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LineOptOutAction {
    OptOut,
    OptOutReview,
}

impl From<LineOptOutAction> for unsolicited::Action {
    fn from(value: LineOptOutAction) -> Self {
        match value {
            LineOptOutAction::OptOut => Self::Stop,
            LineOptOutAction::OptOutReview => Self::Review,
        }
    }
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
    /// Founder-gated one-attempt MMS spike grant (#438). Issued only when the
    /// server is configured with the single gateway device and the controlled
    /// recipient, and the recipient has not stopped. Default-off.
    #[serde(rename = "mms_spike_grant")]
    MmsSpikeGrant {
        v: u8,
        grant_id: Uuid,
        device_id: Uuid,
        connection_epoch: i64,
        recipient_digest: String,
        expires_at_ms: i64,
        recipient_e164: String,
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
    #[serde(rename = "line_opt_out_ack")]
    LineOptOutAck {
        v: u8,
        event_id: Uuid,
        created: bool,
    },
    #[serde(rename = "sms_line_challenge")]
    SmsLineChallenge {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        line_id: Uuid,
        device_id: Uuid,
        generation: i64,
        nonce: String,
        expires_at_ms: i64,
    },
    #[serde(rename = "sms_line_proof_ack")]
    SmsLineProofAck {
        v: u8,
        challenge_id: Uuid,
        accepted: bool,
    },
    #[serde(rename = "sms_line_activated")]
    SmsLineActivated {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        line_id: Uuid,
        device_id: Uuid,
        generation: i64,
        device_statement_sha256: String,
        device_signature_sha256: String,
    },
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Mount at `/v1/device-stream`. Deploy behind TLS/WSS; this route accepts
/// neither a browser Origin nor an identity token in URL or headers.
pub fn router(state: DeviceSocketState) -> Router {
    router_with_account_share(state, DEFAULT_DEVICE_SOCKETS_PER_ACCOUNT)
}

/// [`router`] with `sockets_per_account` capping one account's share of the
/// process's authenticated device sockets.
pub fn router_with_account_share(state: DeviceSocketState, sockets_per_account: usize) -> Router {
    router_with_admission(
        state,
        DEVICE_SOCKET_ADMISSION
            .clone()
            .with_account_limit(sockets_per_account),
    )
}

fn router_with_admission(state: DeviceSocketState, admission: SocketAdmission) -> Router {
    Router::new()
        .route("/v1/device-stream", get(upgrade))
        .with_state(SocketRoute {
            state,
            admission,
            conversation: None,
        })
}

/// Explicit future composition only. Main continues to call the default disabled router.
/// The configured WSS origin must match the phone's independently approved endpoint.
pub fn conversation_origin_check(origin: &str) -> Result<(), &'static str> {
    conversation::Policy::new(origin).map(|_| ())
}

pub fn router_with_conversations(
    state: DeviceSocketState,
    origin: &str,
) -> Result<Router, &'static str> {
    router_with_conversations_and_account_share(state, origin, DEFAULT_DEVICE_SOCKETS_PER_ACCOUNT)
}

/// Conversation negotiation retains the ordinary account socket admission budget.
pub fn router_with_conversations_and_account_share(
    state: DeviceSocketState,
    origin: &str,
    sockets_per_account: usize,
) -> Result<Router, &'static str> {
    let policy = conversation::Policy::new(origin)?;
    Ok(Router::new()
        .route("/v1/device-stream", get(upgrade))
        .with_state(SocketRoute {
            state,
            admission: DEVICE_SOCKET_ADMISSION
                .clone()
                .with_account_limit(sockets_per_account),
            conversation: Some(policy),
        }))
}

async fn upgrade(
    State(SocketRoute {
        state,
        admission,
        conversation,
    }): State<SocketRoute>,
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
    let frame_limit = socket_frame_limit(conversation.is_some());
    websocket
        .protocols([preconditions::PROTOCOL_V2, preconditions::PROTOCOL])
        .max_message_size(frame_limit)
        .max_frame_size(frame_limit)
        .on_upgrade(move |socket| {
            run_socket(
                socket,
                state,
                admission,
                handshake_slot,
                deadline,
                conversation,
            )
        })
        .into_response()
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

#[derive(Debug, Eq, PartialEq)]
enum HeartbeatAction {
    /// Check out a device database client and renew the lease.
    Renew,
    /// Acknowledge without storage; the lease was renewed recently.
    AckFromMemory,
    /// Close the socket: the peer exceeded the per-window heartbeat cap.
    Abuse,
}

/// Longest time between two verifications of a socket's session against the
/// writer; `protocol/v1/device-stream.md` documents at most 10 seconds.
const SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// When the next standalone [`session_current`] query is due. A successful
/// lease renewal or status write evaluates the same revocation, account,
/// site, epoch, lease and writer predicates, so it counts as a verification
/// and pushes the query back. Verification times are taken before the
/// statement is sent, so the next check is never more than
/// `SESSION_CHECK_INTERVAL` after the database last confirmed the session:
/// a fence committed after that confirmation closes the socket within the
/// same bound as before.
struct SessionCheckSchedule {
    due: Instant,
}

impl SessionCheckSchedule {
    fn new(established_at: Instant) -> Self {
        Self {
            due: established_at + SESSION_CHECK_INTERVAL,
        }
    }

    fn verified(&mut self, at: Instant) {
        self.due = self.due.max(at + SESSION_CHECK_INTERVAL);
    }

    fn due(&self) -> Instant {
        self.due
    }
}

/// Per-socket heartbeat budget, enforced before any database checkout. The
/// first heartbeat renews; later ones renew at most once per
/// `HEARTBEAT_RENEW_INTERVAL`, so a flood cannot multiply lease writes.
/// Revocation and fencing are still observed by the periodic session check.
struct HeartbeatBudget {
    last_renewal: Option<Instant>,
    window_start: Instant,
    in_window: u32,
}
impl HeartbeatBudget {
    fn new(now: Instant) -> Self {
        Self {
            last_renewal: None,
            window_start: now,
            in_window: 0,
        }
    }
    fn admit(&mut self, now: Instant) -> HeartbeatAction {
        if now.saturating_duration_since(self.window_start) >= HEARTBEAT_ABUSE_WINDOW {
            self.window_start = now;
            self.in_window = 0;
        }
        self.in_window = self.in_window.saturating_add(1);
        if self.in_window > MAX_HEARTBEATS_PER_WINDOW {
            return HeartbeatAction::Abuse;
        }
        if self.last_renewal.is_some_and(|previous| {
            now.saturating_duration_since(previous) < HEARTBEAT_RENEW_INTERVAL
        }) {
            return HeartbeatAction::AckFromMemory;
        }
        self.last_renewal = Some(now);
        HeartbeatAction::Renew
    }
}

async fn receive_frame(socket: &mut WebSocket, budget: &mut FrameBudget) -> Option<ClientFrame> {
    loop {
        let message = socket.recv().await?.ok()?;
        if !budget.admit(Instant::now()) {
            return None;
        }
        match message {
            Message::Text(text) => {
                if text.len() > MAX_FRAME_BYTES {
                    return None;
                }
                return serde_json::from_str(text.as_str()).ok();
            }
            Message::Binary(bytes) => return Some(ClientFrame::ConversationBinary(bytes.to_vec())),
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
        | InboundError::SourceRetired
        | InboundError::StaleLease
        | InboundError::BudgetExhausted
        | InboundError::Database(_) => RETRY_LATER,
    }
}

fn line_opt_out_close_code(error: &LineOptOutError) -> u16 {
    match error {
        LineOptOutError::InvalidInput
        | LineOptOutError::InvalidSignature
        | LineOptOutError::EventConflict
        | LineOptOutError::SequenceConflict => EVIDENCE_REJECTED,
        LineOptOutError::Unauthorized => close_code::POLICY,
        LineOptOutError::BudgetExhausted | LineOptOutError::Database(_) => RETRY_LATER,
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
/// verified identity. Database checkouts never span a peer's proof wait.
async fn authenticate(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    frame_budget: &mut FrameBudget,
    step_timeout: Duration,
) -> Result<AuthenticatedDevice, HandshakeRefusal> {
    let Some(ClientFrame::Hello { v: 1, device_id }) =
        timeout(step_timeout, receive_frame(socket, frame_budget))
            .await
            .ok()
            .flatten()
    else {
        return Err(Some(close_code::POLICY));
    };
    let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
        return Err(Some(RETRY_LATER));
    };
    // The pre-proof step is stateless and budgeted only by shared route
    // ceilings and handshake slots. There is deliberately no per-device
    // counter: the device ID is public, so anyone who knows it would be able
    // to spend one and keep the enrolled phone's handshake refused. A
    // concurrent-socket cap alone cannot bound rapid hello/close cycles, so
    // the anonymous route ceiling bounds issuance reads fleet-wide. When
    // made-up device IDs have filled it, an enrolled device is still admitted
    // through the separate verified-route ceiling, which unknown IDs never
    // reach. Each device ID may use only a small share of that ceiling, so
    // traffic naming one known ID can delay only that device, never the fleet.
    let Ok(anonymous) =
        abuse_limits::consume(&client, &state.auth_hasher, Limit::DeviceChallenge, None).await
    else {
        return Err(Some(RETRY_LATER));
    };
    let account = match enrollment::live_device_account(&client, device_id).await {
        Ok(Some(account_id)) => account_id,
        Ok(None) if anonymous => return Err(Some(close_code::POLICY)),
        Ok(None) => return Err(Some(RETRY_LATER)),
        Err(error) => return Err(Some(enrollment_close_code(&error))),
    };
    if !anonymous
        && !matches!(
            abuse_limits::consume_verified(
                &client,
                &state.auth_hasher,
                Limit::DeviceChallenge,
                &device_id.to_string(),
            )
            .await,
            Ok(true)
        )
    {
        return Err(Some(RETRY_LATER));
    }
    let challenge = enrollment::issue_socket_challenge(
        &state.enrollment_hasher,
        account,
        device_id,
        enrollment::unix_now_ms(),
    );
    drop(client);
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
    let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
        return Err(Some(RETRY_LATER));
    };
    // Route ceilings only, for the same reason as issuance: a per-device proof
    // budget would be spendable by anyone naming the device ID. Every proof
    // reaching this point passed a charged hello on this connection, so the
    // verification work below is bounded by issuance. When the anonymous
    // ceiling is full, only a proof that verifies is admitted, through the
    // verified-route ceiling; a failed proof never reaches that ceiling.
    let Ok(anonymous) =
        abuse_limits::consume(&client, &state.auth_hasher, Limit::DeviceAuthenticate, None).await
    else {
        return Err(Some(RETRY_LATER));
    };
    let identity = enrollment::authenticate_socket_proof(
        &client,
        &state.enrollment_hasher,
        &challenge,
        &signature,
        enrollment::unix_now_ms(),
    )
    .await
    .map_err(|error| Some(enrollment_close_code(&error)))?;
    if !anonymous
        && !matches!(
            abuse_limits::consume_verified_route(
                &client,
                &state.auth_hasher,
                Limit::DeviceAuthenticate
            )
            .await,
            Ok(true)
        )
    {
        return Err(Some(RETRY_LATER));
    }
    Ok(identity)
}

async fn run_socket(
    mut socket: WebSocket,
    state: DeviceSocketState,
    admission: SocketAdmission,
    handshake_slot: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
    conversation_policy: Option<conversation::Policy>,
) {
    let status_protocol = socket
        .protocol()
        .map(|value| value.to_str().unwrap_or_default().to_owned());
    let mut status_budget = preconditions::ReportBudget::default();
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
    let session_slot = match &authenticated {
        Ok(identity) => admission.admit_session(identity.account_id, identity.device_id),
        Err(_) => None,
    };
    // The handshake budget is released on every path before any close write or
    // steady-state work; only a verified device continues with a session slot.
    drop(handshake_slot);
    let (identity, session_slot) = match (authenticated, session_slot) {
        (Ok(identity), Some(slot)) => (identity, slot),
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
    let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
        close_handshake(&mut socket, RETRY_LATER).await;
        return;
    };
    let session = match claim_session(&mut client, identity, &state).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            let code = match enrollment::device_still_active(&client, identity).await {
                Ok(false) => close_code::POLICY,
                _ => RETRY_LATER,
            };
            drop(client);
            close_handshake(&mut socket, code).await;
            return;
        }
        Err(_) => {
            drop(client);
            close_handshake(&mut socket, RETRY_LATER).await;
            return;
        }
    };
    drop(client);
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
        release_socket_session(&state, session).await;
        return;
    }
    let mut last_heartbeat = Instant::now();
    let mut heartbeat_budget = HeartbeatBudget::new(last_heartbeat);
    let mut session_checks = SessionCheckSchedule::new(Instant::now());
    let mut dispatch_checks = interval(Duration::from_secs(DISPATCH_POLL_SECONDS));
    dispatch_checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    dispatch_checks.tick().await;
    let mut sms_line_next_poll = tokio::time::Instant::now();
    let mut sms_line_last_retire: Option<Instant> = None;
    let mut sms_line_acks_sent: Vec<Uuid> = Vec::new();
    let mut last_grant_at: Option<Instant> = None;
    let mut alpha_ready: Option<([u8; 32], Instant)> = None;
    let mut alpha_ready_used = false;
    let mut mms_spike_ready_used = false;
    // Enabled only for controlled local liveness probes. Emit bounded,
    // content-free timing and exit markers, never frames or device IDs.
    let diagnostic = std::env::var("ZT_DEVICE_STREAM_DIAGNOSTIC").is_ok_and(|value| value == "1");
    let mut diagnostic_tally = stream_diagnostic::StreamTally::new(last_heartbeat);
    let mut close_reason = "other_stream_exit";
    let mut close_with_code = None;
    let mut conversation_session = None;
    loop {
        tokio::select! {
            message = receive_frame(&mut socket, &mut frame_budget) => {
                match message {
                    Some(ClientFrame::ConversationReady {v:1,connection_epoch,challenge}) => {
                        if conversation_session.is_some() || connection_epoch!=session.connection_epoch || challenge.is_nil() {
                            close_with_code=Some(close_code::POLICY);break;
                        }
                        let Some(policy)=conversation_policy.as_ref() else {close_with_code=Some(close_code::POLICY);break;};
                        let Ok(client)=runtime_db::connect_device(&state.database_url).await else {close_with_code=Some(RETRY_LATER);break;};
                        if !session_current(&client,session,&state).await.unwrap_or(false) {close_with_code=Some(close_code::POLICY);break;}
                        drop(client);
                        let negotiated=policy.negotiate(session,state.deployment_epoch,challenge);
                        let Ok((held,reply))=negotiated else {close_with_code=Some(close_code::POLICY);break;};
                        if socket.send(Message::Text(reply.into())).await.is_err(){break;}
                        conversation_session=Some(held);
                    }
                    Some(ClientFrame::ConversationBinary(bytes)) => {
                        let Some(held)=conversation_session.as_ref() else {close_with_code=Some(close_code::POLICY);break;};
                        let Ok(mut client)=runtime_db::connect_device(&state.database_url).await else {close_with_code=Some(RETRY_LATER);break;};
                        match held.handle(&mut client,session,&state,&bytes).await {
                            Ok(reply)=> {if socket.send(Message::Binary(reply.into())).await.is_err(){break;}}
                            Err(_)=>{close_with_code=Some(close_code::POLICY);break;}
                        }
                    }
                    Some(frame @ (ClientFrame::DeviceStatus { v: 1, .. } | ClientFrame::DeviceStatusV2 { v: 1, .. })) => {
                        let (protocol, connection_epoch, report) = match frame {
                            ClientFrame::DeviceStatus { connection_epoch, selected_sim, sms_permission, airplane_mode, .. } =>
                                (preconditions::PROTOCOL, connection_epoch, preconditions::Report {
                                    selected_sim, sms_permission, airplane_mode, network_service: None }),
                            ClientFrame::DeviceStatusV2 { connection_epoch, selected_sim, sms_permission, airplane_mode, network_service, .. } =>
                                (preconditions::PROTOCOL_V2, connection_epoch, preconditions::Report {
                                    selected_sim, sms_permission, airplane_mode, network_service: Some(network_service) }),
                            _ => unreachable!("status variants matched above"),
                        };
                        if status_protocol.as_deref() != Some(protocol) || connection_epoch != session.connection_epoch {
                            close_with_code = Some(close_code::POLICY);
                            break;
                        }
                        if !status_budget.admit(Instant::now()) { continue; }
                        let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        let verified_at = Instant::now();
                        let accepted = preconditions::record(&mut client, session, &state, report).await;
                        drop(client);
                        match accepted {
                            Ok(true) => session_checks.verified(verified_at),
                            Ok(false) => { close_with_code = Some(close_code::POLICY); break; },
                            Err(_) => { close_with_code = Some(RETRY_LATER); break; },
                        }
                    }
                    Some(ClientFrame::Heartbeat { v: 1 }) => {
                        let received_at = Instant::now();
                        let since_prior_accepted_ms = received_at.duration_since(last_heartbeat).as_millis();
                        match heartbeat_budget.admit(received_at) {
                            HeartbeatAction::Abuse => {
                                close_reason = "heartbeat_flood";
                                close_with_code = Some(close_code::POLICY);
                                break;
                            }
                            HeartbeatAction::AckFromMemory => {}
                            HeartbeatAction::Renew => {
                                let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
                                    close_with_code = Some(RETRY_LATER);
                                    break;
                                };
                                let verified_at = Instant::now();
                                if !renew_session(&client, session, &state).await.unwrap_or(false) {
                                    close_reason = "heartbeat_renew_failed_or_fenced";
                                    break;
                                }
                                drop(client);
                                session_checks.verified(verified_at);
                            }
                        }
                        last_heartbeat = Instant::now();
                        if !send_frame(&mut socket, ServerFrame::HeartbeatAck {
                            v: 1, connection_epoch: session.connection_epoch,
                        }).await {
                            close_reason = "heartbeat_ack_write_failed";
                            break;
                        }
                        if diagnostic && diagnostic_tally.record_heartbeat(since_prior_accepted_ms) {
                            eprintln!(
                                "{}",
                                stream_diagnostic::StreamTally::heartbeat_line(
                                    session.connection_epoch,
                                    since_prior_accepted_ms,
                                    received_at.elapsed().as_millis(),
                                )
                            );
                        }
                    }
                    Some(ClientFrame::AlphaReady { v: 1, connection_epoch, recipient_digest })
                        if connection_epoch == session.connection_epoch && !alpha_ready_used && state.dispatch_runtime_enabled =>
                    {
                        let Ok(bytes) = URL_SAFE_NO_PAD.decode(recipient_digest.as_bytes()) else { break; };
                        let Ok(digest): Result<[u8; 32], _> = bytes.try_into() else { break; };
                        let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        if URL_SAFE_NO_PAD.encode(digest) != recipient_digest
                            || !state.alpha_policy.allows_recipient_digest(session.account_id, &digest)
                            || !session_current(&client, session, &state).await.unwrap_or(false)
                        { break; }
                        alpha_ready = Some((digest, Instant::now()));
                        alpha_ready_used = true;
                    }
                    // The grant is strictly solicited (#438): only an armed
                    // debug build that names this session and an allowlisted
                    // recipient digest receives one, at most once per
                    // connection. Old and release clients never send this
                    // frame, so they never receive a grant.
                    Some(ClientFrame::MmsSpikeReady { v: 1, connection_epoch, recipient_digest })
                        if connection_epoch == session.connection_epoch && !mms_spike_ready_used =>
                    {
                        mms_spike_ready_used = true;
                        let Ok(bytes) = URL_SAFE_NO_PAD.decode(recipient_digest.as_bytes()) else { break; };
                        let Ok(digest): Result<[u8; 32], _> = bytes.try_into() else { break; };
                        if URL_SAFE_NO_PAD.encode(digest) != recipient_digest {
                            break;
                        }
                        let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        if !session_current(&client, session, &state).await.unwrap_or(false) {
                            break;
                        }
                        match mms_spike_grant_if_due(&client, session, &state, &digest).await {
                            Ok(Some(frame)) => {
                                if !send_frame(&mut socket, frame).await {
                                    break;
                                }
                            }
                            // A ready frame that cannot yield a grant — wrong
                            // digest, unnamed device, stopped recipient, spent
                            // one-use budget, or the feature off — is refused
                            // outright rather than silently ignored, so the
                            // phone learns and the once-per-connection flag is
                            // never stranded.
                            Ok(None) => {
                                close_with_code = Some(close_code::POLICY);
                                break;
                            }
                            Err(_) => {
                                close_with_code = Some(RETRY_LATER);
                                break;
                            }
                        }
                    }
                    // A second or malformed mms_spike_ready (the per-request
                    // flag is spent, or the epoch does not match this
                    // session) is a policy refusal, not a silent skip.
                    Some(ClientFrame::MmsSpikeReady { .. }) => {
                        close_with_code = Some(close_code::POLICY);
                        break;
                    }
                    Some(ClientFrame::RadioEvent {
                        v: 1, connection_epoch, event_id, message_id, attempt_id,
                        evidence, observed_at_ms, segment_index, segment_count,
                    }) if connection_epoch == session.connection_epoch => {
                        let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        if !session_current(&client, session, &state).await.unwrap_or(false) {
                            break;
                        }
                        if matches!(evidence, RadioEvidence::DurableSubmitIntent) {
                            let (current_grant, previous_intent) = match durable_intent_preflight(
                                &client, session, event_id, message_id, attempt_id, &state,
                            ).await {
                                Ok((grant, intent)) => {
                                    let grant = grant && conversation_execution_current(
                                        &mut client, session, &state, conversation_session.as_ref(), message_id, attempt_id,
                                    ).await.unwrap_or(false);
                                    (Some(grant), Some(intent))
                                },
                                Err(_) => (None, None),
                            };
                            if let Some(code) = durable_intent_preflight_close_code(
                                current_grant, previous_intent)
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
                                .unwrap_or(false)
                            && conversation_execution_current(
                                &mut client, session, &state, conversation_session.as_ref(), message_id, attempt_id,
                            ).await.unwrap_or(false);
                        drop(client);
                        if !send_frame(&mut socket, ServerFrame::RadioEventAck {
                            v: 1, event_id, state: next, submit_permitted,
                        }).await { break; }
                    }
                    Some(ClientFrame::InboundEvent {
                        v: 1, connection_epoch, event_id, sequence, message_id,
                        attempt_id, classification, observed_at_ms, part_count, signature_der,
                        device_sent_at_ms,
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
                        let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        let outcome = match inbound::ingest_with_clock(
                            &mut client, inbound_session, &event, device_sent_at_ms,
                        ).await {
                            Ok(outcome) => outcome,
                            Err(error) => {
                                close_with_code = Some(inbound_evidence_close_code(&error));
                                break;
                            }
                        };
                        drop(client);
                        if !send_frame(&mut socket, ServerFrame::InboundEventAck {
                            v: 1, event_id,
                            created: outcome.created,
                            queued_deliveries: outcome.queued_deliveries,
                            suppression_cleared: outcome.suppression_cleared,
                        }).await { break; }
                    }
                    Some(ClientFrame::LineOptOut {
                        v: 1, connection_epoch, event_id, sequence, line_id,
                        binding_generation, action, recipient_e164, observed_at_ms,
                        signature_der,
                    }) => {
                        if !state.line_opt_out_enabled || connection_epoch != session.connection_epoch {
                            close_with_code = Some(close_code::POLICY);
                            break;
                        }
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
                        let event = LineOptOut {
                            id: event_id, line_id, binding_generation, sequence,
                            recipient_e164: &recipient_e164, action: action.into(),
                            observed_at_ms, signature_der: &signature,
                        };
                        let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        let created = match unsolicited::ingest_line_opt_out(
                            &mut client, inbound_session, &event,
                        ).await {
                            Ok(created) => created,
                            Err(error) => {
                                close_with_code = Some(line_opt_out_close_code(&error));
                                break;
                            }
                        };
                        drop(client);
                        if !send_frame(&mut socket, ServerFrame::LineOptOutAck {
                            v: 1, event_id, created,
                        }).await { break; }
                    }
                    Some(ClientFrame::SmsLineProof {
                        v: 1, connection_epoch, challenge_id, android_api_level,
                        active_subscription_count, selected_subscription_id, signature_der,
                    }) => {
                        if !state.sms_line_activation_enabled || connection_epoch != session.connection_epoch {
                            close_with_code = Some(close_code::POLICY);
                            break;
                        }
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
                        let proof = exchange::DeviceProof {
                            challenge_id,
                            observation: SimObservation {
                                android_api_level,
                                active_subscription_count,
                                selected_subscription_id,
                            },
                            signature_der: &signature,
                        };
                        let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                            close_with_code = Some(RETRY_LATER);
                            break;
                        };
                        let accepted = match exchange::record_device_proof(
                            &mut client, inbound_session, proof,
                        ).await {
                            Ok(accepted) => accepted,
                            Err(_) => {
                                close_with_code = Some(RETRY_LATER);
                                break;
                            }
                        };
                        drop(client);
                        if !send_frame(&mut socket, ServerFrame::SmsLineProofAck {
                            v: 1, challenge_id, accepted,
                        }).await { break; }
                    }
                    _ => break,
                }
            }
            _ = tokio::time::sleep_until(session_checks.due().into()) => {
                if last_heartbeat.elapsed() > HEARTBEAT_DEADLINE {
                    close_reason = "heartbeat_deadline";
                    break;
                }
                let Ok(client) = runtime_db::connect_device(&state.database_url).await else {
                    close_with_code = Some(RETRY_LATER);
                    break;
                };
                let verified_at = Instant::now();
                if !session_current(&client, session, &state).await.unwrap_or(false) {
                    close_reason = "session_check_failed_or_fenced";
                    break;
                }
                session_checks.verified(verified_at);
            }
            _ = dispatch_checks.tick(), if alpha_ready.is_some() => {
                let Some((recipient_digest, armed_at)) = alpha_ready else { continue; };
                if armed_at.elapsed() > Duration::from_secs(ALPHA_READY_SECONDS) {
                    alpha_ready = None;
                    continue;
                }
                if last_grant_at.is_some_and(|at| at.elapsed() < Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS)) {
                    continue;
                }
                let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
                    close_with_code = Some(RETRY_LATER);
                    break;
                };
                let verified_at = Instant::now();
                if !session_current(&client, session, &state).await.unwrap_or(false) {
                    break;
                }
                session_checks.verified(verified_at);
                let grant = poll_synthetic_grant(&mut client, session, &state, &recipient_digest).await;
                drop(client);
                match grant {
                    Ok(Some(frame)) => {
                        alpha_ready = None;
                        if !send_frame(&mut socket, frame).await { break; }
                        last_grant_at = Some(Instant::now());
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep_until(sms_line_next_poll), if state.sms_line_activation_enabled => {
                let inbound_session = InboundSession {
                    account_id: session.account_id,
                    device_id: session.device_id,
                    site_id: &state.site_id,
                    instance_id: &state.instance_id,
                    connection_epoch: session.connection_epoch,
                    deployment_epoch: state.deployment_epoch,
                };
                // Retire finished exchanges on the first poll and about once a minute.
                let retire = sms_line_last_retire.is_none_or(|at| at.elapsed() >= SMS_LINE_RETIRE_INTERVAL);
                if retire {
                    sms_line_last_retire = Some(Instant::now());
                }
                match push_sms_line_frames(&mut socket, &state.database_url, inbound_session,
                    &mut sms_line_acks_sent, retire).await {
                    None => {
                        close_reason = "sms_line_push_failed";
                        close_with_code = Some(RETRY_LATER);
                        break;
                    }
                    Some(pushed) => {
                        // An open exchange keeps the fast cadence; an idle
                        // socket settles into the slow poll.
                        sms_line_next_poll =
                            tokio::time::Instant::now() + sms_line_poll_delay(pushed);
                    }
                }
            },
            // The owner just opened a challenge: poll now instead of waiting
            // for the idle cadence.
            _ = SMS_LINE_CHALLENGE_WAKE.notified(), if state.sms_line_activation_enabled => {
                sms_line_next_poll = tokio::time::Instant::now();
            },
            _ = state.drain_notify.notified() => {
                close_reason = "site_drain";
                break;
            },
            // A newer socket for this device took the slot; claim_session
            // has fenced or is about to fence this epoch, so stop now.
            _ = session_slot.superseded.notified() => {
                close_reason = "superseded";
                break;
            },
        }
    }
    if diagnostic {
        eprintln!(
            "{}",
            diagnostic_tally.close_line(
                close_reason,
                session.connection_epoch,
                last_heartbeat.elapsed(),
                Instant::now(),
            )
        );
    }
    release_socket_session(&state, session).await;
    let _ = socket
        .send(Message::Close(close_with_code.map(|code| CloseFrame {
            code,
            reason: "".into(),
        })))
        .await;
}

async fn release_socket_session(state: &DeviceSocketState, session: DeviceSession) {
    // Best effort: if storage is unavailable the bounded session lease expires.
    if let Ok(client) = runtime_db::connect_device(&state.database_url).await {
        let _ = release_session(&client, session).await;
    }
}

/// Pushes at most one pending SMS line challenge and one activation
/// acknowledgement. A challenge is marked pushed only after its frame was
/// written; an acknowledgement repeats on each new connection until retired.
/// Returns None when the socket must close, otherwise whether anything was
/// pushed, so the caller keeps the fast cadence only for open exchanges.
/// Both reads share one pooled client; the challenge-push write re-checks
/// out only after its frame was written.
async fn push_sms_line_frames(
    socket: &mut WebSocket,
    database_url: &str,
    session: InboundSession<'_>,
    acks_sent: &mut Vec<Uuid>,
    retire: bool,
) -> Option<bool> {
    let client = runtime_db::connect_device(database_url).await.ok()?;
    let retired = if retire {
        exchange::retire(&client, session, exchange::ACK_RESEND_SECONDS)
            .await
            .is_ok()
    } else {
        true
    };
    if !retired {
        return None;
    }
    let challenge = exchange::next_challenge(&client, session).await.ok()?;
    let ack = if acks_sent.len() >= MAX_SMS_LINE_ACKS_PER_CONNECTION {
        None
    } else {
        exchange::next_ack(&client, session, acks_sent).await.ok()?
    };
    drop(client);
    let mut pushed = false;
    if let Some(challenge) = challenge {
        let frame = ServerFrame::SmsLineChallenge {
            v: 1,
            challenge_id: challenge.challenge_id,
            account_id: challenge.account_id,
            line_id: challenge.line_id,
            device_id: challenge.device_id,
            generation: challenge.generation,
            nonce: URL_SAFE_NO_PAD.encode(challenge.nonce),
            expires_at_ms: challenge.expires_at_ms,
        };
        if !send_frame(socket, frame).await {
            return None;
        }
        pushed = true;
        let client = runtime_db::connect_device(database_url).await.ok()?;
        if exchange::mark_challenge_pushed(&client, session, challenge.challenge_id)
            .await
            .is_err()
        {
            return None;
        }
    }
    if let Some(ack) = ack {
        let frame = ServerFrame::SmsLineActivated {
            v: 1,
            challenge_id: ack.challenge_id,
            account_id: ack.account_id,
            line_id: ack.line_id,
            device_id: ack.device_id,
            generation: ack.generation,
            device_statement_sha256: URL_SAFE_NO_PAD.encode(ack.device_statement_sha256),
            device_signature_sha256: URL_SAFE_NO_PAD.encode(ack.device_signature_sha256),
        };
        if !send_frame(socket, frame).await {
            return None;
        }
        acks_sent.push(ack.challenge_id);
        pushed = true;
    }
    Some(pushed)
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

async fn conversation_execution_current(
    client: &mut Client,
    session: DeviceSession,
    state: &DeviceSocketState,
    negotiated: Option<&conversation::Negotiated>,
    message: Uuid,
    attempt: Uuid,
) -> Result<bool, crate::http_owner_conversations::ConversationError> {
    let row = client
        .query_opt(
            "SELECT transport_mode FROM messages WHERE account_id=$1 AND id=$2 AND device_id=$3",
            &[&session.account_id, &message, &session.device_id],
        )
        .await?;
    match row.map(|r| r.get::<_, String>(0)).as_deref() {
        Some("synthetic_alpha") => Ok(true),
        Some("sealed_candidate02") => match negotiated {
            Some(held) => {
                held.execution_current(client, session, state, message, attempt)
                    .await
            }
            None => Ok(false),
        },
        _ => Ok(false),
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

/// Before recording a durable submit intent: whether the grant is still
/// current (exactly [`grant_still_current`]), and whether this exact intent
/// event was already recorded for this device's attempt (an idempotent
/// replay). One statement answers both.
async fn durable_intent_preflight(
    client: &Client,
    session: DeviceSession,
    event_id: Uuid,
    message_id: Uuid,
    attempt_id: Uuid,
    state: &DeviceSocketState,
) -> Result<(bool, bool), tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM dispatch_fences f JOIN deployment_authority a ON a.singleton=TRUE \
              WHERE f.account_id=$1 AND f.device_id=$2 AND f.message_id=$3 AND f.attempt_id=$4 \
              AND f.session_epoch=$5 AND f.deployment_epoch=$6 AND f.grant_expires_at>now() \
              AND f.outcome IN ('granted','submitting') AND a.epoch=$6 AND a.dispatch_enabled=TRUE), \
             EXISTS(SELECT 1 FROM message_events e JOIN message_attempts a ON a.id=e.attempt_id \
              WHERE e.id=$7 AND e.account_id=$1 AND e.message_id=$3 AND e.attempt_id=$4 \
              AND a.device_id=$2 AND e.evidence_code='durable_intent')",
            &[
                &session.account_id,
                &session.device_id,
                &message_id,
                &attempt_id,
                &session.connection_epoch,
                &state.deployment_epoch,
                &event_id,
            ],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

/// One-statement pre-claim filter for an armed dispatch tick; see
/// [`DeliveryStore::synthetic_grant_may_be_due`].
async fn grant_may_be_due(
    client: &mut Client,
    session: DeviceSession,
    state: &DeviceSocketState,
) -> Result<bool, StoreError> {
    DeliveryStore::new(client)
        .synthetic_grant_may_be_due(
            session.account_id,
            session.device_id,
            state.deployment_epoch,
            MIN_SECONDS_BETWEEN_GRANTS as i32,
        )
        .await
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
    if !grant_may_be_due(client, session, state).await? {
        return Ok(None);
    }
    let worker_id = format!(
        "{}:{}:{}",
        state.instance_id, session.device_id, session.connection_epoch
    );
    // The claim transaction returns the message content, so it is read once:
    // policy is applied here, and the same content is released only after
    // the grant is confirmed below.
    let Some((claim, content)) = DeliveryStore::new(client)
        .claim_synthetic_for_device_and_recipient(
            &worker_id,
            session.account_id,
            session.device_id,
            recipient_digest,
        )
        .await?
    else {
        return Ok(None);
    };
    let content = content.ok_or(StoreError::StaleFence)?;
    let recipient = content.recipient_e164;
    let body = String::from_utf8(content.transport_payload).ok();
    let permitted = content.transport_mode == "synthetic_alpha"
        && state.alpha_policy.allows(claim.account_id, &recipient)
        && body.as_deref().is_some_and(synthetic_body_is_fixed);
    let (true, Some(body)) = (permitted, body) else {
        DeliveryStore::new(client)
            .cancel(claim.account_id, claim.message_id)
            .await?;
        return Ok(None);
    };
    let mut store = DeliveryStore::new(client);
    let record = store_session(session, state);
    let grant = match store.issue_grant(&claim, &record, Uuid::new_v4()).await {
        Ok(grant) => grant,
        Err(
            StoreError::DeviceBusy | StoreError::DispatchDisabled | StoreError::RecipientSuppressed,
        ) => return Ok(None),
        Err(error) => return Err(error),
    };
    // Defense in depth after the grant commits: re-check the fence, message,
    // device, session, site and authority without re-reading content, then
    // bind the claimed recipient to the digest issue_grant read under lock.
    store.confirm_synthetic_grant(&grant, &record).await?;
    if grant.recipient_digest.as_slice() != Sha256::digest(recipient.as_bytes()).as_slice()
        || grant.recipient_digest.as_slice() != recipient_digest
        || grant.expires_at_ms <= now_ms()
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(Some(grant_frame(grant, recipient, body)))
}

/// Build the solicited MMS spike grant for this session (#438). Called only
/// from the `mms_spike_ready` handler: `digest` must name an allowlisted
/// recipient for the founder-named device, that recipient must pass the STOP
/// check (no active suppression, no unreleased owner hold; any doubt fails
/// closed), and the server-side one-use budget for this device and recipient
/// must still be open. Any doubt or storage error withholds the grant.
async fn mms_spike_grant_if_due(
    client: &tokio_postgres::Client,
    session: DeviceSession,
    state: &DeviceSocketState,
    digest: &[u8; 32],
) -> Result<Option<ServerFrame>, tokio_postgres::Error> {
    if state.mms_spike_policy.gated_device() != Some(session.device_id) {
        return Ok(None);
    }
    for recipient in state.mms_spike_policy.recipients() {
        if Sha256::digest(recipient.as_bytes()).as_slice() != &digest[..] {
            continue;
        }
        let stopped: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM recipient_suppressions \
                 WHERE account_id=$1 AND recipient_e164=$2 AND active) \
                 OR EXISTS(SELECT 1 FROM owner_recipient_holds \
                 WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL)",
                &[&session.account_id, &recipient],
            )
            .await?
            .get(0);
        if stopped {
            return Ok(None);
        }
        // Server-side one-use: the subject budget allows a single grant for
        // this device and recipient, so a replayed or repeated ready frame
        // cannot obtain a second grant even across instances or reconnects.
        let subject = format!("{}:{}", session.device_id, recipient);
        if !abuse_limits::consume(
            client,
            &state.auth_hasher,
            abuse_limits::Limit::MmsSpikeGrant,
            Some(&subject),
        )
        .await?
        {
            return Ok(None);
        }
        return Ok(Some(ServerFrame::MmsSpikeGrant {
            v: 1,
            grant_id: Uuid::new_v4(),
            device_id: session.device_id,
            connection_epoch: session.connection_epoch,
            recipient_digest: URL_SAFE_NO_PAD.encode(Sha256::digest(recipient.as_bytes())),
            expires_at_ms: now_ms() + mms_spike_policy::MMS_SPIKE_GRANT_TTL_MS,
            recipient_e164: recipient.to_string(),
        }));
    }
    Ok(None)
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
    Ok(client.query_typed_opt(
        "SELECT 1 FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery()",
        &[(&session.account_id, Type::UUID), (&session.device_id, Type::UUID),
          (&state.site_id, Type::TEXT), (&state.instance_id, Type::TEXT),
          (&session.connection_epoch, Type::INT8), (&state.deployment_epoch, Type::INT8)],
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
    Ok(client.execute_typed(
        "UPDATE device_sessions s SET lease_until=now()+($7::integer * interval '1 second') WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND EXISTS (SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=$3 JOIN deployment_authority p ON p.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery())",
        &[(&session.account_id, Type::UUID), (&session.device_id, Type::UUID),
          (&state.site_id, Type::TEXT), (&state.instance_id, Type::TEXT),
          (&session.connection_epoch, Type::INT8), (&state.deployment_epoch, Type::INT8),
          (&SESSION_LEASE_SECONDS, Type::INT4)],
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
mod line_opt_out_wire_tests;
#[cfg(test)]
mod virtual_inbound_tests;
#[cfg(test)]
mod virtual_line_opt_out_tests;
#[cfg(test)]
mod sms_line_cadence_tests {
    use super::*;

    #[test]
    fn idle_activation_polls_are_ten_times_slower_than_active_ones() {
        assert_eq!(sms_line_poll_delay(true), Duration::from_secs(3));
        assert_eq!(sms_line_poll_delay(false), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn a_new_owner_challenge_wakes_waiting_device_sockets() {
        let woke = tokio::sync::oneshot::channel();
        let (sender, receiver) = woke;
        tokio::spawn(async move {
            SMS_LINE_CHALLENGE_WAKE.notified().await;
            let _ = sender.send(());
        });
        // The spawned task must register its waiter before the wake fires.
        tokio::time::sleep(Duration::from_millis(20)).await;
        wake_sms_line_activation();
        tokio::time::timeout(Duration::from_secs(1), receiver)
            .await
            .expect("waiting socket was not woken")
            .expect("wake sender dropped");
    }
}

#[cfg(test)]
mod virtual_sms_line_activation_tests;

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
