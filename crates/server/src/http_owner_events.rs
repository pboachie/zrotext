// SPDX-License-Identifier: AGPL-3.0-only
//! Same-origin live-update stream for the owner dashboard.
//!
//! Each authenticated owner session may hold one server-sent-events stream
//! that signals when the tenant-scoped device or message state rendered by the
//! dashboard changes. The stream is a change signal, not a data source: the
//! client re-fetches the existing snapshot endpoints, which stay
//! authoritative. Every poll re-authenticates the session and compares a
//! fingerprint of the same first snapshot pages the dashboard renders, so a
//! revoked or expired session, or an unavailable database, ends the stream and
//! the dashboard falls back to its periodic snapshot refresh. There is no
//! in-process broadcast channel to tap because every dashboard observation is
//! derived from PostgreSQL, which may be written by another hub instance.
//!
//! Streams share the request-class database pool with every other owner and
//! API request, so they are admitted through [`OwnerStreamLimits`]: one open
//! stream per session, a small number per account, and a small number per
//! process. A refused stream gets an ordinary error status and the dashboard
//! keeps its periodic snapshot refresh. Each poll runs only bounded queries:
//! the first device snapshot page (whose queue counts are already capped) and
//! the first message timeline page, both through tenant-leading indexes.

use crate::{
    auth::TokenHasher,
    enrollment::{OWNER_DEVICE_PAGE_SIZE, OWNER_DEVICE_QUEUE_LIMIT, OWNER_DEVICE_STATUS_QUERY},
    http_auth::require_owner,
};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};
use tokio_postgres::Client;
use uuid::Uuid;

/// Fingerprint cadence. One event stream therefore emits at most one change
/// signal per section per interval, however busy the tenant is.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Streams end after this long so connections cannot accumulate indefinitely;
/// the client reconnects. Keepalive comments below keep proxies from closing
/// the stream earlier as idle.
const MAX_STREAM_LIFETIME: Duration = Duration::from_secs(10 * 60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Several signed-in browsers of one account may stream; further tabs fall
/// back to the periodic snapshot refresh.
pub const MAX_STREAMS_PER_ACCOUNT: usize = 3;
/// Bounds this process's total polling load on the shared request pool
/// (16 request-class sockets), whatever the number of tenants.
pub const MAX_STREAMS_PER_PROCESS: usize = 32;
/// Refusals are retried by the dashboard with capped backoff; this is a hint.
const REFUSED_RETRY_AFTER_SECS: &str = "60";

#[derive(Clone)]
pub struct OwnerEventsState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    /// Shared by every router built from this state; one per process.
    pub stream_limits: Arc<OwnerStreamLimits>,
}

pub fn router(state: OwnerEventsState) -> Router {
    Router::new()
        .route("/owner/events", get(events))
        .with_state(Arc::new(state))
}

/// In-process admission for owner event streams. A permit is held for the
/// whole life of a stream and released when the stream ends for any reason:
/// lifetime expiry, session revocation or expiry, a database error, or the
/// client disconnecting (the response body, and with it the permit, is
/// dropped once a write fails; a comment frame is written every poll).
pub struct OwnerStreamLimits {
    per_account: usize,
    per_process: usize,
    open: Mutex<OpenStreams>,
}

#[derive(Default)]
struct OpenStreams {
    sessions: HashSet<Uuid>,
    accounts: HashMap<Uuid, usize>,
    total: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamRefusal {
    /// This session already holds an open stream.
    SessionStreamOpen,
    /// The account already holds [`MAX_STREAMS_PER_ACCOUNT`] streams.
    AccountLimit,
    /// The process already holds [`MAX_STREAMS_PER_PROCESS`] streams.
    ProcessLimit,
}

impl StreamRefusal {
    fn status(self) -> StatusCode {
        match self {
            Self::SessionStreamOpen => StatusCode::CONFLICT,
            Self::AccountLimit => StatusCode::TOO_MANY_REQUESTS,
            Self::ProcessLimit => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for StreamRefusal {
    fn into_response(self) -> Response {
        (
            self.status(),
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::RETRY_AFTER, REFUSED_RETRY_AFTER_SECS),
            ],
        )
            .into_response()
    }
}

impl Default for OwnerStreamLimits {
    fn default() -> Self {
        Self::new(MAX_STREAMS_PER_ACCOUNT, MAX_STREAMS_PER_PROCESS)
    }
}

impl OwnerStreamLimits {
    pub fn new(per_account: usize, per_process: usize) -> Self {
        Self {
            per_account,
            per_process,
            open: Mutex::new(OpenStreams::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, OpenStreams> {
        // The critical sections cannot leave the counts half-updated, so a
        // poisoned lock still holds consistent state.
        self.open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn admit(
        self: &Arc<Self>,
        account_id: Uuid,
        session_id: Uuid,
    ) -> Result<StreamPermit, StreamRefusal> {
        let mut open = self.lock();
        if open.sessions.contains(&session_id) {
            return Err(StreamRefusal::SessionStreamOpen);
        }
        if open.accounts.get(&account_id).copied().unwrap_or(0) >= self.per_account {
            return Err(StreamRefusal::AccountLimit);
        }
        if open.total >= self.per_process {
            return Err(StreamRefusal::ProcessLimit);
        }
        open.sessions.insert(session_id);
        *open.accounts.entry(account_id).or_insert(0) += 1;
        open.total += 1;
        Ok(StreamPermit {
            limits: self.clone(),
            account_id,
            session_id,
        })
    }

    /// Streams currently holding a permit in this process.
    pub fn open_streams(&self) -> usize {
        self.lock().total
    }
}

/// Released on drop, so every stream exit path returns its capacity.
pub struct StreamPermit {
    limits: Arc<OwnerStreamLimits>,
    account_id: Uuid,
    session_id: Uuid,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut open = self.limits.lock();
        open.sessions.remove(&self.session_id);
        if let Some(count) = open.accounts.get_mut(&self.account_id) {
            *count -= 1;
            if *count == 0 {
                open.accounts.remove(&self.account_id);
            }
        }
        open.total -= 1;
    }
}

/// One rendered row of the first device snapshot page. The snapshot's
/// observation timestamp is left out because it changes on every read.
#[derive(Clone, PartialEq, Eq)]
struct DeviceRow {
    id: Uuid,
    display_name: String,
    revoked: bool,
    active_socket_lease: bool,
    pending_messages: i64,
    in_flight_messages: i64,
    report_selected_sim: Option<String>,
    report_sms_permission: Option<String>,
    report_airplane_mode: Option<String>,
    report_network_service: Option<String>,
    report_received_at_ms: Option<i64>,
    report_fresh: Option<bool>,
}

/// One row of the first message timeline page. Every writer state change
/// also bumps `messages.updated_at` in the same transaction as its
/// `message_events` row, so this covers list membership and timeline growth.
#[derive(Clone, PartialEq, Eq)]
struct MessageRow {
    id: Uuid,
    state: String,
    updated_at: SystemTime,
}

#[derive(Clone, PartialEq, Eq)]
struct TenantFingerprint {
    devices: Vec<DeviceRow>,
    messages: Vec<MessageRow>,
}

/// The first page of the message timeline plus its has-more probe, in the
/// timeline's order, through `messages_account_created`.
const MESSAGE_PAGE_SQL: &str = "SELECT id,state,updated_at FROM messages WHERE account_id=$1 \
     ORDER BY created_at DESC,id DESC LIMIT $2";

/// Reads the same bounded first pages as the device and message snapshots:
/// at most `OWNER_DEVICE_PAGE_SIZE + 1` devices whose queue counts are capped
/// at `OWNER_DEVICE_QUEUE_LIMIT`, and at most a message page plus one row.
/// Later pages are only shown while the owner browses them, which pauses
/// automatic refresh of that list anyway.
async fn fingerprint(
    client: &Client,
    account_id: Uuid,
) -> Result<TenantFingerprint, tokio_postgres::Error> {
    let before: Option<Uuid> = None;
    let devices = client
        .query(
            OWNER_DEVICE_STATUS_QUERY,
            &[
                &account_id,
                &before,
                &((OWNER_DEVICE_PAGE_SIZE + 1) as i64),
                &OWNER_DEVICE_QUEUE_LIMIT,
            ],
        )
        .await?
        .iter()
        .map(|row| DeviceRow {
            id: row.get(0),
            display_name: row.get(1),
            revoked: row.get(2),
            active_socket_lease: row.get(3),
            pending_messages: row.get(4),
            in_flight_messages: row.get(5),
            report_selected_sim: row.get("report_selected_sim"),
            report_sms_permission: row.get("report_sms_permission"),
            report_airplane_mode: row.get("report_airplane_mode"),
            report_network_service: row.get("report_network_service"),
            report_received_at_ms: row.get("report_received_at_ms"),
            report_fresh: row.get("report_fresh"),
        })
        .collect();
    let messages = client
        .query(
            MESSAGE_PAGE_SQL,
            &[
                &account_id,
                &((crate::http_owner_messages::PAGE_SIZE + 1) as i64),
            ],
        )
        .await?
        .iter()
        .map(|row| MessageRow {
            id: row.get(0),
            state: row.get(1),
            updated_at: row.get(2),
        })
        .collect();
    Ok(TenantFingerprint { devices, messages })
}

#[derive(Serialize)]
struct ChangedEvent {
    changed: Vec<&'static str>,
    observed_at_ms: u64,
}

fn unix_ms(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Per-stream state carried through the stream steps. Dropping it (the
/// stream ended or its response body was dropped) releases the permit.
struct Watch {
    account_id: Uuid,
    session_id: Uuid,
    ends_at: tokio::time::Instant,
    next_poll: tokio::time::Instant,
    previous: TenantFingerprint,
    _permit: StreamPermit,
}

async fn events(State(state): State<Arc<OwnerEventsState>>, headers: HeaderMap) -> Response {
    // Authenticate, take a stream permit and capture the baseline fingerprint
    // before streaming, so failures and refusals return ordinary statuses.
    let watch = match open_watch(&state, &headers).await {
        Ok(watch) => watch,
        Err(response) => return response,
    };
    let stream = futures_util::stream::unfold(watch, move |mut watch| {
        let state = state.clone();
        let headers = headers.clone();
        async move {
            tokio::select! {
                _ = tokio::time::sleep_until(watch.next_poll) => {}
                _ = tokio::time::sleep_until(watch.ends_at) => return None,
            }
            watch.next_poll = tokio::time::Instant::now() + POLL_INTERVAL;
            // Each poll checks out a pooled client instead of holding one for
            // the stream's lifetime, so an idle dashboard tab never occupies a
            // request-slot between polls. Any failure ends the stream; the
            // client falls back to snapshot refresh and reconnects later.
            let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
                return None;
            };
            let Ok(principal) = require_owner(
                &client,
                &state.auth_hasher,
                &state.canonical_origin,
                &headers,
                false,
            )
            .await
            else {
                return None;
            };
            if principal.tenant.account_id() != watch.account_id
                || principal.session_id != watch.session_id
            {
                return None;
            }
            let Ok(observed) = fingerprint(&client, watch.account_id).await else {
                return None;
            };
            drop(client);
            let mut changed: Vec<&'static str> = Vec::new();
            if watch.previous.devices != observed.devices {
                changed.push("devices");
            }
            if watch.previous.messages != observed.messages {
                changed.push("messages");
            }
            watch.previous = observed;
            let event = if changed.is_empty() {
                // A comment keeps intermediate polls invisible to clients and
                // makes a disconnected client's write fail promptly.
                Event::default().comment("polled")
            } else {
                let payload = ChangedEvent {
                    changed,
                    observed_at_ms: unix_ms(SystemTime::now()),
                };
                Event::default()
                    .event("changed")
                    .data(serde_json::to_string(&payload).expect("serializable change event"))
            };
            Some((Ok::<_, std::convert::Infallible>(event), watch))
        }
    });
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(KEEPALIVE_INTERVAL)
                .text("keepalive"),
        )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn open_watch(state: &OwnerEventsState, headers: &HeaderMap) -> Result<Watch, Response> {
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response()
    };
    let client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| unavailable())?;
    let principal = require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        headers,
        false,
    )
    .await
    .map_err(|error| error.into_response())?;
    let account_id = principal.tenant.account_id();
    // Admission precedes the baseline query, so a refused stream costs only
    // the session check. The permit drops with any early return below.
    let permit = state
        .stream_limits
        .admit(account_id, principal.session_id)
        .map_err(IntoResponse::into_response)?;
    let baseline = fingerprint(&client, account_id)
        .await
        .map_err(|_| unavailable())?;
    let now = tokio::time::Instant::now();
    Ok(Watch {
        account_id,
        session_id: principal.session_id,
        ends_at: now + MAX_STREAM_LIFETIME,
        next_poll: now + POLL_INTERVAL,
        previous: baseline,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests;
