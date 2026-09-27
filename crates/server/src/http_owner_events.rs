// SPDX-License-Identifier: AGPL-3.0-only
//! Same-origin live-update stream for the owner dashboard.
//!
//! Each authenticated owner session may hold one server-sent-events stream
//! that signals when the tenant-scoped device or message state rendered by the
//! dashboard changes. The stream is a change signal, not a data source: the
//! client re-fetches the existing snapshot endpoints, which stay
//! authoritative. Every poll re-authenticates the session and compares a
//! cheap fingerprint of the same tenant state the snapshots render, so a
//! revoked or expired session, or an unavailable database, ends the stream and
//! the dashboard falls back to its periodic snapshot refresh. There is no
//! in-process broadcast channel to tap because every dashboard observation is
//! derived from PostgreSQL, which may be written by another hub instance.

use crate::{auth::TokenHasher, http_auth::require_owner};
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
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_postgres::Row;
use uuid::Uuid;

/// Fingerprint cadence. One event stream therefore emits at most one change
/// signal per section per interval, however busy the tenant is.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Streams end after this long so connections cannot accumulate indefinitely;
/// the client reconnects. Keepalive comments below keep proxies from closing
/// the stream earlier as idle.
const MAX_STREAM_LIFETIME: Duration = Duration::from_secs(10 * 60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct OwnerEventsState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerEventsState) -> Router {
    Router::new()
        .route("/owner/events", get(events))
        .with_state(Arc::new(state))
}

/// Aggregated tenant state behind the devices view. Per-device queue counts
/// move together with message states, so totals cover the visible change.
#[derive(Clone, PartialEq, Eq)]
struct DevicesFingerprint {
    devices: i64,
    revoked: i64,
    leased: i64,
    pending_messages: i64,
    in_flight_messages: i64,
    latest_precondition: Option<SystemTime>,
}

/// Aggregated tenant state behind the message timeline. Every writer state
/// change also bumps `messages.updated_at` in the same transaction as its
/// `message_events` row, so these two columns cover list membership and
/// timeline growth.
#[derive(Clone, PartialEq, Eq)]
struct MessagesFingerprint {
    messages: i64,
    latest_update: Option<SystemTime>,
}

#[derive(Clone, PartialEq, Eq)]
struct TenantFingerprint {
    devices: DevicesFingerprint,
    messages: MessagesFingerprint,
}

/// Mirrors the lease, revocation, queue and precondition semantics of the
/// enrollment device snapshot query, aggregated for the whole tenant.
const FINGERPRINT_SQL: &str = "SELECT \
  (SELECT count(*) FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) WHERE d.account_id=$1), \
  (SELECT count(*) FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
     WHERE d.account_id=$1 AND (d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL)), \
  (SELECT count(*) FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
     JOIN accounts a ON a.id=d.account_id \
     LEFT JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(d.account_id,d.id) \
     LEFT JOIN sites s ON s.site_id=ds.site_id \
     LEFT JOIN deployment_authority p ON p.singleton=TRUE \
     WHERE d.account_id=$1 AND COALESCE(d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL \
       AND ds.lease_until>now() AND ds.connection_epoch>0 \
       AND ds.deployment_epoch=p.epoch AND s.enabled=TRUE AND s.draining=FALSE \
       AND NOT pg_is_in_recovery(),FALSE)), \
  (SELECT count(*) FROM messages m WHERE m.account_id=$1 AND m.state IN ('accepted','queued','claimed')), \
  (SELECT count(*) FROM messages m WHERE m.account_id=$1 AND m.state IN ('submitting','submitted')), \
  (SELECT max(r.received_at) FROM device_preconditions r WHERE r.account_id=$1), \
  (SELECT count(*) FROM messages m WHERE m.account_id=$1), \
  (SELECT max(m.updated_at) FROM messages m WHERE m.account_id=$1)";

fn fingerprint(row: &Row) -> TenantFingerprint {
    TenantFingerprint {
        devices: DevicesFingerprint {
            devices: row.get(0),
            revoked: row.get(1),
            leased: row.get(2),
            pending_messages: row.get(3),
            in_flight_messages: row.get(4),
            latest_precondition: row.get(5),
        },
        messages: MessagesFingerprint {
            messages: row.get(6),
            latest_update: row.get(7),
        },
    }
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

/// Per-stream state carried through the stream steps.
struct Watch {
    account_id: Uuid,
    ends_at: tokio::time::Instant,
    next_poll: tokio::time::Instant,
    previous: Option<TenantFingerprint>,
}

async fn events(State(state): State<Arc<OwnerEventsState>>, headers: HeaderMap) -> Response {
    // Authenticate and capture the baseline fingerprint before streaming, so
    // connection failures return ordinary error statuses instead of a stream.
    let (account_id, baseline) = match observe(&state, &headers).await {
        Ok(observation) => observation,
        Err(response) => return response,
    };
    let now = tokio::time::Instant::now();
    let stream = futures_util::stream::unfold(
        Watch {
            account_id,
            ends_at: now + MAX_STREAM_LIFETIME,
            next_poll: now + POLL_INTERVAL,
            previous: Some(baseline),
        },
        move |mut watch| {
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
                if principal.tenant.account_id() != watch.account_id {
                    return None;
                }
                let Ok(row) = client
                    .query_one(FINGERPRINT_SQL, &[&watch.account_id])
                    .await
                else {
                    return None;
                };
                let observed = fingerprint(&row);
                let mut changed: Vec<&'static str> = Vec::new();
                if let Some(previous) = watch.previous.take() {
                    if previous.devices != observed.devices {
                        changed.push("devices");
                    }
                    if previous.messages != observed.messages {
                        changed.push("messages");
                    }
                }
                watch.previous = Some(observed);
                let event = if changed.is_empty() {
                    // A comment keeps intermediate polls invisible to clients.
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
        },
    );
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

async fn observe(
    state: &OwnerEventsState,
    headers: &HeaderMap,
) -> Result<(Uuid, TenantFingerprint), Response> {
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
    let row = client
        .query_one(FINGERPRINT_SQL, &[&account_id])
        .await
        .map_err(|_| unavailable())?;
    Ok((account_id, fingerprint(&row)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{TokenHasher, login, register, verify_email};
    use axum::{
        body::Body,
        http::{Method, Request, header},
    };
    use futures_util::StreamExt;
    use tokio_postgres::NoTls;
    use tower::ServiceExt;

    fn get(path: &str, token: Option<&str>) -> Request<Body> {
        let mut request = Request::builder().method(Method::GET).uri(path);
        if let Some(token) = token {
            request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
        }
        request.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn events_stream_fails_closed_without_a_database() {
        let app = router(OwnerEventsState {
            database_url: "postgres://unused".into(),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(9)).unwrap()),
            canonical_origin: "https://test.example".into(),
        });
        let response = app.oneshot(get("/owner/events", None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn stream_requires_a_session_and_signals_only_tenant_changes_until_it_ends() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("owner_events_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../deploy/compose/migrations/041_device_preconditions.sql"),
            include_str!("../../../deploy/compose/migrations/047_device_network_service.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap());
        let a = register(
            &mut db,
            &hasher,
            "events-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let b = register(
            &mut db,
            &hasher,
            "events-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        verify_email(&mut db, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut db, &hasher, &b.verification_token)
            .await
            .unwrap();
        let session_a = login(
            &db,
            &hasher,
            "events-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let session_b = login(
            &db,
            &hasher,
            "events-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'A'),($3,$4,'B')",
            &[&device_a, &a.account_id, &device_b, &b.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO device_keys(account_id,device_id,fingerprint,signing_key_sec1) \
             VALUES($1,$2,$3,$4),($5,$6,$7,$8)",
            &[
                &a.account_id,
                &device_a,
                &vec![9_u8; 32],
                &vec![7_u8; 65],
                &b.account_id,
                &device_b,
                &vec![8_u8; 32],
                &vec![6_u8; 65],
            ],
        )
        .await
        .unwrap();
        async fn insert_message(
            db: &tokio_postgres::Client,
            account: Uuid,
            device: Uuid,
            state: &str,
        ) -> Uuid {
            let id = Uuid::new_v4();
            db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
                &[&id, &account, &device, &vec![1_u8; 32],
                    &b"TENANT_NEVER_EXPOSED".as_slice(), &vec![2_u8; 32], &state],
            )
            .await
            .unwrap();
            id
        }
        let app = router(OwnerEventsState {
            database_url,
            auth_hasher: hasher,
            canonical_origin: "https://test.example".to_owned(),
        });

        let anonymous = app
            .clone()
            .oneshot(get("/owner/events", None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(get("/owner/events", Some(&session_a.token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        // Read frames as they arrive; the stream only ends when the session is
        // revoked, so guard every wait with a real-time timeout.
        let mut frames = response.into_body().into_data_stream();

        // A foreign tenant's message must not signal for account A: over at
        // least one poll cycle only comment frames may arrive.
        let _foreign = insert_message(&db, b.account_id, device_b, "queued").await;
        let mut saw_comment = false;
        let quiet_until = std::time::Instant::now() + Duration::from_secs(6);
        while std::time::Instant::now() < quiet_until {
            let Ok(Some(bytes)) = tokio::time::timeout(Duration::from_secs(6), frames.next()).await
            else {
                break;
            };
            let text = String::from_utf8_lossy(&bytes.unwrap()).into_owned();
            assert!(
                !text.contains("event: changed"),
                "foreign tenant activity signaled account A: {text}"
            );
            saw_comment |= text.contains(": polled");
        }
        assert!(saw_comment, "no poll frame arrived for the foreign insert");

        // A new message for account A signals the messages section.
        insert_message(&db, a.account_id, device_a, "queued").await;
        let mut saw_message_change = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !saw_message_change && std::time::Instant::now() < deadline {
            let Ok(Some(bytes)) = tokio::time::timeout(Duration::from_secs(5), frames.next()).await
            else {
                break;
            };
            let text = String::from_utf8_lossy(&bytes.unwrap()).into_owned();
            if text.contains("event: changed") {
                let payload = text.split("data: ").nth(1).unwrap_or_default();
                let value: serde_json::Value = serde_json::from_str(payload.trim()).unwrap();
                let changed = value["changed"].as_array().unwrap();
                assert!(
                    changed
                        .iter()
                        .all(|section| section == "devices" || section == "messages")
                );
                assert!(!payload.contains("+1555"));
                assert!(!payload.contains("TENANT_NEVER_EXPOSED"));
                saw_message_change = changed.iter().any(|s| s == "messages");
            }
        }
        assert!(saw_message_change, "no messages change event arrived");

        // Revoking the session ends the stream cleanly.
        db.execute(
            "UPDATE sessions SET revoked_at=now() WHERE account_id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(15), frames.next()).await;
        match ended {
            Ok(None) => {}
            Ok(Some(frame)) => panic!("expected stream end, got {frame:?}"),
            Err(_) => panic!("stream did not end after the session was revoked"),
        }

        // A revoked session cannot open a new stream.
        let refused = app
            .clone()
            .oneshot(get("/owner/events", Some(&session_a.token)))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        // The other owner keeps a valid session.
        let b_response = app
            .oneshot(get("/owner/events", Some(&session_b.token)))
            .await
            .unwrap();
        assert_eq!(b_response.status(), StatusCode::OK);
        drop(b_response.into_body());
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
