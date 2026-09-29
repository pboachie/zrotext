// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{TokenHasher, login, register, verify_email};
use axum::{
    body::{Body, BodyDataStream},
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
    let limits = Arc::new(OwnerStreamLimits::default());
    let app = router(OwnerEventsState {
        database_url: "postgres://unused".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(9)).unwrap()),
        canonical_origin: "https://test.example".into(),
        stream_limits: limits.clone(),
    });
    let response = app.oneshot(get("/owner/events", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(limits.open_streams(), 0);
}

#[test]
fn second_stream_for_the_same_session_is_refused_until_the_first_is_released() {
    let limits = Arc::new(OwnerStreamLimits::new(3, 32));
    let (account, session) = (Uuid::new_v4(), Uuid::new_v4());
    let first = limits.admit(account, session).unwrap();
    assert_eq!(
        limits.admit(account, session).err(),
        Some(StreamRefusal::SessionStreamOpen)
    );
    assert_eq!(limits.open_streams(), 1);
    drop(first);
    assert_eq!(limits.open_streams(), 0);
    let again = limits.admit(account, session).unwrap();
    assert_eq!(limits.open_streams(), 1);
    drop(again);
}

#[test]
fn account_and_process_caps_refuse_extra_streams_and_release_on_drop() {
    let limits = Arc::new(OwnerStreamLimits::new(2, 3));
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let a1 = limits.admit(a, Uuid::new_v4()).unwrap();
    let a2 = limits.admit(a, Uuid::new_v4()).unwrap();
    assert_eq!(
        limits.admit(a, Uuid::new_v4()).err(),
        Some(StreamRefusal::AccountLimit)
    );
    let b1 = limits.admit(b, Uuid::new_v4()).unwrap();
    assert_eq!(
        limits.admit(c, Uuid::new_v4()).err(),
        Some(StreamRefusal::ProcessLimit)
    );
    assert_eq!(limits.open_streams(), 3);
    // Releasing one of account A's streams frees both an account and a
    // process slot.
    drop(a1);
    let c1 = limits.admit(c, Uuid::new_v4()).unwrap();
    assert_eq!(
        limits.admit(a, Uuid::new_v4()).err(),
        Some(StreamRefusal::ProcessLimit)
    );
    drop((a2, b1, c1));
    assert_eq!(limits.open_streams(), 0);
    let _a3 = limits.admit(a, Uuid::new_v4()).unwrap();
    let _a4 = limits.admit(a, Uuid::new_v4()).unwrap();
}

#[test]
fn refusals_are_distinct_no_store_statuses_with_retry_after() {
    for (refusal, status) in [
        (StreamRefusal::SessionStreamOpen, StatusCode::CONFLICT),
        (StreamRefusal::AccountLimit, StatusCode::TOO_MANY_REQUESTS),
        (StreamRefusal::ProcessLimit, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let response = refusal.into_response();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    }
}

#[test]
fn unchanged_polls_back_off_to_the_snapshot_cadence_cap() {
    let mut cadence = PollCadence::new();
    assert_eq!(cadence.interval, Duration::from_secs(2));
    cadence.after_unchanged_poll();
    assert_eq!(cadence.interval, Duration::from_secs(4));
    cadence.after_unchanged_poll();
    assert_eq!(cadence.interval, Duration::from_secs(8));
    cadence.after_unchanged_poll();
    assert_eq!(cadence.interval, Duration::from_secs(15));
    cadence.after_unchanged_poll();
    assert_eq!(cadence.interval, Duration::from_secs(15));
}

#[test]
fn any_observed_change_resets_the_poll_cadence() {
    let mut cadence = PollCadence::new();
    for _ in 0..5 {
        cadence.after_unchanged_poll();
    }
    assert_eq!(cadence.interval, Duration::from_secs(15));
    cadence.after_change();
    assert_eq!(cadence.interval, Duration::from_secs(2));
    // An active tenant keeps the fast cadence while changes keep arriving.
    cadence.after_change();
    assert_eq!(cadence.interval, Duration::from_secs(2));
}

/// Waits for a `changed` event naming `section`, asserting every changed
/// payload carries only section names. Frame gaps can reach the 15 s poll
/// backoff ceiling between keepalives, so each frame wait outlives it.
async fn wait_for_change(frames: &mut BodyDataStream, section: &str) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let Ok(Some(bytes)) = tokio::time::timeout(Duration::from_secs(16), frames.next()).await
        else {
            return false;
        };
        let text = String::from_utf8_lossy(&bytes.unwrap()).into_owned();
        if text.contains("event: changed") {
            let payload = text.split("data: ").nth(1).unwrap_or_default();
            let value: serde_json::Value = serde_json::from_str(payload.trim()).unwrap();
            let changed = value["changed"].as_array().unwrap();
            assert!(
                changed
                    .iter()
                    .all(|name| name == "devices" || name == "messages")
            );
            assert!(!payload.contains("+1555"));
            assert!(!payload.contains("TENANT_NEVER_EXPOSED"));
            if changed.iter().any(|name| name == section) {
                return true;
            }
        }
    }
    false
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
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/041_device_preconditions.sql"),
        include_str!("../../../../deploy/compose/migrations/047_device_network_service.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
    .unwrap()
    .token;
    let session_a2 = login(
        &db,
        &hasher,
        "events-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap()
    .token;
    let session_b = login(
        &db,
        &hasher,
        "events-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap()
    .token;
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
    let limits = Arc::new(OwnerStreamLimits::default());
    let state = OwnerEventsState {
        database_url: database_url.clone(),
        auth_hasher: hasher.clone(),
        canonical_origin: "https://test.example".to_owned(),
        stream_limits: limits.clone(),
    };
    let app = router(state.clone());

    let anonymous = app
        .clone()
        .oneshot(get("/owner/events", None))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(limits.open_streams(), 0);

    let response = app
        .clone()
        .oneshot(get("/owner/events", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(limits.open_streams(), 1);

    // A second concurrent stream for the same session is refused and does
    // not take a slot; another session of the same account may still stream.
    let duplicate = app
        .clone()
        .oneshot(get("/owner/events", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(duplicate.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(limits.open_streams(), 1);
    let second_session = app
        .clone()
        .oneshot(get("/owner/events", Some(&session_a2)))
        .await
        .unwrap();
    assert_eq!(second_session.status(), StatusCode::OK);
    assert_eq!(limits.open_streams(), 2);
    // Dropping the body, as the server does once a disconnected client's
    // write fails, releases the permit.
    drop(second_session);
    assert_eq!(limits.open_streams(), 1);

    // Per-account and per-process caps refuse extra streams with distinct
    // statuses; each app shares one limits registry.
    let one_per_account = router(OwnerEventsState {
        stream_limits: Arc::new(OwnerStreamLimits::new(1, 32)),
        ..state.clone()
    });
    let held = one_per_account
        .clone()
        .oneshot(get("/owner/events", Some(&session_a2)))
        .await
        .unwrap();
    assert_eq!(held.status(), StatusCode::OK);
    let refused = one_per_account
        .clone()
        .oneshot(get("/owner/events", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.headers()[header::RETRY_AFTER], "60");
    let one_per_process = router(OwnerEventsState {
        stream_limits: Arc::new(OwnerStreamLimits::new(3, 1)),
        ..state.clone()
    });
    let held_b = one_per_process
        .clone()
        .oneshot(get("/owner/events", Some(&session_b)))
        .await
        .unwrap();
    assert_eq!(held_b.status(), StatusCode::OK);
    let refused = one_per_process
        .oneshot(get("/owner/events", Some(&session_a2)))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.headers()[header::RETRY_AFTER], "60");
    drop((held, held_b));

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

    // A new message for account A signals the messages section, and a
    // device rename signals the devices section.
    insert_message(&db, a.account_id, device_a, "queued").await;
    assert!(
        wait_for_change(&mut frames, "messages").await,
        "no messages change event arrived"
    );
    db.execute(
        "UPDATE devices SET display_name='A renamed' WHERE id=$1",
        &[&device_a],
    )
    .await
    .unwrap();
    assert!(
        wait_for_change(&mut frames, "devices").await,
        "no devices change event arrived"
    );

    // Revoking the session ends the stream cleanly and releases its permit.
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
    assert_eq!(limits.open_streams(), 0);

    // A revoked session cannot open a new stream.
    let refused = app
        .clone()
        .oneshot(get("/owner/events", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(limits.open_streams(), 0);
    // The other owner keeps a valid session.
    let b_response = app
        .oneshot(get("/owner/events", Some(&session_b)))
        .await
        .unwrap();
    assert_eq!(b_response.status(), StatusCode::OK);
    assert_eq!(limits.open_streams(), 1);
    drop(b_response);
    assert_eq!(limits.open_streams(), 0);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
