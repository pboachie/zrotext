// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::{Client, NoTls};

async fn database() -> Client {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable test database");
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client
}
fn window<'a>(date: &'a str, zone: Option<&'a str>, open: u16, close: u16) -> LocalWindow<'a> {
    LocalWindow {
        date,
        timezone: zone,
        opens_minute: open,
        closes_minute: close,
    }
}
fn duration(value: Resolution) -> i64 {
    match value {
        Resolution::Ready {
            opens_at_ms,
            closes_at_ms,
        } => closes_at_ms - opens_at_ms,
        _ => panic!("an unambiguous window must resolve"),
    }
}

#[test]
fn expiry_and_missed_windows_never_become_dispatch_or_automatic_retry_permission() {
    let window = Resolution::Ready {
        opens_at_ms: 20,
        closes_at_ms: 80,
    };
    assert_eq!(
        timing(19, 10, 100, 0, window).unwrap(),
        Timing::WaitingUntil(20)
    );
    assert_eq!(
        timing(20, 10, 100, 0, window).unwrap(),
        Timing::WithinWindow
    );
    assert_eq!(
        timing(20, 10, 100, 30, window).unwrap(),
        Timing::WaitingUntil(30)
    );
    assert_eq!(
        timing(80, 10, 100, 0, window).unwrap(),
        Timing::MissedWindow
    );
    assert_eq!(timing(100, 10, 100, 0, window).unwrap(), Timing::Expired);
    assert_eq!(
        timing(20, 10, 100, 80, window).unwrap(),
        Timing::MissedWindow
    );
    let unknown = Resolution::OwnerReview(ReviewReason::UnknownTimezone);
    assert_eq!(
        timing(99, 10, 100, 0, unknown).unwrap(),
        Timing::OwnerReview(ReviewReason::UnknownTimezone)
    );
    assert_eq!(timing(100, 10, 100, 0, unknown).unwrap(), Timing::Expired);
    assert!(timing(-1, 10, 100, 0, window).is_err());
    assert!(timing(20, 100, 100, 0, window).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses read-only timezone queries"]
async fn dst_gap_and_overlap_wait_for_review_instead_of_selecting_an_instant() {
    let db = database().await;
    assert_eq!(
        resolve(
            &db,
            window("2027-03-14", Some("America/New_York"), 150, 210)
        )
        .await
        .unwrap(),
        Resolution::OwnerReview(ReviewReason::NonexistentCivilTime)
    );
    assert_eq!(
        resolve(&db, window("2027-11-07", Some("America/New_York"), 90, 150))
            .await
            .unwrap(),
        Resolution::OwnerReview(ReviewReason::AmbiguousCivilTime)
    );
    assert_eq!(
        duration(
            resolve(&db, window("2027-03-14", Some("America/New_York"), 90, 210))
                .await
                .unwrap()
        ),
        3_600_000
    );
    assert_eq!(
        duration(
            resolve(&db, window("2027-11-07", Some("America/New_York"), 30, 150))
                .await
                .unwrap()
        ),
        10_800_000
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses read-only timezone queries"]
async fn unknown_timezone_and_skipped_civil_day_never_infer_recipient_timing() {
    let db = database().await;
    for zone in [None, Some(""), Some("Unknown/Timezone")] {
        assert_eq!(
            resolve(&db, window("2027-01-01", zone, 540, 1020))
                .await
                .unwrap(),
            Resolution::OwnerReview(ReviewReason::UnknownTimezone)
        );
    }
    assert_eq!(
        resolve(&db, window("2011-12-30", Some("Pacific/Apia"), 540, 1020))
            .await
            .unwrap(),
        Resolution::OwnerReview(ReviewReason::NonexistentCivilTime)
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses read-only timezone queries"]
async fn overnight_windows_and_changed_timezones_have_explicit_distinct_utc_bounds() {
    let db = database().await;
    let utc = resolve(&db, window("2027-06-01", Some("UTC"), 1320, 120))
        .await
        .unwrap();
    assert_eq!(duration(utc), 14_400_000);
    let changed = resolve(
        &db,
        window("2027-06-01", Some("America/New_York"), 1320, 120),
    )
    .await
    .unwrap();
    match (utc, changed) {
        (Resolution::Ready { opens_at_ms: a, .. }, Resolution::Ready { opens_at_ms: b, .. }) => {
            assert_eq!(b - a, 14_400_000)
        }
        _ => panic!("both named-zone windows must be unambiguous"),
    }
    for invalid in [
        window("2027-02-30", Some("UTC"), 0, 60),
        window("2027-01-01", Some("UTC"), 1440, 60),
        window("2027-01-01", Some("UTC"), 60, 60),
    ] {
        assert!(matches!(
            resolve(&db, invalid).await,
            Err(WindowError::Invalid)
        ));
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses an isolated read-only connection"]
async fn server_session_timezone_never_changes_recipient_window_interpretation() {
    let db = database().await;
    let local = window("2027-03-14", Some("America/New_York"), 90, 210);
    db.batch_execute("SET TIME ZONE 'UTC'").await.unwrap();
    let expected = resolve(&db, local).await.unwrap();
    for zone in ["Asia/Tokyo", "Pacific/Honolulu", "Europe/London"] {
        db.execute("SELECT set_config('TimeZone',$1,false)", &[&zone])
            .await
            .unwrap();
        assert_eq!(resolve(&db, local).await.unwrap(), expected);
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses read-only timezone queries"]
async fn recurrence_stays_at_recipient_local_time_instead_of_adding_twenty_four_hours() {
    let db = database().await;
    for (first, spacing) in [
        ("2027-03-13", 23 * 3_600_000),
        ("2027-11-06", 25 * 3_600_000),
    ] {
        let policy = crate::encrypted_schedule::policy::WindowPolicy {
            timezone: Some("America/New_York".into()),
            first_local_date: first.into(),
            opens_minute: 540,
            closes_minute: 1020,
            repeat_every_days: Some(1),
            max_occurrences: 2,
            pacing_seconds: 60,
        };
        let first = policy.resolve_occurrence(&db, 0).await.unwrap();
        let second = policy.resolve_occurrence(&db, 1).await.unwrap();
        match (first, second) {
            (
                Resolution::Ready { opens_at_ms: a, .. },
                Resolution::Ready { opens_at_ms: b, .. },
            ) => assert_eq!(b - a, spacing),
            _ => panic!("daytime recurrence must resolve"),
        }
        assert!(matches!(
            policy.resolve_occurrence(&db, 2).await,
            Err(WindowError::Invalid)
        ));
    }
    let invalid = crate::encrypted_schedule::policy::WindowPolicy {
        timezone: None,
        first_local_date: "2027-02-30".into(),
        opens_minute: 540,
        closes_minute: 1020,
        repeat_every_days: None,
        max_occurrences: 1,
        pacing_seconds: 60,
    };
    assert!(matches!(
        invalid.resolve_occurrence(&db, 0).await,
        Err(WindowError::Invalid)
    ));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; PostgreSQL civil-time parity"]
async fn utc_direct_resolution_matches_generic_calendar_across_session_timezones() {
    let mut db = database().await;
    let tx = db.transaction().await.unwrap();
    for session_zone in ["UTC", "America/New_York", "Asia/Kathmandu"] {
        tx.query_one("SELECT set_config('TimeZone',$1,true)", &[&session_zone])
            .await
            .unwrap();
        for (date, open, close) in [
            ("2030-01-02", 60, 120),
            ("2030-12-31", 1380, 60),
            ("2032-02-28", 1380, 60),
            ("2032-02-29", 1380, 60),
            ("2030-04-30", 1439, 1),
        ] {
            let value = window(date, Some("UTC"), open, close);
            let direct = resolve(&tx, value).await.unwrap();
            let generic = resolve_named(&tx, value, "UTC").await.unwrap();
            assert_eq!(direct, generic);
            assert_eq!(
                duration(direct),
                i64::from((close + 1440 - open) % 1440) * 60000
            );
        }
    }
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; PostgreSQL invalid-calendar parity"]
async fn utc_direct_resolution_retains_invalid_calendar_and_window_refusals() {
    let mut db = database().await;
    for date in [
        "2030-02-29",
        "2032-02-30",
        "2030-13-01",
        "2030-00-01",
        "0000-01-01",
    ] {
        // A calendar error aborts its transaction; isolate both actual paths.
        let tx = db.transaction().await.unwrap();
        assert!(matches!(
            resolve(&tx, window(date, Some("UTC"), 60, 120)).await,
            Err(WindowError::Invalid)
        ));
        tx.rollback().await.unwrap();
        let tx = db.transaction().await.unwrap();
        assert!(matches!(
            resolve_named(&tx, window(date, Some("UTC"), 60, 120), "UTC").await,
            Err(WindowError::Invalid)
        ));
        tx.rollback().await.unwrap();
    }
    for (date, open, close) in [
        ("2030-1-01", 60, 120),
        ("2030-01-01", 60, 60),
        ("2030-01-01", 1440, 60),
    ] {
        assert!(matches!(
            resolve(&db, window(date, Some("UTC"), open, close)).await,
            Err(WindowError::Invalid)
        ));
    }
}
