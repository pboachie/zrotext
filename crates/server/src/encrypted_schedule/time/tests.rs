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
