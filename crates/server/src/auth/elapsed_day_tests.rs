// SPDX-License-Identifier: AGPL-3.0-only
//! Credential duration is elapsed time, independent of the database timezone.
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::panic::{AssertUnwindSafe, resume_unwind};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL; fixed synthetic DST boundaries"]
async fn credential_days_keep_elapsed_bounds_across_timezone_transitions_and_null_opt_in() {
    let fixture = Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
    let outcome = AssertUnwindSafe(async {
        let query = concat!(
            "SELECT extract(epoch FROM (($1::text::timestamptz + ($2::integer * ",
            elapsed_credential_day_sql!(),
            ")) - $1::text::timestamptz))::bigint, ",
            "($1::text::timestamptz + ($3::integer * ",
            elapsed_credential_day_sql!(),
            ")) IS NULL, ",
            "extract(epoch FROM (($1::text::timestamptz + ($2::integer * interval '1 day')) - $1::text::timestamptz))::bigint"
        );
        for zone in ["UTC", "America/Los_Angeles", "Europe/Berlin", "Asia/Kathmandu"] {
            let row = fixture.owner.query_one("SELECT set_config('TimeZone',$1,false)", &[&zone]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), zone);
            for issued in ["2026-03-06T12:00:00Z", "2026-03-27T12:00:00Z", "2026-10-23T12:00:00Z", "2026-10-30T12:00:00Z"] {
                for days in [1i32, 7, 365] {
                    let never: Option<i32> = None;
                    let row = fixture.owner.query_one(query, &[&issued, &days, &never]).await.unwrap();
                    let expected = i64::from(days) * 86_400;
                    assert_eq!(row.get::<_, i64>(0), expected, "{zone}: {issued}, {days}");
                    assert!(row.get::<_, bool>(1), "never-expire remains NULL");
                    // The independent calendar-day control must actually cross
                    // both DST directions; otherwise these probes could miss
                    // the original defect despite their timezone labels.
                    let adjustment = match (zone, issued, days) {
                        ("America/Los_Angeles", "2026-03-06T12:00:00Z", 7)
                        | ("Europe/Berlin", "2026-03-27T12:00:00Z", 7) => Some(-3_600),
                        ("America/Los_Angeles", "2026-10-30T12:00:00Z", 7)
                        | ("Europe/Berlin", "2026-10-23T12:00:00Z", 7) => Some(3_600),
                        _ => None,
                    };
                    if let Some(adjustment) = adjustment {
                        assert_eq!(row.get::<_, i64>(2), expected + adjustment);
                        assert_ne!(row.get::<_, i64>(2), row.get::<_, i64>(0));
                    }
                }
            }
        }
    }).catch_unwind().await;
    fixture.finish().await;
    if let Err(panic) = outcome {
        resume_unwind(panic);
    }
}
