// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use hmac::{Hmac, KeyInit, Mac};
fn sign(body: &[u8], secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(body);
    let hex = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();
    format!("t=1750000000,v1={hex}")
}
fn fixture() -> Value {
    serde_json::json!({"id":"evt_test_SyntheticMeter","object":"v2.core.event","livemode":false,"type":"v1.billing.meter.error_report_triggered","related_object":{"type":"billing.meter","id":"mtr_test_Synthetic"},"data":{"validation_start":"2024-08-28T20:54:00.000Z","validation_end":"2024-08-28T20:54:10.000Z"}})
}
#[test]
fn exact_raw_signature_precedes_thin_event_parsing() {
    let secret = format!("whsec_{}", Uuid::new_v4().simple());
    let body = serde_json::to_vec(&fixture()).unwrap();
    let signature = sign(&body, &secret);
    assert!(verify_meter_error(&body, &signature, &secret, 1_750_000_000).is_ok());
    let mut changed = body.clone();
    changed.push(b' ');
    assert!(matches!(
        verify_meter_error(&changed, &signature, &secret, 1_750_000_000),
        Err(BillingError::InvalidSignature)
    ));
    assert!(matches!(
        verify_meter_error(&body, &signature, &secret, 1_750_000_301),
        Err(BillingError::InvalidSignature)
    ));
}
#[test]
fn missing_live_or_connected_mode_and_reversed_interval_fail_closed() {
    let secret = format!("whsec_{}", Uuid::new_v4().simple());
    for value in [
        {
            let mut v = fixture();
            v.as_object_mut().unwrap().remove("livemode");
            v
        },
        {
            let mut v = fixture();
            v["livemode"] = true.into();
            v
        },
        {
            let mut v = fixture();
            v["account"] = "acct_Synthetic".into();
            v
        },
        {
            let mut v = fixture();
            v["data"]["validation_end"] = "2024-08-28T20:53:10.000Z".into();
            v
        },
    ] {
        let body = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            verify_meter_error(&body, &sign(&body, &secret), &secret, 1_750_000_000),
            Err(BillingError::InvalidEvent)
        ));
    }
}
#[test]
fn utc_intervals_preserve_milliseconds_and_reject_calendar_ambiguity() {
    assert_eq!(
        utc_milliseconds(&"1970-01-01T00:00:00.001Z".into()),
        Some(1)
    );
    assert_eq!(
        utc_milliseconds(&"2000-03-01T00:00:00.000Z".into()),
        Some(951_868_800_000)
    );
    for s in [
        "2025-02-29T00:00:00.000Z",
        "2024-02-30T00:00:00.000Z",
        "2024-01-01T24:00:00.000Z",
        "2024-01-01T00:00:00.000+00:00",
        "2024-01-01T00:00:60.000Z",
    ] {
        assert_eq!(utc_milliseconds(&s.into()), None);
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated schema, no provider calls"]
async fn verified_meter_errors_page_all_policy_versions_and_reject_changed_raw_replay() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let schema = format!("usage_error_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    crate::auth::test_schema::apply(&db).await;
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_SyntheticFanout')",&[&account]).await.unwrap();
    db.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name) SELECT $1,v,'cus_SyntheticFanout','mtr_test_Synthetic','synthetic_fanout' FROM generate_series(1,101) v",&[&account]).await.unwrap();
    let secret = format!("whsec_{}", Uuid::new_v4().simple());
    let body = serde_json::to_vec(&fixture()).unwrap();
    let verified =
        verify_meter_error(&body, &sign(&body, &secret), &secret, 1_750_000_000).unwrap();
    let cursor = ingest_page(&mut db, &verified, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.query_one(
            "SELECT count(*)::bigint FROM billing_usage_meter_errors",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        100
    );
    assert!(
        ingest_page(&mut db, &verified, Some(cursor))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*)::bigint FROM billing_usage_meter_errors",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        101
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*)::bigint FROM billing_usage_meter_error_receipts",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let mut changed = fixture();
    changed["data"]["validation_end"] = "2024-08-28T20:54:11.000Z".into();
    let bytes = serde_json::to_vec(&changed).unwrap();
    let verified_changed =
        verify_meter_error(&bytes, &sign(&bytes, &secret), &secret, 1_750_000_000).unwrap();
    assert!(matches!(
        ingest_page(&mut db, &verified_changed, None).await,
        Err(UsageError::Conflict)
    ));
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
