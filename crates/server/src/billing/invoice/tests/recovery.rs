// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn legitimate_pre_grant_cancellation_refunds_the_original_invoice_unit_once() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    let admitted = case.send("cancelled-before-grant").await.unwrap();
    assert!(
        zrotext_delivery_store::DeliveryStore::new(&mut case.db)
            .cancel(case.account, admitted.message_id)
            .await
            .unwrap()
    );
    let _ = zrotext_delivery_store::DeliveryStore::new(&mut case.db)
        .cancel(case.account, admitted.message_id)
        .await;
    let row = case
        .db
        .query_one(
            "SELECT reserved_units,refunded_units,open_units FROM billing_invoice_periods",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 0);
    let row = case
        .db
        .query_one("SELECT terminal,refunded FROM billing_invoice_usage", &[])
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0) && row.get::<_, bool>(1));
    case.send("replacement").await.unwrap();
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn cancellation_blocks_new_spend_while_preserving_consumption_and_unknown_liability() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("before-cancel").await.unwrap();
    let mut cancelled = case.observation("canceled", "paid", "subscription_cycle");
    cancelled.observation.cancel_at_ms = Some(case.start * 1000);
    case.observe(&cancelled).await.unwrap();
    assert!(case.send("after-cancel").await.is_err());
    let row=case.db.query_one("SELECT e.phase,p.reserved_units,p.open_units FROM billing_invoice_entitlements e JOIN billing_invoice_periods p ON p.id=e.period_id",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn failed_payment_then_paid_and_late_failure_current_paid_reads_preserve_consumption() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("before-failure").await.unwrap();
    let failure = case.observation("past_due", "open", "subscription_cycle");
    case.observe(&failure).await.unwrap();
    assert!(
        case.send("restricted").await.is_err(),
        "no authenticated failure anchor invents grace"
    );
    case.observe(&paid).await.unwrap();
    case.send("recovered").await.unwrap();
    // An unordered failed event queues another current paid read, never a
    // projection of its stale webhook body.
    case.observe(&paid).await.unwrap();
    assert!(matches!(
        case.send("late-failure").await,
        Err(zrotext_delivery_store::StoreError::QuotaExceeded)
    ));
    let consumed: i64 = case
        .db
        .query_one("SELECT reserved_units FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(consumed, 2);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn newer_invoice_period_carries_unknown_work_and_historical_paid_cannot_roll_it_back() {
    let mut case = Case::new().await;
    let now: i64 = case
        .db
        .query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .unwrap()
        .get(0);
    case.end = now + 2;
    let old = case.observation("active", "paid", "subscription_cycle");
    case.observe(&old).await.unwrap();
    case.send("original-unknown").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    case.start = case.end;
    case.end += 3600;
    let mut next = case.observation("active", "paid", "subscription_cycle");
    next.observation.invoice_id = "in_invoice2".into();
    next.observation.subscription.latest_invoice_id = Some("in_invoice2".into());
    next.observation.renewal_line_id = Some("il_invoice2".into());
    case.observe(&next).await.unwrap();
    case.send("new-period").await.unwrap();
    assert!(matches!(
        case.send("carry").await,
        Err(zrotext_delivery_store::StoreError::QuotaExceeded)
    ));
    assert!(matches!(
        case.observe(&old).await,
        Err(BillingError::InvalidEvent)
    ));
    let current: String = case
        .db
        .query_one(
            "SELECT observed_invoice_id FROM billing_invoice_entitlements",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(current, "in_invoice2");
    let count: i64 = case
        .db
        .query_one("SELECT count(*) FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    case.cleanup().await;
}
