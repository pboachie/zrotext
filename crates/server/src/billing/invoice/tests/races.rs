// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn concurrent_admission_wins_exactly_one_remaining_invoice_unit() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("existing").await.unwrap();
    let mut first = case.connect().await;
    let mut second = case.connect().await;
    let input = |key: &'static str| NewMessage {
        account_id: case.account,
        device_id: case.device,
        client_message_id: Uuid::new_v4(),
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"synthetic concurrent invoice fixture",
        expires_at_ms: case.end * 1000,
    };
    let mut a = DeliveryStore::new(&mut first);
    let mut b = DeliveryStore::new(&mut second);
    let (one, two) = tokio::join!(
        a.accept_metered(input("race-one")),
        b.accept_metered(input("race-two"))
    );
    assert_ne!(one.is_ok(), two.is_ok());
    assert!(
        matches!(one, Err(StoreError::QuotaExceeded))
            || matches!(two, Err(StoreError::QuotaExceeded))
    );
    let reserved: i64 = case
        .db
        .query_one("SELECT reserved_units FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(reserved, 2);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn audit_failure_rolls_back_period_marker_entitlement_and_processed_generation() {
    let mut case = Case::new().await;
    // A crash boundary in the unique disposable schema; no real guard bypass.
    case.db.batch_execute("CREATE FUNCTION reject_invoice_audit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit fault'; END $$; CREATE TRIGGER reject_invoice_audit_fixture BEFORE INSERT ON billing_invoice_audit FOR EACH ROW EXECUTE FUNCTION reject_invoice_audit_fixture()").await.unwrap();
    let paid = case.observation("active", "paid", "subscription_cycle");
    assert!(case.observe(&paid).await.is_err());
    let row=case.db.query_one("SELECT (SELECT count(*) FROM billing_invoice_periods),(SELECT count(*) FROM billing_invoice_entitlements),(SELECT processed_generation FROM billing_reconciliations)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    case.db.batch_execute("DROP TRIGGER reject_invoice_audit_fixture ON billing_invoice_audit; DROP FUNCTION reject_invoice_audit_fixture()").await.unwrap();
    case.observe(&paid).await.unwrap();
    let count: i64 = case
        .db
        .query_one("SELECT count(*) FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    case.cleanup().await;
}
