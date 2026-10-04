// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use std::sync::atomic::{AtomicBool, Ordering};
mod invoice_period;

pub(super) async fn invoice_fixture() -> Fixture {
    let fixture = Fixture::new().await;
    // The shared fixture ends at 078. Its billing prerequisites are installed;
    // apply the actual invoice migration only in this caller's isolated schema.
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../../../../deploy/compose/migrations/081_invoice_bound_test_billing.sql"
        ))
        .await
        .unwrap();
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../../../../deploy/compose/migrations/090_invoice_usage_observations.sql"
        ))
        .await
        .unwrap();
    fixture
}

pub(super) async fn seed(
    db: &Database,
    account: Uuid,
    device: Uuid,
    customer: &str,
    meter: &str,
    with_invoice: bool,
) {
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
        &[&account, &customer],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,$2,$3,'gateway_submit',true)", &[&account,&customer,&meter]).await.unwrap();
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',100,'stripe_test')", &[&account]).await.unwrap();
    db.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units) VALUES($1,'outbound_message','2024-01-01','2024-02-01',100,1)", &[&account]).await.unwrap();
    let message = Uuid::new_v4();
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,$4,$5,'synthetic_alpha',$6,$5,'submitted',clock_timestamp()+interval '1 day')",
        &[&message,&account,&device,&format!("+{}{}","1555","1234567"),&vec![7u8;32],&b"synthetic only".as_slice()]).await.unwrap();
    // Real reservation trigger supplies the immutable period/policy binding.
    db.execute("INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) VALUES($1,$2,'outbound_message','2024-01-01','reserve',1)",&[&account,&message]).await.unwrap();
    // Already finalized/acknowledged synthetic observation: execution finalization
    // itself is covered by the delivery-store tests, not simulated radio here.
    db.execute("INSERT INTO billing_usage_finalized(account_id,message_id,success_event_id,success_attempt_id) VALUES($1,$2,$3,$4)", &[&account,&message,&Uuid::new_v4(),&Uuid::new_v4()]).await.unwrap();
    let identifier = format!("zt-usage-v1-{}{}", message.simple(), message.simple());
    db.execute("INSERT INTO billing_usage_outbox(account_id,message_id,identifier,state,acknowledged_at) VALUES($1,$2,$3,'acknowledged',clock_timestamp())", &[&account,&message,&identifier]).await.unwrap();
    if with_invoice {
        db.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,$2,'sub_Synthetic',1)", &[&account,&customer]).await.unwrap();
        db.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit) VALUES($1,$2,'sub_Synthetic','in_Synthetic','il_Synthetic','si_Synthetic',1704067200000,1706745600000,'price_Synthetic',100)", &[&Uuid::new_v4(),&account]).await.unwrap();
    }
}
pub(super) async fn authority_snapshot(db: &Database, account: Uuid) -> Value {
    db.query_one("SELECT json_build_object('limit',(SELECT limit_units FROM usage_quota_policies WHERE account_id=$1),'reserved',(SELECT reserved_units FROM usage_periods WHERE account_id=$1),'refunded',(SELECT refunded_units FROM usage_periods WHERE account_id=$1),'ledger',(SELECT count(*) FROM usage_ledger WHERE account_id=$1),'ack',(SELECT state FROM billing_usage_outbox WHERE account_id=$1),'invoices',(SELECT count(*) FROM billing_invoice_periods WHERE account_id=$1))::text",&[&account]).await.unwrap().get::<_,String>(0).parse().unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine invoice migration and synthetic TLS"]
async fn non_calendar_invoice_binding_stays_pending_without_fetching_its_quantity() {
    let mut f = invoice_fixture().await;
    seed(
        &f.db,
        f.account,
        f.device,
        "cus_Synthetic",
        "mtr_Synthetic",
        false,
    )
    .await;
    f.db.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,'cus_Synthetic','sub_Synthetic',1)", &[&f.account]).await.unwrap();
    f.db.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit) VALUES($1,$2,'sub_Synthetic','in_Synthetic','il_Synthetic','si_Synthetic',1705276800000,1707955200000,'price_Synthetic',100)", &[&Uuid::new_v4(),&f.account]).await.unwrap();
    let before = authority_snapshot(&f.db, f.account).await;
    let (worker, server) = tls(vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(1),
        ),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(1),
        ),
    ])
    .await;
    assert_eq!(
        worker
            .reconcile_period(&mut f.db, f.account, 1, "2024-01-01", Uuid::new_v4())
            .await
            .unwrap(),
        "pending"
    );
    assert_eq!(server.await.unwrap().len(), 3);
    assert_eq!(
        f.db.query_one(
            "SELECT invoice_units FROM billing_usage_reconciliations WHERE account_id=$1",
            &[&f.account]
        )
        .await
        .unwrap()
        .get::<_, Option<i64>>(0),
        None
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated schema and synthetic certificate-validated TLS only"]
async fn actual_https_pg_observation_is_immutable_idempotent_and_cannot_credit_or_change_entitlement()
 {
    let mut f = invoice_fixture().await;
    seed(
        &f.db,
        f.account,
        f.device,
        "cus_Synthetic",
        "mtr_Synthetic",
        true,
    )
    .await;
    let before = authority_snapshot(&f.db, f.account).await;
    let snapshot = Uuid::new_v4();
    for _ in 0..2 {
        let (worker, server) = tls(observation(
            invoice(vec![line("il_Synthetic", 1)], false),
            1,
        ))
        .await;
        worker.validate_schema(&f.db).await.unwrap();
        assert_eq!(
            worker
                .reconcile_period(&mut f.db, f.account, 1, "2024-01-01", snapshot)
                .await
                .unwrap(),
            "observed_equal"
        );
        assert_eq!(server.await.unwrap().len(), 6);
        assert_eq!(
            f.db.query_one(
                "SELECT count(*) FROM billing_usage_reconciliations WHERE account_id=$1",
                &[&f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    }
    let saved=f.db.query_one("SELECT finalized_units,acknowledged_units,provider_units,invoice_units,pending_units,review_units FROM billing_usage_reconciliations WHERE account_id=$1",&[&f.account]).await.unwrap();
    assert_eq!(
        (
            saved.get::<_, i64>(0),
            saved.get::<_, i64>(1),
            saved.get::<_, i64>(2),
            saved.get::<_, Option<i64>>(3),
            saved.get::<_, i64>(4),
            saved.get::<_, i64>(5)
        ),
        (1, 1, 1, Some(1), 0, 0)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated schema and synthetic certificate-validated TLS only"]
async fn failed_account_does_not_starve_the_next_period_or_append_a_foreign_meter_observation() {
    let mut f = invoice_fixture().await;
    seed(&f.db, f.account, f.device, "cus_First", "mtr_First", false).await;
    let account = Uuid::from_u128(u128::MAX);
    let device = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
        &[&device, &account],
    )
    .await
    .unwrap();
    seed(
        &f.db,
        account,
        device,
        "cus_Synthetic",
        "mtr_Synthetic",
        true,
    )
    .await;
    let mut replies = vec![reply("/v1/billing/meters/mtr_First", meter())];
    replies.extend(observation(
        invoice(vec![line("il_Synthetic", 1)], false),
        1,
    ));
    let (worker, server) = tls(replies).await;
    let mut cursor = None;
    let draining = AtomicBool::new(false);
    assert!(
        super::super::super::worker::observe_next(&mut f.db, &worker, &mut cursor, &draining)
            .await
            .is_err()
    );
    assert_eq!(cursor.as_ref().unwrap().0, f.account);
    assert!(
        super::super::super::worker::observe_next(&mut f.db, &worker, &mut cursor, &draining)
            .await
            .unwrap()
    );
    assert_eq!(cursor.as_ref().unwrap().0, account);
    assert_eq!(server.await.unwrap().len(), 7);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM billing_usage_reconciliations WHERE account_id=$1",
            &[&f.account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM billing_usage_reconciliations WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    draining.store(true, Ordering::SeqCst);
    cursor = None;
    assert!(
        !super::super::super::worker::observe_next(&mut f.db, &worker, &mut cursor, &draining)
            .await
            .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated schema, no external provider calls"]
async fn enabled_startup_requires_actual_schema_and_foreign_period_refuses_before_network() {
    let mut f = invoice_fixture().await;
    let (worker, server) = tls(vec![]).await;
    worker.validate_schema(&f.db).await.unwrap();
    assert!(
        worker
            .reconcile_period(&mut f.db, Uuid::new_v4(), 1, "2024-01-01", Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(server.await.unwrap().is_empty());
    f.db.batch_execute("ALTER TABLE billing_usage_reconciliations RENAME COLUMN invoice_units TO unavailable_invoice_units").await.unwrap();
    assert!(worker.validate_schema(&f.db).await.is_err());
    f.db.batch_execute("ALTER TABLE billing_usage_reconciliations RENAME COLUMN unavailable_invoice_units TO invoice_units").await.unwrap();
    f.cleanup().await;
}
