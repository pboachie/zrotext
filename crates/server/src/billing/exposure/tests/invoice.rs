// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn invoice_bound_exposure_requires_exact_current_tenant_period_and_preserves_unknown_liability()
 {
    let f = Fixture::new(4).await;
    let db = &f.case.base.f.db;
    let account = f.action.account_id;
    let period = Uuid::new_v4();
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let start = now - 60000;
    let end = now + 300000;
    db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_invoiceexposure')", &[&account]).await.unwrap();
    db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES('sub_invoiceexposure',$1,'cus_invoiceexposure',1,1)", &[&account]).await.unwrap();
    db.execute("INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,latest_invoice_id,recognized_price) VALUES('sub_invoiceexposure',$1,'cus_invoiceexposure','active','price_invoiceexposure','in_invoiceexposure',true)", &[&account]).await.unwrap();
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source,invoice_bound_test) VALUES($1,'outbound_message',4,'stripe_test',true) ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=4,source='stripe_test',invoice_bound_test=true", &[&account]).await.unwrap();
    db.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit) VALUES($1,$2,'sub_invoiceexposure','in_invoiceexposure','il_invoiceexposure','si_invoiceexposure',$3,$4,'price_invoiceexposure',4)", &[&period,&account,&start,&end]).await.unwrap();
    db.execute("INSERT INTO billing_invoice_entitlements(account_id,subscription_id,customer_id,period_id,observed_invoice_id,effective_price_id,effective_limit,phase,generation) VALUES($1,'sub_invoiceexposure','cus_invoiceexposure',$2,'in_invoiceexposure','price_invoiceexposure',4,'active',1)", &[&account,&period]).await.unwrap();
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    assert!(
        f.reserve(&engine, id).await.is_err(),
        "an unrelated operator tenant epoch cannot become an invoice epoch"
    );
    assert_eq!(f.liability().await, (0, 0));
    // Replace only the unconsumed operator fixture before invoice enrollment;
    // consumed/outstanding real policy epochs cannot be relabelled this way.
    db.execute(
        "DELETE FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind='tenant'",
        &[&account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) VALUES($1,'tenant',$1,2,true,$2,$3,4,4)", &[&account,&start,&end]).await.unwrap();
    f.reserve(&engine, id).await.unwrap();
    let intent = engine
        .first_test_intent(
            &mut f.case.base.f.connect().await,
            &f.case.base.owner,
            f.action,
            id,
        )
        .await
        .unwrap();
    engine
        .settle_test(
            &mut f.case.base.f.connect().await,
            &intent,
            TestOutcome::Unknown,
        )
        .await
        .unwrap();
    assert_eq!(f.liability().await, (1, 0));
    db.execute("UPDATE billing_invoice_entitlements SET phase='cancelled',effective_limit=0 WHERE account_id=$1", &[&account]).await.unwrap();
    let next = f.another_action().await;
    assert!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                next,
                f.route,
                Uuid::new_v4()
            )
            .await
            .is_err()
    );
    assert_eq!(f.liability().await, (1, 0));
    f.case.cleanup().await;
}
