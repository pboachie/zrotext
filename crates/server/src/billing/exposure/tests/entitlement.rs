// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn bind(f: &Fixture) {
    f.case.base.f.db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_exposurefixture')",&[&f.action.account_id]).await.unwrap();
}
async fn project(f: &Fixture) {
    f.case.base.f.db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES('sub_exposurefixture',$1,'cus_exposurefixture',1,1)",&[&f.action.account_id]).await.unwrap();
    f.case.base.f.db.execute("INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,recognized_price) VALUES('sub_exposurefixture',$1,'cus_exposurefixture','active',true)",&[&f.action.account_id]).await.unwrap();
    f.case.base.f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'stripe_test') ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=10,source='stripe_test'",&[&f.action.account_id]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_requires_current_existing_entitlement_and_does_not_replenish_on_recovery() {
    let f = Fixture::new(4).await;
    let engine = TestExposure::synthetic_candidate();
    bind(&f).await;
    assert!(f.reserve(&engine, Uuid::new_v4()).await.is_err());
    assert_eq!(f.liability().await, (0, 0));
    project(&f).await;
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    let next = f.another_action().await;
    f.case
        .base
        .f
        .db
        .execute("UPDATE billing_reconciliations SET dirty_generation=2", &[])
        .await
        .unwrap();
    let next_id = Uuid::new_v4();
    assert!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                next,
                f.route,
                next_id
            )
            .await
            .is_err()
    );
    assert_eq!(f.liability().await, (1, 0));
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE billing_reconciliations SET processed_generation=2",
            &[],
        )
        .await
        .unwrap();
    assert!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                next,
                f.route,
                next_id
            )
            .await
            .unwrap()
            .created
    );
    assert_eq!(f.liability().await, (2, 0));
    f.case.base.f.db.execute("INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES('evt_exposurerisk','charge.refunded',$1,$2,'queued')",&[&f.action.account_id,&vec![1u8;32]]).await.unwrap();
    f.case.base.f.db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES('evt_exposurerisk','ch_exposurefixture','refund',$1)",&[&f.action.account_id]).await.unwrap();
    assert!(
        engine
            .first_test_intent(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                f.action,
                id
            )
            .await
            .is_err()
    );
    assert_eq!(f.liability().await, (2, 0));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_downgrade_committed_during_actual_entitlement_lock_wait_refuses_new_spend() {
    let f = Fixture::new(2).await;
    bind(&f).await;
    project(&f).await;
    let mut blocker = f.case.base.f.connect().await;
    let hold = blocker.transaction().await.unwrap();
    hold.execute(
        "UPDATE usage_quota_policies SET limit_units=0 WHERE account_id=$1",
        &[&f.action.account_id],
    )
    .await
    .unwrap();
    let mut db = f.case.base.f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let engine = TestExposure::synthetic_candidate();
    let reserve = engine.reserve(
        &mut db,
        &f.case.base.owner,
        f.action,
        f.route,
        Uuid::new_v4(),
    );
    let release = async {
        let mut observed = false;
        for _ in 0..100 {
            if f.case.base.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%usage_quota_policies%')",&[&pid]).await.unwrap().get::<_,bool>(0) {
                observed=true;break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            observed,
            "actual entitlement query did not wait for the policy downgrade"
        );
        hold.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(reserve, release);
    assert!(result.is_err());
    assert_eq!(f.liability().await, (0, 0));
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM exposure_reservations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.case.cleanup().await;
}
