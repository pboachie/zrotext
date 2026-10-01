// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn wait_for_scope_lock(f: &Fixture, pid: i32) {
    for _ in 0..100 {
        let waiting:bool=f.case.base.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%exposure_scope_budgets%')",&[&pid]).await.unwrap().get(0);
        if waiting {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("real reservation never waited for the scope lock");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_owner_expiry_after_actual_scope_lock_wait_rolls_back_every_debit() {
    let f = Fixture::new(2).await;
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1",
            &[&f.case.base.owner.session_id],
        )
        .await
        .unwrap();
    let mut blocker = f.case.base.f.connect().await;
    let hold = blocker.transaction().await.unwrap();
    hold.query_one(
        "SELECT 1 FROM exposure_scope_budgets WHERE scope_kind='workflow' FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    let mut connection = f.case.base.f.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let engine = TestExposure::synthetic_candidate();
    let reserve = engine.reserve(
        &mut connection,
        &f.case.base.owner,
        f.action,
        f.route,
        Uuid::new_v4(),
    );
    let release = async {
        wait_for_scope_lock(&f, pid).await;
        hold.query_one("SELECT 1 FROM pg_sleep(3)", &[])
            .await
            .unwrap();
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
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one(
                "SELECT COALESCE(sum(outstanding_units),0)::bigint FROM exposure_scope_budgets",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_scope_withdrawal_after_lock_wait_does_not_use_cached_enabled_policy() {
    let f = Fixture::new(2).await;
    let mut blocker = f.case.base.f.connect().await;
    let hold = blocker.transaction().await.unwrap();
    hold.execute(
        "UPDATE exposure_scope_budgets SET enabled=false WHERE scope_kind='workflow'",
        &[],
    )
    .await
    .unwrap();
    let mut connection = f.case.base.f.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let engine = TestExposure::synthetic_candidate();
    let reserve = engine.reserve(
        &mut connection,
        &f.case.base.owner,
        f.action,
        f.route,
        Uuid::new_v4(),
    );
    let release = async {
        wait_for_scope_lock(&f, pid).await;
        hold.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(reserve, release);
    assert!(result.is_err());
    assert_eq!(f.liability().await, (0, 0));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_expired_worker_intent_and_late_completion_never_refund_or_repeat_work() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
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
    // Actual database time crosses the immutable issued lease boundary.
    f.case
        .base
        .f
        .db
        .query_one("SELECT 1 FROM pg_sleep(16)", &[])
        .await
        .unwrap();
    assert!(f.case.base.f.db.query_one("SELECT lease_until_ms<floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM exposure_reservations",&[]).await.unwrap().get::<_,bool>(0));
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
    assert_eq!(f.liability().await, (1, 0));
    f.case
        .base
        .f
        .db
        .execute("UPDATE exposure_route_policies SET enabled=false", &[])
        .await
        .unwrap();
    // Current policy withdrawal does not discard a confirmed already-started
    // synthetic effect; the original proof can only settle, never execute.
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::Completed {
                    actual_units: 1,
                    digest: [9; 32]
                }
            )
            .await
            .unwrap()
    );
    assert_eq!(f.liability().await, (0, 1));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_policy_revision_retains_finalized_usage_and_rejects_overlapping_period_reset() {
    // Deployment still has a spare unit; only carried scope usage can refuse.
    let f = Fixture::configured(2, 1, 240000).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
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
            TestOutcome::Completed {
                actual_units: 1,
                digest: [3; 32],
            },
        )
        .await
        .unwrap();
    let second = f.another_action().await;
    f.case
        .base
        .f
        .db
        .execute("UPDATE exposure_scope_budgets SET enabled=false", &[])
        .await
        .unwrap();
    let overlap=f.case.base.f.db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT account_id,scope_kind,scope_id,2,true,period_start_ms+1,period_end_ms,soft_units,hard_units FROM exposure_scope_budgets WHERE scope_kind='tenant'",&[]).await;
    assert!(overlap.is_err());
    f.case.base.f.db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT account_id,scope_kind,scope_id,2,true,period_start_ms,period_end_ms,soft_units,hard_units FROM exposure_scope_budgets",&[]).await.unwrap();
    assert!(matches!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                second,
                f.route,
                Uuid::new_v4()
            )
            .await,
        Err(Error::Policy(ExposureError::Limit))
    ));
    assert_eq!(f.liability().await, (0, 1));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_new_period_keeps_unknown_liability_until_confirmed_unused_release_once() {
    let f = Fixture::configured(1, 1, 2000).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
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
    f.case
        .base
        .f
        .db
        .query_one("SELECT 1 FROM pg_sleep(3)", &[])
        .await
        .unwrap();
    let next_deployment = Uuid::new_v4();
    let next_route = Uuid::new_v4();
    f.case
        .base
        .f
        .db
        .execute("UPDATE exposure_deployment_budgets SET enabled=false", &[])
        .await
        .unwrap();
    f.case.base.f.db.execute("INSERT INTO exposure_deployment_budgets(id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT $1,2,true,period_end_ms,period_end_ms+240000,1,1 FROM exposure_deployment_budgets WHERE id=$2",&[&next_deployment,&f.deployment]).await.unwrap();
    f.case.base.f.db.execute("INSERT INTO exposure_route_policies(account_id,id,version,deployment_id,enabled,operation,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding) SELECT account_id,$1,2,$2,true,operation,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding FROM exposure_route_policies WHERE id=$3",&[&next_route,&next_deployment,&f.route]).await.unwrap();
    f.case
        .base
        .f
        .db
        .execute("UPDATE exposure_scope_budgets SET enabled=false", &[])
        .await
        .unwrap();
    f.case.base.f.db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT account_id,scope_kind,CASE WHEN scope_kind='route' THEN $1 ELSE scope_id END,2,true,period_end_ms,period_end_ms+240000,1,1 FROM exposure_scope_budgets",&[&next_route]).await.unwrap();
    let second = f.another_action().await;
    let next_id = Uuid::new_v4();
    assert!(matches!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                second,
                next_route,
                next_id
            )
            .await,
        Err(Error::Policy(ExposureError::Limit))
    ));
    let digest = [8; 32];
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::VerifiedNotStarted { digest }
            )
            .await
            .unwrap()
    );
    assert!(
        !engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::VerifiedNotStarted { digest }
            )
            .await
            .unwrap()
    );
    assert_eq!(f.liability().await, (0, 0));
    assert!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                second,
                next_route,
                next_id
            )
            .await
            .unwrap()
            .created
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_overflowing_cost_configuration_fails_before_reservation_or_scope_debit() {
    let f = Fixture::new(2).await;
    let route = Uuid::new_v4();
    f.case.base.f.db.execute("INSERT INTO exposure_route_policies(account_id,id,version,deployment_id,enabled,operation,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding) VALUES($1,$2,1,$3,true,'provider',$4,$4,$4,$4,0,10)",&[&f.action.account_id,&route,&f.deployment,&i64::MAX]).await.unwrap();
    assert!(matches!(
        TestExposure::synthetic_candidate()
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                f.action,
                route,
                Uuid::new_v4()
            )
            .await,
        Err(Error::Policy(ExposureError::Overflow))
    ));
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
