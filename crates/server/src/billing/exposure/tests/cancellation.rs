// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn cancel(f: &Fixture, engine: &TestExposure, id: Uuid) -> Result<bool, Error> {
    engine
        .cancel_unstarted(&mut f.case.base.f.connect().await, &f.case.base.owner, id)
        .await
}

async fn assert_unchanged_quota(f: &Fixture) {
    let used: i64 = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT COALESCE(sum(reserved_units-refunded_units),0)::bigint FROM usage_periods",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        used, 0,
        "exposure cleanup must not manufacture Android quota credits"
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn pre_intent_cancellation_releases_all_scopes_once_and_survives_reconnect() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    assert_eq!(f.liability().await, (1, 0));
    assert!(cancel(&f, &engine, id).await.unwrap());
    assert_eq!(f.liability().await, (0, 0));
    let row=f.case.base.f.db.query_one("SELECT count(*),sum(outstanding_units)::bigint,sum(finalized_units)::bigint FROM exposure_scope_budgets",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 6);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    assert!(
        !cancel(&f, &TestExposure::synthetic_candidate(), id)
            .await
            .unwrap()
    );
    assert_eq!(f.reserve(&engine, id).await.unwrap().state, "released");
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
    assert_eq!(f.liability().await, (0, 0));
    assert_unchanged_quota(&f).await;
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn cancellation_of_unstarted_work_does_not_require_renewed_action_or_policy() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    f.case.base.f.db.batch_execute("UPDATE workflow_routines SET stopped_at=clock_timestamp(); UPDATE exposure_deployment_budgets SET enabled=false; UPDATE exposure_route_policies SET enabled=false; UPDATE exposure_scope_budgets SET enabled=false").await.unwrap();
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
    assert!(cancel(&f, &engine, id).await.unwrap());
    assert_eq!(f.liability().await, (0, 0));
    assert!(!cancel(&f, &engine, id).await.unwrap());
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_exact_action_can_release_unstarted_exposure_without_new_approval() {
    let f = Fixture::new(2).await;
    let now: i64 = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let mut descriptor = f.case.descriptor.clone();
    descriptor.action_id = Uuid::new_v4().to_string();
    descriptor.expires_at = now + 10;
    let proposed = f.case.propose(descriptor).await;
    let approved = decisions::decide(
        &mut f.case.base.f.connect().await,
        &f.case.base.owner,
        Uuid::new_v4(),
        proposed.record_version,
        proposed.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    f.case.base.f.db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT account_id,scope_kind,$2,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind='turn' AND scope_id=$3",&[&f.action.account_id,&approved.key.action_id,&f.action.action_id]).await.unwrap();
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    engine
        .reserve(
            &mut f.case.base.f.connect().await,
            &f.case.base.owner,
            approved.key,
            f.route,
            id,
        )
        .await
        .unwrap();
    f.case
        .base
        .f
        .db
        .query_one("SELECT pg_sleep(11)", &[])
        .await
        .unwrap();
    let expired:bool=f.case.base.f.db.query_one("SELECT expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2",&[&approved.key.account_id,&approved.key.action_id]).await.unwrap().get(0);
    assert!(expired);
    assert!(
        engine
            .first_test_intent(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                approved.key,
                id
            )
            .await
            .is_err()
    );
    assert!(cancel(&f, &engine, id).await.unwrap());
    assert_eq!(f.liability().await, (0, 0));
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn cancellation_and_first_intent_serialize_to_one_irreversible_winner() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    let mut cancelling = f.case.base.f.connect().await;
    let mut executing = f.case.base.f.connect().await;
    let (cancelled, intent) = tokio::join!(
        engine.cancel_unstarted(&mut cancelling, &f.case.base.owner, id),
        engine.first_test_intent(&mut executing, &f.case.base.owner, f.action, id)
    );
    match (cancelled, intent) {
        (Ok(true), Err(_)) => assert_eq!(f.liability().await, (0, 0)),
        (Err(Error::Conflict), Ok(intent)) => {
            assert_eq!(f.liability().await, (1, 0));
            assert!(
                engine
                    .settle_test(&mut executing, &intent, TestOutcome::Unknown)
                    .await
                    .unwrap()
            );
            assert!(matches!(
                cancel(&f, &engine, id).await,
                Err(Error::Conflict)
            ));
            assert_eq!(f.liability().await, (1, 0));
        }
        _ => panic!("exactly one of cancellation and execution intent must commit"),
    }
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn issued_and_unknown_intents_never_release_liability_through_owner_cancellation() {
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
    assert!(matches!(
        cancel(&f, &engine, id).await,
        Err(Error::Conflict)
    ));
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
        .query_one("SELECT pg_sleep(16)", &[])
        .await
        .unwrap();
    let expired:bool=f.case.base.f.db.query_one("SELECT lease_until_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM exposure_reservations WHERE id=$1",&[&id]).await.unwrap().get(0);
    assert!(expired, "the real issued intent lease must be expired");
    assert!(matches!(
        cancel(&f, &engine, id).await,
        Err(Error::Conflict)
    ));
    assert_eq!(f.liability().await, (1, 0));
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn cancellation_refuses_disabled_candidate_foreign_and_revoked_owners() {
    let f = Fixture::new(2).await;
    let other = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    assert!(matches!(
        cancel(&f, &TestExposure::default(), id).await,
        Err(Error::Unavailable)
    ));
    assert!(
        engine
            .cancel_unstarted(
                &mut f.case.base.f.connect().await,
                &other.case.base.owner,
                id
            )
            .await
            .is_err()
    );
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&f.case.base.owner.session_id],
        )
        .await
        .unwrap();
    assert!(cancel(&f, &engine, id).await.is_err());
    assert_eq!(f.liability().await, (1, 0));
    other.case.base.f.cleanup().await;
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn cancellation_final_write_failure_rolls_back_every_scope_and_global_credit() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    f.case.base.f.db.batch_execute("CREATE FUNCTION reject_cancel() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic cancellation rollback'; END $$; CREATE TRIGGER reject_cancel BEFORE UPDATE ON exposure_reservations FOR EACH ROW WHEN (NEW.state='released') EXECUTE FUNCTION reject_cancel()").await.unwrap();
    assert!(matches!(
        cancel(&f, &engine, id).await,
        Err(Error::Database(_))
    ));
    assert_eq!(f.liability().await, (1, 0));
    let total: i64 = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT sum(outstanding_units)::bigint FROM exposure_scope_budgets",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(total, 6);
    f.case
        .base
        .f
        .db
        .batch_execute(
            "DROP TRIGGER reject_cancel ON exposure_reservations; DROP FUNCTION reject_cancel()",
        )
        .await
        .unwrap();
    assert!(cancel(&f, &engine, id).await.unwrap());
    f.case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn cancellation_owner_expiry_during_final_write_rolls_back_all_credits() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    f.case.base.f.db.batch_execute("CREATE FUNCTION stall_cancel() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER stall_cancel BEFORE UPDATE ON exposure_reservations FOR EACH ROW WHEN (NEW.state='released') EXECUTE FUNCTION stall_cancel()").await.unwrap();
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
    let mut connection = f.case.base.f.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let cancellation = engine.cancel_unstarted(&mut connection, &f.case.base.owner, id);
    let barrier = async {
        for _ in 0..100 {
            let waiting:bool=f.case.base.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep' AND query LIKE '%UPDATE exposure_reservations%')",&[&pid]).await.unwrap().get(0);
            if waiting {
                let live: bool = f
                    .case
                    .base
                    .f
                    .db
                    .query_one(
                        "SELECT expires_at>clock_timestamp() FROM sessions WHERE id=$1",
                        &[&f.case.base.owner.session_id],
                    )
                    .await
                    .unwrap()
                    .get(0);
                assert!(
                    live,
                    "owner must be live at the observed final-write barrier"
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("cancellation must reach the actual final-write barrier");
    };
    let (result, ()) = tokio::join!(cancellation, barrier);
    assert!(matches!(
        result,
        Err(Error::Authority(ConversationError::Forbidden))
    ));
    assert_eq!(f.liability().await, (1, 0));
    let state: String = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT state FROM exposure_reservations WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "reserved");
    f.case
        .base
        .f
        .db
        .batch_execute(
            "DROP TRIGGER stall_cancel ON exposure_reservations; DROP FUNCTION stall_cancel()",
        )
        .await
        .unwrap();
    f.case.base.f.cleanup().await;
}
