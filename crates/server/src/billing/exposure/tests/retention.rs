// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_context_retirement_tombstones_identity_without_releasing_or_restarting_work() {
    for state in ["reserved", "unknown", "settled"] {
        let f = Fixture::new(2).await;
        let engine = TestExposure::synthetic_candidate();
        let id = Uuid::new_v4();
        f.reserve(&engine, id).await.unwrap();
        let intent = if state == "reserved" {
            None
        } else {
            let intent = engine
                .first_test_intent(
                    &mut f.case.base.f.connect().await,
                    &f.case.base.owner,
                    f.action,
                    id,
                )
                .await
                .unwrap();
            let outcome = if state == "unknown" {
                TestOutcome::Unknown
            } else {
                TestOutcome::Completed {
                    actual_units: 1,
                    digest: [7; 32],
                }
            };
            engine
                .settle_test(&mut f.case.base.f.connect().await, &intent, outcome)
                .await
                .unwrap();
            Some(intent)
        };
        let before = f.liability().await;
        f.case
            .base
            .f
            .db
            .execute(
                "UPDATE workflow_contexts SET purged_at=clock_timestamp()-interval '31 days'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            crate::http_owner_conversations::context::lifecycle::prune(
                &mut f.case.base.f.connect().await,
                30,
                100
            )
            .await
            .unwrap(),
            1
        );
        let row = f.case.base.f.db.query_one("SELECT action_id,revision,binding_digest,live_action_id,live_revision,live_binding_digest,state FROM exposure_reservations WHERE account_id=$1 AND id=$2", &[&f.action.account_id,&id]).await.unwrap();
        assert_eq!(row.get::<_, Uuid>(0), f.action.action_id);
        assert_eq!(row.get::<_, i64>(1), f.action.revision);
        assert_eq!(row.get::<_, Vec<u8>>(2), f.action.binding_digest);
        assert!(row.get::<_, Option<Uuid>>(3).is_none());
        assert!(row.get::<_, Option<i64>>(4).is_none());
        assert!(row.get::<_, Option<Vec<u8>>>(5).is_none());
        assert_eq!(row.get::<_, String>(6), state);
        assert_eq!(f.liability().await, before);
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
        let restore = f.case.base.f.db.execute("UPDATE exposure_reservations SET live_action_id=action_id,live_revision=revision,live_binding_digest=binding_digest",&[]).await.unwrap_err();
        assert_eq!(
            restore.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
        );
        if let Some(intent) = intent {
            if state == "unknown" {
                assert!(
                    engine
                        .settle_test(
                            &mut f.case.base.f.connect().await,
                            &intent,
                            TestOutcome::VerifiedNotStarted { digest: [8; 32] }
                        )
                        .await
                        .unwrap()
                );
                assert_eq!(f.liability().await, (0, 0));
                assert!(
                    !engine
                        .settle_test(
                            &mut f.case.base.f.connect().await,
                            &intent,
                            TestOutcome::VerifiedNotStarted { digest: [8; 32] }
                        )
                        .await
                        .unwrap()
                );
            } else {
                assert!(
                    !engine
                        .settle_test(
                            &mut f.case.base.f.connect().await,
                            &intent,
                            TestOutcome::Completed {
                                actual_units: 1,
                                digest: [7; 32]
                            }
                        )
                        .await
                        .unwrap()
                );
                assert_eq!(f.liability().await, before);
            }
        }
        f.case.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_period_expiry_during_final_policy_await_rolls_back_first_intent() {
    let f = Fixture::configured(2, 2, 3000).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    f.reserve(&engine, id).await.unwrap();
    // Pause the final workflow policy SELECT after state becomes executing.
    // A simple updatable view preserves the real budget row locks and FK graph.
    f.case.base.f.db.batch_execute("ALTER TABLE exposure_scope_budgets RENAME TO exposure_scope_storage;
        CREATE TABLE exposure_test_pause_count(n integer NOT NULL); INSERT INTO exposure_test_pause_count VALUES(0);
        CREATE FUNCTION exposure_test_pause(kind text) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN
          IF kind='workflow' AND EXISTS(SELECT 1 FROM exposure_reservations WHERE state='executing') AND (SELECT n=0 FROM exposure_test_pause_count) THEN
            UPDATE exposure_test_pause_count SET n=n+1; PERFORM pg_sleep(4);
          END IF; RETURN true; END $$;
        CREATE VIEW exposure_scope_budgets AS SELECT * FROM exposure_scope_storage WHERE exposure_test_pause(scope_kind);").await.unwrap();
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
    let row = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT state,lease_id FROM exposure_reservations WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "reserved");
    assert!(row.get::<_, Option<Uuid>>(1).is_none());
    assert_eq!(f.liability().await, (1, 0));
    // The delay's transactional marker also rolls back; wall time proves it ran.
    assert!(f.case.base.f.db.query_one("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=period_end_ms FROM exposure_deployment_budgets",&[]).await.unwrap().get::<_,bool>(0));
    // Restore the test-only latency seam before restricted fixture teardown.
    f.case
        .base
        .f
        .db
        .batch_execute(
            "DROP VIEW exposure_scope_budgets;
        ALTER TABLE exposure_scope_storage RENAME TO exposure_scope_budgets;
        DROP FUNCTION exposure_test_pause(text);
        DROP TABLE exposure_test_pause_count;",
        )
        .await
        .unwrap();
    f.case.cleanup().await;
}
