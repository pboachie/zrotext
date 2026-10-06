// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::decisions::{model::Decision, tests::Case};
mod cancellation;
mod entitlement;
mod http;
mod invoice;
mod resilience;
mod retention;
mod transaction;

struct Fixture {
    case: Case,
    action: ActionKey,
    route: Uuid,
    deployment: Uuid,
}
impl Fixture {
    async fn new(cap: i64) -> Self {
        Self::configured(cap, cap, 240000).await
    }
    async fn configured(cap: i64, scope_cap: i64, period_length: i64) -> Self {
        let case = Case::new().await;
        let action = case.approved().await.key;
        let route = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let mut db = case.base.f.connect().await;
        let tx = db.transaction().await.unwrap();
        let now = store::now(&tx).await.unwrap();
        tx.execute("INSERT INTO exposure_deployment_budgets(id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) VALUES($1,1,true,$2,$3,$4,$4)",&[&deployment,&(now-1000),&(now+period_length),&cap]).await.unwrap();
        tx.execute("INSERT INTO exposure_route_policies(account_id,id,version,deployment_id,enabled,operation,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding) VALUES($1,$2,1,$3,true,'ai',0,1000,0,1,0,10)",&[&action.account_id,&route,&deployment]).await.unwrap();
        for (kind, id) in [
            (
                "campaign",
                Uuid::parse_str(&case.descriptor.routine_id).unwrap(),
            ),
            ("device", case.base.f.device),
            ("route", route),
            ("tenant", action.account_id),
            ("turn", action.action_id),
            ("workflow", case.base.h.context),
        ] {
            tx.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) VALUES($1,$2,$3,1,true,$4,$5,$6,$6)",&[&action.account_id,&kind,&id,&(now-1000),&(now+period_length),&scope_cap]).await.unwrap();
        }
        tx.commit().await.unwrap();
        Self {
            case,
            action,
            route,
            deployment,
        }
    }
    async fn reserve(&self, engine: &TestExposure, id: Uuid) -> Result<Reservation, Error> {
        engine
            .reserve(
                &mut self.case.base.f.connect().await,
                &self.case.base.owner,
                self.action,
                self.route,
                id,
            )
            .await
    }
    async fn liability(&self) -> (i64, i64) {
        let row=self.case.base.f.db.query_one("SELECT outstanding_units,finalized_units FROM exposure_deployment_budgets WHERE id=$1",&[&self.deployment]).await.unwrap();
        (row.get(0), row.get(1))
    }
    async fn another_action(&self) -> ActionKey {
        let mut d = self.case.descriptor.clone();
        d.action_id = Uuid::new_v4().to_string();
        let proposed = self.case.propose(d).await;
        let approved = decisions::decide(
            &mut self.case.base.f.connect().await,
            &self.case.base.owner,
            Uuid::new_v4(),
            proposed.record_version,
            proposed.key,
            Decision::Approve,
        )
        .await
        .unwrap();
        self.case.base.f.db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units) SELECT account_id,scope_kind,$2,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind='turn' AND scope_id=$3",&[&self.action.account_id,&approved.key.action_id,&self.action.action_id]).await.unwrap();
        approved.key
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_default_off_exact_replay_and_unknown_liability_do_not_mint_another_intent() {
    let f = Fixture::new(2).await;
    let id = Uuid::new_v4();
    assert!(matches!(
        f.reserve(&TestExposure::default(), id).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.liability().await, (0, 0));
    let engine = TestExposure::synthetic_candidate();
    let first = f.reserve(&engine, id).await.unwrap();
    assert!(first.created);
    assert_eq!(first.maximum_units, 1);
    assert!(!f.reserve(&engine, id).await.unwrap().created);
    assert!(matches!(
        f.reserve(&engine, Uuid::new_v4()).await,
        Err(Error::Conflict)
    ));
    let intent = engine
        .first_test_intent(
            &mut f.case.base.f.connect().await,
            &f.case.base.owner,
            f.action,
            id,
        )
        .await
        .unwrap();
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::Completed {
                    actual_units: 2,
                    digest: [1; 32]
                }
            )
            .await
            .is_err()
    );
    assert_eq!(f.liability().await, (1, 0));
    assert!(
        f.case
            .base
            .f
            .db
            .execute(
                "UPDATE exposure_reservations SET lease_id=$1",
                &[&Uuid::new_v4()]
            )
            .await
            .is_err()
    );
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
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::Unknown
            )
            .await
            .unwrap()
    );
    assert_eq!(f.liability().await, (1, 0));
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
    let digest = [7; 32];
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::Completed {
                    actual_units: 1,
                    digest
                }
            )
            .await
            .unwrap()
    );
    assert!(
        !engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::Completed {
                    actual_units: 1,
                    digest
                }
            )
            .await
            .unwrap()
    );
    assert!(
        engine
            .settle_test(
                &mut f.case.base.f.connect().await,
                &intent,
                TestOutcome::VerifiedNotStarted { digest }
            )
            .await
            .is_err()
    );
    assert_eq!(f.liability().await, (0, 1));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_last_unit_is_serialized_between_real_approved_actions() {
    let f = Fixture::new(1).await;
    let second = f.another_action().await;
    let engine = TestExposure::synthetic_candidate();
    let mut one = f.case.base.f.connect().await;
    let mut two = f.case.base.f.connect().await;
    let (a, b) = tokio::join!(
        engine.reserve(
            &mut one,
            &f.case.base.owner,
            f.action,
            f.route,
            Uuid::new_v4()
        ),
        engine.reserve(
            &mut two,
            &f.case.base.owner,
            second,
            f.route,
            Uuid::new_v4()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(f.liability().await, (1, 0));
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM exposure_reservations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exposure_missing_scope_foreign_action_and_revoked_owner_leave_no_debit() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let mut foreign = f.action;
    foreign.account_id = Uuid::new_v4();
    assert!(
        engine
            .reserve(
                &mut f.case.base.f.connect().await,
                &f.case.base.owner,
                foreign,
                f.route,
                Uuid::new_v4()
            )
            .await
            .is_err()
    );
    f.case
        .base
        .f
        .db
        .execute(
            "DELETE FROM exposure_scope_budgets WHERE scope_kind='device'",
            &[],
        )
        .await
        .unwrap();
    assert!(f.reserve(&engine, Uuid::new_v4()).await.is_err());
    assert_eq!(f.liability().await, (0, 0));
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
    assert!(f.reserve(&engine, Uuid::new_v4()).await.is_err());
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
