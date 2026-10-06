// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::billing::exposure::TestExposure;
use crate::http_owner_conversations::context::decisions::tests::Case;
use crate::provider_sms::{Content, Route};

const SITE: &str = "provider-dispatch-test";
const RECIPIENT: &str = "+15551234567";

struct Fixture {
    case: Case,
    action: ActionKey,
    reservation: Uuid,
    request: Request,
}
impl Fixture {
    /// Reserve and hold a live execution intent for an approved provider
    /// action: the minimum authority `commit_submit_intent` consumes.
    async fn new() -> Self {
        Self::configured(true).await
    }
    /// `intent=false` leaves the reservation merely reserved, never leased.
    async fn configured(intent: bool) -> Self {
        let case = Case::new().await;
        let action = case.approved().await.key;
        let route = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let reservation = Uuid::new_v4();
        let mut db = case.base.f.connect().await;
        db.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) \
        VALUES($1,'cus_dispatchfixture')",
            &[&action.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,\
        stripe_customer_id,dirty_generation,processed_generation) \
        VALUES('sub_dispatchfixture',$1,'cus_dispatchfixture',1,1)",
            &[&action.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,\
        stripe_customer_id,stripe_status,recognized_price) \
        VALUES('sub_dispatchfixture',$1,'cus_dispatchfixture','active',true)",
            &[&action.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) \
        VALUES($1,'outbound_message',10,'stripe_test') \
        ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=10,source='stripe_test'",
            &[&action.account_id],
        )
        .await
        .unwrap();
        let tx = db.transaction().await.unwrap();
        let now: i64 = tx
            .query_one(
                "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        tx.execute(
            "INSERT INTO exposure_deployment_budgets(id,version,enabled,period_start_ms,\
        period_end_ms,soft_units,hard_units) VALUES($1,1,true,$2,$3,10,10)",
            &[&deployment, &(now - 1000), &(now + 240_000)],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO exposure_route_policies(account_id,id,version,deployment_id,enabled,\
        operation,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding) \
        VALUES($1,$2,1,$3,true,'provider',0,1000,0,1,0,10)",
            &[&action.account_id, &route, &deployment],
        )
        .await
        .unwrap();
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
            tx.execute(
                "INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,\
            enabled,period_start_ms,period_end_ms,soft_units,hard_units) \
            VALUES($1,$2,$3,1,true,$4,$5,10,10)",
                &[
                    &action.account_id,
                    &kind,
                    &id,
                    &(now - 1000),
                    &(now + 240_000),
                ],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        let engine = TestExposure::synthetic_candidate();
        engine
            .reserve(
                &mut case.base.f.connect().await,
                &case.base.owner,
                action,
                route,
                reservation,
            )
            .await
            .unwrap();
        if intent {
            engine
                .first_test_intent(
                    &mut case.base.f.connect().await,
                    &case.base.owner,
                    action,
                    reservation,
                )
                .await
                .unwrap();
        }
        case.base
            .f
            .db
            .execute(
                "INSERT INTO sites(site_id) VALUES($1) ON CONFLICT DO NOTHING",
                &[&SITE],
            )
            .await
            .unwrap();
        let request = Request::new(
            Route::telnyx(
                action.account_id,
                Uuid::from_u128(2),
                Uuid::from_u128(3),
                "+15550000000",
                1,
            )
            .unwrap(),
            RECIPIENT,
            Content::ProviderPlaintext("synthetic dispatch fixture"),
        )
        .unwrap();
        Self {
            case,
            action,
            reservation,
            request,
        }
    }
    fn permit(&self) -> ElectedWriterPermit {
        ElectedWriterPermit::synthetic(self.action.account_id, SITE, 1)
    }
    async fn db(&self) -> tokio_postgres::Client {
        self.case.base.f.connect().await
    }
    async fn commit(
        &self,
        attempt: Uuid,
        request: &Request,
        reservation: Uuid,
    ) -> Result<CommitOutcome, DispatchError> {
        commit_submit_intent(
            &mut self.db().await,
            &self.permit(),
            &self.action,
            reservation,
            attempt,
            request,
            RECIPIENT,
        )
        .await
    }
    async fn state(&self, attempt: Uuid) -> String {
        self.case
            .base
            .f
            .db
            .query_one(
                "SELECT state FROM provider_send_attempts WHERE account_id=$1 AND attempt_id=$2",
                &[&self.action.account_id, &attempt],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn attempts(&self) -> i64 {
        self.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM provider_send_attempts", &[])
            .await
            .unwrap()
            .get(0)
    }
    /// Seed one authentic STOP-shaped suppression through its real foreign
    /// keys: message, attempt and captured inbound event.
    async fn stop(&self) {
        let message = Uuid::new_v4();
        self.case
            .base
            .f
            .db
            .execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,\
            transport_mode,transport_payload,request_digest,state,expires_at) \
            VALUES($1,$2,$3,$4,$5,'synthetic_alpha',$6,$7,'delivered',\
            now()+interval '1 hour')",
                &[
                    &message,
                    &self.action.account_id,
                    &self.case.base.f.device,
                    &RECIPIENT,
                    &vec![1_u8; 32],
                    &b"STOP".to_vec(),
                    &vec![2_u8; 32],
                ],
            )
            .await
            .unwrap();
        let attempt = Uuid::new_v4();
        self.case
            .base
            .f
            .db
            .execute(
                "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,\
            session_epoch,deployment_epoch,status) \
            VALUES($1,$2,$3,$4,1,1,1,'submitted')",
                &[
                    &attempt,
                    &self.action.account_id,
                    &message,
                    &self.case.base.f.device,
                ],
            )
            .await
            .unwrap();
        let event = Uuid::new_v4();
        self.case
            .base
            .f
            .db
            .execute(
                "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,\
            device_sequence,classification,observed_at,part_count,content_kind,event_digest,\
            signature_der) \
            VALUES($1,$2,$3,$4,$5,1,'captured_local',now(),1,'metadata_only',$6,$7)",
                &[
                    &event,
                    &self.action.account_id,
                    &self.case.base.f.device,
                    &message,
                    &attempt,
                    &vec![13_u8; 32],
                    &vec![14_u8; 8],
                ],
            )
            .await
            .unwrap();
        self.case
            .base
            .f
            .db
            .execute(
                "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,\
            source_event_id,source_attempt_id,source_observed_at,source) \
            VALUES($1,$2,true,$3,$4,now(),'sms_keyword')",
                &[&self.action.account_id, &RECIPIENT, &event, &attempt],
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_intent_replays_idempotently_and_conflicts_on_changed_commitment() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    assert!(
        f.commit(attempt, &f.request, f.reservation)
            .await
            .unwrap()
            .created
    );
    let replay = f.commit(attempt, &f.request, f.reservation).await.unwrap();
    assert!(!replay.created);
    assert_eq!(replay.attempt_id, attempt);
    // A changed body digest under the same approved action revision conflicts.
    let changed = Request::new(
        Route::telnyx(
            f.action.account_id,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "+15550000000",
            1,
        )
        .unwrap(),
        RECIPIENT,
        Content::ProviderPlaintext("different synthetic commitment"),
    )
    .unwrap();
    assert_eq!(
        f.commit(Uuid::new_v4(), &changed, f.reservation).await,
        Err(DispatchError::Conflict)
    );
    // A nonexistent reservation identity is unavailable before any
    // commitment comparison; a second live reservation for one exact action
    // revision cannot exist because reserve() itself refuses it.
    assert_eq!(
        f.commit(Uuid::new_v4(), &f.request, Uuid::new_v4()).await,
        Err(DispatchError::Unavailable)
    );
    // A recipient that does not hash to the committed request is refused.
    assert_eq!(
        commit_submit_intent(
            &mut f.db().await,
            &f.permit(),
            &f.action,
            f.reservation,
            Uuid::new_v4(),
            &f.request,
            "+15557654321",
        )
        .await,
        Err(DispatchError::Invalid)
    );
    assert_eq!(f.attempts().await, 1);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_intent_refuses_suppression_and_dead_reservations() {
    let f = Fixture::new().await;
    f.stop().await;
    assert_eq!(
        f.commit(Uuid::new_v4(), &f.request, f.reservation).await,
        Err(DispatchError::Suppressed)
    );
    assert_eq!(f.attempts().await, 0);
    f.case
        .base
        .f
        .db
        .execute("DELETE FROM recipient_suppressions", &[])
        .await
        .unwrap();
    // A reservation that never obtained an execution intent is not live
    // submit authority. (An expired lease cannot be simulated by update:
    // the exposure ledger forbids replacing a lease, and expiry sweeps are
    // settlement-side, so the un-intented reservation is the honest check.)
    let reserved = Fixture::configured(false).await;
    assert_eq!(
        reserved
            .commit(Uuid::new_v4(), &reserved.request, reserved.reservation)
            .await,
        Err(DispatchError::Expired)
    );
    assert_eq!(reserved.attempts().await, 0);
    f.case.cleanup().await;
    reserved.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_claim_leases_once_and_records_exactly_one_response() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    f.commit(attempt, &f.request, f.reservation).await.unwrap();
    let leases = claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
        .await
        .unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].attempt_id, attempt);
    assert!(leases[0].lease_until_ms > 0);
    assert!(
        claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.state(attempt).await, "dispatching");
    let message = Uuid::from_u128(77);
    let recorded = record_response(
        &mut f.db().await,
        &f.permit(),
        f.action.account_id,
        attempt,
        ResponseOutcome::Accepted {
            message_id: message,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        recorded,
        ResponseRecorded {
            state: "accepted",
            changed: true
        }
    );
    assert!(
        !record_response(
            &mut f.db().await,
            &f.permit(),
            f.action.account_id,
            attempt,
            ResponseOutcome::Accepted {
                message_id: message
            },
        )
        .await
        .unwrap()
        .changed
    );
    assert_eq!(
        record_response(
            &mut f.db().await,
            &f.permit(),
            f.action.account_id,
            attempt,
            ResponseOutcome::Accepted {
                message_id: Uuid::from_u128(78)
            },
        )
        .await,
        Err(DispatchError::Conflict)
    );
    // An accepted attempt never returns to the intended queue.
    assert!(
        claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_lost_response_is_conservatively_unknown_and_binds_later() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    f.commit(attempt, &f.request, f.reservation).await.unwrap();
    claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
        .await
        .unwrap();
    record_response(
        &mut f.db().await,
        &f.permit(),
        f.action.account_id,
        attempt,
        ResponseOutcome::Lost,
    )
    .await
    .unwrap();
    assert_eq!(f.state(attempt).await, "unknown");
    // Uncertain liability never becomes new sendable work.
    assert!(
        claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    record_response(
        &mut f.db().await,
        &f.permit(),
        f.action.account_id,
        attempt,
        ResponseOutcome::Accepted {
            message_id: Uuid::from_u128(79),
        },
    )
    .await
    .unwrap();
    assert_eq!(f.state(attempt).await, "accepted");
    // A late loss record cannot downgrade recorded evidence.
    let recorded = record_response(
        &mut f.db().await,
        &f.permit(),
        f.action.account_id,
        attempt,
        ResponseOutcome::Lost,
    )
    .await
    .unwrap();
    assert_eq!(recorded.state, "accepted");
    assert!(!recorded.changed);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_release_before_io_and_erasure_keep_the_action_spent() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    f.commit(attempt, &f.request, f.reservation).await.unwrap();
    claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
        .await
        .unwrap();
    record_response(
        &mut f.db().await,
        &f.permit(),
        f.action.account_id,
        attempt,
        ResponseOutcome::Released,
    )
    .await
    .unwrap();
    assert_eq!(f.state(attempt).await, "released");
    assert!(
        claim_intended(&mut f.db().await, &f.permit(), f.action.account_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    // A released fence still consumes the approved action revision.
    assert_eq!(
        f.commit(Uuid::new_v4(), &f.request, f.reservation).await,
        Err(DispatchError::Conflict)
    );
    // Erasure reduces the row to an identity-only fence, like the receipt
    // ledger; the spent action revision still cannot be recommitted.
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE provider_send_attempts SET erased_at=clock_timestamp(),\
        route_fingerprint=NULL,request_digest=NULL,recipient_hash=NULL,\
        reservation_id=NULL,state=NULL,\
        lease_id=NULL,lease_until_ms=NULL,created_epoch=NULL,intended_at=NULL,\
        dispatched_at=NULL,resolved_at=NULL,updated_at=NULL \
        WHERE account_id=$1 AND attempt_id=$2",
            &[&f.action.account_id, &attempt],
        )
        .await
        .unwrap();
    assert_eq!(
        f.commit(Uuid::new_v4(), &f.request, f.reservation).await,
        Err(DispatchError::Conflict)
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_stop_after_intent_keeps_the_attempt_and_its_fence() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    f.commit(attempt, &f.request, f.reservation).await.unwrap();
    // A STOP committing after the intent cannot undo it; the attempt keeps
    // its fence and the suppression records its own limit.
    f.stop().await;
    assert_eq!(f.state(attempt).await, "intended");
    // A replay after the STOP is refused as dispatch authority, not treated
    // as a fresh send; the recorded fence itself is unchanged.
    assert_eq!(
        f.commit(attempt, &f.request, f.reservation).await,
        Err(DispatchError::Suppressed)
    );
    assert_eq!(f.state(attempt).await, "intended");
    f.case.cleanup().await;
}
