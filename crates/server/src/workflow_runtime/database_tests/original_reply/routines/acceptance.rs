// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn assert_preparable(f: &RoutineCase, key: decisions::ActionKey) {
    assert!(f.current(key.action_id).await.is_ok());
    assert!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT workflow_routine_original_action_current($1,$2)",
                &[&key.account_id, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = decisions::lock_approved(&tx, &f.f.case.owner, key)
        .await
        .unwrap();
    permit.recheck().await.unwrap();
    drop(permit);
    tx.rollback().await.unwrap();
}

async fn linked_event(f: &mut RoutineCase) -> Uuid {
    let request = super::super::network::source_request(&mut f.f).await;
    let event = Uuid::new_v4();
    let mut seed = configuration(&f.f, event).await;
    seed["local_sequence"] = json!("2");
    capture(&f.f, &mut seed, &f.scratch, event).await;
    f.invocation.event_id = event;
    let digest: Vec<u8> =
        f.f.case
            .f
            .db
            .query_one(
                "SELECT sha256(envelope) FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
                &[&f.f.case.f.account, &event],
            )
            .await
            .unwrap()
            .get(0);
    f.invocation.event_envelope_digest = decisions::descriptor::hex(&digest);
    request
}

async fn consume(
    f: &mut RoutineCase,
    request: Uuid,
    automatic: bool,
) -> Result<service::consumption::ResultData, ConversationError> {
    let original = service::authenticate(&f.f.case.f.db, &f.f.case.hasher, &f.read.token)
        .await
        .unwrap();
    let (descriptor, output) = if automatic {
        f.f.case.request.permissions =
            Permissions::new(&[Operation::ContextContent, Operation::Propose]).unwrap();
        f.f.case.request.content_envelope = Some(f.f.case.projection().await);
        let token = f.f.case.issue_another().await;
        let output = authenticate(&f.f.case.f.db, &f.f.case.hasher, &token.token)
            .await
            .unwrap();
        let mut d = f.f.case.descriptor().await;
        d.window_id = crate::workflow_runtime::IMMEDIATE_WINDOW_ID.into();
        let deadline: i64 = f.f.case.f.db.query_one(
            "SELECT LEAST(g.expires_ms,r.expires_ms) FROM original_reply_grants g JOIN original_reply_requests r ON r.account_id=g.account_id WHERE g.account_id=$1 AND g.grant_id=$2 AND r.request_id=$3",
            &[&f.f.case.f.account,&f.read.grant_id,&request]).await.unwrap().get(0);
        d.expires_at = d.expires_at.min(deadline / 1000);
        (Some(d), Some(output))
    } else {
        (None, None)
    };
    service::consumption::consume(
        &mut f.f.case.f.connect().await,
        &original,
        f.invocation.accepted_manifest_version,
        service::consumption::Request {
            request_id: Uuid::new_v4(),
            event_id: f.invocation.event_id,
            active_request_id: Some(request),
            descriptor,
        },
        output.as_ref(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real original cross-path authority"]
async fn original_reply_proposal_excludes_routine_execution_for_the_same_event() {
    let mut f = RoutineCase::new().await;
    let request = linked_event(&mut f).await;
    assert!(
        consume(&mut f, request, true)
            .await
            .unwrap()
            .action
            .is_some()
    );
    assert!(matches!(
        f.admit(f.invocation.clone()).await,
        Err(AuthError::Conflict)
    ));
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real original cross-path authority"]
async fn routine_execution_excludes_reply_proposal_but_preserves_owner_review() {
    let mut f = RoutineCase::new().await;
    let request = linked_event(&mut f).await;
    assert!(f.admit(f.invocation.clone()).await.unwrap().execute_once);
    assert!(matches!(
        consume(&mut f, request, true).await,
        Err(ConversationError::Conflict)
    ));
    let receipt = consume(&mut f, request, false).await.unwrap();
    assert_eq!(receipt.disposition, "owner_review");
    assert!(receipt.action.is_none());
    assert_eq!(f.f.case.f.db.query_one("SELECT consumed_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2", &[&f.f.case.f.account,&request]).await.unwrap().get::<_,i32>(0),0);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real original owner review admission"]
async fn owner_review_receipt_does_not_consume_original_routine_execution_authority() {
    let mut f = RoutineCase::new().await;
    let request = linked_event(&mut f).await;
    let receipt = consume(&mut f, request, false).await.unwrap();
    assert_eq!(receipt.disposition, "owner_review");
    assert!(receipt.action.is_none());
    assert!(f.admit(f.invocation.clone()).await.unwrap().execute_once);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual original budget transaction rollback"]
async fn failed_original_call_insert_rolls_back_source_budget_turn_and_replay_identity() {
    let f = RoutineCase::new().await;
    f.f.case.f.db.batch_execute("CREATE FUNCTION refuse_original_call() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic call failure' USING ERRCODE='23514'; END; $$; CREATE TRIGGER refuse_original_call BEFORE INSERT ON workflow_routine_calls FOR EACH ROW EXECUTE FUNCTION refuse_original_call();").await.unwrap();
    assert!(matches!(
        f.admit(f.invocation.clone()).await,
        Err(AuthError::Database(_))
    ));
    let counts=f.f.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_calls WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_turn_debits WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1)", &[&f.f.case.f.account]).await.unwrap();
    for index in 0..5 {
        assert_eq!(counts.get::<_, i64>(index), 0);
    }
    f.f.case
        .f
        .db
        .batch_execute("DROP TRIGGER refuse_original_call ON workflow_routine_calls")
        .await
        .unwrap();
    assert!(f.admit(f.invocation.clone()).await.unwrap().execute_once);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; simultaneous genuine original last turn"]
async fn competing_original_events_spend_the_last_turn_once_and_rollback_losing_source() {
    let f = RoutineCase::new().await;
    let mut policy = f.policy.clone();
    policy.request_id = Uuid::new_v4();
    policy.policy_id = Uuid::new_v4();
    policy.routine_id = Uuid::new_v4();
    policy.turn_limit = 1;
    let original = service::authenticate(&f.f.case.f.db, &f.f.case.hasher, &f.read.token)
        .await
        .unwrap();
    routines::configure_with_original(
        &mut f.f.case.f.connect().await,
        &f.f.case.owner,
        &f.input,
        Some(&original),
        policy.clone(),
    )
    .await
    .unwrap();
    let event = Uuid::new_v4();
    let mut seed = configuration(&f.f, event).await;
    seed["local_sequence"] = json!("2");
    capture(&f.f, &mut seed, &f.scratch, event).await;
    let mut one = f.invocation.clone();
    one.policy_id = policy.policy_id;
    let mut two = one.clone();
    two.request_id = Uuid::new_v4();
    two.event_id = event;
    two.event_envelope_digest = decisions::descriptor::hex(
        &f.f.case
            .f
            .db
            .query_one(
                "SELECT sha256(envelope) FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
                &[&f.f.case.f.account, &event],
            )
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
    );
    let (a, b) = tokio::join!(f.admit(one), f.admit(two));
    assert!(a.is_ok() ^ b.is_ok());
    let loser = if a.is_ok() { b } else { a };
    assert!(matches!(loser, Err(AuthError::RateLimited)));
    let row=f.f.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1),(SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT sum(units)::bigint FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1 AND context_id=$2)",&[&f.f.case.f.account,&f.policy.context_id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Option<i64>>(1), Some(1));
    assert_eq!(row.get::<_, Option<i64>>(2), Some(4));
    assert_eq!(row.get::<_, i64>(3), 1);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original sensitive proposal exact owner authority"]
async fn sensitive_original_output_cannot_prepare_before_exact_owner_approval() {
    let mut f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let key = f.owner_publish_and_propose(call.call_id).await;
    let state = decisions::read(&mut f.f.case.f.connect().await, &f.f.case.owner, key)
        .await
        .unwrap();
    assert_eq!(state.key, key);
    assert_eq!(state.phase, decisions::model::Phase::Proposed);
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(matches!(
        decisions::lock_approved(&tx, &f.f.case.owner, key).await,
        Err(ConversationError::Conflict)
    ));
    tx.rollback().await.unwrap();
    drop(db);
    let descriptor:Vec<u8>=f.f.case.f.db.query_one("SELECT descriptor FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3",&[&key.account_id,&key.action_id,&key.revision]).await.unwrap().get(0);
    assert_eq!(
        serde_json::from_slice::<Value>(&descriptor).unwrap()["commitment"],
        "sensitive"
    );
    f.approve(key).await;
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let permit = decisions::lock_approved(&tx, &f.f.case.owner, key)
        .await
        .unwrap();
    drop(permit);
    tx.rollback().await.unwrap();
    drop(db);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual owner takeover on original source context"]
async fn owner_takeover_stops_original_execution_and_its_separate_proposal() {
    let mut f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let key = f.owner_publish_and_propose(call.call_id).await;
    f.approve(key).await;
    assert_preparable(&f, key).await;
    decisions::takeover(
        &mut f.f.case.f.connect().await,
        &f.f.case.owner,
        Uuid::new_v4(),
        f.policy.context_id,
    )
    .await
    .unwrap();
    assert!(matches!(
        f.current(call.call_id).await,
        Err(AuthError::Forbidden)
    ));
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(matches!(
        decisions::lock_approved(&tx, &f.f.case.owner, key).await,
        Err(ConversationError::Forbidden)
    ));
    tx.rollback().await.unwrap();
    drop(db);
    assert!(
        !f.f.case
            .f
            .db
            .query_one(
                "SELECT workflow_routine_original_action_current($1,$2)",
                &[&key.account_id, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine signed line STOP original source fence"]
async fn signed_line_stop_refuses_original_work_and_preparation_without_refunding_unknown() {
    use crate::inbound::{
        InboundSession,
        unsolicited::{self, Action, LineOptOut},
    };
    use p256::ecdsa::{Signature, signature::Signer};
    let mut f = RoutineCase::new().await;
    // This synthetic fixture initially has an opaque device transport key.
    // Install its real test signer before exercising the signed STOP API.
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    f.f.case
        .f
        .db
        .execute(
            "UPDATE device_keys SET signing_key_sec1=$3 WHERE account_id=$1 AND device_id=$2",
            &[
                &f.f.case.f.account,
                &f.f.case.f.device,
                &key.verifying_key().to_sec1_point(false).as_bytes(),
            ],
        )
        .await
        .unwrap();
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let action = f.owner_publish_and_propose(call.call_id).await;
    f.approve(action).await;
    assert_preparable(&f, action).await;
    let session = InboundSession {
        account_id: f.f.case.f.account,
        device_id: f.f.case.f.device,
        site_id: "manifest-test",
        instance_id: "fixture",
        connection_epoch: 1,
        deployment_epoch: 1,
    };
    let observed: i64 =
        f.f.case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    let unsigned = LineOptOut {
        id: Uuid::new_v4(),
        line_id: f.f.case.f.line,
        binding_generation: 1,
        sequence: 1,
        recipient_e164: "+12",
        action: Action::Stop,
        observed_at_ms: observed,
        signature_der: &[],
    };
    let signature: Signature =
        key.sign(&unsolicited::signed_line_opt_out_bytes(session, &unsigned).unwrap());
    let der = signature.to_der();
    let stop = LineOptOut {
        signature_der: der.as_bytes(),
        ..unsigned
    };
    assert!(
        unsolicited::ingest_line_opt_out(&mut f.f.case.f.connect().await, session, &stop)
            .await
            .unwrap()
    );
    assert!(
        !unsolicited::ingest_line_opt_out(&mut f.f.case.f.connect().await, session, &stop)
            .await
            .unwrap()
    );
    assert!(matches!(
        f.current(call.call_id).await,
        Err(AuthError::Forbidden)
    ));
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(matches!(
        decisions::lock_approved(&tx, &f.f.case.owner, action).await,
        Err(ConversationError::Forbidden)
    ));
    tx.rollback().await.unwrap();
    drop(db);
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, Option<i64>>(0),
        Some(1)
    );
    f.finish().await;
}
