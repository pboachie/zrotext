// SPDX-License-Identifier: AGPL-3.0-only
use super::network::{
    capture, configuration, issued_request, source_request_with_owner, submit_issued_request,
};
use super::*;
use crate::workflow_runtime::routines::tests::service::scratch::Scratch;
use std::time::Duration;
use tokio_postgres::Client;

struct Prepared {
    f: OriginalCase,
    scratch: Scratch,
    event: Uuid,
    request: Uuid,
    read: service::IssuedCredential,
    output: IssuedCredential,
    descriptor: decisions::Descriptor,
    caller: Client,
    blocker: Client,
    request_owner: auth::SessionPrincipal,
}
impl Prepared {
    async fn new(output_lifetime: i64) -> Self {
        let mut f = OriginalCase::new().await;
        // The registering session is independently authenticated and distinct from
        // the still-live original credential's creator and interval owner sessions.
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let hash = digest(b"session-v1", &token);
        f.case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&Uuid::new_v4(),&f.case.f.account,&f.case.owner.user_id,&hash.as_slice(),&vec![4u8;32]]).await.unwrap();
        let request_owner = auth::authenticate_session(&f.case.f.db, &f.case.hasher, &token)
            .await
            .unwrap();
        let request = source_request_with_owner(&mut f, request_owner.clone()).await;
        let scratch = Scratch::create().unwrap();
        let event = Uuid::new_v4();
        let mut config = configuration(&f, event).await;
        capture(&f, &mut config, &scratch, event).await;
        let read = f.issue().await;
        f.bind_workflow_request(read.grant_id).await;
        // Prepare connections before imposing a short grant deadline.
        let caller = f.case.f.connect().await;
        let blocker = f.case.f.connect().await;
        f.case.request.permissions =
            Permissions::new(&[Operation::Propose, Operation::ContextContent]).unwrap();
        f.case.request.content_envelope = Some(f.case.projection().await);
        f.case.request.expires_ms = f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+$1",
                &[&output_lifetime],
            )
            .await
            .unwrap()
            .get(0);
        f.bind_workflow_request(read.grant_id).await;
        let output = f.case.issue_another().await;
        let mut descriptor = f.case.descriptor().await;
        let deadline:i64=f.case.f.db.query_one("SELECT LEAST(g.expires_ms,r.expires_ms) FROM original_reply_grants g JOIN original_reply_requests r ON r.account_id=g.account_id WHERE g.account_id=$1 AND g.grant_id=$2 AND r.request_id=$3", &[&f.case.f.account,&read.grant_id,&request]).await.unwrap().get(0);
        descriptor.expires_at = deadline / 1000;
        Self {
            f,
            scratch,
            event,
            request,
            read,
            output,
            descriptor,
            caller,
            blocker,
            request_owner,
        }
    }
    async fn consume(&mut self) -> Result<service::consumption::ResultData, ConversationError> {
        let p = service::authenticate(&self.caller, &self.f.case.hasher, &self.read.token)
            .await
            .unwrap();
        let output = authenticate(&self.caller, &self.f.case.hasher, &self.output.token)
            .await
            .unwrap();
        service::consumption::consume(
            &mut self.caller,
            &p,
            self.f.statement.activation_version,
            service::consumption::Request {
                request_id: Uuid::new_v4(),
                event_id: self.event,
                active_request_id: Some(self.request),
                descriptor: Some(self.descriptor.clone()),
            },
            Some(&output),
        )
        .await
    }
    async fn cleanup(self) {
        self.scratch.remove().unwrap();
        self.f.case.f.cleanup().await;
    }
}
async fn wait_lock(db: &Client, pid: i32) {
    tokio::time::timeout(Duration::from_secs(10),async{
  loop{if db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", &[&pid]).await.unwrap().get::<_,bool>(0){break}tokio::time::sleep(Duration::from_millis(10)).await;}
 }).await.expect("actual caller must reach the held database barrier");
}
async fn wait_deadline(db: &Client, deadline: i64) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let now: i64 = db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if now >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn expiry_barrier(request_owner: bool) {
    let flow = Prepared::new(if request_owner { 60000 } else { 5000 }).await;
    let barrier = Uuid::new_v4().as_u128() as i64;
    flow.f.case.f.db.batch_execute(&format!("CREATE FUNCTION hold_original_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation='consume' THEN PERFORM pg_advisory_xact_lock({barrier}); END IF; RETURN NEW; END; $$; CREATE TRIGGER hold_original_consume BEFORE INSERT ON original_reply_access FOR EACH ROW EXECUTE FUNCTION hold_original_consume();")).await.unwrap();
    flow.blocker
        .query_one("SELECT pg_advisory_lock($1)", &[&barrier])
        .await
        .unwrap();
    let deadline: i64 = if request_owner {
        flow.f.case.f.db.query_one("UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint", &[&flow.request_owner.session_id]).await.unwrap().get(0)
    } else {
        flow.f.case.f.db.query_one("SELECT expires_ms FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$2", &[&flow.f.case.f.account,&flow.output.grant_id]).await.unwrap().get(0)
    };
    let pid: i32 = flow
        .caller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let p = service::authenticate(&flow.caller, &flow.f.case.hasher, &flow.read.token)
        .await
        .unwrap();
    let output = authenticate(&flow.caller, &flow.f.case.hasher, &flow.output.token)
        .await
        .unwrap();
    let accepted = flow.f.statement.activation_version;
    let input = service::consumption::Request {
        request_id: Uuid::new_v4(),
        event_id: flow.event,
        active_request_id: Some(flow.request),
        descriptor: Some(flow.descriptor.clone()),
    };
    let mut caller = flow.caller;
    let task = tokio::spawn(async move {
        service::consumption::consume(&mut caller, &p, accepted, input, Some(&output)).await
    });
    wait_lock(&flow.f.case.f.db, pid).await;
    let live: bool = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint<$1",
            &[&deadline],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        live,
        "authority must still be live at the observed final-write wait"
    );
    wait_deadline(&flow.f.case.f.db, deadline).await;
    flow.blocker
        .query_one("SELECT pg_advisory_unlock($1)", &[&barrier])
        .await
        .unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(ConversationError::Forbidden)
    ));
    let row=flow.f.case.f.db.query_one("SELECT (SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1),(SELECT consumed_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2),(SELECT count(*) FROM workflow_actions WHERE account_id=$1 AND id=$3)", &[&flow.f.case.f.account,&flow.request,&Uuid::parse_str(&flow.descriptor.action_id).unwrap()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i32>(2), 0);
    assert_eq!(row.get::<_, i64>(3), 0);
    drop(flow.blocker);
    flow.scratch.remove().unwrap();
    flow.f.case.f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; final consumption write barrier"]
async fn original_consumption_rolls_back_when_independent_output_grant_expires_at_final_audit() {
    expiry_barrier(false).await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; final consumption write barrier"]
async fn original_consumption_rolls_back_when_independent_request_owner_expires_at_final_audit() {
    expiry_barrier(true).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual two-generation original authority deadline"]
async fn original_lineage_rechecks_earlier_deadline_after_observed_later_hop_wait() {
    let mut flow = Prepared::new(60000).await;
    submit_issued_request(&flow.f, flow.request).await;
    let first = flow.consume().await.unwrap().action.unwrap();
    let version: i64 = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT record_version FROM workflow_actions WHERE account_id=$1 AND id=$2",
            &[&first.account_id, &first.action_id],
        )
        .await
        .unwrap()
        .get(0);
    let approved = decisions::decide(
        &mut flow.f.case.f.connect().await,
        &flow.f.case.owner,
        Uuid::new_v4(),
        version,
        first,
        decisions::model::Decision::Approve,
    )
    .await
    .unwrap();
    let next_request = issued_request(&mut flow.f, approved).await;
    let next_event = Uuid::new_v4();
    let mut config = configuration(&flow.f, next_event).await;
    config["local_sequence"] = serde_json::json!("2");
    capture(&flow.f, &mut config, &flow.scratch, next_event).await;
    // Prepare the independent output before issuing the short original authority.
    // These checks are prerequisite snapshots, never permits for the later consume.
    let mut descriptor = flow.f.case.descriptor().await;
    let output = authenticate(&flow.caller, &flow.f.case.hasher, &flow.output.token)
        .await
        .unwrap();
    let request_state = flow.f.case.f.db.query_one(
        "SELECT action_id,revision,binding_digest,expires_ms,original_reply_source_current(account_id,action_id),workflow_action_origin_current(account_id,action_id) FROM original_reply_requests WHERE account_id=$1 AND request_id=$2",
        &[&flow.f.case.f.account, &next_request],
    ).await.unwrap();
    assert_eq!(request_state.get::<_, Uuid>(0), first.action_id);
    assert_eq!(request_state.get::<_, i64>(1), first.revision);
    assert_eq!(
        request_state.get::<_, Vec<u8>>(2).as_slice(),
        first.binding_digest.as_slice()
    );
    let request_deadline: i64 = request_state.get(3);
    assert!(
        request_state.get::<_, bool>(4),
        "issued parent source must be current"
    );
    assert!(
        request_state.get::<_, bool>(5),
        "issued parent origin must be current"
    );
    {
        let tx = flow.caller.transaction().await.unwrap();
        let checked = crate::workflow_runtime::scope::lock_scope(
            &tx,
            &output,
            flow.f.case.header.context,
            Operation::Propose,
        )
        .await
        .expect("independent output scope must be current");
        checked
            .check_descriptor(&descriptor)
            .expect("prepared output descriptor must match its scope");
        drop(checked);
        tx.rollback().await.unwrap();
    }
    // Verify the newly captured event under the actual still-live first reader
    // before issuing the ten-second credential. This never supplies a cached
    // proof to the later consume, which reauthenticates and verifies it again.
    let history_reader = service::authenticate(&flow.caller, &flow.f.case.hasher, &flow.read.token)
        .await
        .unwrap();
    {
        let tx = flow.caller.transaction().await.unwrap();
        let history_started = std::time::Instant::now();
        let history = service::verified_event(
            &tx,
            &history_reader,
            next_event,
            flow.f.statement.activation_version,
        )
        .await;
        let code = match &history {
            Ok(_) => "ok",
            Err(ConversationError::Forbidden) => "forbidden",
            Err(ConversationError::Database(_)) => "database",
            Err(_) => "other_refusal",
        };
        eprintln!(
            "original_reply_consume phase=event_history reader=parent code={code} elapsed_ms={}",
            history_started.elapsed().as_millis()
        );
        let verified = history.map(|(_, statement, _)| statement.interval);
        tx.rollback().await.unwrap();
        assert!(
            verified
                .map_err(|_| ())
                .expect("captured second event history must verify")
                == flow.f.statement.interval,
            "verified event must retain the selected interval"
        );
    }
    // Sample the actual parent ceilings before the target consume. These are
    // diagnostic snapshots, never authority retained across the next call.
    let parent_snapshot_started = std::time::Instant::now();
    let parent_before = flow.f.case.f.db.query_one(
        "SELECT r.expires_ms,v.expires_at_ms,v.context_authority_deadline_ms,c.expires_at_ms,original_reply_integration_origin_deadline(a.account_id,a.integration_origin_grant,a.id),CASE WHEN EXISTS(SELECT 1 FROM workflow_routine_original_sources o WHERE (o.account_id,o.call_id)=(a.account_id,a.id)) THEN workflow_routine_original_deadline(a.account_id,a.id) ELSE original_reply_source_one_deadline(a.account_id,a.id) END FROM original_reply_requests r JOIN workflow_actions a ON (a.account_id,a.id,a.revision,a.binding_digest)=(r.account_id,r.action_id,r.revision,r.binding_digest) JOIN workflow_action_versions v ON (v.account_id,v.action_id,v.revision,v.binding_digest)=(a.account_id,a.id,a.revision,a.binding_digest) JOIN workflow_contexts c ON (c.account_id,c.id)=(a.account_id,a.context_id) WHERE r.account_id=$1 AND r.request_id=$2",
        &[&flow.f.case.f.account, &next_request],
    ).await.ok();
    let parent_before_clock = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .ok()
        .map(|row| row.get::<_, i64>(0));
    eprintln!(
        "original_reply_consume phase=parent_before available={} clock_present={} elapsed_ms={}",
        parent_before.is_some(),
        parent_before_clock.is_some(),
        parent_snapshot_started.elapsed().as_millis()
    );
    for (index, label) in [
        "parent_request",
        "parent_action",
        "parent_authority",
        "parent_context",
        "parent_origin",
        "parent_ancestry",
    ]
    .into_iter()
    .enumerate()
    {
        let cap = parent_before
            .as_ref()
            .and_then(|row| row.get::<_, Option<i64>>(index));
        let remaining = cap
            .zip(parent_before_clock)
            .map(|(cap, now)| cap.saturating_sub(now));
        eprintln!(
            "original_reply_consume phase=parent_before cap={label} present={} sampled={} live={} remaining_ms={}",
            cap.is_some(),
            remaining.is_some(),
            remaining.is_some_and(|v| v > 0),
            remaining.unwrap_or(0)
        );
    }
    // Both caller/blocker were opened before issuing this bounded short authority.
    let second_read = flow.f.issue_with_lifetime(10000).await;
    let deadline: i64 = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT expires_ms FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
            &[&flow.f.case.f.account, &second_read.grant_id],
        )
        .await
        .unwrap()
        .get(0);
    // Preserve the independent live request and the original ten-second target.
    assert!(request_deadline > deadline);
    descriptor.expires_at = deadline.min(request_deadline) / 1000;
    let p = service::authenticate(&flow.caller, &flow.f.case.hasher, &second_read.token)
        .await
        .unwrap();
    {
        let tx = flow.caller.transaction().await.unwrap();
        let (proof, statement) = service::locked(&tx, &p, flow.f.statement.activation_version)
            .await
            .expect("second reader must have current original authority");
        assert_eq!(statement.interval, flow.f.statement.interval);
        assert_eq!(proof.interval_id, flow.f.statement.interval);
        assert_eq!(
            proof.expires_at_ms, deadline,
            "short grant must remain the limiting original authority"
        );
        assert!(proof.observed_at_ms < deadline);
        assert!(descriptor.expires_at_ms().unwrap() <= proof.expires_at_ms);
        tx.rollback().await.unwrap();
    }
    let consumption_id = Uuid::new_v4();
    let selected_child = descriptor.key().unwrap().action_id;
    let child_deadline = descriptor.expires_at_ms().unwrap();
    let consume_before_clock = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .ok()
        .map(|row| row.get::<_, i64>(0));
    let consume_started = std::time::Instant::now();
    let second_attempt = service::consumption::consume(
        &mut flow.caller,
        &p,
        flow.f.statement.activation_version,
        service::consumption::Request {
            request_id: consumption_id,
            event_id: next_event,
            active_request_id: Some(next_request),
            descriptor: Some(descriptor),
        },
        Some(&output),
    )
    .await;
    let consume_elapsed_ms = consume_started.elapsed().as_millis();
    if second_attempt.is_err() {
        // The consume has already settled. These read-only diagnostics cannot
        // change its returned refusal, renew authority, or replace its assertion.
        let code = match &second_attempt {
            Err(ConversationError::Forbidden) => "forbidden",
            Err(ConversationError::Database(_)) => "database",
            Err(_) => "other_refusal",
            Ok(_) => "ok",
        };
        let post_started = std::time::Instant::now();
        let settled_clock = flow
            .f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .ok()
            .map(|row| row.get::<_, i64>(0));
        let parent_after = flow.f.case.f.db.query_one(
            "SELECT r.expires_ms,v.expires_at_ms,v.context_authority_deadline_ms,c.expires_at_ms,original_reply_integration_origin_deadline(a.account_id,a.integration_origin_grant,a.id),CASE WHEN EXISTS(SELECT 1 FROM workflow_routine_original_sources o WHERE (o.account_id,o.call_id)=(a.account_id,a.id)) THEN workflow_routine_original_deadline(a.account_id,a.id) ELSE original_reply_source_one_deadline(a.account_id,a.id) END FROM original_reply_requests r JOIN workflow_actions a ON (a.account_id,a.id,a.revision,a.binding_digest)=(r.account_id,r.action_id,r.revision,r.binding_digest) JOIN workflow_action_versions v ON (v.account_id,v.action_id,v.revision,v.binding_digest)=(a.account_id,a.id,a.revision,a.binding_digest) JOIN workflow_contexts c ON (c.account_id,c.id)=(a.account_id,a.context_id) WHERE r.account_id=$1 AND r.request_id=$2",
            &[&flow.f.case.f.account, &next_request],
        ).await.ok();
        let status = flow.f.case.f.db.query_one(
            "SELECT original_reply_grant_current($1,$2),original_reply_source_current($1,$3),workflow_action_origin_current($1,$3),EXISTS(SELECT 1 FROM workflow_actions WHERE account_id=$1 AND id=$4),EXISTS(SELECT 1 FROM original_reply_sources WHERE account_id=$1 AND action_id=$4),EXISTS(SELECT 1 FROM original_reply_consumptions WHERE account_id=$1 AND consumption_id=$5)",
            &[&flow.f.case.f.account, &second_read.grant_id, &first.action_id, &selected_child, &consumption_id],
        ).await.ok();
        let after_clock = flow
            .f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .ok()
            .map(|row| row.get::<_, i64>(0));
        eprintln!(
            "original_reply_consume phase=settled code={code} consume_elapsed_ms={consume_elapsed_ms} clock_span_sampled={} clock_span_ms={} child_before_sampled={} child_before_remaining_ms={} child_settled_sampled={} child_settled_remaining_ms={} post_elapsed_ms={} caps_available={} status_available={}",
            consume_before_clock.zip(settled_clock).is_some(),
            consume_before_clock
                .zip(settled_clock)
                .map(|(before, after)| after.saturating_sub(before))
                .unwrap_or(0),
            consume_before_clock.is_some(),
            consume_before_clock
                .map(|now| child_deadline.saturating_sub(now))
                .unwrap_or(0),
            settled_clock.is_some(),
            settled_clock
                .map(|now| child_deadline.saturating_sub(now))
                .unwrap_or(0),
            post_started.elapsed().as_millis(),
            parent_after.is_some(),
            status.is_some()
        );
        for (index, label) in [
            "parent_request",
            "parent_action",
            "parent_authority",
            "parent_context",
            "parent_origin",
            "parent_ancestry",
        ]
        .into_iter()
        .enumerate()
        {
            let cap = parent_after
                .as_ref()
                .and_then(|row| row.get::<_, Option<i64>>(index));
            let remaining = cap
                .zip(after_clock)
                .map(|(cap, now)| cap.saturating_sub(now));
            eprintln!(
                "original_reply_consume phase=post_refusal cap={label} present={} sampled={} live={} remaining_ms={}",
                cap.is_some(),
                remaining.is_some(),
                remaining.is_some_and(|v| v > 0),
                remaining.unwrap_or(0)
            );
        }
        for (index, label) in [
            "reader_current",
            "parent_source_current",
            "parent_origin_current",
            "child_action_present",
            "child_source_present",
            "consume_receipt_present",
        ]
        .into_iter()
        .enumerate()
        {
            eprintln!(
                "original_reply_consume phase=post_refusal status={label} available={} value={}",
                status.is_some(),
                status.as_ref().is_some_and(|row| row.get::<_, bool>(index))
            );
        }
    }
    let second = second_attempt.unwrap().action.unwrap();
    for key in [first, second] {
        assert!(
            flow.f
                .case
                .f
                .db
                .query_one(
                    "SELECT original_reply_source_current($1,$2)",
                    &[&key.account_id, &key.action_id]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    let barrier = Uuid::new_v4().as_u128() as i64;
    flow.blocker
        .query_one("SELECT pg_advisory_lock($1)", &[&barrier])
        .await
        .unwrap();
    // Only the isolated fixture wraps the real one-hop predicate. It first captures
    // its actual enforced deadline, then waits at the later ancestor. No unconditional
    // valid deadline, fabricated provider success, or production sleep is installed.
    flow.f.case.f.db.batch_execute("CREATE TABLE fixture_original_deadline_barrier(action_id uuid PRIMARY KEY,barrier bigint NOT NULL)").await.unwrap();
    flow.f
        .case
        .f
        .db
        .execute(
            "INSERT INTO fixture_original_deadline_barrier(action_id,barrier) VALUES($1,$2)",
            &[&first.action_id, &barrier],
        )
        .await
        .unwrap();
    flow.f.case.f.db.batch_execute("ALTER FUNCTION original_reply_source_one_deadline(uuid,uuid) RENAME TO original_reply_source_one_real_deadline; CREATE FUNCTION original_reply_source_one_deadline(wanted_account uuid,wanted_action uuid) RETURNS bigint LANGUAGE plpgsql VOLATILE SET search_path FROM CURRENT AS $$ DECLARE actual_deadline bigint; wait_barrier bigint; BEGIN actual_deadline:=original_reply_source_one_real_deadline(wanted_account,wanted_action); SELECT barrier INTO wait_barrier FROM fixture_original_deadline_barrier WHERE action_id=wanted_action; IF FOUND THEN PERFORM pg_advisory_xact_lock(wait_barrier); END IF; RETURN actual_deadline; END; $$;").await.unwrap();
    let pid: i32 = flow
        .caller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let caller = flow.caller;
    let task = tokio::spawn(async move {
        caller
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&second.account_id, &second.action_id],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    });
    wait_lock(&flow.f.case.f.db, pid).await;
    assert!(
        flow.f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint<$1",
                &[&deadline]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    wait_deadline(&flow.f.case.f.db, deadline).await;
    flow.blocker
        .query_one("SELECT pg_advisory_unlock($1)", &[&barrier])
        .await
        .unwrap();
    assert!(
        !task.await.unwrap(),
        "earlier real authority must not survive a later-hop wait"
    );
    drop(flow.blocker);
    flow.scratch.remove().unwrap();
    flow.f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; exact multiple qualifying original requests"]
async fn original_reply_ambiguous_active_requests_require_owner_review_without_debit_or_proposal() {
    let mut flow = Prepared::new(60000).await;
    submit_issued_request(&flow.f, flow.request).await;
    // A second independently approved/issued request is genuinely eligible for the
    // same interval and observation. Supplying one ID must not choose for the owner.
    let owner = flow.f.case.owner.clone();
    let _other = source_request_with_owner(&mut flow.f, owner).await;
    let later = Uuid::new_v4();
    let mut config = configuration(&flow.f, later).await;
    config["local_sequence"] = serde_json::json!("2");
    capture(&flow.f, &mut config, &flow.scratch, later).await;
    flow.event = later;
    let result = flow.consume().await.unwrap();
    assert_eq!(result.disposition, "owner_review");
    assert!(result.action.is_none());
    let row=flow.f.case.f.db.query_one("SELECT (SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT sum(consumed_turns)::bigint FROM original_reply_requests WHERE account_id=$1)",&[&flow.f.case.f.account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, Option<i64>>(1), Some(0));
    flow.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; retained event page/purge barrier"]
async fn original_page_serializes_selected_event_purge_and_refuses_deleted_cursor() {
    let flow = Prepared::new(60000).await;
    let barrier = Uuid::new_v4().as_u128() as i64;
    flow.f.case.f.db.batch_execute(&format!("CREATE FUNCTION hold_original_page() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation='page' THEN PERFORM pg_advisory_xact_lock({barrier}); END IF; RETURN NEW; END; $$; CREATE TRIGGER hold_original_page BEFORE INSERT ON original_reply_access FOR EACH ROW EXECUTE FUNCTION hold_original_page();")).await.unwrap();
    flow.blocker
        .query_one("SELECT pg_advisory_lock($1)", &[&barrier])
        .await
        .unwrap();
    let purger = flow.f.case.f.connect().await;
    let purge_pid: i32 = purger
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let page_pid: i32 = flow
        .caller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let p = service::authenticate(&flow.caller, &flow.f.case.hasher, &flow.read.token)
        .await
        .unwrap();
    let accepted = flow.f.statement.activation_version;
    let cursor_time:i64=flow.f.case.f.db.query_one("SELECT accepted_at_ms FROM conversation_inbound_provenance WHERE account_id=$1 AND event_id=$2",&[&flow.f.case.f.account,&flow.event]).await.unwrap().get(0);
    let account = flow.f.case.f.account;
    let event = flow.event;
    let mut caller = flow.caller;
    let page_task = tokio::spawn(async move {
        let result = service::page::page(&mut caller, &p, accepted, None, 32).await;
        (caller, p, result)
    });
    wait_lock(&flow.f.case.f.db, page_pid).await;
    let purge_task = tokio::spawn(async move {
        purger
            .execute(
                "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
                &[&account, &event],
            )
            .await
            .unwrap()
    });
    wait_lock(&flow.f.case.f.db, purge_pid).await;
    assert!(flow.f.case.f.db.query_one("SELECT envelope IS NOT NULL FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",&[&account,&event]).await.unwrap().get::<_,bool>(0));
    flow.blocker
        .query_one("SELECT pg_advisory_unlock($1)", &[&barrier])
        .await
        .unwrap();
    let (mut caller, p, page) = page_task.await.unwrap();
    let page = page.unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event_id, event);
    assert_eq!(purge_task.await.unwrap(), 1);
    assert!(
        service::page::page(&mut caller, &p, accepted, None, 32)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert!(matches!(
        service::page::page(
            &mut caller,
            &p,
            accepted,
            Some(service::page::Cursor {
                accepted_at_ms: cursor_time,
                event_id: event
            }),
            32
        )
        .await,
        Err(ConversationError::Unavailable)
    ));
    assert!(matches!(
        service::page::page(
            &mut caller,
            &p,
            accepted,
            Some(service::page::Cursor {
                accepted_at_ms: cursor_time,
                event_id: Uuid::new_v4()
            }),
            32
        )
        .await,
        Err(ConversationError::Unavailable)
    ));
    drop(caller);
    drop(flow.blocker);
    flow.scratch.remove().unwrap();
    flow.f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original turn admission race"]
async fn original_reply_concurrent_distinct_events_cannot_exceed_one_owner_approved_turn() {
    let flow = Prepared::new(60000).await;
    let next = Uuid::new_v4();
    let mut config = configuration(&flow.f, next).await;
    config["local_sequence"] = serde_json::json!("2");
    capture(&flow.f, &mut config, &flow.scratch, next).await;
    let mut second_client = flow.f.case.f.connect().await;
    let p1 = service::authenticate(&flow.caller, &flow.f.case.hasher, &flow.read.token)
        .await
        .unwrap();
    let p2 = service::authenticate(&second_client, &flow.f.case.hasher, &flow.read.token)
        .await
        .unwrap();
    let output = authenticate(&flow.caller, &flow.f.case.hasher, &flow.output.token)
        .await
        .unwrap();
    let output2 = output.clone();
    let accepted = flow.f.statement.activation_version;
    let first_input = service::consumption::Request {
        request_id: Uuid::new_v4(),
        event_id: flow.event,
        active_request_id: Some(flow.request),
        descriptor: Some(flow.descriptor.clone()),
    };
    let mut descriptor = flow.descriptor.clone();
    descriptor.action_id = Uuid::new_v4().to_string();
    descriptor.routine_id = Uuid::new_v4().to_string();
    let second_input = service::consumption::Request {
        request_id: Uuid::new_v4(),
        event_id: next,
        active_request_id: Some(flow.request),
        descriptor: Some(descriptor),
    };
    let mut caller = flow.caller;
    let a = tokio::spawn(async move {
        service::consumption::consume(&mut caller, &p1, accepted, first_input, Some(&output))
            .await
            .unwrap()
    });
    let b = tokio::spawn(async move {
        service::consumption::consume(
            &mut second_client,
            &p2,
            accepted,
            second_input,
            Some(&output2),
        )
        .await
        .unwrap()
    });
    let results = [a.await.unwrap(), b.await.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| r.disposition == "proposal")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r.disposition == "owner_review")
            .count(),
        1
    );
    let row=flow.f.case.f.db.query_one("SELECT (SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1),(SELECT consumed_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2)",&[&flow.f.case.f.account,&flow.request]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 2);
    assert_eq!(row.get::<_, i32>(2), 1);
    drop(flow.blocker);
    flow.scratch.remove().unwrap();
    flow.f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original final write rollback"]
async fn original_reply_final_audit_failure_rolls_back_proposal_source_turn_and_receipt() {
    let mut flow = Prepared::new(60000).await;
    flow.f.case.f.db.batch_execute("CREATE FUNCTION reject_original_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation='consume' THEN RAISE EXCEPTION 'synthetic final write refusal' USING ERRCODE='23514'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_original_consume BEFORE INSERT ON original_reply_access FOR EACH ROW EXECUTE FUNCTION reject_original_consume();").await.unwrap();
    assert!(matches!(
        flow.consume().await,
        Err(ConversationError::Database(_))
    ));
    let row=flow.f.case.f.db.query_one("SELECT (SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1),(SELECT consumed_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2),(SELECT count(*) FROM workflow_actions WHERE account_id=$1 AND id=$3)",&[&flow.f.case.f.account,&flow.request,&Uuid::parse_str(&flow.descriptor.action_id).unwrap()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i32>(2), 0);
    assert_eq!(row.get::<_, i64>(3), 0);
    flow.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; retained original source provenance after pruning"]
async fn original_source_survives_grant_and_ciphertext_deletion_and_cannot_become_ordinary() {
    let mut flow = Prepared::new(60000).await;
    let key = flow.consume().await.unwrap().action.unwrap();
    assert!(
        flow.f
            .case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&key.account_id, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    flow.f
        .case
        .f
        .db
        .execute(
            "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
            &[&key.account_id, &flow.event],
        )
        .await
        .unwrap();
    flow.f
        .case
        .f
        .db
        .execute(
            "DELETE FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
            &[&key.account_id, &flow.read.grant_id],
        )
        .await
        .unwrap();
    assert_eq!(
        flow.f
            .case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM original_reply_sources WHERE account_id=$1 AND action_id=$2",
                &[&key.account_id, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert!(
        !flow
            .f
            .case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&key.account_id, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let record: i64 = flow
        .f
        .case
        .f
        .db
        .query_one(
            "SELECT record_version FROM workflow_actions WHERE account_id=$1 AND id=$2",
            &[&key.account_id, &key.action_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(matches!(
        decisions::decide(
            &mut flow.f.case.f.connect().await,
            &flow.f.case.owner,
            Uuid::new_v4(),
            record,
            key,
            decisions::model::Decision::Approve
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    flow.cleanup().await;
}
