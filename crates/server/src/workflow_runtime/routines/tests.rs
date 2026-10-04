// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::workflow_runtime::{Permissions, authenticate, database_tests::Case};

mod consent;

async fn prepared() -> (Case, IntegrationPrincipal, Policy, Invocation) {
    prepared_with_signer(false).await
}

async fn prepared_with_signer(
    with_signer: bool,
) -> (Case, IntegrationPrincipal, Policy, Invocation) {
    let mut case = if with_signer {
        Case::for_customer_routine(Some(120000)).await
    } else {
        Case::for_customer_routine(None).await
    };
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    case.request.content_envelope = Some(case.projection().await);
    let credential = case.issue().await.unwrap();
    let input = authenticate(&case.f.db, &case.hasher, &credential.token)
        .await
        .unwrap();
    let declared = case.descriptor().await;
    let clock=case.f.db.query_one("WITH snapshot(t) AS (SELECT clock_timestamp()) SELECT to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD'),(extract(hour FROM t AT TIME ZONE 'UTC')::integer*60+extract(minute FROM t AT TIME ZONE 'UTC')::integer) FROM snapshot",&[]).await.unwrap();
    let date: String = clock.get(0);
    let minute: u16 = clock.get::<_, i32>(1).try_into().unwrap();
    let policy = Policy {
        request_id: Uuid::new_v4(),
        policy_id: Uuid::new_v4(),
        context_id: case.header.context,
        routine_id: Uuid::new_v4(),
        generation: 3,
        kind: contracts::Kind::Faq,
        executor: contracts::Executor::DeterministicLocal,
        original_input: None,
        adapter_id: None,
        artifact_digest: None,
        period: contracts::Period::UtcDay,
        expires_ms: case.request.expires_ms,
        call_limit: 100,
        unit_limit: 1000,
        units_per_call: 5,
        turn_limit: 3,
        timeout_ms: 1000,
        window: crate::encrypted_schedule::policy::WindowPolicy {
            timezone: Some("UTC".into()),
            first_local_date: date,
            opens_minute: minute.saturating_sub(1),
            closes_minute: (minute + 30) % 1440,
            repeat_every_days: None,
            max_occurrences: 1,
            pacing_seconds: 60,
        },
    };
    configure(
        &mut case.f.connect().await,
        &case.owner,
        &input,
        policy.clone(),
    )
    .await
    .unwrap();
    let invocation = Invocation {
        request_id: Uuid::new_v4(),
        policy_id: policy.policy_id,
        context_id: case.header.context,
        input_revision: 1,
        input_source_digest: declared.content_digest,
        direction: Direction::OwnerDeclared,
    };
    (case, input, policy, invocation)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn local_process_installation_is_owner_pinned_and_cannot_change_on_replay() {
    let (case, input, mut policy, _) = prepared().await;
    policy.policy_id = Uuid::new_v4();
    policy.request_id = Uuid::new_v4();
    policy.executor = contracts::Executor::LocalProcess;
    policy.adapter_id = Some("customer_faq".into());
    policy.artifact_digest = Some("ab".repeat(32));
    configure(
        &mut case.f.connect().await,
        &case.owner,
        &input,
        policy.clone(),
    )
    .await
    .unwrap();
    let stored = current(
        &mut case.f.connect().await,
        &input,
        policy.context_id,
        policy.policy_id,
    )
    .await
    .unwrap();
    assert_eq!(stored.executor, contracts::Executor::LocalProcess);
    assert_eq!(stored.adapter_id, policy.adapter_id);
    assert_eq!(stored.artifact_digest, policy.artifact_digest);
    assert!(case.f.db.execute("INSERT INTO workflow_routine_policies SELECT account_id,$2,input_grant_id,context_id,input_revision,input_digest,routine_id,generation,policy-'artifact_digest',policy_digest,created_by_user,created_session,expires_ms,withdrawn_ms FROM workflow_routine_policies WHERE id=$1", &[&policy.policy_id,&Uuid::new_v4()]).await.is_err());
    let mut changed = policy.clone();
    changed.artifact_digest = Some("cd".repeat(32));
    assert!(matches!(
        configure(&mut case.f.connect().await, &case.owner, &input, changed).await,
        Err(AuthError::Conflict)
    ));
    assert!(case.f.db.execute("UPDATE workflow_routine_policies SET policy=jsonb_set(policy,'{artifact_digest}','\"changed\"') WHERE id=$1", &[&policy.policy_id]).await.is_err());
    withdraw(&mut case.f.connect().await, &case.owner, policy.policy_id)
        .await
        .unwrap();
    assert!(matches!(
        current(
            &mut case.f.connect().await,
            &input,
            policy.context_id,
            policy.policy_id
        )
        .await,
        Err(AuthError::Forbidden)
    ));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn unknown_admission_replay_never_executes_or_debits_twice() {
    let (case, input, _, v) = prepared().await;
    let first = admit(&mut case.f.connect().await, &input, v.clone())
        .await
        .unwrap();
    assert!(first.execute_once);
    let replay = admit(&mut case.f.connect().await, &input, v).await.unwrap();
    assert!(!replay.execute_once);
    assert_eq!(replay.phase, Phase::Unknown);
    let row = case
        .f
        .db
        .query_one(
            "SELECT calls,units FROM workflow_routine_period_debits WHERE account_id=$1",
            &[&case.f.account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 5);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn lifetime_admission_ceiling_does_not_reset_on_new_utc_period() {
    let (case, input, _, v) = prepared().await;
    case.f.db.execute("INSERT INTO workflow_routine_admission_tombstones(account_id,call_id,request_digest) SELECT $1,md5(n::text)::uuid,decode(repeat('ab',32),'hex') FROM generate_series(1,1000) n",&[&case.f.account]).await.unwrap();
    // No daily debit exists yet: lifetime replay bound still refuses admission.
    assert!(matches!(
        admit(&mut case.f.connect().await, &input, v).await,
        Err(AuthError::RateLimited)
    ));
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_period_debits WHERE account_id=$1",
                &[&case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1",
                &[&case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1000
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn withdrawn_policy_pruning_preserves_spent_turns_and_replay_identity() {
    let (mut case, input, p, v) = prepared().await;
    admit(&mut case.f.connect().await, &input, v.clone())
        .await
        .unwrap();
    withdraw(&mut case.f.connect().await, &case.owner, p.policy_id)
        .await
        .unwrap();
    assert_eq!(
        lifecycle::prune(&mut case.f.connect().await, 1)
            .await
            .unwrap(),
        1
    );
    for (table, expected) in [
        ("workflow_routine_calls", 0),
        ("workflow_routine_policies", 0),
        ("workflow_routine_period_debits", 1),
        ("workflow_routine_turn_debits", 1),
        ("workflow_routine_admission_tombstones", 1),
    ] {
        assert_eq!(
            case.f
                .db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&case.f.account]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            expected
        );
    }
    assert!(matches!(
        admit(&mut case.f.connect().await, &input, v.clone()).await,
        Err(AuthError::Forbidden)
    ));
    let mut replacement = p.clone();
    replacement.policy_id = Uuid::new_v4();
    replacement.request_id = Uuid::new_v4();
    replacement.call_limit = 1;
    replacement.unit_limit = 5;
    replacement.turn_limit = 1;
    configure(
        &mut case.f.connect().await,
        &case.owner,
        &input,
        replacement.clone(),
    )
    .await
    .unwrap();
    let next = Invocation {
        request_id: Uuid::new_v4(),
        policy_id: replacement.policy_id,
        ..v
    };
    let now = case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    let remaining = replacement.expires_ms - now;
    let result = admit(&mut case.f.connect().await, &input, next).await;
    let after = case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert!(
        matches!(result, Err(AuthError::RateLimited)),
        "expected retained debit refusal, got {result:?}; policy_remaining_ms={remaining}; remaining_after_ms={}",
        replacement.expires_ms - after
    );

    let tx = case.f.db.transaction().await.unwrap();
    lifecycle::erase_account(&tx, case.f.account).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1",
                &[&case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}

#[tokio::test]
async fn disabled_routine_mount_exposes_neither_execution_nor_owner_publication() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let hasher =
        std::sync::Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let app = http::router(
        crate::workflow_runtime::http::WorkflowHttpState {
            database_url: "unavailable".into(),
            hasher: hasher.clone(),
        },
        false,
    )
    .merge(http::owner_router(
        crate::http_owner_conversations::OwnerConversationsState {
            database_url: "unavailable".into(),
            auth_hasher: hasher,
            canonical_origin: "https://owner.example.test".into(),
        },
        false,
    ));
    for path in [
        "/v1/workflow/routines",
        "/v1/owner/workflow/routines/policy",
        "/v1/owner/workflow/routines/output",
        "/v1/owner/workflow/contexts",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable migrated routine graph"]
async fn output_stop_propagates_through_a_chain_and_fanout_without_reopening_fences() {
    let (mut case, input, p, _) = prepared().await;
    // Relational trigger fixture, not a content-reader/admission fixture: cloned
    // ciphertext metadata is never decrypted or used for effects.
    let tx = case.f.db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&case.f.account],
    )
    .await
    .unwrap();
    let mut previous_context = case.header.context;
    let mut previous_routine = p.routine_id;
    let mut previous_grant = input.grant_id();
    for index in 0..192 {
        let output = Uuid::new_v4();
        let grant = Uuid::new_v4();
        tx.execute("INSERT INTO workflow_contexts SELECT (jsonb_populate_record(NULL::workflow_contexts,to_jsonb(c)||jsonb_build_object('id',$2::uuid))).* FROM workflow_contexts c WHERE c.account_id=$1 AND c.id=$3",&[&case.f.account,&output,&case.header.context]).await.unwrap();
        tx.execute("INSERT INTO workflow_context_versions SELECT (jsonb_populate_record(NULL::workflow_context_versions,to_jsonb(v)||jsonb_build_object('context_id',$2::uuid,'id',$2::uuid,'request_id',$2::uuid))).* FROM workflow_context_versions v WHERE v.account_id=$1 AND v.context_id=$3 AND v.revision=1",&[&case.f.account,&output,&case.header.context]).await.unwrap();
        tx.execute(
            "INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$2,1)",
            &[&case.f.account, &output],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO workflow_integration_grants SELECT (jsonb_populate_record(NULL::workflow_integration_grants,to_jsonb(g)||jsonb_build_object('grant_id',$2::uuid,'context_id',$3::uuid,'credential_hash',decode(md5($2::uuid::text)||md5($2::uuid::text),'hex')))).* FROM workflow_integration_grants g WHERE g.account_id=$1 AND g.grant_id=$4",&[&case.f.account,&grant,&output,&input.grant_id()]).await.unwrap();
        let policy = if index < 64 {
            let mut next = p.clone();
            next.policy_id = Uuid::new_v4();
            next.request_id = Uuid::new_v4();
            next.context_id = previous_context;
            next.routine_id = previous_routine;
            next.generation = if index == 0 { 3 } else { 1 };
            tx.execute("INSERT INTO workflow_routine_policies SELECT (jsonb_populate_record(NULL::workflow_routine_policies,to_jsonb(p)||jsonb_build_object('id',$2::uuid,'input_grant_id',$3::uuid,'context_id',$4::uuid,'routine_id',$5::uuid,'generation',$6::bigint,'policy',$7::text::jsonb,'policy_digest',decode(repeat('ab',32),'hex')))).* FROM workflow_routine_policies p WHERE p.account_id=$1 AND p.id=$8",&[&case.f.account,&next.policy_id,&previous_grant,&previous_context,&previous_routine,&next.generation,&serde_json::to_string(&next).unwrap(),&p.policy_id]).await.unwrap();
            next.policy_id
        } else {
            p.policy_id
        };
        tx.execute("INSERT INTO workflow_routine_calls(account_id,id,policy_id,request_digest,units,phase,created_ms,produced_digest,output_grant_id,output_context_id,output_revision,output_digest,publication_request,publication_digest,published_by_user,published_session) VALUES($1,$2,$3,decode(repeat('ab',32),'hex'),1,'published',1,decode(repeat('ab',32),'hex'),$4,$2,1,decode(repeat('ab',32),'hex'),$2,decode(repeat('ab',32),'hex'),$5,$6)",&[&case.f.account,&output,&policy,&grant,&case.owner.user_id,&case.owner.session_id]).await.unwrap();
        previous_context = output;
        previous_routine = output;
        previous_grant = grant;
    }
    tx.commit().await.unwrap();
    decisions::takeover(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        case.header.context,
    )
    .await
    .unwrap();
    assert_eq!(case.f.db.query_one("SELECT count(*) FROM workflow_routines WHERE account_id=$1 AND stopped_at IS NOT NULL",&[&case.f.account]).await.unwrap().get::<_,i64>(0),193);
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routines WHERE account_id=$1 AND stopped_at IS NULL",
                &[&case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn unbound_call_uuid_collision_cannot_stop_an_existing_shared_input_routine() {
    let (case, input, p, mut v) = prepared().await;
    v.request_id = p.routine_id;
    assert!(
        admit(&mut case.f.connect().await, &input, v)
            .await
            .unwrap()
            .execute_once
    );
    withdraw(&mut case.f.connect().await, &case.owner, p.policy_id)
        .await
        .unwrap();
    assert!(!case.f.db.query_one("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2",&[&case.f.account,&p.routine_id]).await.unwrap().get::<_,bool>(0));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine authority schema"]
async fn simultaneous_last_turn_admissions_have_one_winner_and_one_atomic_debit() {
    let (case, input, mut policy, mut v) = prepared().await;
    policy.policy_id = Uuid::new_v4();
    policy.request_id = Uuid::new_v4();
    policy.call_limit = 1;
    policy.unit_limit = 5;
    policy.turn_limit = 1;
    configure(
        &mut case.f.connect().await,
        &case.owner,
        &input,
        policy.clone(),
    )
    .await
    .unwrap();
    v.policy_id = policy.policy_id;
    let mut other = v.clone();
    other.request_id = Uuid::new_v4();
    let mut first = case.f.connect().await;
    let mut second = case.f.connect().await;
    let (one, two) = tokio::join!(
        admit(&mut first, &input, v),
        admit(&mut second, &input, other)
    );
    assert!(one.is_ok() ^ two.is_ok());
    let loser = if one.is_ok() { two } else { one };
    assert!(matches!(loser, Err(AuthError::RateLimited)));
    let debit = case
        .f
        .db
        .query_one(
            "SELECT calls,units FROM workflow_routine_period_debits WHERE account_id=$1",
            &[&case.f.account],
        )
        .await
        .unwrap();
    assert_eq!(debit.get::<_, i64>(0), 1);
    assert_eq!(debit.get::<_, i64>(1), 5);
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1",
                &[&case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(first);
    drop(second);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable routine rollback fixture"]
async fn final_call_insert_failure_rolls_back_period_turn_and_replay_debits() {
    let (case, input, _, v) = prepared().await;
    case.f.db.batch_execute("CREATE FUNCTION refuse_new_routine_call() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic final call failure' USING ERRCODE='23514'; END; $$; CREATE TRIGGER refuse_new_routine_call BEFORE INSERT ON workflow_routine_calls FOR EACH ROW EXECUTE FUNCTION refuse_new_routine_call();").await.unwrap();
    let mut client = case.f.connect().await;
    assert!(matches!(
        admit(&mut client, &input, v).await,
        Err(AuthError::Database(_))
    ));
    for table in [
        "workflow_routine_calls",
        "workflow_routine_period_debits",
        "workflow_routine_turn_debits",
        "workflow_routine_admission_tombstones",
    ] {
        assert_eq!(
            client
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&case.f.account]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    drop(client);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable real owner policy lock wait"]
async fn policy_issuing_owner_expiry_during_observed_row_wait_refuses_current_authority() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let (case, input, mut p, _) = prepared().await;
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let session = Uuid::new_v4();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",&[&session,&case.f.account,&case.owner.user_id,&auth_hash(b"session-v1",&token),&auth_hash(b"csrf-v1","example")]).await.unwrap();
    let owner = crate::auth::authenticate_session(&case.f.db, &case.hasher, &token)
        .await
        .unwrap();
    p.policy_id = Uuid::new_v4();
    p.request_id = Uuid::new_v4();
    configure(&mut case.f.connect().await, &owner, &input, p.clone())
        .await
        .unwrap();
    let mut blocker = case.f.connect().await;
    let block = blocker.transaction().await.unwrap();
    block
        .query_one(
            "SELECT id FROM workflow_routine_policies WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&case.f.account, &p.policy_id],
        )
        .await
        .unwrap();
    let mut caller = case.f.connect().await;
    let pid: i32 = caller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let deadline:i64=case.f.db.query_one("UPDATE sessions SET expires_at=clock_timestamp()+interval '1500 milliseconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",&[&session]).await.unwrap().get(0);
    let observer = async {
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let row=case.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'),floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[&pid]).await.unwrap();
            if row.get::<_, bool>(0) {
                assert!(
                    row.get::<_, i64>(1) < deadline,
                    "policy query must wait while its real issuing owner is live"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < bound,
                "policy query did not reach the actual lock wait"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        while case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        block.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(
        current(&mut caller, &input, p.context_id, p.policy_id),
        observer
    );
    assert!(matches!(result, Err(AuthError::Forbidden)));
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM workflow_routine_calls", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(caller);
    drop(blocker);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable real read-only grant"]
async fn context_read_grant_never_implies_an_unconfigured_policy_or_original_inbound_execution() {
    let (case, input, _, v) = prepared().await;
    let mut undeclared = v.clone();
    undeclared.policy_id = Uuid::new_v4();
    assert!(matches!(
        admit(&mut case.f.connect().await, &input, undeclared).await,
        Err(AuthError::Forbidden)
    ));
    let mut inbound = v;
    inbound.direction = Direction::Inbound;
    assert!(matches!(
        admit(&mut case.f.connect().await, &input, inbound).await,
        Err(AuthError::Forbidden)
    ));
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_admission_tombstones",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}

fn auth_hash(domain: &[u8], value: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac, digest::KeyInit};
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub(crate) mod service;
