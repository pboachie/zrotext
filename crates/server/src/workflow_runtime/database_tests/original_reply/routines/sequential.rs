// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, built SDK and Node; sequential original conversation HTTPS"]
async fn sequential_original_conversation_preserves_input_and_requires_each_output_approval() {
    let mut f = RoutineCase::with_crypto_context(true).await;
    // A new immutable owner policy explicitly approves two turns; never mutate
    // the committed policy or renew source expiry to make this fixture pass.
    let mut policy = f.policy.clone();
    policy.request_id = Uuid::new_v4();
    policy.policy_id = Uuid::new_v4();
    policy.routine_id = Uuid::new_v4();
    policy.turn_limit = 2;
    policy.kind = routines::contracts::Kind::OwnerReply;
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
    f.policy = policy;
    f.invocation.policy_id = f.policy.policy_id;
    let database_url =
        transport::database_url_with_schema(&f.f.case.f.url, &f.f.case.f.schema).unwrap();
    let hasher = std::sync::Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let workflow = crate::workflow_runtime::http::WorkflowHttpState {
        database_url: database_url.clone(),
        hasher: hasher.clone(),
    };
    let app = service::http::router(
        service::http::StateData {
            database_url,
            hasher,
        },
        true,
    )
    .merge(crate::workflow_runtime::http::router(
        workflow.clone(),
        true,
    ))
    .merge(routines::http::router_with_original(workflow, true, true));
    let tls = Https::start(app).await;
    let mut config = f.network_input.take().unwrap();
    let port = tls.origin.rsplit_once(':').unwrap().1;
    config["origin"] = json!(format!("https://localhost:{port}"));
    config["ca_pem"] = json!(tls.ca);
    config["read_credential"] = json!(f.read.token.as_str());
    config["input_credential"] = json!(f.input_token.as_str());
    config["routine_policy"] = serde_json::to_value(&f.policy).unwrap();
    config["archive_private_jwk"] = jwk(&f.f.case.f.archive_key);
    let input_header = f.f.case.header.clone();
    let input_projection = f.f.case.request.content_envelope.clone();
    let input_permissions = f.f.case.request.permissions;
    let input_context = f.f.case.request.context;
    let input_expiry = f.f.case.request.expires_ms;
    let mut keys = Vec::new();
    let mut call_events = Vec::new();
    for ordinal in 1..=2 {
        if ordinal == 2 {
            let event = Uuid::new_v4();
            let mut seed = configuration(&f.f, event).await;
            seed["local_sequence"] = json!("2");
            capture(&f.f, &mut seed, &f.scratch, event).await;
            f.invocation.event_id = event;
            f.invocation.request_id = Uuid::new_v4();
        }
        config["event_id"] = json!(f.invocation.event_id);
        config["request_id"] = json!(f.invocation.request_id);
        config["phase"] = json!("exercise_original");
        let executed = run_driver(config.clone(), &f.scratch.path, Driver::OriginalRoutine).await;
        assert_eq!(executed["state"], "awaiting_owner_publication");
        config["phase"] = json!("recover_original");
        let replay = run_driver(config.clone(), &f.scratch.path, Driver::OriginalRoutine).await;
        assert_eq!(replay["call"]["execute_once"], false);
        assert_eq!(replay["call"]["call_id"], executed["call"]["call_id"]);
        config["phase"] = json!("publish_original");
        let artifact = run_driver(config.clone(), &f.scratch.path, Driver::OriginalRoutine).await;
        assert_eq!(artifact["invocations"], ordinal);
        let archive = STANDARD
            .decode(artifact["archive_b64"].as_str().unwrap())
            .unwrap();
        let projection = STANDARD
            .decode(artifact["projection_b64"].as_str().unwrap())
            .unwrap();
        let key = f
            .owner_publish_real_and_propose(f.invocation.request_id, archive, projection)
            .await;
        let mut db = f.f.case.f.connect().await;
        let tx = db.transaction().await.unwrap();
        assert!(matches!(
            decisions::lock_approved(&tx, &f.f.case.owner, key).await,
            Err(ConversationError::Conflict)
        ));
        tx.rollback().await.unwrap();
        // Prior turn approval does not authorize the next output action.
        f.approve(key).await;
        let mut db = f.f.case.f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut permit = decisions::lock_approved(&tx, &f.f.case.owner, key)
            .await
            .unwrap();
        permit.recheck().await.unwrap();
        drop(permit);
        tx.rollback().await.unwrap();
        assert_eq!(key.action_id, f.invocation.request_id);
        assert_ne!(key.action_id, input_context);
        let source = f.f.case.f.db.query_one(
            "SELECT event_id,context_id FROM workflow_routine_original_sources WHERE account_id=$1 AND call_id=$2 AND policy_id=$3",
            &[&f.f.case.f.account,&key.action_id,&f.policy.policy_id],
        ).await.unwrap();
        assert_eq!(source.get::<_, Uuid>(0), f.invocation.event_id);
        assert_eq!(source.get::<_, Uuid>(1), input_context);
        let published = f.f.case.f.db.query_one(
            "SELECT output_context_id,output_revision FROM workflow_routine_calls WHERE account_id=$1 AND id=$2",
            &[&f.f.case.f.account,&key.action_id],
        ).await.unwrap();
        assert_eq!(published.get::<_, Option<Uuid>>(0), Some(key.action_id));
        assert_eq!(published.get::<_, Option<i64>>(1), Some(1));
        call_events.push((key.action_id, f.invocation.event_id));
        keys.push(key);
        // Hold the same independently issued input capability throughout.
        f.f.case.header = input_header.clone();
        f.f.case.request.context = input_context;
        f.f.case.request.permissions = input_permissions;
        f.f.case.request.expires_ms = input_expiry;
        f.f.case.request.content_envelope = input_projection.clone();
        assert_eq!(f.input.grant_id(), f.f.case.f.db.query_one(
            "SELECT input_grant_id FROM workflow_routine_policies WHERE account_id=$1 AND id=$2",
            &[&f.f.case.f.account,&f.policy.policy_id]).await.unwrap().get::<_,Uuid>(0));
    }
    assert_ne!(keys[0].action_id, keys[1].action_id);
    assert_ne!(call_events[0].1, call_events[1].1);
    let third_event = Uuid::new_v4();
    let mut seed = configuration(&f.f, third_event).await;
    seed["local_sequence"] = json!("3");
    capture(&f.f, &mut seed, &f.scratch, third_event).await;
    let mut third = f.invocation.clone();
    third.request_id = Uuid::new_v4();
    third.event_id = third_event;
    third.event_envelope_digest = decisions::descriptor::hex(
        &f.f.case
            .f
            .db
            .query_one(
                "SELECT sha256(envelope) FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
                &[&f.f.case.f.account, &third_event],
            )
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
    );
    assert!(matches!(f.admit(third).await, Err(AuthError::RateLimited)));
    config["phase"] = json!("recover_original");
    let replay = run_driver(config.clone(), &f.scratch.path, Driver::OriginalRoutine).await;
    assert_eq!(replay["call"]["execute_once"], false);
    config["phase"] = json!("publish_original");
    let retained = run_driver(config, &f.scratch.path, Driver::OriginalRoutine).await;
    assert_eq!(retained["invocations"], 2);
    let counts=f.f.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_calls WHERE account_id=$1),(SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1 AND context_id=$2),(SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT count(*) FROM messages WHERE account_id=$1),(SELECT count(*) FROM message_attempts WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1 AND policy_id=$3),(SELECT sum(units)::bigint FROM workflow_routine_period_debits WHERE account_id=$1)",&[&f.f.case.f.account,&input_context,&f.policy.policy_id]).await.unwrap();
    assert_eq!(
        (
            counts.get::<_, i64>(0),
            counts.get::<_, i64>(1),
            counts.get::<_, Option<i64>>(2)
        ),
        (2, 2, Some(2))
    );
    assert_eq!((counts.get::<_, i64>(3), counts.get::<_, i64>(4)), (0, 0));
    assert_eq!(counts.get::<_, i64>(5), 2);
    assert_eq!(counts.get::<_, Option<i64>>(6), Some(8));
    // Replays and the refused third event must not rewrite either provenance.
    for (call, event) in call_events {
        let source = f.f.case.f.db.query_one(
            "SELECT event_id,context_id FROM workflow_routine_original_sources WHERE account_id=$1 AND call_id=$2 AND policy_id=$3",
            &[&f.f.case.f.account,&call,&f.policy.policy_id],
        ).await.unwrap();
        assert_eq!(source.get::<_, Uuid>(0), event);
        assert_eq!(source.get::<_, Uuid>(1), input_context);
    }
    tls.close().await;
    f.finish().await;
}
