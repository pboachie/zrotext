// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn ready() -> (Flow, decisions::ActionKey, Uuid, Uuid) {
    let mut flow = prepared(&[Operation::Send], true).await;
    let (bound, message) = flow
        .case
        .bind_message(flow.action.clone(), Uuid::new_v4())
        .await;
    let prepared_request = Uuid::new_v4();
    assert!(
        matches!(send_action(&mut flow.case.f.connect().await, &flow.principal,
        prepared_request, bound.key, None).await.unwrap(), SendOutcome::Prepared { message_id, .. } if message_id == message)
    );
    (flow, bound.key, message, prepared_request)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated workflow cancellation schema"]
async fn own_prepared_output_cancels_once_and_replay_rechecks_revocation() {
    let (flow, key, message, _) = ready().await;
    let request = Uuid::new_v4();
    let first = cancel_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        request,
        key,
    )
    .await
    .unwrap();
    assert_eq!(
        first,
        CancelOutcome {
            key,
            message_id: message,
            state: CancelState::Cancelled
        }
    );
    for id in [request, Uuid::new_v4()] {
        assert_eq!(
            cancel_action(&mut flow.case.f.connect().await, &flow.principal, id, key)
                .await
                .unwrap(),
            first
        );
    }
    let row = flow.case.f.db.query_one("SELECT state,state_version,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT count(*) FROM message_attempts) FROM messages WHERE id=$1", &[&message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, i64>(3), 0);
    let version: i64 = row.get(1);
    revoke_grant(
        &mut flow.case.f.connect().await,
        &flow.case.owner,
        flow.principal.grant_id(),
    )
    .await
    .unwrap();
    assert!(
        cancel_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            request,
            key
        )
        .await
        .is_err()
    );
    assert_eq!(
        flow.case
            .f
            .db
            .query_one(
                "SELECT state_version FROM messages WHERE id=$1",
                &[&message]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        version
    );
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated workflow cancellation schema"]
async fn cancellation_refuses_other_permissions_grants_foreign_keys_and_request_collisions() {
    let (mut flow, key, message, prepared_request) = ready().await;
    for permission in [Operation::Status, Operation::Propose, Operation::Send] {
        flow.case.request.permissions = Permissions::new(&[permission]).unwrap();
        let issued = flow.case.issue_another().await;
        let other = authenticate(&flow.case.f.db, &flow.case.hasher, &issued.token)
            .await
            .unwrap();
        assert!(
            cancel_action(
                &mut flow.case.f.connect().await,
                &other,
                Uuid::new_v4(),
                key
            )
            .await
            .is_err()
        );
    }
    let foreign = decisions::ActionKey {
        account_id: Uuid::new_v4(),
        ..key
    };
    assert!(
        cancel_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            foreign
        )
        .await
        .is_err()
    );
    let reused = prepared_request;
    assert!(matches!(
        cancel_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            reused,
            key
        )
        .await,
        Err(crate::auth::AuthError::Conflict)
    ));
    let row = flow.case.f.db.query_one("SELECT state,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund') FROM messages WHERE id=$1", &[&message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(row.get::<_, i64>(1), 0);
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated workflow cancellation schema"]
async fn actual_execution_grant_wins_cancellation_without_refund_or_resend() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let (flow, key, message, _) = ready().await;
    // This isolated configured-writer fixture enables its real dispatch fence.
    flow.case
        .f
        .db
        .batch_execute("UPDATE deployment_authority SET dispatch_enabled=TRUE")
        .await
        .unwrap();
    let session = zrotext_delivery_store::SessionRecord {
        account_id: key.account_id,
        device_id: flow.case.f.device,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        epoch: 1,
        deployment_epoch: 1,
    };
    let readiness = crate::sealed_dispatch::wire::Ready {
        grant_version: 1,
        connection_epoch: 1,
        line_id: flow.case.f.line,
        binding_generation: flow.case.header.binding_generation,
        reader_key_id: URL_SAFE_NO_PAD.encode(flow.case.phone_reader.unwrap()),
    };
    let policy = crate::alpha_policy::AlphaPolicy::parse(
        Some("true"),
        Some(&key.account_id.to_string()),
        Some("+12"),
    )
    .unwrap();
    let frame = crate::sealed_dispatch::grant(
        &mut flow.case.f.connect().await,
        &session,
        &readiness,
        &policy,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(frame.message_id, message);
    assert!(matches!(
        cancel_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            key
        )
        .await,
        Err(crate::auth::AuthError::Conflict)
    ));
    let row = flow.case.f.db.query_one("SELECT (SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT count(*) FROM message_attempts) FROM messages WHERE id=$1", &[&message]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert!(
        crate::sealed_dispatch::grant(
            &mut flow.case.f.connect().await,
            &session,
            &readiness,
            &policy
        )
        .await
        .unwrap()
        .is_none()
    );
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated workflow cancellation schema"]
async fn cancellation_replay_expiring_during_job_lock_wait_rolls_back_access() {
    let (flow, key, message, _) = ready().await;
    cancel_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        Uuid::new_v4(),
        key,
    )
    .await
    .unwrap();
    // The cancelled-message replay bypasses the store's message-expiry guard:
    // only the runtime's final live authority check can reject this replay.
    let deadline: i64 = flow.case.f.db.query_one("SELECT LEAST(g.expires_ms,c.expires_at_ms,v.expires_at_ms) FROM workflow_integration_grants g JOIN workflow_contexts c ON (c.account_id,c.id)=(g.account_id,g.context_id) JOIN workflow_action_versions v ON v.account_id=g.account_id AND v.action_id=$1 AND v.revision=$2 WHERE g.grant_id=$3", &[&key.action_id,&key.revision,&flow.principal.grant_id()]).await.unwrap().get(0);
    // Prepare both connections and the exact blocker before entering the expiry
    // window. Connection setup after a one-second window can expire authority
    // before cancellation reaches the lock this test must exercise.
    let mut blocker = flow.case.f.connect().await;
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT message_id FROM dispatch_jobs WHERE message_id=$1 FOR UPDATE",
        &[&message],
    )
    .await
    .unwrap();
    let mut client = flow.case.f.connect().await;
    let pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    // Keep a deliberate slow preparation phase: the former ordering would
    // spend its entire admission margin here and never observe the job lock.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    loop {
        let now: i64 = flow
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if now >= deadline - 2000 {
            assert!(now < deadline);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let request = Uuid::new_v4();
    let principal = &flow.principal;
    let waiting = cancel_action(&mut client, principal, request, key);
    tokio::pin!(waiting);
    let release = async {
        let started = std::time::Instant::now();
        loop {
            let row = flow
                .case
                .f
                .db
                .query_one("SELECT $2=ANY(pg_blocking_pids($1))", &[&pid, &blocker_pid])
                .await
                .unwrap();
            if row.get::<_, bool>(0) {
                break;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "must reach actual job lock wait"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        loop {
            let now: i64 = flow
                .case
                .f
                .db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if now >= deadline + 25 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(&mut waiting, release);
    assert!(matches!(result, Err(crate::auth::AuthError::Forbidden)));
    let row = flow.case.f.db.query_one("SELECT state,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT count(*) FROM workflow_integration_access WHERE request_id=$2) FROM messages WHERE id=$1", &[&message,&request]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 0);
    flow.case.f.cleanup().await;
}
