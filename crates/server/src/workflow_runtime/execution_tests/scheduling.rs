// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

pub(super) async fn retry_due(flow: &Flow, id: Uuid) {
    let started = tokio::time::Instant::now();
    loop {
        let due: bool = flow.case.f.db.query_one("SELECT retry_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_schedule_occurrences WHERE id=$1", &[&id]).await.unwrap().get(0);
        if due {
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(6));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable scheduling runtime schema"]
async fn offline_phone_wait_survives_reconnect_and_cancellation_projects_once() {
    let mut flow = prepared(&[Operation::Schedule, Operation::Send], true).await;
    let occurrence = schedule_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        flow.action.key,
        request(),
        &flow.policy,
    )
    .await
    .unwrap();
    let (bound, message) = flow
        .case
        .bind_message(flow.action.clone(), occurrence.dispatch_id)
        .await;
    flow.case
        .f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",
            &[],
        )
        .await
        .unwrap();
    let waiting_request = Uuid::new_v4();
    assert_eq!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            waiting_request,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        SendOutcome::WaitingPhone
    );
    let row = flow
        .case
        .f
        .db
        .query_one(
            "SELECT phase,lease_id,expires_at_ms FROM workflow_schedule_occurrences WHERE id=$1",
            &[&occurrence.id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "waiting_phone");
    assert_eq!(row.get::<_, Option<Uuid>>(1), None);
    assert_eq!(row.get::<_, i64>(2), occurrence.expires_at_ms);
    // Reauthenticate the exact credential on a fresh connection, as after a
    // customer process restart. Stored actor ids never recreate authority.
    let reconnected = authenticate(
        &flow.case.f.connect().await,
        &flow.case.hasher,
        &flow.credential,
    )
    .await
    .unwrap();
    flow.case
        .f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '1 minute'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        send_action(
            &mut flow.case.f.connect().await,
            &reconnected,
            waiting_request,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        SendOutcome::WaitingPhone
    );
    retry_due(&flow, occurrence.id).await;
    let prepared_request = Uuid::new_v4();
    let expected = SendOutcome::Prepared {
        message_id: message,
        dispatch_id: occurrence.dispatch_id,
    };
    assert_eq!(
        send_action(
            &mut flow.case.f.connect().await,
            &reconnected,
            prepared_request,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        expected
    );
    assert_eq!(
        send_action(
            &mut flow.case.f.connect().await,
            &reconnected,
            prepared_request,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        expected
    );
    let cancel_request = Uuid::new_v4();
    for _ in 0..2 {
        cancel_action(
            &mut flow.case.f.connect().await,
            &reconnected,
            cancel_request,
            bound.key,
        )
        .await
        .unwrap();
    }
    let row = flow.case.f.db.query_one("SELECT o.phase,o.observed_message_state,m.state,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT count(*) FROM message_attempts),(SELECT count(*) FROM workflow_schedule_audit WHERE operation='cancel') FROM workflow_schedule_occurrences o JOIN messages m ON(m.account_id,m.id)=(o.account_id,o.message_id) WHERE o.id=$1", &[&occurrence.id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "failed");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some("cancelled")
    );
    assert_eq!(row.get::<_, String>(2), "cancelled");
    assert_eq!(row.get::<_, i64>(3), 1);
    assert_eq!(row.get::<_, i64>(4), 0);
    assert_eq!(row.get::<_, i64>(5), 1);
    assert_eq!(
        crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
            .await
            .unwrap(),
        0
    );
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable scheduling runtime schema"]
async fn missing_authorized_ciphertext_wait_expires_without_renderer_or_actor_reconstruction() {
    let flow = prepared_bounded(&[Operation::Schedule, Operation::Send], true, false, true).await;
    let occurrence = schedule_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        flow.action.key,
        request(),
        &flow.policy,
    )
    .await
    .unwrap();
    let request_id = Uuid::new_v4();
    assert_eq!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            request_id,
            flow.action.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        SendOutcome::WaitingOwnerBinding
    );
    let row = flow
        .case
        .f
        .db
        .query_one(
            "SELECT phase,expires_at_ms FROM workflow_schedule_occurrences WHERE id=$1",
            &[&occurrence.id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "waiting_renderer");
    assert_eq!(row.get::<_, i64>(1), occurrence.expires_at_ms);
    // The anonymous worker cannot use this stored grant after withdrawal.
    revoke_grant(
        &mut flow.case.f.connect().await,
        &flow.case.owner,
        flow.principal.grant_id(),
    )
    .await
    .unwrap();
    loop {
        let expired:bool=flow.case.f.db.query_one("SELECT expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_schedule_occurrences WHERE id=$1",&[&occurrence.id]).await.unwrap().get(0);
        if expired {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        flow.case
            .f
            .db
            .query_one(
                "SELECT phase FROM workflow_schedule_occurrences WHERE id=$1",
                &[&occurrence.id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "expired"
    );
    assert_eq!(counts(&flow.case).await, (1, 0, 0));
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable scheduling runtime schema"]
async fn anonymous_projection_observes_real_owner_cancel_takeover_and_grant_withdrawal_without_execution()
 {
    for operation in ["cancel", "takeover", "withdraw"] {
        let flow = prepared(&[Operation::Schedule, Operation::Send], true).await;
        let occurrence = schedule_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            flow.action.key,
            request(),
            &flow.policy,
        )
        .await
        .unwrap();
        assert_eq!(
            crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
                .await
                .unwrap(),
            0,
            "anonymous sweep must not claim or execute due approved work"
        );
        match operation {
            "cancel" => {
                decisions::decide(
                    &mut flow.case.f.connect().await,
                    &flow.case.owner,
                    Uuid::new_v4(),
                    flow.action.record_version,
                    flow.action.key,
                    Decision::Cancel,
                )
                .await
                .unwrap();
            }
            "takeover" => {
                decisions::takeover(
                    &mut flow.case.f.connect().await,
                    &flow.case.owner,
                    Uuid::new_v4(),
                    flow.case.header.context,
                )
                .await
                .unwrap();
            }
            _ => {
                revoke_grant(
                    &mut flow.case.f.connect().await,
                    &flow.case.owner,
                    flow.principal.grant_id(),
                )
                .await
                .unwrap();
            }
        }
        if operation == "takeover" {
            let row = flow.case.f.db.query_one("SELECT o.phase,o.lease_id IS NULL,o.lease_until_ms IS NULL,r.stopped_at IS NOT NULL,f.stopped_at IS NOT NULL,(SELECT count(*) FROM workflow_schedule_audit WHERE occurrence_id=o.id AND operation='cancel'),(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund') FROM workflow_schedule_occurrences o JOIN workflow_schedule_series s ON(s.account_id,s.id)=(o.account_id,o.series_id) JOIN workflow_routines r ON(r.account_id,r.id)=(s.account_id,s.routine_id) JOIN workflow_context_fences f ON(f.account_id,f.context_id)=(s.account_id,s.context_id) WHERE o.id=$1", &[&occurrence.id]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), "cancelled");
            for column in 1..=4 {
                assert!(row.get::<_, bool>(column));
            }
            assert_eq!(row.get::<_, i64>(5), 1);
            assert_eq!(row.get::<_, i64>(6), 0);
        }
        assert_eq!(
            crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
                .await
                .unwrap(),
            if operation == "takeover" { 0 } else { 1 }
        );
        assert_eq!(
            crate::encrypted_schedule::worker::tick(&mut flow.case.f.connect().await)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            flow.case
                .f
                .db
                .query_one(
                    "SELECT phase FROM workflow_schedule_occurrences WHERE id=$1",
                    &[&occurrence.id]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "cancelled"
        );
        assert_eq!(counts(&flow.case).await, (1, 0, 0));
        let audit = flow.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_schedule_audit WHERE occurrence_id=$1 AND operation='cancel'),(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund')", &[&occurrence.id]).await.unwrap();
        assert_eq!(audit.get::<_, i64>(0), 1);
        assert_eq!(audit.get::<_, i64>(1), 0);
        flow.case.f.cleanup().await;
    }
}
