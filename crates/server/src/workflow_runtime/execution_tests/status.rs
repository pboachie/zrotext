// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn snapshot(flow: &Flow) -> Result<ActionStatus, crate::auth::AuthError> {
    read_action_delivery_status(
        &mut flow.case.f.connect().await,
        &flow.principal,
        Uuid::new_v4(),
        flow.case.header.context,
        flow.action.key.action_id,
    )
    .await
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn status_uses_exact_bound_delivery_and_never_guesses_from_owner_approval() {
    let mut flow = prepared(&[Operation::Status, Operation::Send], true).await;
    let initial = snapshot(&flow).await.unwrap();
    assert!(matches!(initial.delivery, Some(DeliveryStatus::NotBound)));
    let dispatch = Uuid::new_v4();
    let (bound, message) = flow.case.bind_message(flow.action.clone(), dispatch).await;
    flow.action = bound;
    let sent = send_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        Uuid::new_v4(),
        flow.action.key,
        None,
    )
    .await
    .unwrap();
    assert!(
        matches!(sent, SendOutcome::Prepared { message_id, dispatch_id } if message_id==message && dispatch_id==dispatch)
    );
    let queued = snapshot(&flow).await.unwrap();
    assert_eq!(queued.key, flow.action.key);
    assert!(matches!(queued.delivery, Some(DeliveryStatus::Available {
        message_id, dispatch_id, state: zrotext_domain::MessageState::Queued, ..
    }) if message_id==message && dispatch_id==dispatch));
    cancel_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        Uuid::new_v4(),
        flow.action.key,
    )
    .await
    .unwrap();
    let cancelled = snapshot(&flow).await.unwrap();
    assert_eq!(cancelled.action.phase, queued.action.phase);
    assert!(matches!(
        cancelled.delivery,
        Some(DeliveryStatus::Available {
            state: zrotext_domain::MessageState::Cancelled,
            ..
        })
    ));
    // Match the existing tombstone lifecycle fixture: clear dependent terminal
    // job and ledger records before removing only this message. The immutable
    // workflow binding must survive with its live-message reference cleared.
    let mut db = flow.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute(
        "DELETE FROM usage_ledger WHERE account_id=$1 AND message_id=$2",
        &[&flow.action.key.account_id, &message],
    )
    .await
    .unwrap();
    assert_eq!(
        tx.execute(
            "DELETE FROM dispatch_jobs WHERE account_id=$1 AND message_id=$2 AND finished_at IS NOT NULL AND grant_issued_at IS NULL",
            &[&flow.action.key.account_id, &message],
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        tx.execute(
            "DELETE FROM messages WHERE account_id=$1 AND id=$2",
            &[&flow.action.key.account_id, &message],
        )
        .await
        .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    let retained = db
        .query_one(
            "SELECT message_id,dispatch_id,live_message_id FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4",
            &[&flow.action.key.account_id, &flow.action.key.action_id, &flow.action.key.revision, &&flow.action.key.binding_digest[..]],
        )
        .await
        .unwrap();
    assert_eq!(retained.get::<_, Uuid>(0), message);
    assert_eq!(retained.get::<_, Uuid>(1), dispatch);
    assert!(retained.get::<_, Option<Uuid>>(2).is_none());
    assert!(matches!(
        snapshot(&flow).await.unwrap().delivery,
        Some(DeliveryStatus::Unavailable)
    ));
    revoke_grant(
        &mut flow.case.f.connect().await,
        &flow.case.owner,
        flow.principal.grant_id(),
    )
    .await
    .unwrap();
    assert!(snapshot(&flow).await.is_err());
    flow.case.f.cleanup().await;
}
