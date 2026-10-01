// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn late_signed_reply_enters_exception_without_fencing_a_new_request() {
    let mut c = Case::new().await;
    let now = activation::now(&c.base.f.connect().await.transaction().await.unwrap())
        .await
        .unwrap();
    c.descriptor.expires_at = now / 1000 + 3;
    let old = c.propose(c.descriptor.clone()).await;
    let mut newer = c.descriptor.clone();
    newer.action_id = Uuid::new_v4().to_string();
    newer.routine_id = Uuid::new_v4().to_string();
    newer.expires_at += 60;
    let future = c.propose(newer).await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let event = c.capture(1).await;
    let result = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        Correlation {
            context_id: c.base.h.context,
            context_revision: 1,
            event_id: event,
            request_action: Some(old.key),
        },
    )
    .await
    .unwrap();
    assert_eq!(result.disposition, "late");
    assert_eq!(result.stopped_routines, 0);
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, future.key)
            .await
            .unwrap()
            .phase,
        Phase::Proposed
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_exceptions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn signed_event_from_an_unrelated_account_cannot_select_or_fence_a_request() {
    let c = Case::new().await;
    let other = Case::new().await;
    let request = c.approved().await;
    let event = other.capture(1).await;
    assert!(
        correlate_reply(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            Correlation {
                context_id: c.base.h.context,
                context_revision: 1,
                event_id: event,
                request_action: Some(request.key)
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, request.key)
            .await
            .unwrap()
            .phase,
        Phase::Approved
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_reply_correlations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
    other.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn qualifying_reply_races_followup_grant_and_no_later_effect_passes_its_fence() {
    let mut c = Case::new().await;
    let first = c.approved().await;
    let bound = c.bind(first).await;
    c.dispatch(bound.key).await;
    c.grant().await.unwrap().unwrap();
    let mut d = c.descriptor.clone();
    d.action_id = Uuid::new_v4().to_string();
    let next = c.propose(d).await;
    let approved = decide(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        1,
        next.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    let followup = c.bind(approved).await;
    c.dispatch(followup.key).await;
    let event = c.capture(1).await;
    let mut reply_connection = c.base.f.connect().await;
    let (reply, grant) = tokio::join!(
        correlate_reply(
            &mut reply_connection,
            &c.base.owner,
            Uuid::new_v4(),
            Correlation {
                context_id: c.base.h.context,
                context_revision: 1,
                event_id: event,
                request_action: Some(bound.key)
            }
        ),
        c.grant()
    );
    let reply = reply.unwrap();
    assert_eq!(reply.disposition, "qualifying");
    let issued = matches!(grant, Ok(Some(_)));
    assert_eq!(reply.irreversible_messages, 1 + i64::from(issued));
    assert_eq!(reply.cancelled_messages, i64::from(!issued));
    assert!(!matches!(c.grant().await, Ok(Some(_))));
    assert!(!c.base.f.db.query_one("SELECT workflow_effect_current($1,message_id) FROM workflow_message_links WHERE account_id=$1 AND action_id=$2",&[&c.base.f.account,&followup.key.action_id]).await.unwrap().get::<_,bool>(0));
    c.cleanup().await;
}
