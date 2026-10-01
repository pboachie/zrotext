// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn real_grant_is_allowed_once_then_takeover_fences_fetch_and_first_intent() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    let bound = c.bind(approved).await;
    let message = c.dispatch(bound.key).await;
    let grant = c.grant().await.unwrap().unwrap();
    assert_eq!(grant.message_id, message);
    assert!(!c.fetch(grant.clone()).await.unwrap().is_empty());
    let result = takeover(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        c.base.h.context,
    )
    .await
    .unwrap();
    assert_eq!(result.irreversible_messages, 1);
    assert_eq!(result.cancelled_messages, 0);
    assert!(c.fetch(grant.clone()).await.is_err());
    let mut db = c.base.f.connect().await;
    let now = activation::now(&db.transaction().await.unwrap())
        .await
        .unwrap();
    let event = zrotext_delivery_store::RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: c.base.f.account,
        device_id: c.base.f.device,
        message_id: message,
        attempt_id: grant.attempt_id,
        evidence: zrotext_domain::Evidence::DurableSubmitIntent,
        observed_at_ms: now,
        segment_index: None,
        segment_count: None,
    };
    assert!(
        zrotext_delivery_store::DeliveryStore::new(&mut db)
            .record_radio_event(event)
            .await
            .is_err()
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one(
                "SELECT count(*) FROM message_events WHERE evidence_code='durable_intent'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn qualifying_signed_reply_stops_only_its_exact_routine_and_unsent_followups() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    let bound = c.bind(approved).await;
    c.dispatch(bound.key).await;
    c.grant().await.unwrap().unwrap();
    let mut followup = c.descriptor.clone();
    followup.action_id = Uuid::new_v4().to_string();
    let future = c.propose(followup).await;
    let mut separate = c.descriptor.clone();
    separate.action_id = Uuid::new_v4().to_string();
    separate.routine_id = Uuid::new_v4().to_string();
    let other = c.propose(separate).await;
    let event = c.capture(1).await;
    let input = Correlation {
        context_id: c.base.h.context,
        context_revision: 1,
        event_id: event,
        request_action: Some(bound.key),
    };
    let result = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        input.clone(),
    )
    .await
    .unwrap();
    assert_eq!(result.disposition, "qualifying");
    assert_eq!(result.stopped_routines, 1);
    assert_eq!(result.irreversible_messages, 1);
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, future.key)
            .await
            .unwrap()
            .phase,
        Phase::Cancelled
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, other.key)
            .await
            .unwrap()
            .phase,
        Phase::Proposed
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, bound.key)
            .await
            .unwrap()
            .phase,
        Phase::Unknown
    );
    assert_eq!(
        correlate_reply(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            input
        )
        .await
        .unwrap()
        .disposition,
        "qualifying"
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn dispatch_takeover_race_has_no_new_effect_after_the_fence() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    let bound = c.bind(approved).await;
    c.dispatch(bound.key).await;
    let run = c.grant();
    let cancel = async {
        takeover(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            c.base.h.context,
        )
        .await
    };
    let (granted, cancelled) = tokio::join!(run, cancel);
    let cancelled = cancelled.unwrap();
    let issued = granted.as_ref().ok().and_then(|f| f.as_ref()).is_some();
    assert_eq!(cancelled.irreversible_messages, i64::from(issued));
    assert_eq!(cancelled.cancelled_messages, i64::from(!issued));
    assert!(matches!(c.grant().await, Err(_) | Ok(None)));
    assert!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0)
            <= 1
    );
    c.cleanup().await;
}
