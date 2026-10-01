// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn safety_replay_is_exact_and_later_events_cannot_allocate_another_routine_stop() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    let bound = c.bind(approved).await;
    c.dispatch(bound.key).await;
    c.grant().await.unwrap().unwrap();
    let event = c.capture(1).await;
    let input = Correlation {
        context_id: c.base.h.context,
        context_revision: 1,
        event_id: event,
        request_action: Some(bound.key),
    };
    let request = Uuid::new_v4();
    let first = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        input.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first.disposition, "qualifying");
    assert!(
        takeover(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            c.base.h.context
        )
        .await
        .is_err()
    );
    let event2 = c.capture(2).await;
    let mut later = input.clone();
    later.event_id = event2;
    let result = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        later,
    )
    .await
    .unwrap();
    assert_eq!(result.disposition, "ambiguous");
    assert_eq!(result.stopped_routines, 0);
    assert_eq!(c.base.f.db.query_one("SELECT count(*) FROM workflow_reply_correlations WHERE safety_routine_id IS NOT NULL",&[]).await.unwrap().get::<_,i64>(0),1);
    let repeated = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        input,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(repeated).unwrap()
    );
    c.cleanup().await;
}

async fn fill_journal(c: &Case) {
    c.base.f.db.execute("INSERT INTO workflow_action_mutations(account_id,request_id,context_id,subject_id,operation,request_digest,result,actor_user_id) SELECT $1,gen_random_uuid(),$2,gen_random_uuid(),1,decode(repeat('ab',32),'hex'),convert_to('{}','UTF8'),$3 FROM generate_series(1,8192-(SELECT count(*) FROM workflow_action_mutations WHERE account_id=$1))", &[&c.base.f.account,&c.base.h.context,&c.base.owner.user_id]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn takeover_at_full_journal_commits_and_replays_exactly_without_more_rows() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    c.bind(approved).await;
    fill_journal(&c).await;
    let request = Uuid::new_v4();
    let first = takeover(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        c.base.h.context,
    )
    .await
    .unwrap();
    assert_eq!(first.cancelled_messages, 1);
    let replay = takeover(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        c.base.h.context,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    assert!(
        takeover(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            c.base.h.context
        )
        .await
        .is_err()
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_action_mutations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        8192
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT state FROM messages", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "cancelled"
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn qualifying_stop_at_full_journal_survives_source_erasure_and_replays() {
    let mut c = Case::new().await;
    let approved = c.approved().await;
    let bound = c.bind(approved).await;
    c.dispatch(bound.key).await;
    c.grant().await.unwrap().unwrap();
    // The signed observation must follow the grant's exact issue time.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let event = c.capture(1).await;
    fill_journal(&c).await;
    let input = Correlation {
        context_id: c.base.h.context,
        context_revision: 1,
        event_id: event,
        request_action: Some(bound.key),
    };
    let request = Uuid::new_v4();
    let first = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        input.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first.disposition, "qualifying");
    assert_eq!(first.stopped_routines, 1);
    c.base
        .f
        .db
        .execute(
            "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
            &[&c.base.f.account, &event],
        )
        .await
        .unwrap();
    let (_, removed, _) = crate::http_owner_conversations::lifecycle::activation::prune(
        &mut c.base.f.connect().await,
        30,
        20,
    )
    .await
    .unwrap();
    assert_eq!(removed, 1);
    assert!(
        c.base
            .f
            .db
            .query_one(
                "SELECT live_event_id IS NULL FROM workflow_reply_correlations",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        c.base
            .f
            .db
            .execute(
                "UPDATE workflow_reply_correlations SET live_event_id=event_id",
                &[]
            )
            .await
            .is_err()
    );
    assert!(
        c.base
            .f
            .db
            .execute(
                "UPDATE workflow_reply_correlations SET result=convert_to('{}','UTF8')",
                &[]
            )
            .await
            .is_err()
    );
    c.base
        .f
        .db
        .execute(
            "DELETE FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&c.base.f.account, &event],
        )
        .await
        .unwrap();
    let replay = correlate_reply(&mut c.base.f.connect().await, &c.base.owner, request, input)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_action_mutations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        8192
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_reply_correlations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    c.cleanup().await;
}

#[test]
fn edits_keep_context_and_routine_identity_while_allowing_content_revision_changes() {
    let d: Descriptor = serde_json::from_value(serde_json::json!({"account_id":"00000000-0000-0000-0000-000000000001","action_id":"00000000-0000-0000-0000-000000000002","revision":1,"line_id":"00000000-0000-0000-0000-000000000003","recipient_id":"00000000-0000-0000-0000-000000000004","purpose_id":"00000000-0000-0000-0000-000000000001","content_ref":"00000000-0000-0000-0000-000000000005","content_digest":"abababababababababababababababababababababababababababababababab","content_version":1,"not_before":1,"expires_at":10,"timezone":"UTC","window_id":"window","routine_id":"00000000-0000-0000-0000-000000000006","authority_generation":1,"commitment":"sensitive"})).unwrap();
    let mut next = d.clone();
    next.revision = 2;
    next.content_version = 2;
    assert!(model::edit(&d, &next, Phase::Approved).is_ok());
    next.content_ref = Uuid::new_v4().to_string();
    assert!(model::edit(&d, &next, Phase::Approved).is_err());
    next.content_ref = d.content_ref.clone();
    next.routine_id = Uuid::new_v4().to_string();
    assert!(model::edit(&d, &next, Phase::Approved).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn interval_and_origin_revocation_fence_every_new_execution_effect() {
    for mode in ["pause", "withdraw", "origin"] {
        for stage in ["grant", "fetch", "intent"] {
            let mut c = Case::new().await;
            let approved = c.approved().await;
            let bound = c.bind(approved).await;
            let message = c.dispatch(bound.key).await;
            assert!(
                c.base
                    .f
                    .db
                    .query_one(
                        "SELECT workflow_effect_current($1,$2)",
                        &[&c.base.f.account, &message]
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
            );
            let grant = if stage != "grant" {
                Some(c.grant().await.unwrap().unwrap())
            } else {
                None
            };
            if stage == "intent" {
                assert!(!c.fetch(grant.clone().unwrap()).await.unwrap().is_empty());
            }
            if mode == "origin" {
                c.base
                    .f
                    .db
                    .execute(
                        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                        &[&c.base.s.originating_session],
                    )
                    .await
                    .unwrap();
            } else {
                activation::close(
                    &mut c.base.f.connect().await,
                    &c.base.owner,
                    c.base.s.interval,
                    mode == "withdraw",
                )
                .await
                .unwrap();
            }
            assert!(
                !c.base
                    .f
                    .db
                    .query_one(
                        "SELECT workflow_effect_current($1,$2)",
                        &[&c.base.f.account, &message]
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0),
                "{mode}/{stage}"
            );
            if stage == "grant" {
                assert!(matches!(c.grant().await, Err(_) | Ok(None)));
            } else if stage == "fetch" {
                assert!(c.fetch(grant.unwrap()).await.is_err());
            } else {
                let mut db = c.base.f.connect().await;
                let now = activation::now(&db.transaction().await.unwrap())
                    .await
                    .unwrap();
                let event = zrotext_delivery_store::RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: c.base.f.account,
                    device_id: c.base.f.device,
                    message_id: message,
                    attempt_id: grant.unwrap().attempt_id,
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
            }
            c.cleanup().await;
        }
    }
}
