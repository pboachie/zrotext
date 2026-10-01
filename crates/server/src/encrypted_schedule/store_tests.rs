// SPDX-License-Identifier: AGPL-3.0-only
use super::{policy::WindowPolicy, store::*};
use crate::http_owner_conversations::context::decisions::{lock_approved, tests::Case};
use uuid::Uuid;

async fn prepared() -> (Case, WindowPolicy) {
    let mut c = Case::new().await;
    c.base
        .f
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/077_encrypted_schedule.sql"
        ))
        .await
        .unwrap();
    let row = c.base.f.db.query_one("SELECT to_char((clock_timestamp() AT TIME ZONE 'UTC')-interval '2 minutes','YYYY-MM-DD'),extract(hour FROM (clock_timestamp() AT TIME ZONE 'UTC')-interval '2 minutes')::int*60+extract(minute FROM (clock_timestamp() AT TIME ZONE 'UTC')-interval '2 minutes')::int",&[]).await.unwrap();
    let opens: i32 = row.get(1);
    let p = WindowPolicy {
        timezone: Some("UTC".into()),
        first_local_date: row.get(0),
        opens_minute: opens as u16,
        closes_minute: ((opens + 60) % 1440) as u16,
        repeat_every_days: None,
        max_occurrences: 1,
        pacing_seconds: 60,
    };
    c.descriptor.window_id = p.identity().unwrap();
    c.descriptor.timezone = "UTC".into();
    (c, p)
}
async fn reserve(
    c: &Case,
    p: &WindowPolicy,
    key: crate::http_owner_conversations::context::decisions::ActionKey,
    r: ScheduleRequest,
) -> Occurrence {
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, key).await.unwrap();
    let result = schedule(&mut permit, r, p).await.unwrap();
    drop(permit);
    tx.commit().await.unwrap();
    result
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exact_schedule_replays_preserve_dispatch_and_renderer_absence_creates_no_message() {
    let (c, p) = prepared().await;
    let a = c.approved().await;
    let r = ScheduleRequest {
        request_id: Uuid::new_v4(),
        series_id: Uuid::new_v4(),
        ordinal: 0,
    };
    let o = reserve(&c, &p, a.key, r).await;
    assert_eq!(o.phase, "waiting_window");
    assert_eq!(o, reserve(&c, &p, a.key, r).await);
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, a.key).await.unwrap();
    let lease = claim(&mut permit, o.id).await.unwrap().unwrap();
    assert_eq!(lease.occurrence.dispatch_id, o.dispatch_id);
    defer(&mut permit, &lease, Unavailable::Renderer)
        .await
        .unwrap();
    drop(permit);
    tx.commit().await.unwrap();
    let row=c.base.f.db.query_one("SELECT phase,(SELECT count(*) FROM messages),dispatch_id FROM workflow_schedule_occurrences",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "waiting_renderer");
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, Uuid>(2), o.dispatch_id);
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn schedule_rejects_changed_replay_and_already_bound_dispatch_adoption() {
    let (mut c, p) = prepared().await;
    let a = c.approved().await;
    let r = ScheduleRequest {
        request_id: Uuid::new_v4(),
        series_id: Uuid::new_v4(),
        ordinal: 0,
    };
    reserve(&c, &p, a.key, r).await;
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, a.key).await.unwrap();
    assert!(
        schedule(
            &mut permit,
            ScheduleRequest {
                series_id: Uuid::new_v4(),
                ..r
            },
            &p
        )
        .await
        .is_err()
    );
    drop(permit);
    tx.rollback().await.unwrap();
    let mut next = c.descriptor.clone();
    next.action_id = Uuid::new_v4().to_string();
    next.routine_id = Uuid::new_v4().to_string();
    c.descriptor = next;
    let b = c.approved().await;
    let bound = c.bind(b).await;
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, bound.key).await.unwrap();
    assert!(
        schedule(
            &mut permit,
            ScheduleRequest {
                request_id: Uuid::new_v4(),
                series_id: Uuid::new_v4(),
                ordinal: 0
            },
            &p
        )
        .await
        .is_err()
    );
    drop(permit);
    tx.rollback().await.unwrap();
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn exact_confirmed_message_dispatch_requires_initiating_live_owner_session() {
    let (mut c, p) = prepared().await;
    let a = c.approved().await;
    let o = reserve(
        &c,
        &p,
        a.key,
        ScheduleRequest {
            request_id: Uuid::new_v4(),
            series_id: Uuid::new_v4(),
            ordinal: 0,
        },
    )
    .await;
    let bound = c.bind_with_dispatch(a, o.dispatch_id).await;
    let message: Uuid = c
        .base
        .f
        .db
        .query_one("SELECT message_id FROM workflow_message_links", &[])
        .await
        .unwrap()
        .get(0);
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, bound.key).await.unwrap();
    let lease = claim(&mut permit, o.id).await.unwrap().unwrap();
    assert_eq!(
        begin_dispatch(&mut permit, &lease, message).await.unwrap(),
        o.dispatch_id
    );
    drop(permit);
    tx.commit().await.unwrap();
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
    c.base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.base.owner.session_id],
        )
        .await
        .unwrap();
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
            .get::<_, bool>(0)
    );
    assert!(
        c.grant().await.is_err()
            || c.base
                .f
                .db
                .query_one("SELECT count(*) FROM dispatch_fences", &[])
                .await
                .unwrap()
                .get::<_, i64>(0)
                == 0
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM dispatch_fences", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn concurrent_claims_have_one_lease_and_cancel_replays_do_not_refund_twice() {
    let (mut c, p) = prepared().await;
    let a = c.approved().await;
    let o = reserve(
        &c,
        &p,
        a.key,
        ScheduleRequest {
            request_id: Uuid::new_v4(),
            series_id: Uuid::new_v4(),
            ordinal: 0,
        },
    )
    .await;
    async fn contender(
        c: &Case,
        key: crate::http_owner_conversations::context::decisions::ActionKey,
        id: Uuid,
    ) -> bool {
        let mut db = c.base.f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut permit = lock_approved(&tx, &c.base.owner, key).await.unwrap();
        let won = claim(&mut permit, id).await.unwrap().is_some();
        drop(permit);
        tx.commit().await.unwrap();
        won
    }
    let (a_won, b_won) = tokio::join!(contender(&c, a.key, o.id), contender(&c, a.key, o.id));
    assert_ne!(a_won, b_won);
    let bound = c.bind_with_dispatch(a, o.dispatch_id).await;
    for _ in 0..2 {
        let mut db = c.base.f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut permit = lock_approved(&tx, &c.base.owner, bound.key).await.unwrap();
        cancel(&mut permit, o.id).await.unwrap();
        drop(permit);
        tx.commit().await.unwrap();
    }
    let row=c.base.f.db.query_one("SELECT (SELECT phase FROM workflow_schedule_occurrences),(SELECT state FROM messages),(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund')",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, String>(1), "cancelled");
    assert_eq!(row.get::<_, i64>(2), 1);
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_export_is_scoped_and_retention_preserves_cancelled_live_action_identity() {
    let (c, p) = prepared().await;
    let a = c.approved().await;
    let r = ScheduleRequest {
        request_id: Uuid::new_v4(),
        series_id: Uuid::new_v4(),
        ordinal: 0,
    };
    let o = reserve(&c, &p, a.key, r).await;
    let export = super::lifecycle::export(
        &mut c.base.f.connect().await,
        &c.base.owner,
        super::lifecycle::Cursors::default(),
    )
    .await
    .unwrap();
    assert_eq!(export.policies.items.len(), 1);
    assert_eq!(export.occurrences.items.len(), 1);
    assert_eq!(export.series.items.len(), 1);
    assert_eq!(export.audit.items.len(), 1);
    assert!(
        super::lifecycle::export(
            &mut c.base.f.connect().await,
            &c.base.owner,
            super::lifecycle::Cursors {
                occurrences: Some(Uuid::new_v4()),
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut permit = lock_approved(&tx, &c.base.owner, a.key).await.unwrap();
    cancel(&mut permit, o.id).await.unwrap();
    drop(permit);
    tx.commit().await.unwrap();
    assert_eq!(super::lifecycle::prune(&mut db, 1, 1).await.unwrap(), 0);
    assert_eq!(reserve(&c, &p, a.key, r).await.id, o.id);
    for (table, sql) in crate::http_owner_erasure::DELETE_PLAN
        .iter()
        .filter(|(table, _)| table.starts_with("workflow_schedule_"))
    {
        assert_eq!(
            db.execute(*sql, &[&c.base.f.account]).await.unwrap(),
            if *table == "workflow_schedule_audit" {
                2
            } else {
                1
            }
        );
    }
    c.cleanup().await;
}
