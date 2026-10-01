// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::ConversationError;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn erasure_plan_deletes_each_populated_decision_table_before_context_and_message_parents() {
    let mut c = Case::new().await;
    let a = c.approved().await;
    c.bind(a).await;
    let event = c.capture(1).await;
    correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        Correlation {
            context_id: c.base.h.context,
            context_revision: 1,
            event_id: event,
            request_action: None,
        },
    )
    .await
    .unwrap();
    let expected = [
        "workflow_message_links",
        "workflow_reply_correlations",
        "workflow_action_mutations",
        "workflow_action_versions",
        "workflow_actions",
        "workflow_routines",
        "workflow_context_fences",
    ];
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut seen = Vec::new();
    for (table, sql) in crate::http_owner_erasure::DELETE_PLAN {
        if expected.contains(table) {
            assert!(
                tx.execute(*sql, &[&c.base.f.account]).await.unwrap() > 0,
                "{table}"
            );
            seen.push(*table);
        } else if [
            "workflow_context_audit",
            "workflow_exceptions",
            "workflow_context_versions",
            "workflow_contexts",
        ]
        .contains(table)
        {
            assert_eq!(
                seen, expected,
                "all decision children must precede context parents"
            );
            assert!(
                tx.execute(*sql, &[&c.base.f.account]).await.unwrap() > 0,
                "{table}"
            );
        }
    }
    assert_eq!(seen, expected);
    for table in ["usage_ledger", "dispatch_jobs", "messages"] {
        assert!(
            tx.execute(
                &format!("DELETE FROM {table} WHERE account_id=$1"),
                &[&c.base.f.account]
            )
            .await
            .unwrap()
                > 0
        );
    }
    tx.commit().await.unwrap();
    for table in expected {
        assert_eq!(
            db.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&c.base.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn decision_export_is_bounded_account_scoped_and_survives_reader_revocation() {
    let c = Case::new().await;
    for _ in 0..21 {
        let mut d = c.descriptor.clone();
        d.action_id = Uuid::new_v4().to_string();
        c.propose(d).await;
    }
    let mut db = c.base.f.connect().await;
    let first = super::super::lifecycle::export(&mut db, &c.base.owner, [None; 7])
        .await
        .unwrap();
    assert_eq!(first.actions.items.len(), 20);
    assert_eq!(first.versions.items.len(), 20);
    assert!(
        first
            .actions
            .items
            .iter()
            .all(|row| row["account_id"] == c.base.f.account.to_string())
    );
    let cursor = first.actions.next_cursor.as_deref();
    let next = super::super::lifecycle::export(
        &mut db,
        &c.base.owner,
        [cursor, None, None, None, None, None, None],
    )
    .await
    .unwrap();
    assert_eq!(next.actions.items.len(), 1);
    assert!(next.actions.next_cursor.is_none());
    let bad = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(&serde_json::json!({"id":Uuid::new_v4(),"revision":0})).unwrap(),
    );
    assert!(matches!(
        super::super::lifecycle::export(
            &mut db,
            &c.base.owner,
            [Some(&bad), None, None, None, None, None, None]
        )
        .await,
        Err(ConversationError::NotFound)
    ));
    db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    assert!(
        read(&mut db, &c.base.owner, c.descriptor.key().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        super::super::lifecycle::export(&mut db, &c.base.owner, [None; 7])
            .await
            .unwrap()
            .actions
            .items
            .len(),
        20
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn takeover_fence_cannot_reopen_and_retention_erases_unlinked_decision_metadata() {
    let c = Case::new().await;
    c.approved().await;
    let mut db = c.base.f.connect().await;
    takeover(&mut db, &c.base.owner, Uuid::new_v4(), c.base.h.context)
        .await
        .unwrap();
    assert!(
        db.execute(
            "UPDATE workflow_context_fences SET stopped_at=NULL WHERE account_id=$1",
            &[&c.base.f.account]
        )
        .await
        .is_err()
    );
    assert!(
        db.execute(
            "UPDATE workflow_routines SET stopped_at=NULL WHERE account_id=$1",
            &[&c.base.f.account]
        )
        .await
        .is_err()
    );
    db.execute("UPDATE workflow_contexts SET purged_at=clock_timestamp()-interval '2 days' WHERE account_id=$1",&[&c.base.f.account]).await.unwrap();
    assert_eq!(
        super::super::super::lifecycle::prune(&mut db, 1, 20)
            .await
            .unwrap(),
        1
    );
    for table in [
        "workflow_actions",
        "workflow_action_versions",
        "workflow_action_mutations",
        "workflow_routines",
        "workflow_context_fences",
        "workflow_contexts",
    ] {
        assert_eq!(
            db.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&c.base.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0,
            "{table}"
        );
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn retention_preserves_an_existing_message_fence_and_erases_after_message_removal() {
    let mut c = Case::new().await;
    let a = c.approved().await;
    c.bind(a).await;
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(
        !super::super::lifecycle::erase_context(&tx, c.base.f.account, c.base.h.context)
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        db.query_one("SELECT count(*) FROM workflow_message_links", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // Full owner erasure deletes the link before messages in one deferred-FK transaction.
    let tx = db.transaction().await.unwrap();
    for table in [
        "workflow_message_links",
        "workflow_reply_correlations",
        "workflow_action_mutations",
        "workflow_action_versions",
        "workflow_actions",
        "workflow_routines",
        "workflow_context_fences",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE account_id=$1"),
            &[&c.base.f.account],
        )
        .await
        .unwrap();
    }
    tx.execute(
        "DELETE FROM dispatch_jobs WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM usage_ledger WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM messages WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn message_retention_preserves_immutable_dispatch_tombstone_without_reopening_authority() {
    let mut c = Case::new().await;
    let a = c.approved().await;
    let bound = c.bind(a).await;
    let mut db = c.base.f.connect().await;
    let old = db
        .query_one(
            "SELECT message_id,dispatch_id FROM workflow_message_links",
            &[],
        )
        .await
        .unwrap();
    let message: Uuid = old.get(0);
    let dispatch: Uuid = old.get(1);
    let tx = db.transaction().await.unwrap();
    tx.execute(
        "DELETE FROM usage_ledger WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM dispatch_jobs WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM messages WHERE account_id=$1",
        &[&c.base.f.account],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let row = db
        .query_one(
            "SELECT message_id,dispatch_id,live_message_id FROM workflow_message_links",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Uuid>(0), message);
    assert_eq!(row.get::<_, Uuid>(1), dispatch);
    assert!(row.get::<_, Option<Uuid>>(2).is_none());
    assert!(
        !db.query_one(
            "SELECT workflow_effect_current($1,$2)",
            &[&c.base.f.account, &message]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert!(
        db.execute(
            "UPDATE workflow_message_links SET message_id=$1",
            &[&Uuid::new_v4()]
        )
        .await
        .is_err()
    );
    assert!(
        db.execute(
            "UPDATE workflow_message_links SET live_message_id=message_id",
            &[]
        )
        .await
        .is_err()
    );
    let tx = db.transaction().await.unwrap();
    assert!(
        super::super::lifecycle::erase_context(&tx, c.base.f.account, c.base.h.context)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert!(read(&mut db, &c.base.owner, bound.key).await.is_err());
    c.cleanup().await;
}
