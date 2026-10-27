// SPDX-License-Identifier: AGPL-3.0-only
//! Historical optional-storage SQL contracts, never current HTTP admission.
use super::*;
use tokio_postgres::{GenericClient, Transaction};

async fn snapshot<C: GenericClient + Sync>(db: &C) -> Vec<(String, String)> {
    let mut tables: Vec<_> = DELETE_PLAN
        .iter()
        .map(|(table, _)| *table)
        .filter(|table| *table != OBSERVER_USERS_TABLE)
        .chain(BLOCKED_TABLES.iter().copied())
        .chain(OPTIONAL_BLOCKED_TABLES.iter().copied())
        .chain(["users", "accounts", "payload_profile_account_anchors"])
        .collect();
    tables.sort_unstable();
    tables.dedup();
    let mut result = Vec::new();
    for table in tables {
        if db
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            let row = db.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM {table} t"), &[]).await.unwrap();
            result.push((table.to_owned(), row.get(0)));
        }
    }
    result
}

/// Historical inventory uses the route's named table lists and count primitive.
/// This is not execution of its current HTTP/native admission branch.
async fn blocker_inventory(
    tx: &Transaction<'_>,
    account: Uuid,
) -> (Vec<(&'static str, u64)>, Vec<&'static str>) {
    let mut blocked = Vec::new();
    let mut omitted = Vec::new();
    for &table in BLOCKED_TABLES.iter().chain(OPTIONAL_BLOCKED_TABLES.iter()) {
        if OPTIONAL_BLOCKED_TABLES.contains(&table) {
            assert_eq!(table, "sealed_line_activation_exchanges");
            let installed = tx
                .query_one(
                    "SELECT to_regclass('sealed_line_activation_exchanges') IS NOT NULL",
                    &[],
                )
                .await
                .unwrap()
                .get::<_, bool>(0);
            if !installed {
                omitted.push(table);
                continue;
            }
        }
        let rows = count(
            tx,
            &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
            account,
        )
        .await
        .unwrap();
        if rows > 0 {
            blocked.push((table, rows));
        }
    }
    (blocked, omitted)
}

/// Select the route's actual ordered statements using the same installed
/// predicates. This executes SQL only: it is not native entry or auth evidence.
async fn execute_plan(tx: &Transaction<'_>, account: Uuid) -> Vec<(&'static str, u64)> {
    let android = crate::http_owner_conversations::android_proposal::lifecycle::prepare_erase(tx)
        .await
        .unwrap();
    let managed = crate::managed_ai::lifecycle::installed(tx).await.unwrap();
    let provider = crate::provider_sms::receipts::lifecycle::installed(tx)
        .await
        .unwrap();
    let execution = crate::http_owner_conversations::channel::execution::lifecycle::installed(tx)
        .await
        .unwrap();
    let confirmation = crate::http_owner_conversations::confirmation_records::installed(tx)
        .await
        .unwrap();
    let integration = crate::workflow_runtime::lifecycle::installed(tx)
        .await
        .unwrap();
    if execution {
        assert!(
            crate::http_owner_conversations::channel::execution::lifecycle::validate(tx)
                .await
                .unwrap()
        );
    }
    if confirmation {
        assert!(
            crate::http_owner_conversations::confirmation_records::validate(tx)
                .await
                .unwrap()
        );
    }
    let mut counts = Vec::new();
    for &(table, sql) in DELETE_PLAN {
        if (table == "owner_android_proposals" && !android)
            || (crate::managed_ai::lifecycle::TABLES.contains(&table) && !managed)
            || (["provider_receipt_events", "provider_receipt_attempts"].contains(&table)
                && !provider)
            || (table == "conversation_execution_records" && !execution)
            || (table == "conversation_confirmation_records" && !confirmation)
            || ([
                "workflow_integration_access",
                "workflow_connector_context_envelopes",
                "workflow_integration_grants",
            ]
            .contains(&table)
                && !integration)
        {
            continue;
        }
        counts.push((table, tx.execute(sql, &[&account]).await.unwrap()));
    }
    counts
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical optional deletion SQL, not HTTP acceptance"]
async fn historical_execution_sealed_setup_and_android_absence_preserve_exact_sql_deletion() {
    for absent in ["execution", "sealed_setup", "android"] {
        let (admin, mut db, url, schema) = migrated_schema_with_optional_setup(
            "execution_erase",
            absent != "execution",
            absent != "sealed_setup",
        )
        .await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
        let (a, _session, b, _, _app) = fixture(&mut db, &hasher, &url, None).await;
        if absent == "android" {
            db.batch_execute("DROP TABLE owner_android_proposals; DROP FUNCTION reject_owner_android_proposal_update()").await.unwrap();
        }
        let absent_table = match absent {
            "execution" => "conversation_execution_records",
            "sealed_setup" => "sealed_line_activation_exchanges",
            _ => "owner_android_proposals",
        };
        assert!(
            !db.query_one("SELECT to_regclass($1) IS NOT NULL", &[&absent_table])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        if absent == "sealed_setup" {
            assert!(OPTIONAL_BLOCKED_TABLES.contains(&absent_table));
        }
        let tx = db.transaction().await.unwrap();
        let (blocked, omitted) = blocker_inventory(&tx, a.account_id).await;
        assert!(blocked.is_empty());
        assert_eq!(
            omitted,
            if absent == "sealed_setup" {
                vec!["sealed_line_activation_exchanges"]
            } else {
                Vec::new()
            }
        );
        let counts = execute_plan(&tx, a.account_id).await;
        assert!(!counts.iter().any(|(table, _)| *table == absent_table));
        for (table, expected) in [
            ("dispatch_fences", 2),
            ("messages", 2),
            ("message_attempts", 2),
            ("sessions", 1),
        ] {
            assert_eq!(
                counts.iter().find(|(name, _)| *name == table).unwrap().1,
                expected
            );
        }
        assert_eq!(
            tx.execute("DELETE FROM users WHERE id=$1", &[&a.user_id])
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            tx.execute("DELETE FROM accounts WHERE id=$1", &[&a.account_id])
                .await
                .unwrap(),
            1
        );
        assert!(matches!(
            crate::payload_profile_anchor::retention(&tx, a.account_id)
                .await
                .unwrap(),
            crate::payload_profile_anchor::Retention::Deleted
        ));
        tx.commit().await.unwrap();
        assert_eq!(
            rows(
                &db,
                "SELECT count(*) FROM accounts WHERE id=$1",
                a.account_id
            )
            .await,
            0
        );
        assert_eq!(
            rows(
                &db,
                "SELECT count(*) FROM accounts WHERE id=$1",
                b.account_id
            )
            .await,
            1
        );
        assert_eq!(
            rows(
                &db,
                "SELECT count(*) FROM messages WHERE account_id=$1",
                b.account_id
            )
            .await,
            1
        );
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical partial preflight contracts, not native admission"]
async fn historical_partial_confirmation_execution_and_android_fail_before_sql_deletion() {
    for shape in [
        "confirmation",
        "execution",
        "android_partial",
        "android_disabled",
        "sealed_setup",
    ] {
        let (admin, mut db, url, schema) = if shape == "sealed_setup" {
            migrated_schema_with_optional_setup("optional_setup_malformed", true, false).await
        } else {
            migrated_schema("execution_partial").await
        };
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
        let (a, _, _, _, _) = fixture(&mut db, &hasher, &url, None).await;
        match shape {
            "sealed_setup" => db.batch_execute("CREATE TABLE sealed_line_activation_exchanges(wrong_column uuid)").await.unwrap(),
            "confirmation" => db.batch_execute("DROP TABLE conversation_execution_records CASCADE; DROP TABLE conversation_confirmation_records; CREATE TABLE conversation_confirmation_records(account_id uuid NOT NULL)").await.unwrap(),
            "execution" => db.batch_execute("ALTER TABLE conversation_execution_records DROP COLUMN unsigned_digest").await.unwrap(),
            "android_partial" => db.batch_execute("DROP TABLE owner_android_proposals; DROP FUNCTION reject_owner_android_proposal_update(); CREATE TABLE owner_android_proposals(account_id uuid)").await.unwrap(),
            _ => db.batch_execute("ALTER TABLE owner_android_proposals DISABLE TRIGGER owner_android_proposals_immutable").await.unwrap(),
        }
        let before = snapshot(&db).await;
        let tx = db.transaction().await.unwrap();
        match shape {
            "confirmation" => {
                let error = crate::http_owner_conversations::confirmation_records::validate(&tx)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.code(),
                    Some(&tokio_postgres::error::SqlState::UNDEFINED_COLUMN)
                );
            }
            "sealed_setup" => {
                let table = OPTIONAL_BLOCKED_TABLES[0];
                assert_eq!(table, "sealed_line_activation_exchanges");
                let error = count(
                    &tx,
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    a.account_id,
                )
                .await
                .unwrap_err();
                assert_eq!(
                    error.code(),
                    Some(&tokio_postgres::error::SqlState::UNDEFINED_COLUMN)
                );
            }
            "execution" => assert!(
                !crate::http_owner_conversations::channel::execution::lifecycle::validate(&tx)
                    .await
                    .unwrap()
            ),
            _ => assert!(
                crate::http_owner_conversations::android_proposal::lifecycle::prepare_erase(&tx)
                    .await
                    .is_err()
            ),
        }
        tx.rollback().await.unwrap();
        assert_eq!(snapshot(&db).await, before);
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical exact observer SQL rollback, not current HTTP"]
async fn historical_observer_user_fk_failure_rolls_back_witnessed_prior_deletes() {
    let (admin, mut db, url, schema) = migrated_schema("observer_block").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(44)).unwrap());
    let (a, session, _, _, _) = fixture(&mut db, &hasher, &url, None).await;
    let owner = principal_of(&db, &hasher, &session).await;
    let (observer, _) = seat_observer(
        &mut db,
        &hasher,
        &owner,
        &crate::test_keys::password(1),
        "pinned-observer@example.test",
        true,
    )
    .await;
    db.batch_execute("CREATE TABLE observer_user_pin(user_id uuid PRIMARY KEY CONSTRAINT synthetic_observer_pin REFERENCES users(id))").await.unwrap();
    db.execute("INSERT INTO observer_user_pin VALUES($1)", &[&observer])
        .await
        .unwrap();
    let before = snapshot(&db).await;
    let tx = db.transaction().await.unwrap();
    zrotext_delivery_store::sealed::lock_account(&tx, a.account_id, false)
        .await
        .unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&a.account_id]
        )
        .await
        .unwrap(),
        1
    );
    let mut reached = false;
    for &(table, sql) in DELETE_PLAN {
        if ["provider_receipt_events", "provider_receipt_attempts"].contains(&table) {
            continue;
        }
        if table == OBSERVER_USERS_TABLE {
            assert_eq!(
                tx.query_one(
                    "SELECT count(*) FROM messages WHERE account_id=$1",
                    &[&a.account_id]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                0
            );
            assert_eq!(
                tx.query_one(
                    "SELECT count(*) FROM sessions WHERE account_id=$1",
                    &[&a.account_id]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                0
            );
            let error = tx.execute(sql, &[&a.account_id]).await.unwrap_err();
            let error = error.as_db_error().unwrap();
            assert_eq!(
                error.code(),
                &tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION
            );
            assert_eq!(error.constraint(), Some("synthetic_observer_pin"));
            reached = true;
            break;
        }
        tx.execute(sql, &[&a.account_id]).await.unwrap();
    }
    assert!(reached);
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&db).await, before);
    assert_eq!(
        rows(
            &db,
            "SELECT count(*) FROM observer_user_pin WHERE user_id=$1",
            observer
        )
        .await,
        1
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical anchor retention contract, no HTTP fallback"]
async fn historical_missing_anchor_update_is_not_committed_retention() {
    let (admin, mut db, _, schema) = migrated_schema("anchor_drift").await;
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.batch_execute("DROP TRIGGER payload_profile_anchor_after_account_delete ON accounts")
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        tx.execute("DELETE FROM accounts WHERE id=$1", &[&account])
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        crate::payload_profile_anchor::retention(&tx, account)
            .await
            .unwrap(),
        crate::payload_profile_anchor::Retention::Invalid
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        rows(&db, "SELECT count(*) FROM accounts WHERE id=$1", account).await,
        1
    );
    assert_eq!(
        db.query_one(
            "SELECT state FROM payload_profile_account_anchors WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "live"
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
