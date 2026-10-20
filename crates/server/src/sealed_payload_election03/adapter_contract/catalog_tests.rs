// SPDX-License-Identifier: AGPL-3.0-only
//! Closed installed writer graph; structural acceptance is not effect authority.
use super::{
    fence_tests::{close, connect},
    sha,
};
use std::path::Path;
use tokio_postgres::{Config, GenericClient, Row};
use uuid::Uuid;

fn digest_json(raw: Option<String>) -> String {
    let value: serde_json::Value = serde_json::from_str(raw.as_deref().unwrap_or("[]")).unwrap();
    sha(&serde_json::to_vec(&value).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn catalog<C: GenericClient + Sync>(db: &C) -> Vec<Row> {
    db.query(
        r#"SELECT c.relname,
         (SELECT json_agg(json_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull) ORDER BY a.attnum)::text
          FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
         (SELECT json_agg(json_build_array(p.relname,pg_get_constraintdef(k.oid)) ORDER BY p.relname COLLATE "C",pg_get_constraintdef(k.oid) COLLATE "C")::text
          FROM pg_constraint k JOIN pg_class p ON p.oid=k.confrelid WHERE k.conrelid=c.oid AND k.contype='f'),
         (SELECT json_agg(json_build_array(t.tgname,p.proname,pg_get_triggerdef(t.oid),t.tgenabled::text) ORDER BY t.tgname COLLATE "C",p.proname COLLATE "C",pg_get_triggerdef(t.oid) COLLATE "C")::text
          FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)
         FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') ORDER BY c.relname COLLATE "C"
        "#,
        &[],
    ).await.unwrap()
}

fn matches_graph(rows: &[Row], wanted: &[serde_json::Value]) -> bool {
    rows.len() == wanted.len()
        && rows.iter().zip(wanted).all(|(row, expected)| {
            row.get::<_, String>(0) == expected[0]
                && (1usize..=3).all(|field| digest_json(row.get(field)) == expected[field + 1])
        })
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn candidate_inventory_covers_exact_numbered_schema_relations_columns_fk_and_trigger_graph() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    let (admin, admin_driver) = connect(&config).await;
    let name = format!("zt_inventory_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    config.dbname(&name);
    let (mut db, driver) = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    zrotext_migrator::apply(&mut db, &directory, false)
        .await
        .unwrap();
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/profile03-writer-inventory-candidate.json"
    ))
    .unwrap();
    let version: i64 = db
        .query_one("SELECT max(version) FROM public.schema_migrations", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        Some(version),
        corpus["migration_version"].as_i64(),
        "new migrations require reviewed inventory evolution"
    );
    let rows = catalog(&db).await;
    let wanted = corpus["relations"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        wanted.len(),
        "unknown or missing relation must not silently join a production fence"
    );
    for (row, expected) in rows.iter().zip(wanted) {
        let table: String = row.get(0);
        assert_eq!(table, expected[0], "relation inventory");
        for field in 1usize..=3 {
            assert_eq!(
                digest_json(row.get(field)),
                expected[field + 1],
                "{table}: catalog graph component {field}"
            );
        }
        assert!(
            expected[1].as_str().is_some_and(|scope| !scope.is_empty()),
            "{table}: extraction review class"
        );
        let policy = corpus["operation_policies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|policy| policy["relation"] == table)
            .unwrap();
        for operation in ["insert", "update", "delete"] {
            assert!(
                policy[operation]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "{table}: {operation} policy"
            );
        }
        assert!(
            matches!(
                policy["current_profile"].as_str(),
                Some(
                    "ordinary_state_or_actual_accepted_epoch1_with_explicit_operation_policy"
                        | "originals_retained_without_rewrite_or_backfill_after_selection"
                        | "relation_specific_legacy02_fence_and_typed_initial03_or_monotone_security_policy"
                        | "closed_rows_never_accept_or_restore02_fallback"
                        | "historical_acceptance_not_current_permission"
                )
            ) || matches!(
                (table.as_str(), policy["current_profile"].as_str()),
                (
                    "payload_profile_selection_challenges",
                    Some(
                        "new_mutations_version_actual_anchor_at_unchanged_epoch1_no_historical_retry_touch"
                    )
                ) | (
                    "payload_profile_selection_receipts",
                    Some(
                        "one_accepted_per_full_connection_historical_receipt_not_message_permission"
                    )
                )
            ) || matches!(
                (table.as_str(), policy["current_profile"].as_str()),
                (
                    "payload_profile_manifest_successors",
                    Some("immutable_same_root03_successor_receipt_without_content_permission")
                ) | (
                    "conversation_profile03_intervals",
                    Some(
                        "original_content_consent_requires_live_independent_owner_device_custody_and_installed_ACK"
                    )
                ) | (
                    "conversation_reviewed_sends03",
                    Some(
                        "retained_reviewed03_originals_require_complete_same_transaction_queue_quota_or_one_way_content_erasure"
                    )
                ) | (
                    "messages",
                    Some(
                        "exact_reviewed03_admission_or_retention_without_implicit_effect_permission"
                    )
                ) | (
                    "dispatch_jobs",
                    Some(
                        "exact_reviewed03_initial_job_or_real_erasure_without_claim_or_grant_permission"
                    )
                )
            ),
            "{table}: unknown current-profile writer policy"
        );
    }
    assert_eq!(
        corpus["operation_policies"].as_array().unwrap().len(),
        wanted.len()
    );
    // This fixture pins relation extraction metadata. The separate mandatory
    // writer tests qualify actual locks, state policies and function/ACL checks.
    assert!(matches_graph(&rows, wanted));
    for mutation in [
        "ALTER TABLE public.device_sessions ADD COLUMN unreviewed boolean",
        "CREATE TABLE public.unreviewed_relation(id uuid)",
        "ALTER TABLE public.device_sessions DISABLE TRIGGER device_session_line_activation_version_before_update",
        "ALTER TABLE public.device_sessions DROP CONSTRAINT device_sessions_owner",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(!matches_graph(&catalog(&tx).await, wanted), "{mutation}");
        tx.rollback().await.unwrap();
        assert!(matches_graph(&catalog(&db).await, wanted));
    }
    close(db, driver).await;
    // Require known driver completion; never FORCE or terminate another backend.
    admin
        .batch_execute(&format!("DROP DATABASE {name}"))
        .await
        .unwrap();
    close(admin, admin_driver).await;
}
