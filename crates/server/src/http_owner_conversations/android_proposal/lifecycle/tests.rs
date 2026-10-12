// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::tests::prepared;
use crate::sealed_manifest_store::tests::Fixture;

const MIGRATION: &str =
    include_str!("../../../../../../deploy/compose/migrations/097_owner_android_proposals.sql");

async fn observed_require(f: &Fixture) -> Result<(), ConversationError> {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let result = require_installed(&tx).await;
    tx.rollback().await.unwrap();
    result
}
async fn observed_inventory(f: &Fixture) -> Result<serde_json::Value, ConversationError> {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let result = inventory(&tx, f.account).await;
    tx.rollback().await.unwrap();
    result
}
async fn observed_prune(f: &Fixture, limit: i64) -> Result<u64, ConversationError> {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let result = prune(&tx, limit).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    result
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn absent_optional_schema_is_inert_and_complete_schema_is_required() {
    let (f, _) = prepared().await;
    assert!(!installed(&f.db).await.unwrap());
    assert!(observed_require(&f).await.is_err());
    assert_eq!(observed_prune(&f, 100).await.unwrap(), 0);
    assert_eq!(
        observed_inventory(&f).await.unwrap(),
        serde_json::json!({"installed":false,"proposals":[]})
    );
    f.db.batch_execute(MIGRATION).await.unwrap();
    assert!(installed(&f.db).await.unwrap());
    assert_eq!(
        observed_inventory(&f).await.unwrap(),
        serde_json::json!({"installed":true,"proposals":[]})
    );
    f.db.batch_execute(
        "ALTER TABLE owner_android_proposals DISABLE TRIGGER owner_android_proposals_immutable",
    )
    .await
    .unwrap();
    assert!(installed(&f.db).await.is_err());
    assert!(observed_prune(&f, 100).await.is_err());
    f.db.batch_execute("ALTER TABLE owner_android_proposals ENABLE TRIGGER owner_android_proposals_immutable; DROP INDEX owner_android_proposals_session").await.unwrap();
    assert!(installed(&f.db).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn partial_optional_schema_cannot_export_or_enable_proposals() {
    let (f, _) = prepared().await;
    f.db.batch_execute("CREATE TABLE owner_android_proposals(account_id uuid)")
        .await
        .unwrap();
    assert!(installed(&f.db).await.is_err());
    assert!(observed_inventory(&f).await.is_err());
    assert!(observed_require(&f).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn same_count_weaker_check_and_named_wrong_index_fail_closed() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    assert!(installed(&f.db).await.unwrap());
    f.db.batch_execute("ALTER TABLE owner_android_proposals DROP CONSTRAINT owner_android_proposals_proposal_sha256_check; ALTER TABLE owner_android_proposals ADD CONSTRAINT owner_android_proposals_proposal_sha256_check CHECK(TRUE)").await.unwrap();
    assert!(installed(&f.db).await.is_err());
    f.db.batch_execute("ALTER TABLE owner_android_proposals DROP CONSTRAINT owner_android_proposals_proposal_sha256_check; ALTER TABLE owner_android_proposals ADD CONSTRAINT owner_android_proposals_proposal_sha256_check CHECK(octet_length(proposal_sha256)=32)").await.unwrap();
    assert!(installed(&f.db).await.unwrap());
    f.db.batch_execute("DROP INDEX owner_android_proposals_session; CREATE INDEX owner_android_proposals_session ON owner_android_proposals(account_id,user_id)").await.unwrap();
    assert!(installed(&f.db).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn catalog_drift_refuses_every_lifecycle_operation_and_rolls_back() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let mut db = f.connect().await;
    assert!(installed(&db).await.unwrap());
    let expiry = db.query(
        "SELECT quote_ident(conname) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='c' AND pg_get_constraintdef(oid)=$1",
        &[&"CHECK (((expires_ms > issued_ms) AND ((expires_ms - issued_ms) <= 300000)))"],
    ).await.unwrap();
    assert_eq!(expiry.len(), 1, "one exact installed expiry CHECK");
    let expiry: String = expiry[0].get(0);
    let expiry_drift = format!(
        "ALTER TABLE owner_android_proposals DROP CONSTRAINT {expiry}; ALTER TABLE owner_android_proposals ADD CONSTRAINT {expiry} CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300001)"
    );
    for drift in [
        "ALTER TABLE owner_android_proposals ADD COLUMN unexpected boolean",
        "ALTER TABLE owner_android_proposals ALTER COLUMN origin DROP NOT NULL",
        "ALTER TABLE owner_android_proposals ALTER COLUMN expected_context SET DEFAULT '{}'::jsonb",
        "ALTER TABLE owner_android_proposals ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE owner_android_proposals SET UNLOGGED",
        expiry_drift.as_str(),
        "ALTER TABLE owner_android_proposals DROP CONSTRAINT owner_android_proposals_origin_check; ALTER TABLE owner_android_proposals ADD CONSTRAINT owner_android_proposals_origin_check CHECK(octet_length(origin) BETWEEN 1 AND 512) NOT VALID",
        "ALTER TABLE owner_android_proposals ALTER CONSTRAINT owner_android_proposals_account_id_session_id_fkey DEFERRABLE",
        "DROP INDEX owner_android_proposals_expiry; CREATE INDEX owner_android_proposals_expiry ON owner_android_proposals(expires_ms DESC)",
        "CREATE INDEX unexpected_proposal_index ON owner_android_proposals(issued_ms)",
        "DROP TRIGGER owner_android_proposals_immutable ON owner_android_proposals; CREATE TRIGGER owner_android_proposals_immutable BEFORE UPDATE ON owner_android_proposals FOR EACH ROW WHEN(FALSE) EXECUTE FUNCTION reject_owner_android_proposal_update()",
        "CREATE TRIGGER unexpected_proposal_trigger BEFORE DELETE ON owner_android_proposals FOR EACH ROW EXECUTE FUNCTION reject_owner_android_proposal_update()",
        "ALTER FUNCTION reject_owner_android_proposal_update() SECURITY DEFINER",
        "ALTER FUNCTION reject_owner_android_proposal_update() SET search_path TO public",
        "CREATE OR REPLACE FUNCTION reject_owner_android_proposal_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
        "CREATE TABLE unexpected_proposal_reference(account_id uuid,kind smallint,FOREIGN KEY(account_id,kind) REFERENCES owner_android_proposals(account_id,kind))",
    ] {
        assert!(installed(&db).await.unwrap());
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(drift).await.unwrap();
        assert!(installed(&tx).await.is_err(), "{drift}");
        assert!(require_installed(&tx).await.is_err(), "{drift}");
        assert!(inventory(&tx, f.account).await.is_err(), "{drift}");
        assert!(prune(&tx, 100).await.is_err(), "{drift}");
        tx.rollback().await.unwrap();
        assert!(installed(&db).await.unwrap());
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn orphaned_function_and_search_path_shadow_are_not_optional_absence() {
    let (f, _) = prepared().await;
    f.db.batch_execute("CREATE FUNCTION reject_owner_android_proposal_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owner proposal is immutable'; END; $$")
        .await.unwrap();
    assert!(installed(&f.db).await.is_err());
    assert!(observed_inventory(&f).await.is_err());
    f.db.batch_execute("DROP FUNCTION reject_owner_android_proposal_update()")
        .await
        .unwrap();
    assert!(!installed(&f.db).await.unwrap());
    f.db.batch_execute(MIGRATION).await.unwrap();
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let shadow = format!("proposal_shadow_{}", Uuid::new_v4().simple());
    tx.batch_execute(&format!("CREATE SCHEMA {shadow}; ALTER TABLE owner_android_proposals SET SCHEMA {shadow}; SET LOCAL search_path TO {},{shadow}", f.schema))
        .await.unwrap();
    assert!(installed(&tx).await.is_err());
    assert!(prune(&tx, 100).await.is_err());
    tx.rollback().await.unwrap();
    assert!(installed(&f.db).await.unwrap());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema and administrative trigger privileges"]
async fn each_owned_foreign_key_check_and_parent_action_trigger_must_enforce() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let definitions = f.db.query("SELECT oid,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='f' ORDER BY oid", &[])
        .await.unwrap().into_iter().map(|r| (r.get::<_, u32>(0), r.get::<_, String>(1))).collect::<Vec<_>>();
    assert_eq!(definitions.len(), 4);
    let triggers = f.db.query("SELECT format('%I.%I',n.nspname,c.relname),quote_ident(t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE k.conrelid=to_regclass('owner_android_proposals') AND k.contype='f' ORDER BY t.oid", &[])
        .await.unwrap();
    assert_eq!(triggers.len(), 16);
    let mut db = f.connect().await;
    for trigger in triggers {
        let table: String = trigger.get(0);
        let name: String = trigger.get(1);
        for action in [
            "DISABLE TRIGGER",
            "ENABLE REPLICA TRIGGER",
            "ENABLE ALWAYS TRIGGER",
        ] {
            assert!(installed(&db).await.unwrap());
            let tx = db.transaction().await.unwrap();
            tx.batch_execute(&format!("ALTER TABLE {table} {action} {name}"))
                .await
                .unwrap();
            let retained = tx.query("SELECT oid,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='f' ORDER BY oid", &[])
                .await.unwrap().into_iter().map(|r| (r.get::<_, u32>(0), r.get::<_, String>(1))).collect::<Vec<_>>();
            assert_eq!(retained, definitions);
            assert_eq!(tx.query_one("SELECT count(*) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE k.conrelid=to_regclass('owner_android_proposals') AND k.contype='f'", &[]).await.unwrap().get::<_, i64>(0), 16);
            assert!(installed(&tx).await.is_err());
            assert!(require_installed(&tx).await.is_err());
            assert!(inventory(&tx, f.account).await.is_err());
            assert!(prune(&tx, 1).await.is_err());
            tx.rollback().await.unwrap();
            assert!(installed(&db).await.unwrap());
        }
    }
    // Readiness is specific to our four FKs. An unrelated user trigger on a
    // parent must not be mistaken for another proposal enforcement trigger.
    f.db.batch_execute("CREATE FUNCTION proposal_parent_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER proposal_parent_probe BEFORE UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION proposal_parent_probe()")
        .await.unwrap();
    assert!(installed(&f.db).await.unwrap());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema and session_replication_role SET privilege"]
async fn replica_execution_mode_cannot_bypass_installed_foreign_keys() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let mut db = f.connect().await;
    for mode in ["origin", "local", "replica"] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL session_replication_role='{mode}'"))
            .await
            .unwrap();
        if mode == "replica" {
            assert!(installed(&tx).await.is_err());
            assert!(require_installed(&tx).await.is_err());
            assert!(inventory(&tx, f.account).await.is_err());
            assert!(prune(&tx, 1).await.is_err());
        } else {
            assert!(installed(&tx).await.unwrap());
            require_installed(&tx).await.unwrap();
            assert_eq!(prune(&tx, 1).await.unwrap(), 0);
        }
        tx.rollback().await.unwrap();
        assert!(installed(&db).await.unwrap());
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema and existing table-lock privileges"]
async fn transaction_schema_fence_refuses_trigger_ddl_and_allows_ordinary_writes() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let tables = f.db.query("SELECT format('%I.%I',n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('owner_android_proposals') OR c.oid IN(SELECT confrelid FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='f') ORDER BY c.oid", &[])
        .await.unwrap().into_iter().map(|r| r.get::<_, String>(0)).collect::<Vec<_>>();
    assert_eq!(tables.len(), 5);
    let mut ready_db = f.connect().await;
    let mut other_db = f.connect().await;
    let tx = ready_db.transaction().await.unwrap();
    require_installed(&tx).await.unwrap();
    for table in &tables {
        let other = other_db.transaction().await.unwrap();
        // DELETE with no matching rows still takes the ordinary DML table
        // lock. It must stay compatible with the retained schema fence.
        other
            .batch_execute(&format!("DELETE FROM {table} WHERE FALSE"))
            .await
            .unwrap();
        other.rollback().await.unwrap();
        let other = other_db.transaction().await.unwrap();
        let error = other
            .batch_execute(&format!(
                "LOCK TABLE ONLY {table} IN SHARE ROW EXCLUSIVE MODE NOWAIT"
            ))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        );
        other.rollback().await.unwrap();
    }
    assert!(installed(&tx).await.unwrap());
    tx.rollback().await.unwrap();
    for table in &tables {
        let other = other_db.transaction().await.unwrap();
        // Hold the documented trigger-ALTER table lock in the other
        // connection. Readiness must fail NOWAIT and abort its transaction.
        other
            .batch_execute(&format!(
                "LOCK TABLE ONLY {table} IN SHARE ROW EXCLUSIVE MODE NOWAIT"
            ))
            .await
            .unwrap();
        let tx = ready_db.transaction().await.unwrap();
        let error = require_installed(&tx).await.err().unwrap();
        let ConversationError::Database(error) = error else {
            panic!("expected nonwaiting schema-lock refusal");
        };
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        );
        assert_eq!(
            tx.query_one("SELECT 1", &[]).await.unwrap_err().code(),
            Some(&tokio_postgres::error::SqlState::IN_FAILED_SQL_TRANSACTION)
        );
        tx.rollback().await.unwrap();
        other.rollback().await.unwrap();
        let tx = ready_db.transaction().await.unwrap();
        require_installed(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn catalog_first_search_path_uses_existing_application_namespace() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(&format!(
        "SET LOCAL search_path TO pg_catalog, {}",
        f.schema
    ))
    .await
    .unwrap();
    assert_eq!(
        tx.query_one("SELECT current_schema()", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
    assert!(installed(&tx).await.unwrap());
    require_installed(&tx).await.unwrap();
    assert_eq!(
        inventory(&tx, f.account).await.unwrap(),
        serde_json::json!({"installed":true,"proposals":[]})
    );
    assert_eq!(prune(&tx, 100).await.unwrap(), 0);
    assert!(prepare_erase(&tx).await.unwrap());
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema and temporary table privilege"]
async fn temporary_application_anchors_cannot_select_proposal_namespace() {
    let (f, _) = prepared().await;
    f.db.batch_execute(MIGRATION).await.unwrap();
    let mut db = f.connect().await;
    for anchor in [
        "accounts",
        "sessions",
        "memberships",
        "device_line_bindings",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(&format!("CREATE TEMP TABLE {anchor}(synthetic integer)"))
            .await
            .unwrap();
        assert!(installed(&tx).await.is_err(), "{anchor}");
        assert!(require_installed(&tx).await.is_err(), "{anchor}");
        assert!(inventory(&tx, f.account).await.is_err(), "{anchor}");
        assert!(prune(&tx, 100).await.is_err(), "{anchor}");
        assert!(prepare_erase(&tx).await.is_err(), "{anchor}");
        tx.rollback().await.unwrap();
        assert!(installed(&db).await.unwrap());
    }
    f.cleanup().await;
}
