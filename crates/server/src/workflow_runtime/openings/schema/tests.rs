// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::decisions::tests::Case;
const CANDIDATE: &str = include_str!(
    "../../../../../../deploy/compose/migration-candidates/owner_opening_capacity.sql"
);

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; exact optional candidate catalog and rollback"]
async fn absent_pristine_and_partial_schema_have_distinct_outcomes() {
    let c = Case::new().await;
    let mut db = c.base.f.connect().await;
    let original_path: String = db
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .unwrap()
        .get(0);
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL search_path = ''").await.unwrap();
    assert!(
        tx.query_one("SELECT current_schema() IS NULL", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    for (table, _) in TABLES {
        assert!(
            tx.query_one("SELECT to_regclass($1) IS NULL", &[&table])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    assert!(!installed(&tx).await.unwrap());
    assert!(
        super::super::lifecycle::erase_account(&tx, c.base.f.account)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(tx.query_one("SELECT 1", &[]).await.unwrap().get::<_, i32>(0), 1);
    tx.rollback().await.unwrap();
    assert_eq!(
        db.query_one("SELECT current_setting('search_path')", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        original_path
    );
    let tx = db.transaction().await.unwrap();
    assert!(!installed(&tx).await.unwrap());
    assert!(
        super::super::lifecycle::erase_account(&tx, c.base.f.account)
            .await
            .unwrap()
            .is_empty()
    );
    tx.rollback().await.unwrap();
    assert!(matches!(
        super::super::store::begin(&mut db).await,
        Err(crate::http_owner_conversations::ConversationError::Unavailable)
    ));
    assert!(matches!(
        super::super::status(&mut db, &c.base.owner, uuid::Uuid::new_v4()).await,
        Err(crate::http_owner_conversations::ConversationError::Unavailable)
    ));
    let exported = super::super::export::export(&mut db, &c.base.owner, [None; 4])
        .await
        .unwrap();
    for page in [
        &exported.openings,
        &exported.offers,
        &exported.allocations,
        &exported.requests,
    ] {
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }
    assert!(matches!(
        super::super::export::export(
            &mut db,
            &c.base.owner,
            [Some(uuid::Uuid::new_v4()), None, None, None]
        )
        .await,
        Err(crate::http_owner_conversations::ConversationError::NotFound)
    ));
    c.base.f.db.batch_execute(CANDIDATE).await.unwrap();
    let tx = db.transaction().await.unwrap();
    let server_version: String = tx
        .query_one("SELECT current_setting('server_version_num')", &[])
        .await
        .unwrap()
        .get(0);
    let check_definitions: Vec<(String, String, String)> = tx
        .query(
            "SELECT r.relname::text, c.conname::text, pg_get_constraintdef(c.oid) \
             FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid \
             JOIN pg_namespace n ON n.oid=r.relnamespace \
             WHERE n.nspname=current_schema() AND c.contype='c' \
             AND r.relname IN ('workflow_openings','workflow_opening_offers',\
             'workflow_opening_allocations','workflow_opening_requests') \
             ORDER BY r.relname,c.conname",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert!(
        matches!(installed(&tx).await, Ok(true)),
        "pristine candidate must pass; server_version_num={server_version}; CHECK definitions={check_definitions:?}"
    );
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("DROP TABLE workflow_opening_requests")
        .await
        .unwrap();
    assert!(installed(&tx).await.is_err());
    assert!(
        tx.query_one("SELECT 1", &[]).await.is_err(),
        "malformed gate must abort borrowed transaction"
    );
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(
        installed(&tx).await.unwrap(),
        "DDL rollback must restore pristine candidate"
    );
    tx.rollback().await.unwrap();
    drop(db);
    c.cleanup().await;
}

async fn remove_constraint(tx: &Transaction<'_>, table: &str, kind: &str, fragment: &str) {
    let rows=tx.query("SELECT format('ALTER TABLE %s DROP CONSTRAINT %I',conrelid::regclass,conname) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype::text=$2 AND pg_get_constraintdef(oid) LIKE $3", &[&table,&kind,&fragment]).await.unwrap();
    assert_eq!(rows.len(), 1, "select one actual constraint");
    tx.batch_execute(&rows[0].get::<_, String>(0))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual constraint/default/table drift refusal"]
async fn malformed_complete_candidate_refuses_and_rolls_back_each_drift() {
    let c = Case::new().await;
    c.base.f.db.batch_execute(CANDIDATE).await.unwrap();
    let mut db = c.base.f.connect().await;
    for drift in [
        "ALTER TABLE workflow_openings ALTER COLUMN capacity DROP NOT NULL",
        "ALTER TABLE workflow_opening_requests ALTER COLUMN admission_charged SET DEFAULT false",
        "ALTER TABLE workflow_openings ADD COLUMN unreviewed text",
        "ALTER TABLE workflow_openings ALTER COLUMN created_session TYPE text USING created_session::text",
        "ALTER TABLE workflow_openings ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE workflow_opening_allocations DISABLE TRIGGER ALL",
        "DROP INDEX workflow_opening_capacity_count",
        "DROP INDEX workflow_opening_capacity_count; CREATE INDEX workflow_opening_capacity_count ON workflow_opening_allocations(opening_id,account_id,phase)",
        "CREATE TABLE opening_parent (); ALTER TABLE workflow_openings INHERIT opening_parent",
        "DROP INDEX workflow_opening_capacity_count; CREATE INDEX workflow_opening_capacity_count ON workflow_opening_allocations(account_id,opening_id,phase) WHERE phase='pending'",
        "DROP TABLE workflow_opening_requests; CREATE VIEW workflow_opening_requests AS SELECT 1 AS account_id",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(drift).await.unwrap();
        assert!(installed(&tx).await.is_err(), "accepted drift: {drift}");
        assert!(tx.query_one("SELECT 1", &[]).await.is_err());
        tx.rollback().await.unwrap();
    }
    for (table, kind, fragment, replacement) in [
        (
            "workflow_opening_allocations",
            "u",
            "%response_use_digest%",
            "",
        ),
        (
            "workflow_openings",
            "c",
            "%capacity%",
            "ALTER TABLE workflow_openings ADD CHECK (capacity BETWEEN 1 AND 101)",
        ),
        (
            "workflow_openings",
            "c",
            "%octet_length(description_digest)%",
            "ALTER TABLE workflow_openings ADD CHECK (octet_length(description_digest) >= 32)",
        ),
        (
            "workflow_openings",
            "f",
            "%description_context_id%",
            "CREATE TABLE opening_wrong_context(account_id uuid,id uuid,PRIMARY KEY(account_id,id)); ALTER TABLE workflow_openings ADD FOREIGN KEY(account_id,description_context_id) REFERENCES opening_wrong_context(account_id,id)",
        ),
        (
            "workflow_openings",
            "c",
            "%capacity%",
            "ALTER TABLE workflow_openings ADD CHECK (capacity BETWEEN 1 AND 100) NOT VALID",
        ),
        (
            "workflow_openings",
            "c",
            "%phase%open%description_context_id%",
            "ALTER TABLE workflow_openings ADD CHECK (phase <> 'open' OR description_context_id IS NOT NULL OR decision_deadline_ms IS NOT NULL)",
        ),
        (
            "workflow_opening_allocations",
            "f",
            "%REFERENCES workflow_openings%",
            "ALTER TABLE workflow_opening_allocations ADD FOREIGN KEY(account_id,opening_id) REFERENCES workflow_openings(account_id,id) ON DELETE RESTRICT",
        ),
        (
            "workflow_opening_allocations",
            "f",
            "%REFERENCES workflow_openings%",
            "ALTER TABLE workflow_opening_allocations ADD FOREIGN KEY(account_id,opening_id) REFERENCES workflow_openings(account_id,id) ON DELETE CASCADE NOT VALID",
        ),
        (
            "workflow_opening_requests",
            "p",
            "%",
            "ALTER TABLE workflow_opening_requests ADD PRIMARY KEY(request_id,account_id)",
        ),
    ] {
        let tx = db.transaction().await.unwrap();
        remove_constraint(&tx, table, kind, fragment).await;
        tx.batch_execute(replacement).await.unwrap();
        assert!(
            installed(&tx).await.is_err(),
            "accepted altered constraint: {table} {fragment}"
        );
        assert!(tx.query_one("SELECT 1", &[]).await.is_err());
        tx.rollback().await.unwrap();
    }
    let tx = db.transaction().await.unwrap();
    assert!(
        installed(&tx).await.unwrap(),
        "all drift DDL was rolled back"
    );
    tx.rollback().await.unwrap();
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual search path and namespace refusal"]
async fn resolved_relations_must_belong_to_the_current_schema() {
    let c = Case::new().await;
    c.base.f.db.batch_execute(CANDIDATE).await.unwrap();
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let current: String = tx
        .query_one("SELECT current_schema()", &[])
        .await
        .unwrap()
        .get(0);
    let shadow = format!("opening_shadow_{}", uuid::Uuid::new_v4().simple());
    let sql=tx.query_one("SELECT format('CREATE SCHEMA %I; SET LOCAL search_path=%I,%I', $1::text,$1::text,$2::text)",&[&shadow,&current]).await.unwrap().get::<_,String>(0);
    tx.batch_execute(&sql).await.unwrap();
    assert!(
        installed(&tx).await.is_err(),
        "fallback relation names must not validate another namespace"
    );
    assert!(tx.query_one("SELECT 1", &[]).await.is_err());
    tx.rollback().await.unwrap();
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; malformed schema stops borrowed lifecycle and rolls back"]
async fn malformed_schema_stops_borrowed_lifecycle_before_effects() {
    let c = Case::new().await;
    c.base.f.db.batch_execute(CANDIDATE).await.unwrap();
    let mut db = c.base.f.connect().await;
    let id = uuid::Uuid::new_v4();
    let tx = db.transaction().await.unwrap();
    // Closed scrubbed fixture metadata conveys no source or allocation authority.
    tx.execute("INSERT INTO workflow_openings(account_id,id,definition_version,state_version,capacity,phase) VALUES($1,$2,1,1,1,'closed')", &[&c.base.f.account,&id]).await.unwrap();
    remove_constraint(
        &tx,
        "workflow_opening_allocations",
        "u",
        "%response_use_digest%",
    )
    .await;
    assert!(
        super::super::lifecycle::erase_account(&tx, c.base.f.account)
            .await
            .is_err()
    );
    assert!(
        tx.query_one("SELECT 1", &[]).await.is_err(),
        "borrowed lifecycle refusal must abort earlier writes"
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM workflow_openings WHERE account_id=$1 AND id=$2",
            &[&c.base.f.account, &id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let tx = db.transaction().await.unwrap();
    assert!(installed(&tx).await.unwrap());
    tx.rollback().await.unwrap();
    drop(db);
    c.cleanup().await;
}
