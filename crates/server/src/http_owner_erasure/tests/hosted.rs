// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::escape_identifier;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; whole absent versus partial hosted installation"]
async fn hosted_absence_does_not_accept_partial_tables_functions_or_migration_evidence() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    let driver = tokio::spawn(async move { connection.await.unwrap() });
    for component in [
        "",
        "CREATE TABLE hosted_runtime_sessions(dummy integer)",
        "CREATE FUNCTION hosted_runtime_schema_ready() RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "CREATE TABLE schema_migrations(version bigint); INSERT INTO schema_migrations VALUES(106)",
        "CREATE VIEW schema_migrations AS SELECT 106::bigint AS version",
    ] {
        let schema = format!("erasure_absence_{}", Uuid::new_v4().simple());
        let quoted = escape_identifier(&schema);
        db.batch_execute(&format!("CREATE SCHEMA {quoted}; SET search_path TO {quoted}; CREATE TABLE accounts(id uuid PRIMARY KEY)"))
            .await.unwrap();
        let account = Uuid::new_v4();
        db.execute("INSERT INTO accounts VALUES($1)", &[&account])
            .await
            .unwrap();
        db.batch_execute(component).await.unwrap();
        let tx = db.transaction().await.unwrap();
        let result = super::super::hosted::blockers(&tx, account).await;
        assert_eq!(result.is_ok(), component.is_empty());
        if let Ok(rows) = result {
            assert!(rows.is_empty());
        }
        assert_eq!(
            tx.query_one("SELECT count(*) FROM accounts", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        tx.rollback().await.unwrap();
        db.batch_execute(&format!(
            "SET search_path TO pg_catalog; DROP SCHEMA {quoted} CASCADE"
        ))
        .await
        .unwrap();
    }
    drop(db);
    driver.await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full107 integrity and exact hosted blockers"]
async fn hosted_complete_inventory_requires_namespace_fks_and_ignores_temp_replacements() {
    let (admin, mut db, _, schema) = migrated_schema("hosted_integrity").await;
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    for drift in [
        "DROP TABLE hosted_runtime_sessions; CREATE TEMP TABLE hosted_runtime_sessions(dummy integer)",
        "ALTER TABLE hosted_billing_customers DROP CONSTRAINT hosted_billing_customers_namespace_id_fkey",
        "CREATE OR REPLACE FUNCTION hosted_runtime_schema_ready() RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(drift).await.unwrap();
        assert!(super::super::hosted::blockers(&tx, account).await.is_err());
        assert_eq!(
            tx.query_one("SELECT count(*) FROM accounts", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        tx.rollback().await.unwrap();
    }
    let namespace = Uuid::new_v4();
    db.execute("INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision) VALUES($1,'test','acct_erasure_fixture',1)", &[&namespace]).await.unwrap();
    db.execute("INSERT INTO hosted_billing_customers(namespace_id,account_id,customer_id) VALUES($1,$2,'cus_ErasureFixture')", &[&namespace,&account]).await.unwrap();
    let tx = db.transaction().await.unwrap();
    let counts = super::super::hosted::blockers(&tx, account).await.unwrap();
    assert_eq!(counts.len(), 1);
    assert_eq!(counts[0].table, "hosted_billing_customers");
    assert_eq!(counts[0].rows, 1);
    assert!(
        super::super::hosted::blockers(&tx, Uuid::new_v4())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        tx.query_one(
            "SELECT count(*) FROM hosted_billing_customers WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    tx.rollback().await.unwrap();
    drop(db);
    admin
        .batch_execute(&format!(
            "DROP SCHEMA {} CASCADE",
            escape_identifier(&schema)
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; stock current ordinary role without operator visibility"]
async fn hosted_empty_namespace_preserves_ordinary_erasure_without_operator_table_grants() {
    for populated in [false, true] {
        current_case(async |db, admin, database_url| {
            let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(184)).unwrap());
            let password = crate::test_keys::password(184);
            let signup = register(db, &hasher, "hosted-erase@example.test", &password).await.unwrap();
            assert!(verify_email(db, &hasher, &signup.verification_token).await.unwrap());
            let session = login(&*db, &hasher, "hosted-erase@example.test", &password).await.unwrap();
            for table in ["public.hosted_billing_resolutions", "public.schema_migrations"] {
                let privileges = db.query_one("SELECT pg_catalog.has_table_privilege(current_user,$1,'SELECT'),pg_catalog.has_any_column_privilege(current_user,$1,'SELECT')", &[&table]).await.unwrap();
                assert!(!privileges.get::<_,bool>(0) && !privileges.get::<_,bool>(1));
            }
            if populated {
                admin.execute("INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision) VALUES($1,'test','acct_erasure_fixture',1)", &[&Uuid::new_v4()]).await.unwrap();
            }
            // Namespace rows do not alter the pinned schema identity. Actual
            // native admission separately refuses unbound hosted state.
            crate::hosted_runtime_identity::require(&*db).await.unwrap();
            if populated {
                assert!(crate::runtime_db::begin_native(db).await.is_err());
            }
            let tx = db.transaction().await.unwrap();
            let counts = super::super::hosted::blockers(&tx, signup.account_id).await;
            assert_eq!(counts.is_ok(), !populated);
            assert_eq!(tx.query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&signup.account_id]).await.unwrap().get::<_,i64>(0), 1,
                "permission refusal must not abort the transaction or erase rows");
            tx.rollback().await.unwrap();
            let app = router(OwnerErasureState { database_url: database_url.to_owned(), auth_hasher: hasher, canonical_origin: ORIGIN.into(), mfa_cipher: None });
            let response = app.oneshot(erasure_post(Some(&session.token),Some(&session.csrf_token),Some(ORIGIN),&password,None)).await.unwrap();
            assert_eq!(response.status(), if populated { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK });
            assert_eq!(db.query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&signup.account_id]).await.unwrap().get::<_,i64>(0), i64::from(populated));
        }).await;
    }
}
