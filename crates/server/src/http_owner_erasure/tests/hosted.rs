// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};

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
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEROLE; ordinary full107 erasure without operator visibility"]
async fn hosted_empty_namespace_preserves_ordinary_erasure_without_operator_table_grants() {
    for populated in [false, true] {
        let (admin, mut db, database_url, schema) = migrated_schema("hosted_role").await;
        // Same ledger definition as the real migrator. The service cannot read
        // its rows; complete hosted storage must qualify through its catalogs.
        db.batch_execute(
            "CREATE TABLE schema_migrations (
            version bigint PRIMARY KEY CHECK(version>0),filename text NOT NULL UNIQUE,
            checksum_sha256 bytea NOT NULL CHECK(octet_length(checksum_sha256)=32),
            kind text NOT NULL CHECK(kind IN ('applied','legacy_baseline')),
            applied_at timestamptz NOT NULL DEFAULT now())",
        )
        .await
        .unwrap();
        let checksum = <sha2::Sha256 as sha2::Digest>::digest(include_bytes!(
            "../../../../../deploy/compose/migrations/106_hosted_runtime.sql"
        ))
        .to_vec();
        db.execute("INSERT INTO schema_migrations(version,filename,checksum_sha256,kind) VALUES(106,'106_hosted_runtime.sql',$1,'applied')",&[&checksum]).await.unwrap();
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(184)).unwrap());
        let password = crate::test_keys::password(184);
        let signup = register(&mut db, &hasher, "hosted-erase@example.test", &password)
            .await
            .unwrap();
        verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let session = login(&db, &hasher, "hosted-erase@example.test", &password)
            .await
            .unwrap();
        if populated {
            db.execute("INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision) VALUES($1,'test','acct_erasure_fixture',1)", &[&Uuid::new_v4()]).await.unwrap();
        }
        let role = format!("zt_erasure_app_{}", Uuid::new_v4().simple());
        let role_password = Uuid::new_v4().to_string();
        let verifier = postgres_protocol::password::scram_sha_256(role_password.as_bytes());
        let qrole = escape_identifier(&role);
        let ns = escape_identifier(&schema);
        admin.batch_execute(&format!("CREATE ROLE {qrole} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            GRANT USAGE ON SCHEMA {ns} TO {qrole};
            GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {ns} TO {qrole};
            GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA {ns} TO {qrole};
            REVOKE ALL ON {ns}.hosted_runtime_secrets,{ns}.hosted_runtime_sessions,{ns}.hosted_billing_resolutions,{ns}.payload_profile_account_anchors,{ns}.schema_migrations FROM {qrole};
            GRANT SELECT,UPDATE(account_id) ON {ns}.payload_profile_account_anchors TO {qrole};
            GRANT EXECUTE ON FUNCTION {ns}.payload_profile_account_fence_key(uuid) TO {qrole}",escape_literal(&verifier))).await.unwrap();
        let mut url = url::Url::parse(&database_url).unwrap();
        url.set_username(&role).unwrap();
        url.set_password(Some(&role_password)).unwrap();
        let (mut ordinary, connection) =
            tokio_postgres::connect(url.as_str(), NoTls).await.unwrap();
        let driver = tokio::spawn(async move { connection.await.unwrap() });
        let resolution = format!("{ns}.hosted_billing_resolutions");
        let privileges = ordinary.query_one("SELECT pg_catalog.has_table_privilege(current_user,$1,'SELECT'),pg_catalog.has_any_column_privilege(current_user,$1,'SELECT')", &[&resolution]).await.unwrap();
        assert!(!privileges.get::<_, bool>(0) && !privileges.get::<_, bool>(1));
        let ledger = format!("{ns}.schema_migrations");
        let privileges = ordinary.query_one("SELECT pg_catalog.has_table_privilege(current_user,$1,'SELECT'),pg_catalog.has_any_column_privilege(current_user,$1,'SELECT')", &[&ledger]).await.unwrap();
        assert!(!privileges.get::<_, bool>(0) && !privileges.get::<_, bool>(1));
        let tx = ordinary.transaction().await.unwrap();
        let counts = super::super::hosted::blockers(&tx, signup.account_id).await;
        assert_eq!(counts.is_ok(), !populated);
        assert_eq!(
            tx.query_one(
                "SELECT count(*) FROM accounts WHERE id=$1",
                &[&signup.account_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1,
            "permission refusal must not abort the transaction or erase rows"
        );
        tx.rollback().await.unwrap();
        let app = router(OwnerErasureState {
            database_url: url.to_string(),
            auth_hasher: hasher,
            canonical_origin: ORIGIN.into(),
            mfa_cipher: None,
        });
        let response = app
            .oneshot(erasure_post(
                Some(&session.token),
                Some(&session.csrf_token),
                Some(ORIGIN),
                &password,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if populated {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(
            db.query_one(
                "SELECT count(*) FROM accounts WHERE id=$1",
                &[&signup.account_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            i64::from(populated)
        );
        drop(ordinary);
        driver.await.unwrap();
        drop(db);
        admin
            .batch_execute(&format!("DROP SCHEMA {ns} CASCADE; DROP ROLE {qrole}"))
            .await
            .unwrap();
    }
}
