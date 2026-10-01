// SPDX-License-Identifier: AGPL-3.0-only
//! Test-owned teardown releases relation locks after every DDL statement.
use super::{Client, Fixture};

fn valid_name(name: &str) -> bool {
    name.strip_prefix("manifest_authority_")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn step(db: &Client, sql: &str) -> Result<(), String> {
    // A prior write transaction would retain locks across these calls.
    // An empty explicit BEGIN may reach one DDL; the postcondition refuses
    // before a second DDL. The caller must roll back that transaction.
    let unassigned: bool = db
        .query_one("SELECT txid_current_if_assigned() IS NULL", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    if !unassigned {
        return Err("fixture cleanup requires autocommit".into());
    }
    db.batch_execute(sql).await.map_err(|e| e.to_string())?;
    let released: bool = db.query_one("SELECT txid_current_if_assigned() IS NULL AND NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND mode='AccessExclusiveLock')", &[]).await.map_err(|e|e.to_string())?.get(0);
    if !released {
        return Err("fixture DDL locks were not released".into());
    }
    Ok(())
}

pub(super) async fn drop_fixture(db: &Client, schema: &str) -> Result<(), String> {
    if !valid_name(schema) {
        return Err("invalid fixture schema".into());
    }
    let row = db.query_one("SELECT COALESCE(current_schema()=$1,false), EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1 AND nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))", &[&schema]).await.map_err(|e|e.to_string())?;
    if !row.get::<_, bool>(0) || !row.get::<_, bool>(1) {
        return Err("fixture schema identity mismatch".into());
    }
    // Refuse dependencies crossing another user schema before changing anything.
    // Catalog dependencies (types, language, built-ins) are not fixture objects.
    let foreign: bool = db.query_one("SELECT EXISTS(SELECT 1 FROM pg_depend d CROSS JOIN LATERAL pg_identify_object(d.classid,d.objid,d.objsubid) a CROSS JOIN LATERAL pg_identify_object(d.refclassid,d.refobjid,d.refobjsubid) b WHERE (a.schema=$1 AND b.schema IS NOT NULL AND b.schema<>$1 AND b.schema NOT IN ('pg_catalog','information_schema','pg_toast')) OR (b.schema=$1 AND a.schema IS NOT NULL AND a.schema<>$1 AND a.schema NOT IN ('pg_catalog','information_schema','pg_toast')))", &[&schema]).await.map_err(|e|e.to_string())?.get(0);
    if foreign {
        return Err("foreign fixture dependency".into());
    }
    let prefix = quote(schema);
    let constraints = db.query("SELECT c.relname,k.conname FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND k.contype='f' ORDER BY c.relname,k.conname", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in constraints {
        step(
            db,
            &format!(
                "ALTER TABLE {prefix}.{} DROP CONSTRAINT {}",
                quote(row.get(0)),
                quote(row.get(1))
            ),
        )
        .await?;
    }
    let tables = db.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','p') ORDER BY c.relname", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in tables {
        step(
            db,
            &format!("DROP TABLE {prefix}.{} RESTRICT", quote(row.get(0))),
        )
        .await?;
    }
    let functions = db.query("SELECT p.proname,pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 ORDER BY p.proname,p.oid", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in functions {
        step(
            db,
            &format!(
                "DROP FUNCTION {prefix}.{}({}) RESTRICT",
                quote(row.get(0)),
                row.get::<_, String>(1)
            ),
        )
        .await?;
    }
    let sequences = db.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind='S'", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in sequences {
        step(
            db,
            &format!("DROP SEQUENCE {prefix}.{} RESTRICT", quote(row.get(0))),
        )
        .await?;
    }
    step(db, &format!("DROP SCHEMA {prefix} RESTRICT")).await
}

#[test]
fn only_generated_fixture_names_are_accepted_and_identifiers_are_quoted() {
    assert!(valid_name(
        "manifest_authority_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    for name in [
        "public",
        "manifest_authority_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "manifest_authority_a;DROP SCHEMA public",
    ] {
        assert!(!valid_name(name));
    }
    assert_eq!(quote("a\"b"), "\"a\"\"b\"");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixtures"]
async fn cleanup_refuses_invalid_current_schema_and_foreign_dependencies_before_ddl() {
    let f = Fixture::new().await;
    assert!(drop_fixture(&f.db, "public").await.is_err());
    let missing = format!("manifest_authority_{}", uuid::Uuid::new_v4().simple());
    f.db.batch_execute(&format!("SET search_path TO {}", quote(&missing)))
        .await
        .unwrap();
    assert!(drop_fixture(&f.db, &missing).await.is_err());
    f.db.batch_execute("SET search_path TO public")
        .await
        .unwrap();
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    f.db.batch_execute(&format!("SET search_path TO {}", quote(&f.schema)))
        .await
        .unwrap();
    let owner: String =
        f.db.query_one("SELECT current_user", &[])
            .await
            .unwrap()
            .get(0);
    f.db.batch_execute(&format!(
        "ALTER SCHEMA {} OWNER TO pg_database_owner",
        quote(&f.schema)
    ))
    .await
    .unwrap();
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    f.db.batch_execute(&format!(
        "ALTER SCHEMA {} OWNER TO {}",
        quote(&f.schema),
        quote(&owner)
    ))
    .await
    .unwrap();
    let other = format!("manifest_authority_{}", uuid::Uuid::new_v4().simple());
    f.db.batch_execute(&format!(
        "CREATE SCHEMA {}; CREATE TABLE {}.foreign_fixture(id uuid REFERENCES {}.accounts(id))",
        quote(&other),
        quote(&other),
        quote(&f.schema)
    ))
    .await
    .unwrap();
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    assert!(
        f.db.query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("{}.accounts", f.schema)]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.db.batch_execute(&format!(
        "DROP TABLE {}.foreign_fixture RESTRICT; CREATE TABLE {}.foreign_parent(id uuid PRIMARY KEY)",
        quote(&other),
        quote(&other)
    ))
    .await
    .unwrap();
    f.db.batch_execute(&format!(
        "CREATE TABLE {}.outgoing_fixture(id uuid REFERENCES {}.foreign_parent(id))",
        quote(&f.schema),
        quote(&other)
    ))
    .await
    .unwrap();
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    assert!(
        f.db.query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("{}.foreign_parent", other)]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.db.batch_execute(&format!("DROP TABLE {}.outgoing_fixture RESTRICT; DROP TABLE {}.foreign_parent RESTRICT; DROP SCHEMA {} RESTRICT",quote(&f.schema),quote(&other),quote(&other))).await.unwrap();
    let count_sql = "SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND k.contype='f'";
    let before: i64 =
        f.db.query_one(count_sql, &[&f.schema])
            .await
            .unwrap()
            .get(0);
    assert!(before > 1);
    f.db.batch_execute("BEGIN").await.unwrap();
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    let after: i64 =
        f.db.query_one(count_sql, &[&f.schema])
            .await
            .unwrap()
            .get(0);
    assert_eq!(
        before - after,
        1,
        "explicit transaction cannot accumulate multiple DDL drops"
    );
    f.db.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        f.db.query_one(count_sql, &[&f.schema])
            .await
            .unwrap()
            .get::<_, i64>(0),
        before
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; four fully migrated disposable fixtures"]
async fn four_complete_schemas_cleanup_concurrently_without_accumulating_ddl_locks() {
    async fn one() {
        let f = Fixture::new().await;
        // Apply the actual complete train, including 079, to this owned schema.
        // Fixture's partial prerequisites cannot substitute for full migrations.
        let schema = f.schema.clone();
        f.cleanup().await;
        let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL").unwrap();
        let (db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db.batch_execute(&format!(
            "CREATE SCHEMA {}; SET search_path TO {}",
            quote(&schema),
            quote(&schema)
        ))
        .await
        .unwrap();
        crate::auth::test_schema::apply(&db).await;
        drop_fixture(&db, &schema).await.unwrap();
        assert!(
            !db.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
                &[&schema]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
    }
    tokio::join!(one(), one(), one(), one());
}
