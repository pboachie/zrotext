// SPDX-License-Identifier: AGPL-3.0-only
//! Test-owned teardown releases relation locks after every DDL statement.
use super::{Client, Fixture};
mod catalog_retry;
mod regressions;

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

async fn step(
    db: &Client,
    schema: &str,
    operation: &str,
    object: &str,
    detail: &str,
    function: u32,
) -> Result<(), String> {
    // A prior write transaction would retain locks across these calls.
    // Installing the temporary helper assigns an empty explicit BEGIN, so
    // refusal precedes every owned DDL. The caller must roll back that transaction.
    let unassigned: bool = db
        .query_one("SELECT txid_current_if_assigned() IS NULL", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    if !unassigned {
        return Err("fixture cleanup requires autocommit".into());
    }
    db.query_one(
        "SELECT pg_temp.fixture_drop_step($1,$2,$3,$4,$5)",
        &[&schema, &operation, &object, &detail, &function],
    )
    .await
    .map_err(|e| e.to_string())?;
    let released: bool = db.query_one("SELECT txid_current_if_assigned() IS NULL AND NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND mode='AccessExclusiveLock')", &[]).await.map_err(|e|e.to_string())?.get(0);
    if !released {
        return Err("fixture DDL locks were not released".into());
    }
    Ok(())
}

const FOREIGN_DEPENDENCY_QUERY: &str = "SELECT EXISTS(SELECT 1 FROM pg_depend d \
        CROSS JOIN LATERAL pg_identify_object(d.classid,d.objid,d.objsubid) a \
        CROSS JOIN LATERAL pg_identify_object(d.refclassid,d.refobjid,d.refobjsubid) b \
        LEFT JOIN pg_rewrite ar ON d.classid='pg_rewrite'::regclass AND ar.oid=d.objid \
        LEFT JOIN pg_class ac ON ac.oid=ar.ev_class LEFT JOIN pg_namespace an ON an.oid=ac.relnamespace \
        LEFT JOIN pg_rewrite br ON d.refclassid='pg_rewrite'::regclass AND br.oid=d.refobjid \
        LEFT JOIN pg_class bc ON bc.oid=br.ev_class LEFT JOIN pg_namespace bn ON bn.oid=bc.relnamespace \
        CROSS JOIN LATERAL (SELECT COALESCE(a.schema,an.nspname) AS source_schema,COALESCE(b.schema,bn.nspname) AS target_schema) scoped \
        WHERE (scoped.source_schema=$1 AND scoped.target_schema IS NOT NULL AND scoped.target_schema<>$1 AND scoped.target_schema NOT IN ('pg_catalog','information_schema','pg_toast')) \
        OR (scoped.target_schema=$1 AND scoped.source_schema IS NOT NULL AND scoped.source_schema<>$1 AND scoped.source_schema NOT IN ('pg_catalog','information_schema','pg_toast')))";

async fn foreign_dependency(db: &Client, schema: &str) -> Result<bool, String> {
    // Object identification can race unrelated catalog DDL in another fixture.
    // Retry only this complete read-only guard, never a teardown operation.
    for attempt in 0..3 {
        match db.query_one(FOREIGN_DEPENDENCY_QUERY, &[&schema]).await {
            Ok(row) => return Ok(row.get(0)),
            Err(error) => {
                let transient = error.as_db_error().is_some_and(|error| {
                    error.code() == &tokio_postgres::error::SqlState::INTERNAL_ERROR
                        && error
                            .message()
                            .starts_with("cache lookup failed for attribute ")
                });
                if !transient || attempt == 2 {
                    return Err(error.to_string());
                }
            }
        }
    }
    unreachable!("every preflight attempt returns or retries within the bound")
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
    // Rewrite rules identify a view without returning its namespace through
    // pg_identify_object. Resolve their owning relation explicitly so an
    // external view is refused before even a fixture constraint is removed.
    let foreign = foreign_dependency(db, schema).await?;
    if foreign {
        return Err("foreign fixture dependency".into());
    }
    // Install only a session-temporary, invoker-authority helper. Rust passes
    // parameters, never SQL text; PostgreSQL quotes every catalog identifier.
    db.batch_execute(r#"
        CREATE OR REPLACE FUNCTION pg_temp.fixture_drop_step(
            fixture_schema text, operation text, object_name text, detail text, function_id oid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER AS $$
        DECLARE function_name text; function_arguments text;
        BEGIN
            IF fixture_schema !~ '^manifest_authority_[0-9a-f]{32}$'
                OR current_schema() IS DISTINCT FROM fixture_schema
                OR NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=fixture_schema
                    AND nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)) THEN
                RAISE EXCEPTION 'fixture schema identity mismatch';
            END IF;
            CASE operation
                WHEN 'constraint' THEN EXECUTE format('ALTER TABLE %I.%I DROP CONSTRAINT %I RESTRICT',fixture_schema,object_name,detail);
                WHEN 'trigger' THEN EXECUTE format('DROP TRIGGER %I ON %I.%I RESTRICT',detail,fixture_schema,object_name);
                WHEN 'function' THEN
                    SELECT p.proname,pg_get_function_identity_arguments(p.oid)
                        INTO STRICT function_name,function_arguments
                        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                        WHERE p.oid=function_id AND n.nspname=fixture_schema;
                    EXECUTE format('DROP FUNCTION %I.%I(%s) RESTRICT',fixture_schema,function_name,function_arguments);
                WHEN 'table' THEN EXECUTE format('DROP TABLE %I.%I RESTRICT',fixture_schema,object_name);
                WHEN 'sequence' THEN EXECUTE format('DROP SEQUENCE %I.%I RESTRICT',fixture_schema,object_name);
                WHEN 'schema' THEN EXECUTE format('DROP SCHEMA %I RESTRICT',fixture_schema);
                ELSE RAISE EXCEPTION 'invalid fixture operation';
            END CASE;
            RETURN true;
        END; $$;
    "#).await.map_err(|e|e.to_string())?;
    let constraints = db.query("SELECT c.relname,k.conname FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND (k.contype='f' OR (k.contype='c' AND EXISTS(SELECT 1 FROM pg_depend d JOIN pg_proc p ON d.refclassid='pg_proc'::regclass AND p.oid=d.refobjid JOIN pg_namespace function_namespace ON function_namespace.oid=p.pronamespace WHERE d.classid='pg_constraint'::regclass AND d.objid=k.oid AND function_namespace.nspname=$1))) ORDER BY (k.contype='f') DESC,c.relname,k.conname", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in constraints {
        step(db, schema, "constraint", row.get(0), row.get(1), 0).await?;
    }
    // Triggers retain function dependencies. Remove only this schema's own
    // user triggers before functions whose composite parameters retain tables.
    let triggers = db.query("SELECT c.relname,t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT t.tgisinternal ORDER BY c.relname,t.tgname", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in triggers {
        step(db, schema, "trigger", row.get(0), row.get(1), 0).await?;
    }
    let function_count: i64 = db.query_one("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1", &[&schema]).await.map_err(|e|e.to_string())?.get(0);
    // A finite topological walk also handles SQL-body function dependencies.
    // No retries or CASCADE can silently delete an unreviewed dependent object.
    for _ in 0..function_count {
        let row = db.query_opt("SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.refclassid='pg_proc'::regclass AND d.refobjid=p.oid AND d.classid='pg_proc'::regclass AND d.objid<>p.oid) ORDER BY p.proname,p.oid LIMIT 1", &[&schema]).await.map_err(|e|e.to_string())?.ok_or("fixture function dependency cycle")?;
        step(db, schema, "function", "", "", row.get(0)).await?;
    }
    let tables = db.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','p') ORDER BY c.relname", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in tables {
        step(db, schema, "table", row.get(0), "", 0).await?;
    }
    let sequences = db.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind='S'", &[&schema]).await.map_err(|e|e.to_string())?;
    for row in sequences {
        step(db, schema, "sequence", row.get(0), "", 0).await?;
    }
    step(db, schema, "schema", "", "", 0).await
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
        0,
        "explicit transaction must refuse before any owned constraint drop"
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
