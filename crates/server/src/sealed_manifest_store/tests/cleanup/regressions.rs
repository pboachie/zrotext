// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn teardown_removes_owned_triggers_and_composite_function_dependencies_before_tables() {
    let f = Fixture::new().await;
    f.db.batch_execute(
        r#"
        CREATE TABLE typed_cleanup_row(id uuid);
        CREATE FUNCTION checked_cleanup_value(item uuid) RETURNS boolean
            LANGUAGE sql AS 'SELECT item IS NOT NULL';
        ALTER TABLE typed_cleanup_row ADD CONSTRAINT typed_cleanup_check
            CHECK (checked_cleanup_value(id));
        CREATE FUNCTION a_typed_predicate(item typed_cleanup_row) RETURNS boolean
            LANGUAGE sql BEGIN ATOMIC SELECT (item).id IS NOT NULL; END;
        CREATE FUNCTION z_typed_dependent(item typed_cleanup_row) RETURNS boolean
            LANGUAGE sql BEGIN ATOMIC SELECT a_typed_predicate(item); END;
        CREATE FUNCTION typed_cleanup_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT z_typed_dependent(NEW) THEN RAISE EXCEPTION 'invalid synthetic row'; END IF;
            RETURN NEW;
        END; $$;
        CREATE TRIGGER typed_cleanup_before_insert BEFORE INSERT ON typed_cleanup_row
            FOR EACH ROW EXECUTE FUNCTION typed_cleanup_trigger();
    "#,
    )
    .await
    .unwrap();
    let result = drop_fixture(&f.db, &f.schema).await;
    let present: bool =
        f.db.query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
            &[&f.schema],
        )
        .await
        .unwrap()
        .get(0);
    if result.is_err() {
        // Remove only this test's dependency chain so an original-red result
        // can still clean its generated fixture, then assert the captured result.
        f.db.batch_execute(
            r#"
            ALTER TABLE typed_cleanup_row DROP CONSTRAINT IF EXISTS typed_cleanup_check;
            DROP FUNCTION IF EXISTS checked_cleanup_value(uuid);
            DROP TRIGGER IF EXISTS typed_cleanup_before_insert ON typed_cleanup_row;
            DROP FUNCTION IF EXISTS typed_cleanup_trigger();
            DROP FUNCTION IF EXISTS z_typed_dependent(typed_cleanup_row);
            DROP FUNCTION IF EXISTS a_typed_predicate(typed_cleanup_row);
        "#,
        )
        .await
        .unwrap();
        f.cleanup().await;
    }
    assert!(
        result.is_ok(),
        "restricted teardown must handle its own composite dependency chain: {result:?}"
    );
    assert!(!present, "the complete owned fixture must be gone");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixtures"]
async fn external_view_dependency_refuses_teardown_before_any_owned_constraint_drop() {
    let f = Fixture::new().await;
    let other = format!("manifest_authority_{}", uuid::Uuid::new_v4().simple());
    f.db.batch_execute(&format!(
        "CREATE SCHEMA {}; CREATE VIEW {}.external_view AS SELECT id FROM {}.accounts",
        quote(&other),
        quote(&other),
        quote(&f.schema),
    ))
    .await
    .unwrap();
    let count_sql = "SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND k.contype='f'";
    let before: i64 =
        f.db.query_one(count_sql, &[&f.schema])
            .await
            .unwrap()
            .get(0);
    assert!(before > 1);
    let result = drop_fixture(&f.db, &f.schema).await;
    let after: i64 =
        f.db.query_one(count_sql, &[&f.schema])
            .await
            .unwrap()
            .get(0);
    let external_present: bool =
        f.db.query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("{other}.external_view")],
        )
        .await
        .unwrap()
        .get(0);
    f.db.batch_execute(&format!(
        "DROP VIEW {}.external_view RESTRICT; DROP SCHEMA {} RESTRICT",
        quote(&other),
        quote(&other),
    ))
    .await
    .unwrap();
    f.cleanup().await;
    assert!(result.is_err(), "external dependencies must refuse cleanup");
    assert!(external_present, "cleanup must retain the external view");
    assert_eq!(
        after, before,
        "external view preflight must precede every owned DDL mutation"
    );
}
