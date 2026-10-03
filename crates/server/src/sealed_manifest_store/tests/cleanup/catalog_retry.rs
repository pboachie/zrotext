// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn inject_catalog_error(f: &Fixture, failures: i64, message: &str) {
    assert!(matches!(
        message,
        "cache lookup failed for attribute 1 of relation 1"
            | "cache lookup failed for relation 1"
            | "synthetic unrelated catalog failure"
    ));
    f.db.batch_execute(&format!(
        r#"
        CREATE SEQUENCE catalog_identification_calls;
        CREATE FUNCTION pg_identify_object(class_id oid, object_id oid, sub_id integer)
            RETURNS TABLE("type" text,"schema" text,"name" text,"identity" text)
            LANGUAGE plpgsql ROWS 1 AS $$
        BEGIN
            IF nextval('catalog_identification_calls') <= {failures} THEN
                RAISE EXCEPTION USING ERRCODE='XX000', MESSAGE='{message}';
            END IF;
            RETURN QUERY SELECT * FROM pg_catalog.pg_identify_object(class_id,object_id,sub_id);
        END; $$;
        SET search_path TO {},pg_catalog;
    "#,
        quote(&f.schema)
    ))
    .await
    .unwrap();
}

async fn inventory(f: &Fixture) -> (i64, i64) {
    let row = f.db.query_one("SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1), (SELECT count(*) FROM pg_constraint k JOIN pg_namespace n ON n.oid=k.connamespace WHERE n.nspname=$1)", &[&f.schema]).await.unwrap();
    (row.get(0), row.get(1))
}

async fn calls(f: &Fixture) -> i64 {
    f.db.query_one("SELECT last_value FROM catalog_identification_calls", &[])
        .await
        .unwrap()
        .get(0)
}

async fn remove_injection(f: &Fixture) {
    f.db.batch_execute("DROP FUNCTION pg_identify_object(oid,oid,integer) RESTRICT")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn transient_catalog_invalidation_rechecks_the_complete_guard_before_teardown() {
    let f = Fixture::new().await;
    inject_catalog_error(&f, 1, "cache lookup failed for attribute 1 of relation 1").await;
    drop_fixture(&f.db, &f.schema).await.unwrap();
    let present: bool =
        f.db.query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
            &[&f.schema],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!present);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn transient_relation_invalidation_rechecks_the_complete_guard_before_teardown() {
    let f = Fixture::new().await;
    inject_catalog_error(&f, 1, "cache lookup failed for relation 1").await;
    let result = drop_fixture(&f.db, &f.schema).await;
    if let Err(error) = result {
        // Preserve cleanup on the original failing implementation.
        remove_injection(&f).await;
        f.cleanup().await;
        panic!("transient relation invalidation was not retried: {error}");
    }
    let present: bool =
        f.db.query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
            &[&f.schema],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!present);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn persistent_catalog_invalidation_exhausts_three_attempts_without_owned_ddl() {
    let f = Fixture::new().await;
    inject_catalog_error(&f, 100, "cache lookup failed for attribute 1 of relation 1").await;
    let before = inventory(&f).await;
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    assert_eq!(calls(&f).await, 3);
    assert_eq!(inventory(&f).await, before);
    remove_injection(&f).await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn persistent_relation_invalidation_exhausts_three_attempts_without_owned_ddl() {
    let f = Fixture::new().await;
    inject_catalog_error(&f, 100, "cache lookup failed for relation 1").await;
    let before = inventory(&f).await;
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    assert_eq!(calls(&f).await, 3);
    assert_eq!(inventory(&f).await, before);
    remove_injection(&f).await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixture"]
async fn unrelated_internal_catalog_error_is_not_retried_or_treated_as_clearance() {
    let f = Fixture::new().await;
    inject_catalog_error(&f, 100, "synthetic unrelated catalog failure").await;
    let before = inventory(&f).await;
    assert!(drop_fixture(&f.db, &f.schema).await.is_err());
    assert_eq!(calls(&f).await, 1);
    assert_eq!(inventory(&f).await, before);
    remove_injection(&f).await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixtures"]
async fn successful_catalog_retry_still_refuses_an_external_view_before_owned_ddl() {
    let f = Fixture::new().await;
    let other = format!("manifest_authority_{}", uuid::Uuid::new_v4().simple());
    f.db.batch_execute(&format!(
        "CREATE SCHEMA {}; CREATE VIEW {}.external_view AS SELECT id FROM {}.accounts",
        quote(&other),
        quote(&other),
        quote(&f.schema)
    ))
    .await
    .unwrap();
    inject_catalog_error(&f, 1, "cache lookup failed for attribute 1 of relation 1").await;
    let before = inventory(&f).await;
    assert_eq!(
        drop_fixture(&f.db, &f.schema).await.unwrap_err(),
        "foreign fixture dependency"
    );
    assert!(calls(&f).await > 1);
    assert_eq!(inventory(&f).await, before);
    f.db.batch_execute(&format!(
        "DROP VIEW {}.external_view RESTRICT; DROP SCHEMA {} RESTRICT",
        quote(&other),
        quote(&other)
    ))
    .await
    .unwrap();
    remove_injection(&f).await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; unique disposable fixtures"]
async fn successful_relation_retry_still_refuses_an_external_view_before_owned_ddl() {
    let f = Fixture::new().await;
    let other = format!("manifest_authority_{}", uuid::Uuid::new_v4().simple());
    f.db.batch_execute(&format!(
        "CREATE SCHEMA {}; CREATE VIEW {}.external_view AS SELECT id FROM {}.accounts",
        quote(&other),
        quote(&other),
        quote(&f.schema)
    ))
    .await
    .unwrap();
    inject_catalog_error(&f, 1, "cache lookup failed for relation 1").await;
    let before = inventory(&f).await;
    assert_eq!(
        drop_fixture(&f.db, &f.schema).await.unwrap_err(),
        "foreign fixture dependency"
    );
    assert!(calls(&f).await > 1);
    assert_eq!(inventory(&f).await, before);
    f.db.batch_execute(&format!(
        "DROP VIEW {}.external_view RESTRICT; DROP SCHEMA {} RESTRICT",
        quote(&other),
        quote(&other)
    ))
    .await
    .unwrap();
    remove_injection(&f).await;
    f.cleanup().await;
}
