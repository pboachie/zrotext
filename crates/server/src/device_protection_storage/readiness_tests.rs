// SPDX-License-Identifier: AGPL-3.0-only
//! Real stock ordinary-runtime readiness after complete, uncached schema checks.
//! Capability is not native HMAC entry, socket authentication or provider custody.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::{Client, GenericClient};

async fn stock<C: GenericClient + Sync>(db: &C) {
    assert!(optional(db).await.unwrap());
    assert!(
        db.query_one("SELECT public.hosted_runtime_identity_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        db.query_one("SELECT public.device_protection_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    require(db).await.unwrap();
}
async fn original(db: &Client, name: &str) -> String {
    db.query_one(
        "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1::text))",
        &[&format!("public.{name}()")],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; stock runtime readiness"]
async fn schema_success_does_not_replace_fresh_native_column_and_helper_readiness() {
    let mut f = Fixture::runtime().await;
    stock(&f.reader).await;
    let role = escape_identifier(
        &f.reader
            .query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
    );
    // Keep one actual READ COMMITTED transaction through prior success,
    // independent committed ACL changes and restoration. No ready cache may
    // turn that earlier success into permission after a later await.
    let tx = f.reader.transaction().await.unwrap();
    stock(&tx).await;
    for (change, restore) in [
        (
            format!("REVOKE INSERT(proof) ON public.hosted_runtime_requests FROM {role}"),
            format!("GRANT INSERT(proof) ON public.hosted_runtime_requests TO {role}"),
        ),
        (
            format!("GRANT SELECT(native_pid) ON public.hosted_runtime_requests TO {role}"),
            format!("REVOKE SELECT(native_pid) ON public.hosted_runtime_requests FROM {role}"),
        ),
        (
            "GRANT EXECUTE ON FUNCTION public.hosted_runtime_native_schema_valid() TO PUBLIC"
                .into(),
            "REVOKE EXECUTE ON FUNCTION public.hosted_runtime_native_schema_valid() FROM PUBLIC"
                .into(),
        ),
    ] {
        f.owner.batch_execute(&change).await.unwrap();
        // These deliberately leave every body/table/version/graph intact.
        // Only the independently required native runtime predicate refuses.
        assert!(optional(&tx).await.unwrap(), "{change}");
        assert!(
            !tx.query_one("SELECT public.hosted_runtime_identity_ready()", &[])
                .await
                .unwrap()
                .get::<_, bool>(0),
            "{change}"
        );
        assert!(require(&tx).await.is_err(), "{change}");
        f.owner.batch_execute(&restore).await.unwrap();
        stock(&tx).await;
    }
    tx.rollback().await.unwrap();
    stock(&f.reader).await;
    assert!(require(&f.owner).await.is_err());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; exact helper bodies"]
async fn native_and_protection_helpers_are_pinned_before_readiness_execution() {
    let f = Fixture::runtime().await;
    for name in [
        "hosted_runtime_identity_ready",
        "hosted_runtime_native_schema_valid",
        "device_protection_ready",
    ] {
        stock(&f.reader).await;
        let definition = original(&f.owner, name).await;
        f.owner.batch_execute(&format!(
            "CREATE OR REPLACE FUNCTION public.{name}() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'"
        )).await.unwrap();
        assert!(optional(&f.reader).await.is_err(), "changed body {name}");
        assert!(require(&f.reader).await.is_err(), "changed body {name}");
        f.owner.batch_execute(&definition).await.unwrap();
        stock(&f.reader).await;
        f.owner
            .batch_execute(&format!(
                "ALTER FUNCTION public.{name}() SET search_path TO pg_catalog,pg_temp"
            ))
            .await
            .unwrap();
        assert!(optional(&f.reader).await.is_err(), "changed config {name}");
        assert!(require(&f.reader).await.is_err(), "changed config {name}");
        f.owner.batch_execute(&definition).await.unwrap();
        stock(&f.reader).await;
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; protection ACL and partial installation"]
async fn protection_rights_partial_native_installation_and_shadow_paths_still_refuse() {
    let f = Fixture::runtime().await;
    stock(&f.reader).await;
    let role = escape_identifier(
        &f.reader
            .query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
    );
    f.owner
        .batch_execute(&format!(
            "GRANT UPDATE(created_ms) ON public.device_protection_origins TO {role}"
        ))
        .await
        .unwrap();
    assert!(optional(&f.reader).await.unwrap());
    assert!(
        !f.reader
            .query_one("SELECT public.device_protection_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(require(&f.reader).await.is_err());
    f.owner
        .batch_execute(&format!(
            "REVOKE UPDATE(created_ms) ON public.device_protection_origins FROM {role}"
        ))
        .await
        .unwrap();
    stock(&f.reader).await;
    for table in ["hosted_runtime_requests", "device_protection_origins"] {
        f.owner
            .batch_execute(&format!(
                "ALTER TABLE public.{table} RENAME TO withheld_original_table"
            ))
            .await
            .unwrap();
        assert!(optional(&f.reader).await.is_err(), "{table}");
        assert!(require(&f.reader).await.is_err(), "{table}");
        f.owner
            .batch_execute(&format!(
                "ALTER TABLE public.withheld_original_table RENAME TO {table}"
            ))
            .await
            .unwrap();
        stock(&f.reader).await;
    }
    let schema = escape_identifier(&format!("shadow_{}", uuid::Uuid::new_v4().simple()));
    f.owner
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC"
        ))
        .await
        .unwrap();
    f.reader
        .batch_execute(&format!("SET search_path TO pg_catalog,{schema},public"))
        .await
        .unwrap();
    assert!(optional(&f.reader).await.is_err());
    assert!(require(&f.reader).await.is_err());
    f.reader
        .batch_execute("SET search_path TO pg_catalog,public")
        .await
        .unwrap();
    stock(&f.reader).await;
    f.owner
        .batch_execute(&format!("DROP SCHEMA {schema}"))
        .await
        .unwrap();
    stock(&f.reader).await;
    f.finish().await;
}
