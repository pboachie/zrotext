// SPDX-License-Identifier: AGPL-3.0-only
//! Exact catalog batching equivalence; no stored row is effect authority.
use super::*;
use crate::conversation_profile03_storage::test_fixture;
use serde_json::{Value, json};

fn metadata_fields(row: &tokio_postgres::Row) -> Value {
    json!([
        row.get::<_, String>(0),
        row.get::<_, bool>(1),
        row.get::<_, bool>(2),
        row.get::<_, String>(3),
        row.get::<_, String>(4),
        row.get::<_, bool>(5),
        row.get::<_, bool>(6),
        row.get::<_, bool>(7),
        row.get::<_, Option<Vec<String>>>(8),
        row.get::<_, Option<Vec<String>>>(9),
        row.get::<_, bool>(10),
        row.get::<_, bool>(11),
        row.get::<_, bool>(12),
        row.get::<_, bool>(13),
        row.get::<_, bool>(14),
        row.get::<_, bool>(15)
    ])
}
async fn batch<C: GenericClient + Sync>(db: &C) -> Vec<tokio_postgres::Row> {
    let names = REQUIRED_FUNCTIONS.iter().map(|f| f.0).collect::<Vec<_>>();
    let results = REQUIRED_FUNCTIONS.iter().map(|f| f.2).collect::<Vec<_>>();
    let signatures = REQUIRED_FUNCTIONS
        .iter()
        .map(|f| qualified_signature(f.0, f.1))
        .collect::<Vec<_>>();
    db.query(FUNCTION_METADATA, &[&names, &results, &signatures])
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn batch_matches_every_individual_descriptor_under_supported_lookup_paths() {
    let mut f = test_fixture::new().await;
    for path in ["pg_catalog", "pg_catalog, public", "public"] {
        let tx = f.runtime.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL search_path TO {path}"))
            .await
            .unwrap();
        let rows = batch(&tx).await;
        assert_eq!(rows.len(), REQUIRED_FUNCTIONS.len());
        for (index, (function, row)) in REQUIRED_FUNCTIONS.iter().zip(rows).enumerate() {
            let signature = qualified_signature(function.0, function.1);
            let individual = tx.query("SELECT p.prosrc,coalesce(p.oid=pg_catalog.to_regprocedure($3::text),false),p.prorettype=$2::text::pg_catalog.regtype,l.lanname,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes IS NULL,p.proallargtypes IS NULL,p.proparallel='u',p.prokind='f',p.pronargdefaults=0,p.proowner=c.relowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1", &[&function.0, &function.2, &signature]).await.unwrap();
            assert_eq!(individual.len(), 1);
            assert_eq!(row.get::<_, i64>(16), index as i64 + 1);
            assert_eq!(
                metadata_fields(&row),
                metadata_fields(&individual[0]),
                "{}",
                function.0
            );
        }
        functions(&tx, 119).await.unwrap();
        require(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn batch_refuses_missing_overloaded_offsetting_and_changed_descriptors() {
    let mut f = test_fixture::new().await;
    require(&f.runtime).await.unwrap();
    for index in [
        0,
        REQUIRED_FUNCTIONS.len() / 2,
        REQUIRED_FUNCTIONS.len() - 1,
    ] {
        let signature =
            qualified_signature(REQUIRED_FUNCTIONS[index].0, REQUIRED_FUNCTIONS[index].1);
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(&format!(
            "ALTER FUNCTION {signature} RENAME TO synthetic_missing_grant_helper"
        ))
        .await
        .unwrap();
        assert!(matches!(
            functions(&tx, 119).await,
            Err(GrantSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require(&f.runtime).await.unwrap();
    }
    let overload = "CREATE FUNCTION public.conversation_profile03_grant_same_scope(bytea,bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true'";
    for missing in [false, true] {
        let tx = f.owner.transaction().await.unwrap();
        if missing {
            let signature = qualified_signature(REQUIRED_FUNCTIONS[0].0, REQUIRED_FUNCTIONS[0].1);
            tx.batch_execute(&format!(
                "ALTER FUNCTION {signature} RENAME TO synthetic_missing_grant_helper"
            ))
            .await
            .unwrap();
        }
        tx.batch_execute(overload).await.unwrap();
        assert_eq!(
            batch(&tx).await.len(),
            REQUIRED_FUNCTIONS.len() + usize::from(!missing)
        );
        assert!(matches!(
            functions(&tx, 119).await,
            Err(GrantSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require(&f.runtime).await.unwrap();
    }
    for sql in [
        "ALTER FUNCTION public.conversation_profile03_grant_mode(uuid) SET search_path TO public",
        "ALTER FUNCTION public.conversation_profile03_grant_mode(uuid) IMMUTABLE",
        "ALTER FUNCTION public.conversation_profile03_grant_mode(uuid) STRICT",
        "ALTER FUNCTION public.conversation_profile03_grant_mode(uuid) SECURITY INVOKER",
        "ALTER FUNCTION public.conversation_profile03_grant_mode(uuid) PARALLEL SAFE",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_mode(account uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN; END'",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(
            matches!(functions(&tx, 119).await, Err(GrantSchemaError::Invalid)),
            "{sql}"
        );
        tx.rollback().await.unwrap();
        require(&f.runtime).await.unwrap();
    }
    let signature = "public.conversation_profile03_grant_mode(uuid)";
    let definition: String = f
        .owner
        .query_one(
            "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1::text))",
            &[&signature],
        )
        .await
        .unwrap()
        .get(0);
    for (from, to) in [
        ("account uuid", "account text"),
        ("RETURNS void", "RETURNS bigint"),
        ("account uuid)", "account uuid, OUT diagnostic bigint)"),
    ] {
        assert_eq!(definition.matches(from).count(), 1);
        let mut changed = definition.replacen(from, to, 1);
        if to.contains("OUT diagnostic") {
            changed = changed.replacen("RETURNS void", "RETURNS bigint", 1);
        }
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(&format!("DROP FUNCTION {signature}; {changed}"))
            .await
            .unwrap();
        assert!(matches!(
            functions(&tx, 119).await,
            Err(GrantSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require(&f.runtime).await.unwrap();
    }
    f.finish().await;
}
