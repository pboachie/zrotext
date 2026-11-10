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
    let expected = required_functions(120);
    let names = expected.iter().map(|f| f.0).collect::<Vec<_>>();
    let results = expected.iter().map(|f| f.2).collect::<Vec<_>>();
    let signatures = expected
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
    let expected = required_functions(120);
    let mut f = test_fixture::new().await;
    for path in ["pg_catalog", "pg_catalog, public", "public"] {
        let tx = f.runtime.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL search_path TO {path}"))
            .await
            .unwrap();
        let rows = batch(&tx).await;
        assert_eq!(rows.len(), expected.len());
        for (index, (function, row)) in expected.iter().zip(rows).enumerate() {
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
        functions(&tx, 120).await.unwrap();
        require_v2(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn batch_refuses_missing_overloaded_offsetting_and_changed_descriptors() {
    let expected = required_functions(120);
    let mut f = test_fixture::new().await;
    require_v2(&f.runtime).await.unwrap();
    for index in [0, expected.len() / 2, expected.len() - 1] {
        let signature = qualified_signature(expected[index].0, expected[index].1);
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(&format!(
            "ALTER FUNCTION {signature} RENAME TO synthetic_missing_reviewed_helper"
        ))
        .await
        .unwrap();
        assert!(matches!(
            functions(&tx, 120).await,
            Err(ReviewedSendSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require_v2(&f.runtime).await.unwrap();
    }
    let overload = "CREATE FUNCTION public.conversation_reviewed_send03_ready(bytea,bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true'";
    for missing in [false, true] {
        let tx = f.owner.transaction().await.unwrap();
        if missing {
            let signature = qualified_signature(expected[0].0, expected[0].1);
            tx.batch_execute(&format!(
                "ALTER FUNCTION {signature} RENAME TO synthetic_missing_reviewed_helper"
            ))
            .await
            .unwrap();
        }
        tx.batch_execute(overload).await.unwrap();
        assert_eq!(
            batch(&tx).await.len(),
            expected.len() + usize::from(!missing)
        );
        assert!(matches!(
            functions(&tx, 120).await,
            Err(ReviewedSendSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require_v2(&f.runtime).await.unwrap();
    }
    for sql in [
        "ALTER FUNCTION public.conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03,bytea) SET search_path TO public",
        "ALTER FUNCTION public.conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03,bytea) VOLATILE",
        "ALTER FUNCTION public.conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03,bytea) CALLED ON NULL INPUT",
        "ALTER FUNCTION public.conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03,bytea) SECURITY DEFINER",
        "ALTER FUNCTION public.conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03,bytea) PARALLEL SAFE",
        r#"CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_envelope("row" public.conversation_reviewed_sends03, envelope bytea) RETURNS void LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS 'BEGIN RETURN; END'"#,
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(
            matches!(
                functions(&tx, 120).await,
                Err(ReviewedSendSchemaError::Invalid)
            ),
            "{sql}"
        );
        tx.rollback().await.unwrap();
        require_v2(&f.runtime).await.unwrap();
    }
    f.finish().await;
}

#[test]
fn version_specific_descriptor_membership_is_unchanged() {
    for version in 114..=120 {
        let expected = required_functions(version);
        assert_eq!(expected.len(), if version >= 117 { 14 } else { 13 });
        assert_eq!(
            expected
                .iter()
                .filter(|f| f.0 == "conversation_reviewed_send03_v2_ready")
                .count(),
            usize::from(version >= 117)
        );
        assert_eq!(expected[0].0, "conversation_reviewed_send03_parse");
        assert_eq!(expected[12].0, "conversation_reviewed_send03_ready");
    }
}
