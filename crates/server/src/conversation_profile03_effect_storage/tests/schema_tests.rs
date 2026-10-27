// SPDX-License-Identifier: AGPL-3.0-only
//! Current ordinary-role refusal and exact restoration of missing schema layers.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use postgres_protocol::escape::escape_identifier;

async fn restored(f: &mut Fixture) {
    let tx = f.reader.transaction().await.unwrap();
    require(&tx).await.unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn current_effect_readiness_refuses_absent_and_partial_families_then_restores() {
    let mut f = Fixture::runtime().await;
    restored(&mut f).await;
    for (hide, restore) in [
        (
            "ALTER TABLE public.conversation_reviewed_sends03 RENAME TO synthetic_hidden_reviewed_sends",
            "ALTER TABLE public.synthetic_hidden_reviewed_sends RENAME TO conversation_reviewed_sends03",
        ),
        (
            "ALTER FUNCTION public.conversation_reviewed_send03_v2_ready() RENAME TO synthetic_hidden_v2_ready",
            "ALTER FUNCTION public.synthetic_hidden_v2_ready() RENAME TO conversation_reviewed_send03_v2_ready",
        ),
        (
            "ALTER TABLE public.conversation_profile03_effect_actors RENAME TO synthetic_hidden_effect_actors",
            "ALTER TABLE public.synthetic_hidden_effect_actors RENAME TO conversation_profile03_effect_actors",
        ),
    ] {
        f.owner.batch_execute(hide).await.unwrap();
        let refused = require(&f.reader).await.is_err();
        f.owner.batch_execute(restore).await.unwrap();
        assert!(refused);
        restored(&mut f).await;
    }

    // Hide the complete family without deleting any row, changing a grant, or
    // disabling a guard. Rename types back before restoring composite signatures.
    let functions = FUNCTIONS
        .iter()
        .filter(|f| f.name.starts_with("conversation_profile03_effect_"))
        .collect::<Vec<_>>();
    assert_eq!(functions.len(), 22);
    let tables = TABLES.iter().map(|t| t.0).collect::<Vec<_>>();
    let indexes: Vec<String> = f.reader.query("SELECT c.relname::text FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::pg_catalog.regnamespace AND c.relkind='i' AND EXISTS(SELECT FROM unnest($1::text[]) AS family(name) WHERE pg_catalog.starts_with(c.relname::text,family.name)) ORDER BY c.relname", &[&tables]).await.unwrap().iter().map(|row| row.get(0)).collect();
    assert!(!indexes.is_empty());
    let tx = f.owner.transaction().await.unwrap();
    for (index, name) in indexes.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER INDEX public.{} RENAME TO synthetic_hidden_effect_index_{index}",
            escape_identifier(name)
        ))
        .await
        .unwrap();
    }
    for (index, function) in functions.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER FUNCTION {} RENAME TO synthetic_hidden_effect_{index}",
            function.signature
        ))
        .await
        .unwrap();
    }
    for (index, (table, _)) in TABLES.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER TABLE public.{table} RENAME TO synthetic_hidden_effect_table_{index}"
        ))
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let row=f.reader.query_one("SELECT(SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'conversation_profile03_effect_%'),(SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace='public'::pg_catalog.regnamespace AND relname=ANY($1::text[])),EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::pg_catalog.regnamespace AND EXISTS(SELECT FROM unnest($1::text[]) AS family(name) WHERE pg_catalog.starts_with(c.relname::text,family.name)))",&[&TABLES.iter().map(|t|t.0).collect::<Vec<_>>()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert!(!row.get::<_, bool>(2));
    let optional_refused = optional(&f.reader).await.is_err();
    let required_refused = require(&f.reader).await.is_err();
    let tx = f.owner.transaction().await.unwrap();
    for (index, (table, _)) in TABLES.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER TABLE public.synthetic_hidden_effect_table_{index} RENAME TO {table}"
        ))
        .await
        .unwrap();
    }
    for (index, function) in functions.iter().enumerate() {
        let signature = function.signature.replacen(
            &format!("public.{}", function.name),
            &format!("public.synthetic_hidden_effect_{index}"),
            1,
        );
        tx.batch_execute(&format!(
            "ALTER FUNCTION {signature} RENAME TO {}",
            function.name
        ))
        .await
        .unwrap();
    }
    for (index, name) in indexes.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER INDEX public.synthetic_hidden_effect_index_{index} RENAME TO {}",
            escape_identifier(name)
        ))
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    assert!(optional_refused && required_refused);
    restored(&mut f).await;
    f.finish().await;
}
