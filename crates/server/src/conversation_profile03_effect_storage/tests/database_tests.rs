// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine full-public/stock ordinary-runtime structural capability controls.
//! These do not authenticate a socket or establish message/effect permission.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tokio_postgres::error::SqlState;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn stock_runtime_reads_history_without_direct_dml_or_internal_helper_authority() {
    let f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    for (table, columns) in TABLES {
        let row=f.reader.query_one("SELECT pg_catalog.has_table_privilege(CURRENT_USER,pg_catalog.to_regclass(pg_catalog.format('public.%I',$1::text)),'SELECT'),pg_catalog.has_table_privilege(CURRENT_USER,pg_catalog.to_regclass(pg_catalog.format('public.%I',$1::text)),'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),pg_catalog.has_any_column_privilege(CURRENT_USER,pg_catalog.to_regclass(pg_catalog.format('public.%I',$1::text)),'INSERT,UPDATE,REFERENCES')",&[table]).await.unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(!row.get::<_, bool>(1));
        assert!(!row.get::<_, bool>(2));
        assert!(!columns.is_empty());
        let error = f
            .reader
            .batch_execute(&format!("DELETE FROM public.{table}"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    for function in FUNCTIONS
        .iter()
        .filter(|f| f.name.starts_with("conversation_profile03_effect_"))
    {
        let expected = matches!(
            function.name,
            "conversation_profile03_effect_history_lock"
                | "conversation_profile03_effect_submit"
                | "conversation_profile03_effect_outcome"
                | "conversation_profile03_effect_closure_challenge"
                | "conversation_profile03_effect_closure_accept"
                | "conversation_profile03_effect_ready"
        );
        assert_eq!(f.reader.query_one("SELECT pg_catalog.has_function_privilege(CURRENT_USER,pg_catalog.to_regprocedure($1::text),'EXECUTE')",&[&function.signature]).await.unwrap().get::<_,bool>(0),expected,"{}",function.name);
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn database_fetch_bytes_equal_independent_existing_grant_codec() {
    let f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    let v: Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/sealed-profile03-contract-01.json"
    ))
    .unwrap();
    let wire = &v["grant"]["frame"];
    let grant =
        crate::sealed_dispatch::wire03::GrantFrame03::parse(&serde_json::to_vec(wire).unwrap())
            .unwrap();
    let mut row = serde_json::Map::new();
    for name in [
        "account_id",
        "device_id",
        "line_id",
        "message_id",
        "attempt_id",
        "connection_epoch",
        "deployment_epoch",
        "binding_generation",
        "attempt_generation",
        "expires_at_ms",
        "trust_generation",
        "manifest_version",
    ] {
        row.insert(name.to_owned(), wire[name].clone());
    }
    for name in [
        "reader_key_id",
        "envelope_sha256",
        "unsigned_sha256",
        "manifest_digest",
        "root_fingerprint",
        "election_digest",
    ] {
        let bytes = URL_SAFE_NO_PAD
            .decode(wire[name].as_str().unwrap())
            .unwrap();
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        row.insert(name.to_owned(), json!(format!("\\x{hex}")));
    }
    row.insert(
        "authenticated_segment_ceiling".to_owned(),
        wire["segment_count"].clone(),
    );
    let row_json = Value::Object(row).to_string();
    let actual:Vec<u8>=f.owner.query_one("SELECT public.conversation_profile03_effect_fetch(pg_catalog.jsonb_populate_record(NULL::public.conversation_profile03_grants,$1::text::jsonb))",&[&row_json]).await.unwrap().get(0);
    assert_eq!(actual, grant.fetch_transcript());
    assert_eq!(actual.len(), 362);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn unknown_helper_and_composite_family_objects_refuse_and_rollback_restores() {
    let f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    f.owner
        .batch_execute(
            "CREATE TYPE public.conversation_profile03_submits_unknown AS (value integer)",
        )
        .await
        .unwrap();
    assert!(optional(&f.reader).await.is_err());
    f.owner
        .batch_execute("DROP TYPE public.conversation_profile03_submits_unknown")
        .await
        .unwrap();
    require(&f.reader).await.unwrap();
    f.owner.batch_execute("CREATE FUNCTION public.conversation_profile03_effect_unknown() RETURNS boolean LANGUAGE sql AS 'SELECT true'").await.unwrap();
    assert!(optional(&f.reader).await.is_err());
    f.owner
        .batch_execute("DROP FUNCTION public.conversation_profile03_effect_unknown()")
        .await
        .unwrap();
    require(&f.reader).await.unwrap();
    f.finish().await;
}

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
        row.get::<_, Option<Vec<String>>>(10),
        row.get::<_, Option<Vec<String>>>(11),
        row.get::<_, bool>(12)
    ])
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn batched_metadata_equals_every_individual_closed_function_descriptor() {
    let f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    let signatures = FUNCTIONS.iter().map(|f| f.signature).collect::<Vec<_>>();
    let results = FUNCTIONS.iter().map(|f| f.result).collect::<Vec<_>>();
    let rows = f
        .reader
        .query(FUNCTION_METADATA, &[&signatures, &results])
        .await
        .unwrap();
    assert_eq!(rows.len(), FUNCTIONS.len());
    for (index, (function, batch)) in FUNCTIONS.iter().zip(rows).enumerate() {
        let individual = f.reader.query_one("SELECT p.prosrc,p.proowner=c.relowner,p.prorettype=pg_catalog.to_regtype($2::text),l.lanname::text,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes::text[],CASE WHEN p.proallargtypes IS NULL THEN NULL ELSE ARRAY(SELECT pg_catalog.format_type(t,NULL) FROM unnest(p.proallargtypes) t) END,p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0 AND NOT p.proleakproof AND p.proargdefaults IS NULL AND(SELECT count(*) FROM pg_catalog.pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.oid=pg_catalog.to_regprocedure($1::text)", &[&function.signature, &function.result]).await.unwrap();
        assert_eq!(batch.get::<_, i64>(13), index as i64 + 1);
        assert_eq!(
            metadata_fields(&batch),
            metadata_fields(&individual),
            "{}",
            function.name
        );
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn batched_metadata_refuses_missing_overloaded_and_changed_declarations() {
    let mut f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    for index in [0, FUNCTIONS.len() / 2, FUNCTIONS.len() - 1] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(&format!(
            "ALTER FUNCTION {} RENAME TO synthetic_missing_effect_helper",
            FUNCTIONS[index].signature
        ))
        .await
        .unwrap();
        assert!(matches!(
            functions(&tx).await,
            Err(EffectSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require(&f.reader).await.unwrap();
    }
    for sql in [
        "CREATE FUNCTION public.conversation_profile03_effect_fetch(text) RETURNS bytea LANGUAGE sql IMMUTABLE AS 'SELECT NULL::bytea'",
        "ALTER FUNCTION public.conversation_profile03_effect_identity(uuid,uuid,bytea) SET search_path TO public",
        "ALTER FUNCTION public.conversation_profile03_effect_identity(uuid,uuid,bytea) IMMUTABLE",
        "ALTER FUNCTION public.conversation_profile03_effect_identity(uuid,uuid,bytea) STRICT",
        "ALTER FUNCTION public.conversation_profile03_effect_identity(uuid,uuid,bytea) SECURITY INVOKER",
        "ALTER FUNCTION public.conversation_profile03_effect_identity(uuid,uuid,bytea) PARALLEL SAFE",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_effect_identity(account uuid,attempt uuid,command bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN; END'",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(
            matches!(functions(&tx).await, Err(EffectSchemaError::Invalid)),
            "{sql}"
        );
        tx.rollback().await.unwrap();
        require(&f.reader).await.unwrap();
    }
    let signature = "public.conversation_profile03_effect_identity(uuid,uuid,bytea)";
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
        ("command bytea", "command text"),
        ("RETURNS void", "RETURNS bigint"),
        ("command bytea)", "command bytea, OUT diagnostic bigint)"),
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
            functions(&tx).await,
            Err(EffectSchemaError::Invalid)
        ));
        tx.rollback().await.unwrap();
        require(&f.reader).await.unwrap();
    }
    f.finish().await;
}
