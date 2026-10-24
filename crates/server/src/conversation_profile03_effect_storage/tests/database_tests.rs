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
    let actual:Vec<u8>=f.owner.query_one("SELECT public.conversation_profile03_effect_fetch(pg_catalog.jsonb_populate_record(NULL::public.conversation_profile03_grants,$1::jsonb))",&[&Value::Object(row)]).await.unwrap().get(0);
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
