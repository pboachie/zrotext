// SPDX-License-Identifier: AGPL-3.0-only
//! Full-public ordinary-runtime transitive capability checks. These establish no
//! owner, socket, message or effect permission and do not cache schema results.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::Client;

const ANCESTORS: &[&str] = &[
    "payload_profile_writer_version",
    "payload_profile_v2_ready",
    "payload_profile_election_ready",
    "payload_profile_selection_ready",
    "payload_profile_manifest_ready",
    "conversation_profile03_interval_ready",
    "conversation_reviewed_send03_ready",
];

async fn original_definition(db: &Client, name: &str) -> String {
    db.query_one(
        "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1::text))",
        &[&format!("public.{name}()")],
    )
    .await
    .unwrap()
    .get(0)
}

async fn ancestor_refuses(db: &Client, name: &str) {
    let refused = match name {
        "payload_profile_writer_version" => {
            crate::payload_profile_writer::optional(db, "public.line_activation_v2_pending")
                .await
                .is_err()
        }
        "payload_profile_v2_ready" => crate::payload_profile_v2_receipts::optional(db)
            .await
            .is_err(),
        "payload_profile_election_ready" => crate::payload_profile_elections::optional(db)
            .await
            .is_err(),
        "payload_profile_selection_ready" => crate::payload_profile_selections::optional(db)
            .await
            .is_err(),
        "payload_profile_manifest_ready" => crate::payload_profile_manifests::optional(db)
            .await
            .is_err(),
        "conversation_profile03_interval_ready" => {
            crate::conversation_profile03_storage::optional(db)
                .await
                .is_err()
        }
        "conversation_reviewed_send03_ready" => optional(db).await.is_err(),
        _ => panic!("unknown controlled ancestor"),
    };
    assert!(refused, "independent ancestor accepted changed {name}");
    assert!(
        require_v2(db).await.is_err(),
        "top-level accepted changed {name}"
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn every_ancestor_body_and_metadata_is_rechecked_after_prior_success_and_restoration() {
    let f = Fixture::runtime().await;
    for name in ANCESTORS {
        require_v2(&f.reader).await.unwrap();
        let original = original_definition(&f.owner, name).await;
        f.owner.batch_execute(&format!(
            "CREATE OR REPLACE FUNCTION public.{name}() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'"
        )).await.unwrap();
        ancestor_refuses(&f.reader, name).await;
        f.owner.batch_execute(&original).await.unwrap();
        require_v2(&f.reader).await.unwrap();
        // A previous success must not cache readiness: mutate again without
        // changing the body, then require the complete chain to fail freshly.
        f.owner
            .batch_execute(&format!(
                "ALTER FUNCTION public.{name}() SET search_path TO pg_catalog,pg_temp"
            ))
            .await
            .unwrap();
        ancestor_refuses(&f.reader, name).await;
        f.owner.batch_execute(&original).await.unwrap();
        require_v2(&f.reader).await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn public_ancestor_execute_grants_refuse_then_fresh_restored_calls_work() {
    let f = Fixture::runtime().await;
    for name in ANCESTORS {
        require_v2(&f.reader).await.unwrap();
        f.owner
            .batch_execute(&format!(
                "GRANT EXECUTE ON FUNCTION public.{name}() TO PUBLIC"
            ))
            .await
            .unwrap();
        ancestor_refuses(&f.reader, name).await;
        f.owner
            .batch_execute(&format!(
                "REVOKE EXECUTE ON FUNCTION public.{name}() FROM PUBLIC"
            ))
            .await
            .unwrap();
        require_v2(&f.reader).await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn partial_ancestor_and_extra_family_objects_cannot_bypass_the_transitive_chain() {
    let f = Fixture::runtime().await;
    require_v2(&f.reader).await.unwrap();
    f.owner.batch_execute("ALTER TABLE public.payload_profile_selection_receipts RENAME TO renamed_selection_receipts").await.unwrap();
    assert!(
        crate::payload_profile_selections::optional(&f.reader)
            .await
            .is_err()
    );
    assert!(require_v2(&f.reader).await.is_err());
    f.owner.batch_execute("ALTER TABLE public.renamed_selection_receipts RENAME TO payload_profile_selection_receipts").await.unwrap();
    require_v2(&f.reader).await.unwrap();
    for (create, drop) in [
        (
            "CREATE FUNCTION public.payload_profile_manifest_unexpected() RETURNS boolean LANGUAGE sql AS 'SELECT true'",
            "DROP FUNCTION public.payload_profile_manifest_unexpected()",
        ),
        (
            "CREATE SEQUENCE public.payload_profile_selection_receipts_unexpected",
            "DROP SEQUENCE public.payload_profile_selection_receipts_unexpected",
        ),
    ] {
        f.owner.batch_execute(create).await.unwrap();
        assert!(require_v2(&f.reader).await.is_err(), "{create}");
        f.owner.batch_execute(drop).await.unwrap();
        require_v2(&f.reader).await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable CREATEDB/CREATEROLE"]
async fn namespace_shadow_and_owner_role_still_cannot_supply_runtime_readiness() {
    let f = Fixture::runtime().await;
    require_v2(&f.reader).await.unwrap();
    assert!(require_v2(&f.owner).await.is_err());
    let ordinary: bool = f.reader.query_one(
        "SELECT NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_catalog.pg_roles WHERE rolname=current_user",
        &[],
    ).await.unwrap().get(0);
    assert!(ordinary);
    let schema = escape_identifier(&format!("shadow_{}", uuid::Uuid::new_v4().simple()));
    f.owner.batch_execute(&format!(
        "CREATE SCHEMA {schema}; CREATE TABLE {schema}.line_activation_v2_pending(value integer); GRANT USAGE ON SCHEMA {schema} TO PUBLIC"
    )).await.unwrap();
    f.reader
        .batch_execute(&format!("SET search_path TO pg_catalog,{schema},public"))
        .await
        .unwrap();
    assert!(optional(&f.reader).await.is_err());
    assert!(require_v2(&f.reader).await.is_err());
    f.reader
        .batch_execute("SET search_path TO pg_catalog,public")
        .await
        .unwrap();
    require_v2(&f.reader).await.unwrap();
    f.owner
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    require_v2(&f.reader).await.unwrap();
    f.finish().await;
}
