// SPDX-License-Identifier: AGPL-3.0-only
//! Ordinary stock-runtime equivalence checks for uncached native metadata reads.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::{Client, GenericClient};

async fn stock<C: GenericClient + Sync>(db: &C) {
    assert!(optional(db).await.unwrap());
    require(db).await.unwrap();
    crate::device_protection_storage::require(db).await.unwrap();
}
async fn refused<C: GenericClient + Sync>(db: &C) {
    assert!(optional(db).await.is_err());
    assert!(require(db).await.is_err());
    assert!(crate::device_protection_storage::require(db).await.is_err());
}
async fn definition(db: &Client, signature: &str) -> String {
    db.query_one(
        "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1::text))",
        &[&signature],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; exact native metadata"]
async fn early_middle_and_applied_source_bodies_and_config_are_reloaded_after_success() {
    let mut f = Fixture::runtime().await;
    let tx = f.reader.transaction().await.unwrap();
    // The same READ COMMITTED runtime transaction must observe committed owner
    // changes after earlier successes. The last item uses the applied106 hash
    // alternatives rather than the replacement-body source path.
    for signature in [
        "public.hosted_runtime_native_start()",
        "public.hosted_runtime_expiry(uuid,bigint)",
        "public.hosted_runtime_projection(uuid)",
    ] {
        stock(&tx).await;
        let original = definition(&f.owner, signature).await;
        assert!(original.contains("AS $function$"));
        let changed = original.replacen(
            "AS $function$",
            "AS $function$\n-- Deliberately changed catalog body.\n",
            1,
        );
        f.owner.batch_execute(&changed).await.unwrap();
        refused(&tx).await;
        f.owner.batch_execute(&original).await.unwrap();
        stock(&tx).await;
        f.owner
            .batch_execute(&format!(
                "ALTER FUNCTION {signature} SET search_path TO pg_catalog,pg_temp"
            ))
            .await
            .unwrap();
        refused(&tx).await;
        f.owner.batch_execute(&original).await.unwrap();
        stock(&tx).await;
    }
    tx.rollback().await.unwrap();
    stock(&f.reader).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; native ordinal and overload refusal"]
async fn missing_first_middle_last_metadata_and_extra_overload_cannot_shift_expected_items() {
    let f = Fixture::runtime().await;
    for (signature, original_name) in [
        (
            "hosted_runtime_native_start()",
            "hosted_runtime_native_start",
        ),
        (
            "hosted_runtime_expiry(uuid,bigint)",
            "hosted_runtime_expiry",
        ),
        (
            "hosted_runtime_projection(uuid)",
            "hosted_runtime_projection",
        ),
    ] {
        stock(&f.reader).await;
        // Keep the native family count unchanged. The missing exact signature
        // must be refused by the closed metadata set, not hidden by row zipping.
        f.owner
            .batch_execute(&format!(
                "ALTER FUNCTION public.{signature} RENAME TO hosted_runtime_batch_withheld"
            ))
            .await
            .unwrap();
        assert_eq!(
            f.reader
                .query_one("SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'hosted_runtime_%'", &[])
                .await.unwrap().get::<_, i64>(0),
            15
        );
        refused(&f.reader).await;
        let arguments = signature.split_once('(').unwrap().1;
        f.owner
            .batch_execute(&format!(
                "ALTER FUNCTION public.hosted_runtime_batch_withheld({arguments} RENAME TO {original_name}"
            ))
            .await
            .unwrap();
        stock(&f.reader).await;
    }
    // This name is required by native validation but is outside its hosted
    // family counter, so the per-name overload predicate must still refuse.
    f.owner
        .batch_execute("CREATE FUNCTION public.payload_profile_writer_json(integer) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT $1::text'")
        .await.unwrap();
    refused(&f.reader).await;
    f.owner
        .batch_execute("DROP FUNCTION public.payload_profile_writer_json(integer)")
        .await
        .unwrap();
    stock(&f.reader).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; native table shape restoration"]
async fn table_ordinals_kinds_columns_and_default_flags_cannot_replace_exact_shapes() {
    let f = Fixture::runtime().await;
    stock(&f.reader).await;
    for (change, restore) in [
        (
            "ALTER TABLE public.hosted_runtime_entries ADD COLUMN batch_unexpected boolean",
            "ALTER TABLE public.hosted_runtime_entries DROP COLUMN batch_unexpected",
        ),
        (
            "ALTER TABLE public.hosted_runtime_entries ALTER COLUMN expires_at DROP NOT NULL",
            "ALTER TABLE public.hosted_runtime_entries ALTER COLUMN expires_at SET NOT NULL",
        ),
        (
            "ALTER TABLE public.hosted_runtime_entries ALTER COLUMN native_xid SET DEFAULT pg_catalog.pg_current_xact_id()",
            "ALTER TABLE public.hosted_runtime_entries ALTER COLUMN native_xid DROP DEFAULT",
        ),
        (
            "ALTER TABLE public.hosted_runtime_requests ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE public.hosted_runtime_requests DISABLE ROW LEVEL SECURITY",
        ),
    ] {
        f.owner.batch_execute(change).await.unwrap();
        refused(&f.reader).await;
        f.owner.batch_execute(restore).await.unwrap();
        stock(&f.reader).await;
    }
    // Preserve the actual table and every row/ACL/dependency while a wrong-kind
    // or reordered lookalike occupies its public name. Restoration renames the
    // same retained original back; it never reconstructs native bookkeeping.
    for (name, replacement, remove) in [
        (
            "hosted_runtime_entries",
            "CREATE VIEW public.hosted_runtime_entries AS SELECT * FROM public.native_batch_original",
            "DROP VIEW public.hosted_runtime_entries",
        ),
        (
            "hosted_runtime_requests",
            "CREATE TABLE public.hosted_runtime_requests(result jsonb,operation text NOT NULL)",
            "DROP TABLE public.hosted_runtime_requests",
        ),
    ] {
        f.owner
            .batch_execute(&format!(
                "ALTER TABLE public.{name} RENAME TO native_batch_original; {replacement}"
            ))
            .await
            .unwrap();
        refused(&f.reader).await;
        f.owner
            .batch_execute(&format!(
                "{remove}; ALTER TABLE public.native_batch_original RENAME TO {name}"
            ))
            .await
            .unwrap();
        stock(&f.reader).await;
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; public native namespace identity"]
async fn shadow_table_cannot_replace_a_missing_public_native_relation() {
    let f = Fixture::runtime().await;
    stock(&f.reader).await;
    let schema = escape_identifier(&format!(
        "native_batch_shadow_{}",
        uuid::Uuid::new_v4().simple()
    ));
    f.owner
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; CREATE TABLE {schema}.hosted_runtime_requests(LIKE public.hosted_runtime_requests INCLUDING ALL); GRANT USAGE ON SCHEMA {schema} TO PUBLIC; ALTER TABLE public.hosted_runtime_requests RENAME TO native_batch_original"
        ))
        .await.unwrap();
    f.reader
        .batch_execute(&format!("SET search_path TO pg_catalog,{schema},public"))
        .await
        .unwrap();
    assert!(f.reader.query_one("SELECT pg_catalog.to_regclass('hosted_runtime_requests') IS NOT NULL AND pg_catalog.to_regclass('public.hosted_runtime_requests') IS NULL", &[]).await.unwrap().get::<_, bool>(0));
    refused(&f.reader).await;
    f.reader
        .batch_execute("SET search_path TO pg_catalog,public")
        .await
        .unwrap();
    f.owner
        .batch_execute(&format!(
            "ALTER TABLE public.native_batch_original RENAME TO hosted_runtime_requests; DROP SCHEMA {schema} CASCADE"
        ))
        .await.unwrap();
    stock(&f.reader).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; fresh native role and column readiness"]
async fn prior_metadata_success_never_caches_runtime_execute_or_column_readiness() {
    let mut f = Fixture::runtime().await;
    stock(&f.reader).await;
    assert!(require(&f.owner).await.is_err());
    let role = escape_identifier(
        &f.reader
            .query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
    );
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
        assert!(optional(&tx).await.unwrap());
        assert!(require(&tx).await.is_err());
        assert!(
            crate::device_protection_storage::require(&tx)
                .await
                .is_err()
        );
        f.owner.batch_execute(&restore).await.unwrap();
        stock(&tx).await;
    }
    tx.rollback().await.unwrap();
    stock(&f.reader).await;
    f.finish().await;
}
