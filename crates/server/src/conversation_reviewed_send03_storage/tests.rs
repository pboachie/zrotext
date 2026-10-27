// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::conversation_profile03_storage::test_fixture as current_fixture;
use crate::test_database::Fixture;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

pub(super) async fn fixture() -> Fixture {
    let fixture = current_fixture::new().await;
    crate::payload_profile_manifests::require(&fixture.runtime)
        .await
        .unwrap();
    crate::conversation_profile03_storage::require(&fixture.runtime)
        .await
        .unwrap();
    require(&fixture.runtime).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

pub(super) fn intent() -> Vec<u8> {
    let mut bytes = b"ZTRI\x01\x03\x03\0".to_vec();
    for _ in 0..8 {
        bytes.extend(Uuid::new_v4().as_bytes());
    }
    for n in [2_u64, 1, 3, 1, 1000, 3000, 1001, 2000] {
        bytes.extend(n.to_be_bytes());
    }
    for n in 1..=11 {
        bytes.extend([n; 32]);
    }
    bytes.extend([3, b'+', b'1', b'2', 2, 1]);
    bytes.extend([1; 32]);
    bytes.push(2);
    bytes.extend([12; 32]);
    bytes.push(1);
    bytes
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn reviewed_intent_keeps_exact_identity_readers_peer_windows_and_signed_ceiling() {
    let fixture = fixture().await;
    let original = intent();
    assert_eq!(original.len(), 624);
    let parsed=fixture.owner.query_one("SELECT (public.conversation_reviewed_send03_parse($1)).peer,(public.conversation_reviewed_send03_parse($1)).authenticated_segment_ceiling",&[&original]).await.unwrap();
    assert_eq!(parsed.get::<_, String>(0), "+12");
    assert_eq!(parsed.get::<_, i16>(1), 1);
    let mut six = original.clone();
    *six.last_mut().unwrap() = 6;
    assert_eq!(fixture.owner.query_one("SELECT (public.conversation_reviewed_send03_parse($1)).authenticated_segment_ceiling",&[&six]).await.unwrap().get::<_,i16>(0),6);
    let mut variants = Vec::new();
    for at in [0, 4, 5, 6, 7, 552, 553, 556, 557, 590] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        variants.push(changed);
    }
    for range in [8..24, 200..232, 520..552] {
        let mut changed = original.clone();
        changed[range].fill(0);
        variants.push(changed);
    }
    for ceiling in [0, 7] {
        let mut changed = original.clone();
        *changed.last_mut().unwrap() = ceiling;
        variants.push(changed);
    }
    let mut trailing = original.clone();
    trailing.push(0);
    variants.push(trailing);
    let mut expired = original.clone();
    expired[192..200].copy_from_slice(&1001_u64.to_be_bytes());
    variants.push(expired);
    for changed in variants {
        assert!(
            fixture
                .owner
                .query_one(
                    "SELECT public.conversation_reviewed_send03_parse($1)",
                    &[&changed]
                )
                .await
                .is_err()
        );
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn actual_queue_metadata_constraint_rejects_null_or_out_of_range_profile03_ceiling() {
    let fixture = fixture().await;
    // Evaluate the installed CHECK itself. PostgreSQL accepts a NULL CHECK
    // result, so invalid inputs must produce FALSE rather than merely not TRUE.
    // The full authenticated-sidecar/queue transaction belongs to adapter tests.
    let check: String = fixture
        .owner
        .query_one(
            "SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid='public.messages'::regclass AND conname='messages_sealed_metadata'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let query = format!(
        "SELECT ({check}) IS FALSE FROM (SELECT $1::smallint sealed_segment_limit,
         'sealed_profile03'::text transport_mode,$2::uuid sealed_line_id,
         2::bigint sealed_binding_generation,1::bigint sealed_manifest_generation,
         3::bigint sealed_manifest_version,decode(repeat('01',32),'hex') sealed_manifest_digest,
         decode(repeat('02',32),'hex') sealed_signer_key_id,'queued'::text state,
         $2::uuid account_id,$2::uuid id) candidate"
    );
    let id = Uuid::new_v4();
    for (ceiling, must_refuse) in [
        (None, true),
        (Some(0_i16), true),
        (Some(7), true),
        (Some(1), false),
        (Some(6), false),
    ] {
        let refuses: bool = fixture
            .owner
            .query_one(&query, &[&ceiling, &id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(refuses, must_refuse, "ceiling {ceiling:?}");
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn reviewed_admission_storage_refuses_missing_disabled_unknown_and_substituted_graph() {
    let mut fixture = fixture().await;
    for search_path in ["pg_catalog", "pg_catalog, public", "public"] {
        let tx = fixture.runtime.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL search_path TO {search_path}"))
            .await
            .unwrap();
        require(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    for sql in [
        "ALTER TABLE public.conversation_reviewed_sends03 DISABLE TRIGGER conversation_reviewed_send03_before_change",
        "ALTER TABLE public.conversation_reviewed_sends03 DISABLE TRIGGER conversation_reviewed_send03_after_change",
        "ALTER TABLE public.messages DISABLE TRIGGER conversation_reviewed_send03_after_redaction",
        "ALTER TABLE public.conversation_reviewed_sends03 ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.conversation_reviewed_sends03 ENABLE ROW LEVEL SECURITY",
        "CREATE RULE unreviewed AS ON UPDATE TO public.conversation_reviewed_sends03 DO INSTEAD NOTHING",
        "DROP TABLE public.conversation_reviewed_sends03 CASCADE",
        "CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "ALTER FUNCTION public.conversation_reviewed_send03_admit(uuid,uuid,uuid,bytea,bytea,bytea,bigint) SECURITY INVOKER",
        "CREATE FUNCTION public.conversation_reviewed_send03_envelope(bytea,bytea) RETURNS void LANGUAGE plpgsql AS 'BEGIN RETURN; END'",
        "GRANT EXECUTE ON FUNCTION public.conversation_reviewed_send03_scope(uuid,bytea,bytea,bigint,bigint) TO PUBLIC",
    ] {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
        require(&fixture.runtime).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn ordinary_runtime_cannot_edit_restore_originals_or_call_internal_admission_predicates() {
    let fixture = fixture().await;
    for sql in [
        "DELETE FROM public.conversation_reviewed_sends03",
        "UPDATE public.conversation_reviewed_sends03 SET intent=intent",
        "UPDATE public.conversation_reviewed_sends03 SET redacted_ms=NULL",
        "SELECT public.conversation_reviewed_send03_parse(''::bytea)",
        "SELECT public.conversation_reviewed_send03_scope(NULL,NULL,NULL,NULL,NULL)",
        "SELECT public.conversation_reviewed_send03_writer(NULL,1,'messages','INSERT',NULL,NULL)",
    ] {
        let error = fixture.runtime.batch_execute(sql).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    fixture.finish().await;
}
