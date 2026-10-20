// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::payload_profile_writer::tests::Fixture;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    let role = escape_identifier(&fixture.runtime_role);
    fixture.owner.batch_execute(&format!("GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready(),public.payload_profile_election_reserve(uuid,uuid,uuid,uuid,uuid,bytea,bytea,bigint),public.payload_profile_election_device_proof(uuid,uuid,bytea),public.payload_profile_election_accept(uuid,uuid,uuid,bytea,bigint),public.payload_profile_election_ready(),public.payload_profile_selection_reserve(uuid,uuid,uuid,uuid,bytea,bigint),public.payload_profile_selection_device_proof(uuid,uuid,bytea,bytea),public.payload_profile_selection_approve(uuid,uuid,uuid,bytea,bigint),public.payload_profile_selection_install(uuid,uuid,bytea,bytea),public.payload_profile_selection_ready(),public.payload_profile_manifest_install(uuid,uuid,uuid,uuid,bytea,bytea,bytea,bigint),public.payload_profile_manifest_retention(uuid,uuid,bigint,bytea,bytea,bigint,bytea),public.payload_profile_manifest_ready(),public.conversation_profile03_interval_reserve(uuid,uuid,uuid,uuid,uuid,uuid,bytea,bigint),public.conversation_profile03_interval_request(uuid,uuid,uuid,bytea,bigint),public.conversation_profile03_interval_approve(uuid,uuid,bytea),public.conversation_profile03_interval_install(uuid,uuid,bytea),public.conversation_profile03_interval_stop(uuid,uuid,uuid,uuid),public.conversation_profile03_interval_device_stop(uuid,uuid,uuid,text,text,bigint,bigint,bytea),public.conversation_profile03_interval_ready(),public.conversation_reviewed_send03_admit(uuid,uuid,uuid,bytea,bytea,bytea,bigint),public.conversation_reviewed_send03_ready(),public.conversation_reviewed_send03_v2_ready() TO {role}")).await.unwrap();
    require(&fixture.db).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn grant_schema_composes_exact_parents_under_all_supported_lookup_paths() {
    let mut fixture = fixture().await;
    for path in ["pg_catalog", "pg_catalog, public", "public"] {
        let tx = fixture.db.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL search_path TO {path}"))
            .await
            .unwrap();
        crate::conversation_reviewed_send03_storage::require(&tx)
            .await
            .unwrap();
        require(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn grant_schema_rejects_changed_bodies_declarations_acl_rules_and_trigger_graphs() {
    let mut fixture = fixture().await;
    for sql in [
        "ALTER TABLE public.conversation_profile03_grants DISABLE TRIGGER conversation_profile03_grant_before_change",
        "ALTER TABLE public.conversation_profile03_grants DISABLE TRIGGER conversation_profile03_grant_after_change",
        "ALTER TABLE public.conversation_profile03_grants ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.conversation_profile03_grants ENABLE ROW LEVEL SECURITY",
        "CREATE RULE unreviewed AS ON UPDATE TO public.conversation_profile03_grants DO INSTEAD NOTHING",
        "DROP TABLE public.conversation_profile03_grants CASCADE",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "ALTER FUNCTION public.conversation_profile03_grant_lock(uuid,uuid,uuid,text,text,bigint,bigint) SECURITY INVOKER",
        "CREATE FUNCTION public.conversation_profile03_grant_same_scope(bytea,bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "GRANT EXECUTE ON FUNCTION public.conversation_profile03_grant_mode(uuid) TO PUBLIC",
        "ALTER FUNCTION public.alpha_message_effect_guard() SET search_path TO public",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_usage_writer(account uuid,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN; END'",
        "GRANT EXECUTE ON FUNCTION public.conversation_profile03_grant_usage_writer(uuid,text,text,jsonb,jsonb) TO PUBLIC",
        "ALTER TABLE public.usage_ledger DISABLE TRIGGER zz_payload_profile_writer_before_change",
        "ALTER TABLE public.usage_periods DISABLE TRIGGER zz_payload_profile_writer_before_change",
    ] {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn ordinary_runtime_cannot_write_grants_or_invoke_internal_claim_and_billing_predicates() {
    let fixture = fixture().await;
    for sql in [
        "DELETE FROM public.conversation_profile03_grants",
        "UPDATE public.conversation_profile03_grants SET expires_at_ms=expires_at_ms+1",
        "UPDATE public.conversation_profile03_grants SET authenticated_segment_ceiling=NULL",
        "SELECT public.conversation_profile03_grant_mode(NULL)",
        "SELECT public.conversation_profile03_grant_billing(NULL,NULL)",
        "SELECT public.conversation_profile03_grant_usage_writer(NULL,'usage_ledger','INSERT',NULL,NULL)",
        "SELECT public.conversation_profile03_grant_scope(NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        "SELECT public.conversation_profile03_grant_writer(NULL,'message_attempts','INSERT',NULL,NULL)",
        "SELECT public.conversation_profile03_grant_issued(NULL,NULL)",
    ] {
        let error = fixture.db.batch_execute(sql).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn absent_attempt_is_not_authority_and_copied_context_cannot_select_a_positive_epoch() {
    let mut fixture = fixture().await;
    let account = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let device = Uuid::new_v4();
    fixture
        .db
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    let tx = fixture.db.transaction().await.unwrap();
    tx.batch_execute(
        "SET LOCAL zrotext.selection_epoch='1'; SET LOCAL zrotext.grant_authorized='true'",
    )
    .await
    .unwrap();
    let error = tx.query("SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,'synthetic','synthetic',1,1)", &[&account,&attempt,&device]).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    tx.rollback().await.unwrap();
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        let tx = fixture.db.transaction().await.unwrap();
        tx.batch_execute(&format!("SET TRANSACTION ISOLATION LEVEL {isolation}"))
            .await
            .unwrap();
        let error=tx.query("SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,'synthetic','synthetic',1,1)", &[&account,&attempt,&device]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        tx.rollback().await.unwrap();
    }
    assert_eq!(
        fixture
            .db
            .query_one(
                "SELECT count(*) FROM public.conversation_profile03_grants WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    fixture.finish().await;
}
