// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::conversation_profile03_storage::test_fixture as current_fixture;
use crate::test_database::Fixture;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

async fn fixture() -> Fixture {
    let fixture = current_fixture::new().await;
    require(&fixture.runtime).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn grant_schema_composes_exact_parents_under_all_supported_lookup_paths() {
    let mut fixture = fixture().await;
    for path in ["pg_catalog", "pg_catalog, public", "public"] {
        let tx = fixture.runtime.transaction().await.unwrap();
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
        require(&fixture.runtime).await.unwrap();
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
        let error = fixture.runtime.batch_execute(sql).await.unwrap_err();
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
        .runtime
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    let tx = fixture.runtime.transaction().await.unwrap();
    tx.batch_execute(
        "SET LOCAL zrotext.selection_epoch='1'; SET LOCAL zrotext.grant_authorized='true'",
    )
    .await
    .unwrap();
    let error = tx.query("SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,'synthetic','synthetic',1,1)", &[&account,&attempt,&device]).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    tx.rollback().await.unwrap();
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        let tx = fixture.runtime.transaction().await.unwrap();
        tx.batch_execute(&format!("SET TRANSACTION ISOLATION LEVEL {isolation}"))
            .await
            .unwrap();
        let error=tx.query("SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,'synthetic','synthetic',1,1)", &[&account,&attempt,&device]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        tx.rollback().await.unwrap();
    }
    assert_eq!(
        fixture
            .runtime
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

#[test]
fn every_current_grant_required_declaration_uses_its_independent_stock_pin() {
    use sha2::{Digest, Sha256};
    let expected = [
        (
            "conversation_profile03_grant_mode",
            "88cc435625b02027cf88e09b93a5ece91be164073876b837750c6232d211c4f3",
        ),
        (
            "conversation_profile03_grant_issued",
            "660270fb3f84cc662d67a8734c49b254e460d82f3535975970c133aa8f73626e",
        ),
        (
            "conversation_profile03_grant_lock",
            "35544e458bd295ea65c292f85c165f7a68ab54833f39005fa6eb9072f97c4b1d",
        ),
        (
            "conversation_profile03_grant_issue",
            "9d16e12ae65072a8eaefaa43ab17b14b360ed914f2c90c03af83e15a8538fc32",
        ),
        (
            "conversation_profile03_grant_rows_guard",
            "b3a9375ed664177dfb032755071667fa3ceb14dac1ce5e37c1712bb2f31cd427",
        ),
        (
            "conversation_profile03_grant_complete",
            "027bcdfb9e932d3b00efde8cef3bafe6859d1681d82568b0b09bb42ab9085964",
        ),
        (
            "conversation_profile03_grant_billing",
            "2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3",
        ),
        (
            "conversation_profile03_grant_usage_writer",
            "686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed",
        ),
        (
            "conversation_profile03_grant_scope",
            "7f4861c2b72b04b787fbe03dba9ea0df1b453dd90fc63181ed37b707d081231b",
        ),
        (
            "conversation_profile03_grant_same_scope",
            "89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523",
        ),
        (
            "conversation_profile03_grant_writer",
            "fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60",
        ),
        (
            "payload_profile_writer_policy",
            "1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300",
        ),
        (
            "conversation_reviewed_send03_admit",
            "b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb",
        ),
        (
            "alpha_message_effect_guard",
            "f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda",
        ),
        (
            "conversation_profile03_interval_ready",
            "e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f",
        ),
        (
            "payload_profile_writer_version",
            "887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6",
        ),
        (
            "payload_profile_writer_ready",
            "10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458",
        ),
        (
            "conversation_profile03_grant_ready",
            "7a7920d347bb93453f6d11c2044060ba46642135f41dab8223446cafee017448",
        ),
    ];
    assert_eq!(REQUIRED_FUNCTIONS.len(), expected.len());
    let names = REQUIRED_FUNCTIONS
        .iter()
        .map(|entry| entry.0)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names.len(),
        expected.len(),
        "duplicate required declaration"
    );
    for &(name, _, _, _, _, _, _, _, _, _) in REQUIRED_FUNCTIONS {
        let expected = expected
            .iter()
            .find(|(required, _)| *required == name)
            .expect("unreviewed required declaration")
            .1;
        let actual = Sha256::digest(body(name, 117).unwrap().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "{name}");
    }
}
