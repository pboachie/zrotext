// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::payload_profile_writer::tests::Fixture;
use postgres_protocol::escape::escape_identifier;

async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    fixture.owner.batch_execute(&format!("GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready() TO {}",escape_identifier(&fixture.runtime_role))).await.unwrap();
    require(&fixture.db).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn original_receipt_schema_refuses_partial_changed_trigger_function_rule_policy_and_constraints()
 {
    let mut fixture = fixture().await;
    let original:String=fixture.owner.query_one("SELECT pg_catalog.pg_get_functiondef('public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea)'::regprocedure)", &[]).await.unwrap().get(0);
    let changed = original.replacen("accepted_ms bigint", "accepted_ms text", 1);
    assert_ne!(changed, original);
    let changed_output = format!(
        "DROP FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea); {changed}; REVOKE ALL ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) TO {}",
        escape_identifier(&fixture.runtime_role)
    );
    // Keep only a declaration change; no unknown body or PUBLIC ACL is needed.
    let mut mutations=vec![
        "ALTER TABLE public.payload_profile_v2_activation_receipts DISABLE TRIGGER payload_profile_v2_receipt_before_change",
        "ALTER TABLE public.payload_profile_v2_activation_receipts DISABLE TRIGGER payload_profile_v2_receipt_after_insert",
        "ALTER TABLE public.payload_profile_v2_activation_receipts DROP CONSTRAINT payload_profile_v2_activation_receipts_owner_statement_check",
        "ALTER TABLE public.payload_profile_v2_activation_receipts ADD COLUMN unreviewed boolean",
        "CREATE RULE unreviewed AS ON INSERT TO public.payload_profile_v2_activation_receipts DO INSTEAD NOTHING",
        "CREATE POLICY unreviewed ON public.payload_profile_v2_activation_receipts USING(true)",
        "ALTER TABLE public.payload_profile_v2_activation_receipts RENAME TO missing_original_receipts",
        "CREATE OR REPLACE FUNCTION public.payload_profile_v2_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "GRANT UPDATE(accepted_ms) ON public.payload_profile_v2_activation_receipts TO PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.payload_profile_v2_receipt_guard() TO PUBLIC",
    ].into_iter().map(str::to_owned).collect::<Vec<_>>();
    mutations.push(changed_output);
    for mutation in mutations {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(&mutation).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{mutation}");
        tx.rollback().await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn original_receipts_deny_runtime_row_column_or_internal_helper_authority() {
    let fixture = fixture().await;
    let role = escape_identifier(&fixture.runtime_role);
    for (grant, revoke) in [
        (
            format!(
                "GRANT UPDATE(accepted_ms) ON public.payload_profile_v2_activation_receipts TO {role}"
            ),
            format!(
                "REVOKE ALL(accepted_ms) ON public.payload_profile_v2_activation_receipts FROM {role}"
            ),
        ),
        (
            format!("GRANT INSERT ON public.payload_profile_v2_activation_receipts TO {role}"),
            format!("REVOKE INSERT ON public.payload_profile_v2_activation_receipts FROM {role}"),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.payload_profile_v2_receipt_complete() TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_v2_receipt_complete() FROM {role}"
            ),
        ),
    ] {
        fixture.owner.batch_execute(&grant).await.unwrap();
        assert!(require(&fixture.db).await.is_err(), "{grant}");
        fixture.owner.batch_execute(&revoke).await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}
