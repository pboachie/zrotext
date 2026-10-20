// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::payload_profile_writer::tests::Fixture;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::error::SqlState;

async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    fixture.owner.batch_execute(&format!("GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready(),public.payload_profile_election_reserve(uuid,uuid,uuid,uuid,uuid,bytea,bytea,bigint),public.payload_profile_election_device_proof(uuid,uuid,bytea),public.payload_profile_election_accept(uuid,uuid,uuid,bytea,bigint),public.payload_profile_election_ready() TO {}",escape_identifier(&fixture.runtime_role))).await.unwrap();
    require(&fixture.db).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn atomic_election_graph_refuses_partial_disabled_rewritten_policy_and_helper_changes() {
    let mut fixture = fixture().await;
    for mutation in [
        "ALTER TABLE public.payload_profile_election_challenges DISABLE TRIGGER payload_profile_election_challenge_before_change",
        "ALTER TABLE public.payload_profile_elections DISABLE TRIGGER payload_profile_election_accepted_after_insert",
        "ALTER TABLE public.payload_profile_election_challenges DROP CONSTRAINT payload_profile_election_challenges_check",
        "ALTER TABLE public.payload_profile_elections ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.payload_profile_election_challenges ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY unreviewed ON public.payload_profile_elections USING(true)",
        "CREATE RULE unreviewed AS ON UPDATE TO public.payload_profile_elections DO INSTEAD NOTHING",
        "DROP TABLE public.payload_profile_elections CASCADE",
        "CREATE OR REPLACE FUNCTION public.payload_profile_epoch_valid(account uuid,epoch bigint) RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.payload_profile_election_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.payload_profile_election_rows_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN NEW; END'",
        "GRANT EXECUTE ON FUNCTION public.payload_profile_election_scope(uuid,uuid,uuid,bytea,bytea) TO PUBLIC",
    ] {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{mutation}");
        tx.rollback().await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn atomic_elections_deny_row_column_internal_epoch_and_scope_authority() {
    let fixture = fixture().await;
    let role = escape_identifier(&fixture.runtime_role);
    for statement in [
        "DELETE FROM public.payload_profile_election_challenges",
        "UPDATE public.payload_profile_elections SET accepted_at_ms=accepted_at_ms",
        "UPDATE public.payload_profile_account_anchors SET selection_epoch=selection_epoch+1",
        "SELECT public.payload_profile_election_quiescent('00000000-0000-0000-0000-000000000001')",
    ] {
        let error = fixture.db.batch_execute(statement).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    for (grant, revoke) in [
        (
            format!(
                "GRANT UPDATE(closed_unaccepted_ms) ON public.payload_profile_election_challenges TO {role}"
            ),
            format!(
                "REVOKE ALL(closed_unaccepted_ms) ON public.payload_profile_election_challenges FROM {role}"
            ),
        ),
        (
            format!("GRANT INSERT ON public.payload_profile_elections TO {role}"),
            format!("REVOKE INSERT ON public.payload_profile_elections FROM {role}"),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.payload_profile_epoch_valid(uuid,bigint) TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_epoch_valid(uuid,bigint) FROM {role}"
            ),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.payload_profile_election_scope(uuid,uuid,uuid,bytea,bytea) TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_election_scope(uuid,uuid,uuid,bytea,bytea) FROM {role}"
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
