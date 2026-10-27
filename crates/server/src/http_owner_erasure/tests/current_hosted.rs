// SPDX-License-Identifier: AGPL-3.0-only
//! Current stock-role hosted preflight, separate from historical SQL fixtures.
use super::*;
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::{
    ops::AsyncFnOnce,
    panic::{AssertUnwindSafe, resume_unwind},
};

async fn current_case<F>(test: F)
where
    F: for<'a> AsyncFnOnce(&'a mut Fixture),
{
    let mut f = Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
    let result = AssertUnwindSafe(test(&mut f)).catch_unwind().await;
    f.finish().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

async fn account(f: &Fixture) -> Uuid {
    let id = Uuid::new_v4();
    f.runtime
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
        .await
        .unwrap();
    id
}

async fn account_state(f: &Fixture, id: Uuid) -> String {
    f.runtime
        .query_one(
            "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; stock current hosted preflight"]
async fn current_native_preflight_uses_authorized_wrapper_without_internal_execute() {
    current_case(async |f| {
        let id = account(f).await;
        let before = account_state(f, id).await;
        let row = f.runtime.query_one(
            "SELECT pg_catalog.has_function_privilege(CURRENT_USER,'public.hosted_runtime_schema_ready()','EXECUTE'), public.hosted_runtime_role_safe()",
            &[],
        ).await.unwrap();
        assert!(!row.get::<_, bool>(0));
        assert!(row.get::<_, bool>(1));
        let denied = f.runtime
            .query_one("SELECT public.hosted_runtime_schema_ready()", &[])
            .await.unwrap_err();
        assert_eq!(denied.code(), Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE));
        {
            let mut client = crate::runtime_db::connect(&f.runtime_url).await.unwrap();
            let tx = begin_erasure_transaction(&mut client).await.unwrap();
            assert!(super::super::hosted::blockers(&tx, id).await.unwrap().is_empty());
            let blocked = f.owner.execute(
                "INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision) VALUES($1,'test','acct_erasure_fixture',1)",
                &[&Uuid::new_v4()],
            ).await.unwrap_err();
            assert_eq!(blocked.code(), Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE));
            assert_eq!(tx.query_one("SELECT count(*) FROM hosted_billing_namespaces", &[])
                .await.unwrap().get::<_, i64>(0), 0);
            tx.rollback().await.unwrap();
        }
        assert_eq!(account_state(f, id).await, before);
        f.verify().await;
    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; current hosted corruption refusals"]
async fn current_hosted_preflight_refuses_trigger_fk_inheritance_and_helper_drift() {
    for corruption in [
        "ALTER TRIGGER hosted_admit_message ON public.messages RENAME TO synthetic_erasure_wrong_trigger",
        "ALTER TABLE public.hosted_billing_customers DROP CONSTRAINT hosted_billing_customers_namespace_id_fkey",
        "CREATE TABLE public.synthetic_erasure_hosted_child() INHERITS(public.hosted_billing_customers)",
        "CREATE OR REPLACE FUNCTION public.hosted_runtime_schema_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog,public,pg_temp AS 'SELECT false'",
    ] {
        current_case(async |f| {
            let id = account(f).await;
            let before = account_state(f, id).await;
            f.owner.batch_execute(corruption).await.unwrap();
            assert!(
                crate::hosted_runtime_identity::require(&f.runtime)
                    .await
                    .is_err()
            );
            {
                let mut client = crate::runtime_db::connect(&f.runtime_url).await.unwrap();
                assert!(matches!(
                    begin_erasure_transaction(&mut client).await,
                    Err(crate::runtime_db::ConnectError::Identity)
                ));
            }
            // Independently exercise the named preflight predicate, not only
            // the earlier native refusal. The transaction remains usable.
            let tx = f.runtime.transaction().await.unwrap();
            assert!(super::super::hosted::blockers(&tx, id).await.is_err());
            assert_eq!(
                tx.query_one(
                    "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
                    &[&id]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
                before
            );
            tx.rollback().await.unwrap();
            assert_eq!(account_state(f, id).await, before);
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; no operator visibility shortcut"]
async fn current_populated_namespace_cannot_use_the_empty_namespace_shortcut() {
    current_case(async |f| {
        let id = account(f).await;
        let before = account_state(f, id).await;
        f.owner.execute(
            "INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision) VALUES($1,'test','acct_erasure_fixture',1)",
            &[&Uuid::new_v4()],
        ).await.unwrap();
        crate::hosted_runtime_identity::require(&f.runtime).await.unwrap();
        let row = f.runtime.query_one(
            "SELECT pg_catalog.has_table_privilege(CURRENT_USER,'public.hosted_billing_resolutions','SELECT'), pg_catalog.has_any_column_privilege(CURRENT_USER,'public.hosted_billing_resolutions','SELECT')",
            &[],
        ).await.unwrap();
        assert!(!row.get::<_, bool>(0) && !row.get::<_, bool>(1));
        assert!(crate::runtime_db::begin_native(&mut f.runtime).await.is_err());
        let tx = f.runtime.transaction().await.unwrap();
        assert!(super::super::hosted::blockers(&tx, id).await.is_err());
        assert_eq!(tx.query_one("SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1", &[&id])
            .await.unwrap().get::<_, String>(0), before);
        tx.rollback().await.unwrap();
        assert_eq!(account_state(f, id).await, before);
    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; migration-owner refusal"]
async fn current_preflight_does_not_admit_the_privileged_migration_owner() {
    current_case(async |f| {
        let id = account(f).await;
        let before = account_state(f, id).await;
        let row = f
            .owner
            .query_one(
                "SELECT public.hosted_runtime_schema_ready(), public.hosted_runtime_role_safe()",
                &[],
            )
            .await
            .unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(!row.get::<_, bool>(1));
        assert!(crate::runtime_db::begin_native(&mut f.owner).await.is_err());
        let tx = f.owner.transaction().await.unwrap();
        assert!(super::super::hosted::blockers(&tx, id).await.is_err());
        assert_eq!(
            tx.query_one(
                "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
                &[&id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
            before
        );
        tx.rollback().await.unwrap();
        assert_eq!(account_state(f, id).await, before);
    })
    .await;
}
