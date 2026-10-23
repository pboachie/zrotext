// SPDX-License-Identifier: AGPL-3.0-only
//! Reproduce migration-role leftovers without creating or changing a shared role.
use super::*;

async fn ready(f: &Fixture) -> bool {
    f.reader
        .query_one("SELECT public.hosted_runtime_identity_ready()", &[])
        .await
        .unwrap()
        .get(0)
}

async fn grant(f: &Fixture, role: &str, privilege: &str) {
    f.owner
        .batch_execute(&format!("GRANT {privilege} TO {}", escape_identifier(role)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn replacing_runtime_removes_predecessor_relation_column_and_function_grants() {
    let f = Fixture::runtime().await;
    assert!(ready(&f).await);
    crate::hosted_runtime_identity::require(&f.reader)
        .await
        .unwrap();
    let prior = format!("registration_prior_{}", Uuid::new_v4().simple());
    f.admin
        .batch_execute(&format!(
            "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
            escape_identifier(&prior)
        ))
        .await
        .unwrap();
    grant(&f, &prior, "USAGE ON SCHEMA public").await;
    grant(&f, &prior, "SELECT ON public.accounts").await;
    grant(
        &f,
        &prior,
        "EXECUTE ON FUNCTION public.hosted_runtime_scope()",
    )
    .await;
    grant(
        &f,
        &prior,
        "INSERT(operation),SELECT(result) ON public.hosted_runtime_requests",
    )
    .await;
    assert!(!ready(&f).await, "actual extra nonowner grants must refuse");
    assert!(
        crate::hosted_runtime_identity::require(&f.reader)
            .await
            .is_err()
    );

    provision_runtime_from(&f.owner, &f.database, &f.read_role, &prior).await;
    assert!(ready(&f).await);
    crate::hosted_runtime_identity::require(&f.reader)
        .await
        .unwrap();
    let privileges: (bool, bool, bool, bool) = {
        let row = f.owner.query_one(
            "SELECT has_schema_privilege($1,'public','USAGE'),has_table_privilege($1,'public.accounts','SELECT'),has_function_privilege($1,'public.hosted_runtime_scope()','EXECUTE'),has_any_column_privilege($1,'public.hosted_runtime_requests','INSERT,SELECT')",
            &[&prior],
        ).await.unwrap();
        (row.get(0), row.get(1), row.get(2), row.get(3))
    };
    assert_eq!(privileges, (false, false, false, false));

    // Each independent second-grantee boundary remains enforced after reset.
    for privilege in [
        "EXECUTE ON FUNCTION public.hosted_runtime_scope()",
        "SELECT(result) ON public.hosted_runtime_requests",
    ] {
        grant(&f, &prior, privilege).await;
        assert!(!ready(&f).await);
        assert!(
            crate::hosted_runtime_identity::require(&f.reader)
                .await
                .is_err()
        );
        provision_runtime_from(&f.owner, &f.database, &f.read_role, &prior).await;
        assert!(ready(&f).await);
    }
    f.admin
        .batch_execute(&format!("DROP ROLE {}", escape_identifier(&prior)))
        .await
        .unwrap();
    f.finish().await;
}
