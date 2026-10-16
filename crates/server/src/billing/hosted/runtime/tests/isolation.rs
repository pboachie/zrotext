// SPDX-License-Identifier: AGPL-3.0-only
//! Current runtime isolation remains mandatory beside historical contract tests.
use super::fixture::connect;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; complete schema and both installation orders"]
async fn current_runtime_refuses_legacy_billing_mixtures_in_both_installation_orders() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    for legacy_first in [true, false] {
        let db = connect(&url).await;
        let schema = format!("hosted_isolation_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        crate::auth::test_schema::apply(&db).await;
        assert!(
            db.query_one("SELECT hosted_runtime_schema_ready()", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        let account = Uuid::new_v4();
        let namespace = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        let legacy = "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_isolation_fixture')";
        let runtime = "INSERT INTO hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_isolation_fixture',1,true,true)";
        let error = if legacy_first {
            db.execute(legacy, &[&account]).await.unwrap();
            db.execute(runtime, &[&namespace]).await.unwrap_err()
        } else {
            db.execute(runtime, &[&namespace]).await.unwrap();
            db.execute(legacy, &[&account]).await.unwrap_err()
        };
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        let counts = db
            .query_one(
                "SELECT (SELECT count(*) FROM billing_customers), (SELECT count(*) FROM hosted_billing_namespaces)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(counts.get::<_, i64>(0), i64::from(legacy_first));
        assert_eq!(counts.get::<_, i64>(1), i64::from(!legacy_first));
        db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
