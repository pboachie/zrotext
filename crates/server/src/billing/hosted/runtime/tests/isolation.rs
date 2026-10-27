// SPDX-License-Identifier: AGPL-3.0-only
//! Current runtime isolation remains mandatory beside historical contract tests.
use tokio_postgres::error::SqlState;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; current public schema and both installation orders"]
async fn current_runtime_refuses_legacy_billing_mixtures_in_both_installation_orders() {
    for legacy_first in [true, false] {
        let fixture = crate::test_database::Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
        let db = &fixture.owner;
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
        let legacy = "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_IsolationFixture')";
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
        fixture.finish().await;
    }
}
