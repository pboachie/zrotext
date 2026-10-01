// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn final_scope_query_wait_cannot_keep_an_expired_grant_live() {
    let mut case = Case::new().await;
    let now: i64 = case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    case.request.expires_ms = now + 3000;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await
        .unwrap();
    let mut permit = scope::lock_scope(
        &tx,
        &principal,
        case.header.context,
        Operation::ContextMetadata,
    )
    .await
    .unwrap();
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    // Preserve every real grant row and column. Only this isolated fixture's
    // final authorization query acquires latency; constructor checks ran first.
    // A once-per-transaction gate avoids multiplying waits across grant rows.
    tx.batch_execute(
        r#"
        ALTER TABLE connector_grants RENAME TO connector_grants_scope_wait_rows;
        CREATE FUNCTION workflow_scope_query_wait() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
        BEGIN
            IF current_setting('zrotext_test.scope_wait',true) IS DISTINCT FROM 'done' THEN
                PERFORM set_config('zrotext_test.scope_wait','done',true);
                PERFORM pg_sleep(3);
            END IF;
            RETURN true;
        END; $$;
        CREATE VIEW connector_grants AS SELECT * FROM connector_grants_scope_wait_rows
            WHERE workflow_scope_query_wait();
    "#,
    )
    .await
    .unwrap();
    let observer = async {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let row = case.f.db.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep'), floor(extract(epoch FROM clock_timestamp())*1000)::bigint", &[&pid],
            ).await.unwrap();
            if row.get::<_, bool>(0) {
                assert!(
                    row.get::<_, i64>(1) < case.request.expires_ms,
                    "the production authorization query must begin waiting while the grant is live"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "authorization query never entered the positive wait phase"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    let (result, ()) = tokio::join!(permit.recheck(), observer);
    let after: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        after >= case.request.expires_ms,
        "query latency must actually cross the grant deadline"
    );
    drop(permit);
    tx.rollback().await.unwrap();
    case.f.cleanup().await;
    assert!(
        matches!(result, Err(auth::AuthError::Forbidden)),
        "a pre-query clock snapshot cannot authorize the expired grant: {result:?}"
    );
}
