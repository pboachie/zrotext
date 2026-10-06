// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; synthetic original authority"]
async fn join_order_preserves_live_original_deadline_and_transaction_scope() {
    let mut f = OriginalCase::new().await;
    let issued = f.issue().await;
    let mut client = f.case.f.connect().await;
    let settings_query = "SELECT proconfig,current_setting('join_collapse_limit') FROM pg_proc WHERE oid='original_reply_grant_deadline(uuid,uuid)'::regprocedure";
    let initial = client
        .query_one(settings_query, &[])
        .await
        .map_err(|_| ())
        .expect("settings unavailable");
    let initial_config: Option<Vec<String>> = initial.get(0);
    let connection_setting: String = initial.get(1);
    let tx = client
        .transaction()
        .await
        .map_err(|_| ())
        .expect("transaction unavailable");
    let query = "SELECT original_reply_grant_deadline($1,$2),floor(extract(epoch FROM clock_timestamp())*1000)::bigint";
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
        &[&f.case.f.account, &issued.grant_id];
    let started = std::time::Instant::now();
    let before = tx
        .query_one(query, params)
        .await
        .map_err(|_| ())
        .expect("deadline unavailable");
    let before_ms = started.elapsed().as_millis();
    let before_deadline: Option<i64> = before.get(0);
    let before_now: i64 = before.get(1);
    assert!(
        before_deadline.is_some_and(|deadline| deadline > before_now),
        "positive precursor live=false"
    );
    tx.batch_execute(
        "ALTER FUNCTION original_reply_grant_deadline(uuid,uuid) SET join_collapse_limit=1",
    )
    .await
    .map_err(|_| ())
    .expect("function setting unavailable");
    let changed = tx
        .query_one(settings_query, &[])
        .await
        .map_err(|_| ())
        .expect("settings unavailable");
    let changed_config: Option<Vec<String>> = changed.get(0);
    let unchanged_connection: String = changed.get(1);
    let installed = changed_config
        .as_ref()
        .is_some_and(|entries| entries.iter().any(|entry| entry == "join_collapse_limit=1"));
    let started = std::time::Instant::now();
    let after = tx
        .query_one(query, params)
        .await
        .map_err(|_| ())
        .expect("deadline unavailable");
    let after_ms = started.elapsed().as_millis();
    let after_deadline: Option<i64> = after.get(0);
    let after_now: i64 = after.get(1);
    let equal = before_deadline == after_deadline;
    let live = after_deadline.is_some_and(|deadline| deadline > after_now);
    // The ALTER is transactional; restore it before asserting the sampled result.
    tx.rollback()
        .await
        .map_err(|_| ())
        .expect("rollback unavailable");
    let restored = client
        .query_one(settings_query, &[])
        .await
        .map_err(|_| ())
        .expect("settings unavailable");
    let restored_config: Option<Vec<String>> = restored.get(0);
    let restored_connection: String = restored.get(1);
    eprintln!(
        "join_order before_elapsed_ms={before_ms} after_elapsed_ms={after_ms} equal={equal} live={live}"
    );
    assert!(installed, "function-local setting missing");
    assert!(equal && live, "positive deadline equality/live failed");
    assert!(
        initial_config == restored_config,
        "function settings not restored"
    );
    assert!(
        connection_setting == unchanged_connection && connection_setting == restored_connection,
        "connection setting changed"
    );
    drop(client);
    f.case.f.cleanup().await;
}
