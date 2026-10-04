// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::provider_sms::receipts::{self, test_support as provider_fixture};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn partial_receipt_proposal_refuses_owner_erasure_without_deleting_data() {
    let (admin, mut db, url, schema) = migrated_schema("provider_partial").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(81)).unwrap());
    let (a, session, _, _, app) = fixture(&mut db, &hasher, &url, None).await;
    db.batch_execute(provider_fixture::PROPOSAL).await.unwrap();
    provider_fixture::seed(&db, a.account_id, Uuid::new_v4()).await;
    db.batch_execute("ALTER TABLE provider_receipt_events RENAME TO receipt_partial_events")
        .await
        .unwrap();
    let response = app
        .oneshot(erasure_post(
            Some(&session.token),
            Some(&session.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM provider_receipt_attempts WHERE account_id=$1",
    ] {
        assert_eq!(
            db.query_one(sql, &[&a.account_id])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn actual_owner_erasure_account_fence_blocks_late_receipt_and_prevents_recreation() {
    let (admin, mut db, url, schema) = migrated_schema("provider_race").await;
    let erase_url = handler_url(&url, "zt_provider_erasure");
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(82)).unwrap());
    let (a, session, _, _, app) = fixture(&mut db, &hasher, &erase_url, None).await;
    db.batch_execute(provider_fixture::PROPOSAL).await.unwrap();
    let attempt = Uuid::new_v4();
    provider_fixture::seed(&db, a.account_id, attempt).await;
    let (mut blocker, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let block = blocker.transaction().await.unwrap();
    block
        .query_one(
            "SELECT attempt_id FROM provider_receipt_attempts WHERE account_id=$1 FOR UPDATE",
            &[&a.account_id],
        )
        .await
        .unwrap();
    let request = erasure_post(
        Some(&session.token),
        Some(&session.csrf_token),
        Some(ORIGIN),
        &crate::test_keys::password(1),
        None,
    );
    let erase = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    wait_until_handler_is_blocked_by(&admin, "zt_provider_erasure", blocker_pid).await;
    let eraser_pid:i32=admin.query_one("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND $2=ANY(pg_blocking_pids(pid))",
        &[&"zt_provider_erasure",&blocker_pid]).await.unwrap().get(0);
    let receipt_url = handler_url(&url, "zt_provider_receipt");
    let (mut recorder, connection) = tokio_postgres::connect(&receipt_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let account = a.account_id;
    let event =
        provider_fixture::receipt(&provider_fixture::request(account), Uuid::new_v4(), "sent");
    let record = tokio::spawn(async move {
        receipts::record_known_receipt(
            &mut recorder,
            &receipts::ElectedWriterPermit::synthetic(account, provider_fixture::SITE, 1),
            &event,
        )
        .await
    });
    wait_until_handler_is_blocked_by(&admin, "zt_provider_receipt", eraser_pid).await;
    block.commit().await.unwrap();
    let response = erase.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    assert_eq!(deleted_count(&report, "provider_receipt_attempts"), 1);
    assert_eq!(record.await.unwrap(), Err(receipts::Error::Uncorrelated));
    let retry = provider_fixture::receipt(
        &provider_fixture::request(account),
        Uuid::new_v4(),
        "delivered",
    );
    assert_eq!(
        receipts::record_known_receipt(
            &mut db,
            &receipts::ElectedWriterPermit::synthetic(account, provider_fixture::SITE, 1),
            &retry
        )
        .await,
        Err(receipts::Error::Uncorrelated)
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM provider_receipt_attempts WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
