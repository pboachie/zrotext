// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn ready(db: &mut TestDb, account: Uuid, device: Uuid) -> SessionRecord {
    db.client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    DeliveryStore::new(&mut db.client)
        .connect_session(account, device, "test", "test", 300)
        .await
        .unwrap()
}

async fn state(db: &TestDb, id: Uuid) -> String {
    db.client
        .query_one("SELECT state FROM messages WHERE id=$1", &[&id])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn cancellation_refunds_once_skips_granted_and_keeps_other_tenants() {
    let mut db = TestDb::new().await;
    let (account, _, device) = db.tenant().await;
    let (other_account, _, other_device) = db.tenant().await;
    let granted = Uuid::new_v4();
    let queued = Uuid::new_v4();
    let other = Uuid::new_v4();
    let session = ready(&mut db, account, device).await;
    let mut store = DeliveryStore::new(&mut db.client);
    store
        .accept(message(account, device, granted, "granted"))
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("worker", account, device)
        .await
        .unwrap()
        .unwrap();
    store
        .issue_grant(&claim, &session, Uuid::new_v4())
        .await
        .unwrap();
    store
        .accept(message(account, device, queued, "queued"))
        .await
        .unwrap();
    store
        .accept(message(other_account, other_device, other, "other"))
        .await
        .unwrap();
    // A synthetic reservation isolates the refund contract from billing setup.
    db.client.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units) VALUES($1,'outbound_message','2026-09-01','2026-10-01',10,1)", &[&account]).await.unwrap();
    db.client.execute("INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) VALUES($1,$2,'outbound_message','2026-09-01','reserve',1)", &[&account,&queued]).await.unwrap();
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        cancel_pending_recipient(&tx, account, RECIPIENT)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        cancel_pending_recipient(&tx, account, RECIPIENT)
            .await
            .unwrap(),
        0
    );
    tx.commit().await.unwrap();
    assert_eq!(state(&db, queued).await, "cancelled");
    assert_eq!(state(&db, granted).await, "claimed");
    assert_eq!(state(&db, other).await, "queued");
    let row = db
        .client
        .query_one(
            "SELECT refunded_units FROM usage_periods WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert!(
        DeliveryStore::new(&mut db.client)
            .claim_due_for_device("worker", account, device)
            .await
            .unwrap()
            .is_none()
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn grant_waits_for_hold_and_cancels_previously_claimed_message() {
    let mut db = TestDb::new().await;
    let (account, owner, device) = db.tenant().await;
    let session = ready(&mut db, account, device).await;
    let id = Uuid::new_v4();
    let mut store = DeliveryStore::new(&mut db.client);
    store
        .accept(message(account, device, id, "race"))
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("worker", account, device)
        .await
        .unwrap()
        .unwrap();
    let writer = connect(&db.scoped_url).await;
    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .query_one(HOLD_UNDER_ACCOUNT_LOCK, &[&account])
        .await
        .unwrap();
    writer
        .execute(
            INSERT_HOLD,
            &[&Uuid::new_v4(), &account, &RECIPIENT, &owner],
        )
        .await
        .unwrap();
    let url = db.scoped_url.clone();
    let grant = tokio::spawn(async move {
        let mut client = connect(&url).await;
        DeliveryStore::new(&mut client)
            .issue_grant(&claim, &session, Uuid::new_v4())
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!grant.is_finished());
    writer.batch_execute("COMMIT").await.unwrap();
    assert!(matches!(
        grant.await.unwrap(),
        Err(StoreError::RecipientSuppressed)
    ));
    assert_eq!(state(&db, id).await, "cancelled");
    let attempts: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM message_attempts WHERE message_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(attempts, 0);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn cancelled_claim_cannot_obtain_grant_and_rollback_restores_queue() {
    let mut db = TestDb::new().await;
    let (account, _, device) = db.tenant().await;
    let session = ready(&mut db, account, device).await;
    let id = Uuid::new_v4();
    let mut store = DeliveryStore::new(&mut db.client);
    store
        .accept(message(account, device, id, "cancel-claim"))
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("worker", account, device)
        .await
        .unwrap()
        .unwrap();
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        cancel_pending_recipient(&tx, account, RECIPIENT)
            .await
            .unwrap(),
        1
    );
    tx.rollback().await.unwrap();
    assert_eq!(state(&db, id).await, "claimed");
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        cancel_pending_recipient(&tx, account, RECIPIENT)
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        DeliveryStore::new(&mut db.client)
            .issue_grant(&claim, &session, Uuid::new_v4())
            .await,
        Err(StoreError::StaleFence)
    ));
    db.close().await;
}
