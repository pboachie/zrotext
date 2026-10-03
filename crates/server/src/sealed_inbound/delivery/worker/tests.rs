// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::endpoint;
use super::*;
use crate::http_owner_conversations::activation::tests::{activate, capture, pending};

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn recovery_skips_finisher_delivery_lock_without_taking_its_attempt_lock() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    let lease = claim(&mut f.connect().await).await.unwrap().unwrap();
    f.db.execute("UPDATE sealed_event_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&lease.id]).await.unwrap();
    let mut finisher = f.connect().await;
    let tx = finisher.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM sealed_event_deliveries WHERE id=$1 FOR UPDATE",
        &[&lease.id],
    )
    .await
    .unwrap();
    let other = tokio::time::timeout(Duration::from_secs(1), claim(&mut f.connect().await))
        .await
        .expect("recovery must skip locked delivery, not acquire its attempt and deadlock")
        .unwrap();
    assert!(other.is_none());
    finish(&tx, &lease, "ack", Some(204)).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        f.db.query_one("SELECT outcome FROM sealed_event_delivery_attempts", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "ack"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_lease_recovery_retains_exact_identity_and_waits_the_attempt_schedule() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    let lease = claim(&mut f.connect().await).await.unwrap().unwrap();
    f.db.execute("UPDATE sealed_event_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&lease.id]).await.unwrap();
    assert!(claim(&mut f.connect().await).await.unwrap().is_none());
    let row=f.db.query_one("SELECT id,event_id,status,attempt_count,floor(extract(epoch FROM next_attempt_at-clock_timestamp()))::bigint,lease_id IS NULL AND lease_until IS NULL FROM sealed_event_deliveries",&[]).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), lease.id);
    assert_eq!(row.get::<_, Uuid>(1), lease.event);
    assert_eq!(row.get::<_, String>(2), "pending");
    assert_eq!(row.get::<_, i16>(3), 1);
    assert!((58..=60).contains(&row.get::<_, i64>(4)));
    assert!(row.get::<_, bool>(5));
    let malformed =
        f.db.execute(
            "UPDATE sealed_event_deliveries SET lease_id=$1 WHERE id=$2",
            &[&Uuid::new_v4(), &lease.id],
        )
        .await
        .unwrap_err();
    assert_eq!(
        malformed.as_db_error().unwrap().code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn lease_expiring_during_actual_authority_lock_wait_never_connects_or_renews() {
    let (f, _, scope) = pending().await;
    activate(&f, &scope).await;
    endpoint(&f, true).await;
    capture(&f, &scope, Uuid::new_v4(), 1, b"+12")
        .await
        .unwrap();
    let lease = claim(&mut f.connect().await).await.unwrap().unwrap();
    let delivery = lease.id;
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    let blocker_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    tx.query_one(
        "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut waiting = f.connect().await;
    let waiting_pid: i32 = waiting
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let guard = super::super::tests::vault();
    let waiter = tokio::spawn(async move {
        attempt(&mut waiting, &guard, &lease, |_| async {
            panic!("expired lease must fail before connection")
        })
        .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if f.db
            .query_one(
                "SELECT $1=ANY(pg_blocking_pids($2))",
                &[&blocker_pid, &waiting_pid],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.db.execute("UPDATE sealed_event_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&delivery]).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(matches!(
        waiter.await.unwrap(),
        Err(DeliveryError::Forbidden)
    ));
    assert!(claim(&mut f.connect().await).await.unwrap().is_none());
    let result=f.db.query_one("SELECT d.status,d.attempt_count,a.outcome FROM sealed_event_deliveries d JOIN sealed_event_delivery_attempts a ON a.delivery_id=d.id WHERE d.id=$1",&[&delivery]).await.unwrap();
    assert_eq!(result.get::<_, String>(0), "pending");
    assert_eq!(result.get::<_, i16>(1), 1);
    assert_eq!(result.get::<_, String>(2), "timeout");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn retirement_waits_for_delivery_before_attempt_and_expired_recovery_skips_it_without_deadlock()
 {
    let (f, _, scope) = pending().await;
    activate(&f, &scope).await;
    let endpoint_id = endpoint(&f, true).await;
    capture(&f, &scope, Uuid::new_v4(), 1, b"+12")
        .await
        .unwrap();
    let lease = claim(&mut f.connect().await).await.unwrap().unwrap();
    f.db.execute("UPDATE sealed_event_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&lease.id]).await.unwrap();
    let mut holder = f.connect().await;
    let tx = holder.transaction().await.unwrap();
    let holder_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    tx.query_one(
        "SELECT id FROM sealed_event_deliveries WHERE id=$1 FOR UPDATE",
        &[&lease.id],
    )
    .await
    .unwrap();
    let closer = f.connect().await;
    let closer_pid: i32 = closer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let close = tokio::spawn(async move {
        closer
            .execute(
                "UPDATE webhook_endpoints SET enabled=false WHERE id=$1",
                &[&endpoint_id],
            )
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if f.db
            .query_one(
                "SELECT $1=ANY(pg_blocking_pids($2))",
                &[&holder_pid, &closer_pid],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut probe = f.connect().await;
    let probe_tx = probe.transaction().await.unwrap();
    probe_tx.query_one("SELECT delivery_id FROM sealed_event_delivery_attempts WHERE delivery_id=$1 FOR UPDATE NOWAIT",&[&lease.id]).await.expect("retirement must wait on parent before acquiring child attempt locks");
    probe_tx.rollback().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), claim(&mut f.connect().await))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    tx.rollback().await.unwrap();
    assert_eq!(close.await.unwrap().unwrap(), 1);
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_delivery_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}
