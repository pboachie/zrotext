// SPDX-License-Identifier: AGPL-3.0-only
//! Actual runtime tuple schedules, not a claim of a signed provider risk event.
use super::reviewed_send_tests::{active, packet};
use super::*;
use crate::reviewed_intent03::live as reviewed;
use tokio_postgres::{NoTls, error::SqlState};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual customer-first queue/risk tuple schedules"]
async fn customer_tuple_nowait_precedes_account_upgrade_and_is_held_through_real_queue_commit() {
    let (mut c, key, interval) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_reviewed_order')",&[&account]).await.unwrap();
    c.db.owner.execute("INSERT INTO public.billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES('sub_reviewed_order',$1,'cus_reviewed_order',1,1)",&[&account]).await.unwrap();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'stripe_test')",&[&account]).await.unwrap();
    let p = packet(&mut c, &key, &interval).await;
    let (mut other, connection) = c.db.reader_config.connect(NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let risk = other.transaction().await.unwrap();
    risk.query_one(
        "SELECT account_id FROM public.billing_customers WHERE account_id=$1 FOR UPDATE NOWAIT",
        &[&account],
    )
    .await
    .unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    // The actual risk path's account FK KEY SHARE remains compatible with the
    // already authenticated owner's SHARE while the customer is held first.
    risk.query_one(
        "SELECT id FROM public.accounts WHERE id=$1 FOR KEY SHARE NOWAIT",
        &[&account],
    )
    .await
    .unwrap();
    assert!(
        matches!(reviewed::admit(&tx,&mut owner,&p.intent,&p.signature,&p.envelope,ORIGIN).await,
        Err(Error::Database(ref e)) if e.code()==Some(&SqlState::LOCK_NOT_AVAILABLE))
    );
    drop(owner);
    tx.rollback().await.unwrap();
    risk.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        reviewed::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await
        .unwrap()
        .0
    );
    let risk = other.transaction().await.unwrap();
    assert_eq!(
        risk.query_one(
            "SELECT account_id FROM public.billing_customers WHERE account_id=$1 FOR UPDATE NOWAIT",
            &[&account]
        )
        .await
        .unwrap_err()
        .code(),
        Some(&SqlState::LOCK_NOT_AVAILABLE)
    );
    risk.rollback().await.unwrap();
    drop(owner);
    tx.commit().await.unwrap();
    drop(other);
    driver.await.unwrap().unwrap();
    c.db.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual concurrent fresh billing binding"]
async fn uncommitted_customer_binding_refuses_exclusive_queue_mode_without_account_customer_deadlock()
 {
    let (mut c, key, interval) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = packet(&mut c, &key, &interval).await;
    let (mut other, connection) = c.db.reader_config.connect(NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let binder = other.transaction().await.unwrap();
    binder.execute("INSERT INTO public.billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_reviewed_new_binding')",&[&account]).await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        reviewed::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await,
        Err(Error::Conflict)
    ));
    drop(owner);
    tx.rollback().await.unwrap();
    binder.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT (SELECT count(*) FROM public.messages WHERE account_id=$1),(SELECT count(*) FROM public.conversation_reviewed_sends03 WHERE account_id=$1)",&[&account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    drop(other);
    driver.await.unwrap().unwrap();
    c.db.finish().await;
}
