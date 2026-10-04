// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; exact committed snapshot replay"]
async fn snapshot_replay_preserves_original_evidence_after_local_finalization_and_acknowledgement()
{
    let mut f = invoice_fixture().await;
    let period = anchored_state(&f, false).await;
    let row = f.db.query_one("SELECT message_id,success_event_id,success_attempt_id FROM billing_usage_finalized WHERE account_id=$1", &[&f.account]).await.unwrap();
    let message: Uuid = row.get(0);
    let event: Uuid = row.get(1);
    let attempt: Uuid = row.get(2);
    f.db.execute(
        "DELETE FROM billing_usage_finalized WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE billing_invoice_periods SET open_units=1 WHERE account_id=$1 AND id=$2",
        &[&f.account, &period],
    )
    .await
    .unwrap();
    let snapshot = Uuid::new_v4();
    let (worker, server) = tls(responses(1)).await;
    assert_eq!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
            .await
            .unwrap(),
        "diverged"
    );
    assert_eq!(server.await.unwrap().len(), 6);
    f.db.execute("INSERT INTO billing_usage_finalized(account_id,message_id,success_event_id,success_attempt_id) VALUES($1,$2,$3,$4)", &[&f.account,&message,&event,&attempt]).await.unwrap();
    f.db.execute("INSERT INTO billing_usage_outbox(account_id,message_id,identifier,state,acknowledged_at) VALUES($1,$2,$3,'acknowledged',clock_timestamp())", &[&f.account,&message,&format!("zt-usage-v1-{}{}",message.simple(),message.simple())]).await.unwrap();
    f.db.execute(
        "UPDATE billing_invoice_usage SET terminal=true WHERE account_id=$1 AND message_id=$2",
        &[&f.account, &message],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE billing_invoice_periods SET open_units=0 WHERE account_id=$1 AND id=$2",
        &[&f.account, &period],
    )
    .await
    .unwrap();
    let before = authority_snapshot(&f.db, f.account).await;
    let (worker, server) = tls(responses(1)).await;
    assert_eq!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
            .await
            .unwrap(),
        "diverged"
    );
    assert_eq!(server.await.unwrap().len(), 6);
    let saved = f.db.query_one("SELECT finalized_units,acknowledged_units,pending_units,open_units,(SELECT count(*) FROM billing_invoice_usage_observations) FROM billing_invoice_usage_observations", &[]).await.unwrap();
    assert_eq!(
        (
            saved.get::<_, i64>(0),
            saved.get::<_, i64>(1),
            saved.get::<_, i64>(2),
            saved.get::<_, i64>(3),
            saved.get::<_, i64>(4)
        ),
        (0, 0, 1, 1, 1)
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    // A new snapshot observes the transition; replay never replaces old evidence.
    let (worker, server) = tls(responses(1)).await;
    assert_eq!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, Uuid::new_v4())
            .await
            .unwrap(),
        "observed_equal"
    );
    assert_eq!(server.await.unwrap().len(), 6);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; proven reservation refund is not unknown"]
async fn refunded_reservation_without_finalized_charge_is_not_pending_liability() {
    let mut f = invoice_fixture().await;
    let period = anchored_state(&f, false).await;
    f.db.execute(
        "DELETE FROM billing_usage_finalized WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE billing_invoice_periods SET open_units=1 WHERE account_id=$1 AND id=$2",
        &[&f.account, &period],
    )
    .await
    .unwrap();
    f.db.execute("INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) SELECT account_id,message_id,metric,period_start,'refund',-units FROM usage_ledger WHERE account_id=$1 AND entry_kind='reserve'", &[&f.account]).await.unwrap();
    let before = authority_snapshot(&f.db, f.account).await;
    let (worker, server) = tls(responses(0)).await;
    assert_eq!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, Uuid::new_v4())
            .await
            .unwrap(),
        "observed_equal"
    );
    assert_eq!(server.await.unwrap().len(), 6);
    let saved = f.db.query_one("SELECT finalized_units,pending_units,open_units FROM billing_invoice_usage_observations", &[]).await.unwrap();
    assert_eq!(
        (
            saved.get::<_, i64>(0),
            saved.get::<_, i64>(1),
            saved.get::<_, i64>(2)
        ),
        (0, 0, 0)
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original meter mapping cannot be guessed"]
async fn unattributed_period_refuses_active_policy_before_provider_request() {
    let mut f = invoice_fixture().await;
    let period = anchored(&f).await;
    f.db.execute(
        "DELETE FROM billing_invoice_usage WHERE account_id=$1 AND period_id=$2",
        &[&f.account, &period],
    )
    .await
    .unwrap();
    let (worker, server) = tls(vec![]).await;
    assert!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(server.await.unwrap().is_empty());
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM billing_invoice_usage_observations",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}
