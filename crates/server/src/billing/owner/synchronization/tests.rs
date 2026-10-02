// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::decisions::tests::Case;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable billing schema"]
async fn forwarding_counts_follow_real_finalized_delivery_without_cross_tenant_rows() {
    use zrotext_delivery_store::{DeliveryStore, NewMessage, RadioEvent};
    use zrotext_domain::Evidence;
    let case = Case::new().await;
    let account = case.base.f.account;
    let device = case.base.f.device;
    let mut db = case.base.f.connect().await;
    let customer = format!("cus_Synthetic{}", account.simple());
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
        &[&account, &customer],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',100,'stripe_test') ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=100", &[&account]).await.unwrap();
    db.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,$2,'mtr_Synthetic','synthetic_execution',true)", &[&account,&customer]).await.unwrap();
    db.batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
        .await
        .unwrap();
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let message = Uuid::new_v4();
    let key = message.to_string();
    let mut store = DeliveryStore::new(&mut db);
    store
        .accept_metered(NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: message,
            idempotency_key: &key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic only",
            expires_at_ms: now + 60000,
        })
        .await
        .unwrap();
    let session = store
        .connect_session(account, device, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account, device)
        .await
        .unwrap()
        .unwrap();
    let attempt = Uuid::new_v4();
    store.issue_grant(&claim, &session, attempt).await.unwrap();
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: account,
        device_id: device,
        message_id: message,
        attempt_id: attempt,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: now,
        segment_index: None,
        segment_count: None,
    };
    store.record_radio_event(intent).await.unwrap();
    store
        .record_radio_event(RadioEvent {
            event_id: Uuid::new_v4(),
            evidence: Evidence::SentCallbackOk,
            segment_index: Some(0),
            segment_count: Some(1),
            ..intent
        })
        .await
        .unwrap();
    let view = current(&db, account).await.unwrap().unwrap();
    assert!(view.configured);
    assert_eq!(
        (view.pending, view.acknowledged, view.review, view.uncertain),
        (1, 0, 0, 0)
    );
    db.execute(
        "UPDATE billing_usage_outbox SET error_class='unknown' WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    assert_eq!(current(&db, account).await.unwrap().unwrap().uncertain, 1);
    db.execute(
        "UPDATE billing_usage_outbox SET state='review',error_class='response' WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    let view = current(&db, account).await.unwrap().unwrap();
    assert_eq!((view.pending, view.review, view.uncertain), (0, 1, 0));
    let foreign = current(&db, Uuid::new_v4()).await.unwrap().unwrap();
    assert!(!foreign.configured);
    assert_eq!(
        (foreign.pending, foreign.review, foreign.acknowledged),
        (0, 0, 0)
    );
    drop(db);
    case.base.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable billing schema"]
async fn tenant_caps_include_old_outstanding_and_same_period_versions_only() {
    let case = Case::new().await;
    let db = &case.base.f.db;
    let account = case.base.f.account;
    let foreign = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign])
        .await
        .unwrap();
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for (tenant, version, enabled, start, end, outstanding, finalized) in [
        (
            account,
            1_i64,
            false,
            now - 20000,
            now - 10000,
            3_i64,
            90_i64,
        ),
        (account, 2, false, now - 1000, now + 60000, 2, 4),
        (account, 3, true, now - 1000, now + 60000, 1, 5),
        (foreign, 1, true, now - 1000, now + 60000, 999, 999),
    ] {
        db.execute("INSERT INTO exposure_scope_budgets(account_id,scope_kind,scope_id,version,enabled,period_start_ms,period_end_ms,soft_units,hard_units,outstanding_units,finalized_units) VALUES($1,'tenant',$1,$2,$3,$4,$5,10,20,$6,$7)", &[&tenant,&version,&enabled,&start,&end,&outstanding,&finalized]).await.unwrap();
    }
    let cap = exposure(db, account).await.unwrap().unwrap();
    assert_eq!((cap.outstanding_units, cap.finalized_units), (6, 9));
    assert_eq!((cap.soft_units, cap.hard_units), (10, 20));
    db.execute(
        "UPDATE exposure_scope_budgets SET enabled=false WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    assert!(exposure(db, account).await.unwrap().is_none());
    assert!(
        current(db, account)
            .await
            .unwrap()
            .is_some_and(|view| !view.configured && view.pending == 0 && view.acknowledged == 0)
    );
    case.base.f.cleanup().await;
}
