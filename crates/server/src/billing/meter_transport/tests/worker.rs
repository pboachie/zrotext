// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::billable::WorkResult;
use zrotext_delivery_store::{DeliveryStore, NewMessage, RadioEvent};
use zrotext_domain::Evidence;
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
struct Db {
    client: Client,
    schema: String,
    account: Uuid,
    device: Uuid,
    customer: String,
}
impl Db {
    async fn new() -> Self {
        let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL").unwrap();
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let schema = format!("billable_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        crate::auth::test_schema::apply(&client).await;
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let customer = format!("cus_Synthetic{}", account.simple());
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
                &[&device, &account],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
                &[&account, &customer],
            )
            .await
            .unwrap();
        let subscription = format!("sub_Synthetic{}", account.simple());
        client.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,$2,$3,1)",&[&account,&customer,&subscription]).await.unwrap();
        client.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',100,'stripe_test')",&[&account]).await.unwrap();
        client.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,$2,'mtr_Synthetic','synthetic_execution',true)",&[&account,&customer]).await.unwrap();
        client
            .batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
            .await
            .unwrap();
        Self {
            client,
            schema,
            account,
            device,
            customer,
        }
    }
    async fn submit(&mut self, segments: i32) -> (Uuid, RadioEvent) {
        self.submit_at(segments).await
    }
    async fn submit_at(&mut self, segments: i32) -> (Uuid, RadioEvent) {
        let account = self.account;
        let device = self.device;
        let id = Uuid::new_v4();
        let key = id.to_string();
        let mut store = DeliveryStore::new(&mut self.client);
        let input = NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: id,
            idempotency_key: &key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic only",
            expires_at_ms: now_ms() + 60_000,
        };
        store.accept_metered(input).await.unwrap();
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
        let event = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: account,
            device_id: device,
            message_id: id,
            attempt_id: attempt,
            evidence: Evidence::DurableSubmitIntent,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        store.record_radio_event(event).await.unwrap();
        let mut last_callback = event;
        for index in 0..segments {
            last_callback = RadioEvent {
                event_id: Uuid::new_v4(),
                evidence: Evidence::SentCallbackOk,
                segment_index: Some(index),
                segment_count: Some(segments),
                ..event
            };
            store.record_radio_event(last_callback).await.unwrap();
        }
        (id, last_callback)
    }
    async fn close(self) {
        self.client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {} CASCADE",
                self.schema
            ))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated finalized usage and synthetic HTTPS"]
async fn finalized_outbox_https_ack_and_unknown_retry_preserve_one_original_charge() {
    let mut db = Db::new().await;
    let (id, event) = db.submit(2).await;
    let row=db.client.query_one("SELECT o.identifier,floor(extract(epoch FROM b.report_at))::bigint FROM billing_usage_outbox o JOIN billing_usage_bindings b USING(account_id,message_id) WHERE o.message_id=$1",&[&id]).await.unwrap();
    let identifier: String = row.get(0);
    let timestamp: i64 = row.get(1);
    let response = serde_json::json!({"object":"billing.meter_event","identifier":identifier,"event_name":"synthetic_execution","timestamp":timestamp,"livemode":false,"payload":{"stripe_customer_id":db.customer,"value":"1"}});
    let worker = TestUsageWorker::test_candidate();
    let (t, h) = fixture(vec![], "200 OK", "", Duration::ZERO);
    assert_eq!(
        worker.run_one(&mut db.client, &t).await.unwrap(),
        WorkResult::Deferred
    );
    let first = h.join().unwrap();
    db.client
        .batch_execute("UPDATE billing_usage_outbox SET next_attempt_at=clock_timestamp()")
        .await
        .unwrap();
    let (t, h) = fixture(
        serde_json::to_vec(&response).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    assert_eq!(
        worker.run_one(&mut db.client, &t).await.unwrap(),
        WorkResult::Acknowledged
    );
    let second = h.join().unwrap();
    let body = |wire: Vec<u8>| {
        let s = String::from_utf8(wire).unwrap();
        s.split("\r\n\r\n").nth(1).unwrap().to_string()
    };
    assert_eq!(body(first), body(second));
    let row=db.client.query_one("SELECT (SELECT count(*) FROM billing_usage_finalized),state,attempts,acknowledged_at IS NOT NULL FROM billing_usage_outbox",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "acknowledged");
    assert_eq!(row.get::<_, i32>(2), 2);
    assert!(row.get::<_, bool>(3));
    let mut store = DeliveryStore::new(&mut db.client);
    store.record_radio_event(event).await.unwrap();
    assert_eq!(
        worker.run_one(&mut db.client, &t).await.unwrap(),
        WorkResult::Idle
    );
    db.close().await;
}
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated finalized usage and synthetic HTTPS"]
async fn foreign_customer_https_ack_parks_review_without_validated_or_duplicate_usage() {
    let mut db = Db::new().await;
    db.submit(1).await;
    let (t, h) = fixture(
        serde_json::to_vec(&ack()).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    assert_eq!(
        TestUsageWorker::test_candidate()
            .run_one(&mut db.client, &t)
            .await
            .unwrap(),
        WorkResult::Review
    );
    h.join().unwrap();
    let row = db
        .client
        .query_one(
            "SELECT state,error_class,acknowledged_at IS NULL FROM billing_usage_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "review");
    assert_eq!(row.get::<_, String>(1), "response");
    assert!(row.get::<_, bool>(2));
    db.close().await;
}
