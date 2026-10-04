// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::billing::{self, IngestResult};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use tokio_postgres::{Client, NoTls};
mod hosted;
mod lifecycle;
mod races;
mod recovery;
mod security;
mod status;

struct Case {
    db: Client,
    setup: Client,
    schema: String,
    account: Uuid,
    device: Uuid,
    start: i64,
    end: i64,
    generation: i64,
    owner: crate::auth::SessionPrincipal,
}

impl Case {
    async fn new() -> Self {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("invoice_policy_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        crate::auth::test_schema::apply(&db).await;
        let hasher = crate::auth::TokenHasher::new(crate::test_keys::key(77)).unwrap();
        let password = crate::test_keys::password(77);
        let signup =
            crate::auth::register(&mut db, &hasher, "invoice-owner@example.test", &password)
                .await
                .unwrap();
        crate::auth::verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let session = crate::auth::login(&db, &hasher, "invoice-owner@example.test", &password)
            .await
            .unwrap();
        let owner = crate::auth::authenticate_session(&db, &hasher, &session.token)
            .await
            .unwrap();
        let account = signup.account_id;
        let device = Uuid::new_v4();
        billing::bind_customer(&mut db, account, "cus_invoice1")
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'invoice fixture')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source,invoice_bound_test) VALUES($1,'outbound_message',0,'stripe_test',true)", &[&account]).await.unwrap();
        let now: i64 = db
            .query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
            .await
            .unwrap()
            .get(0);
        Self {
            db,
            setup,
            schema,
            account,
            device,
            start: now - 60,
            end: now + 3600,
            generation: 0,
            owner,
        }
    }

    fn observation(&self, status: &str, invoice_status: &str, reason: &str) -> CurrentInvoice {
        self.observation_for_price(
            status,
            invoice_status,
            reason,
            "price_invoice1",
            "in_invoice1",
        )
    }

    fn observation_for_price(
        &self,
        status: &str,
        invoice_status: &str,
        reason: &str,
        price: &str,
        invoice_id: &str,
    ) -> CurrentInvoice {
        let subscription = json!({"id":"sub_invoice1","object":"subscription","livemode":false,
            "customer":"cus_invoice1","status":status,"latest_invoice":invoice_id,
            "cancel_at":null,"cancel_at_period_end":false,
            "items":{"object":"list","has_more":false,"data":[{"id":"si_invoice1","quantity":1,
                "price":{"id":price},"current_period_start":self.start,"current_period_end":self.end}]}});
        let invoice = json!({"id":invoice_id,"object":"invoice","livemode":false,
            "customer":"cus_invoice1","status":invoice_status,"billing_reason":reason,
            "parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_invoice1"}},
            "lines":{"object":"list","has_more":false,"data":[{"id":"il_invoice1",
                "parent":{"type":"subscription_item_details","subscription_item_details":{"subscription_item":"si_invoice1","proration":false}},
                "period":{"start":self.start,"end":self.end},"pricing":{"price_details":{"price":price}}}]}});
        CurrentInvoice {
            observation: model::parse(
                &serde_json::to_vec(&subscription).unwrap(),
                &serde_json::to_vec(&invoice).unwrap(),
            )
            .unwrap(),
        }
    }

    async fn observe(&mut self, proof: &CurrentInvoice) -> Result<(), BillingError> {
        self.generation += 1;
        let event = json!({"id":format!("evt_invoice{}",self.generation),"object":"event","livemode":false,
            "type":"customer.subscription.updated","data":{"object":{"id":"sub_invoice1","customer":"cus_invoice1"}}});
        let body = serde_json::to_vec(&event).unwrap();
        let secret = format!("whsec_{}", Uuid::new_v4().simple());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(&body);
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let verified = billing::verify_event(
            &body,
            &format!("t=1750000000,v1={signature}"),
            &secret,
            1_750_000_000,
        )
        .unwrap();
        assert_eq!(
            billing::ingest(&mut self.db, &verified).await.unwrap(),
            IngestResult::Queued
        );
        billing::reconcile_with_invoice(
            &mut self.db,
            self.account,
            proof.subscription(),
            &["price_invoice1".into()],
            &[TestQuotaPlan {
                price_id: "price_invoice1".into(),
                outbound_limit: 2,
                device_limit: None,
            }],
            self.generation,
            Some(proof),
        )
        .await
    }

    async fn cleanup(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }

    async fn connect(&self) -> Client {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let (db, connection) = tokio_postgres::connect(
            &format!("{base}{separator}options=-csearch_path%3D{}", self.schema),
            NoTls,
        )
        .await
        .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db
    }

    async fn send(
        &mut self,
        key: &str,
    ) -> Result<zrotext_delivery_store::AcceptOutcome, zrotext_delivery_store::StoreError> {
        zrotext_delivery_store::DeliveryStore::new(&mut self.db)
            .accept_metered(zrotext_delivery_store::NewMessage {
                account_id: self.account,
                device_id: self.device,
                client_message_id: Uuid::new_v4(),
                idempotency_key: key,
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic invoice fixture",
                expires_at_ms: self.end * 1000,
            })
            .await
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn current_invoice_allowance_is_enforced_atomically_and_paid_recovery_never_replenishes_it() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    assert!(case.send("first").await.unwrap().created);
    assert!(case.send("second").await.unwrap().created);
    assert!(matches!(
        case.send("full").await,
        Err(zrotext_delivery_store::StoreError::QuotaExceeded)
    ));
    case.observe(&paid).await.unwrap();
    assert!(matches!(
        case.send("recovery").await,
        Err(zrotext_delivery_store::StoreError::QuotaExceeded)
    ));
    let row = case
        .db
        .query_one(
            "SELECT reserved_units,open_units FROM billing_invoice_periods",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
    assert_eq!(row.get::<_, i64>(1), 2);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn partial_invoice_guard_installation_cannot_bypass_the_existing_monthly_limit() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    // Fault injection is confined to this test's unique disposable schema.
    case.db
        .batch_execute("ALTER TABLE usage_ledger DISABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    assert!(matches!(
        case.send("partial").await,
        Err(zrotext_delivery_store::StoreError::QuotaNotConfigured)
    ));
    case.db
        .batch_execute("ALTER TABLE usage_ledger ENABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    assert!(case.send("restored").await.unwrap().created);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn duplicate_current_paid_observations_preserve_original_period_and_consumption() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.db
        .execute(
            "UPDATE billing_invoice_periods SET reserved_units=1,open_units=1 WHERE account_id=$1",
            &[&case.account],
        )
        .await
        .unwrap();
    case.observe(&paid).await.unwrap();
    let row = case.db.query_one("SELECT count(*),sum(reserved_units)::bigint,sum(open_units)::bigint FROM billing_invoice_periods WHERE account_id=$1", &[&case.account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn paid_proration_cannot_create_a_fresh_period_and_missing_proof_rolls_back() {
    let mut case = Case::new().await;
    let update = case.observation("active", "paid", "subscription_update");
    case.observe(&update).await.unwrap();
    let row = case
        .db
        .query_one(
            "SELECT phase,effective_limit FROM billing_invoice_entitlements WHERE account_id=$1",
            &[&case.account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "review");
    assert_eq!(row.get::<_, i64>(1), 0);
    let count: i64 = case
        .db
        .query_one("SELECT count(*) FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    case.generation += 1;
    case.db.execute("UPDATE billing_reconciliations SET dirty_generation=$1,state='queued' WHERE stripe_subscription_id='sub_invoice1'", &[&case.generation]).await.unwrap();
    let result = billing::reconcile_snapshot_with_quotas(
        &mut case.db,
        case.account,
        update.subscription(),
        &["price_invoice1".into()],
        &[TestQuotaPlan {
            price_id: "price_invoice1".into(),
            outbound_limit: 2,
            device_limit: None,
        }],
        case.generation,
    )
    .await;
    assert!(matches!(result, Err(BillingError::InvalidEvent)));
    let processed: i64 = case.db.query_one("SELECT processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_invoice1'", &[]).await.unwrap().get(0);
    assert_eq!(processed, case.generation - 1);
    case.cleanup().await;
}
