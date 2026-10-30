// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::billing::{self, IngestResult};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use tokio_postgres::{Client, NoTls};
mod hosted;
mod liability;
mod lifecycle;
mod races;
mod recovery;
mod security;
mod status;

struct Case {
    db: Client,
    setup: Option<Client>,
    schema: String,
    url: String,
    current: Option<crate::test_database::Fixture>,
    db_driver: crate::test_database::Driver,
    peer_drivers: std::sync::Mutex<Vec<crate::test_database::Driver>>,
    account: Uuid,
    customer: String,
    device: Uuid,
    start: i64,
    end: i64,
    generation: i64,
    owner: crate::auth::SessionPrincipal,
}

enum FixtureSchema {
    Maintained,
    PreRuntimeInvoiceContract,
}

impl Case {
    async fn new() -> Self {
        Self::build(FixtureSchema::Maintained).await
    }

    async fn pre_runtime_invoice_contract() -> Self {
        Self::build(FixtureSchema::PreRuntimeInvoiceContract).await
    }

    async fn build(schema_kind: FixtureSchema) -> Self {
        let (mut db, db_driver, setup, current, schema, url) = match schema_kind {
            FixtureSchema::Maintained => {
                let fixture =
                    crate::test_database::Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
                let (db, driver) = fixture.another_runtime().await;
                let url = fixture.runtime_url.clone();
                (db, driver, None, Some(fixture), "public".to_owned(), url)
            }
            FixtureSchema::PreRuntimeInvoiceContract => {
                let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
                let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
                tokio::spawn(async move { connection.await.unwrap() });
                let schema = format!("invoice_pre_runtime_contract_{}", Uuid::new_v4().simple());
                setup
                    .batch_execute(&format!("CREATE SCHEMA {schema}"))
                    .await
                    .unwrap();
                let separator = if base.contains('?') { '&' } else { '?' };
                let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
                let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
                let driver = tokio::spawn(connection);
                crate::auth::test_schema::apply_pre_runtime_invoice_contract(&db).await;
                (db, driver, Some(setup), None, schema, url)
            }
        };
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
        // Advisory customer locks are database-wide, even with schema-local
        // tables. Parallel fixtures must represent distinct customers.
        let customer = format!("cus_{}", account.simple());
        let device = Uuid::new_v4();
        billing::bind_customer(&mut db, account, &customer)
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
            url,
            current,
            db_driver,
            peer_drivers: std::sync::Mutex::new(Vec::new()),
            account,
            customer,
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
            "customer":&self.customer,"status":status,"latest_invoice":invoice_id,
            "cancel_at":null,"cancel_at_period_end":false,
            "items":{"object":"list","has_more":false,"data":[{"id":"si_invoice1","quantity":1,
                "price":{"id":price},"current_period_start":self.start,"current_period_end":self.end}]}});
        let invoice = json!({"id":invoice_id,"object":"invoice","livemode":false,
            "customer":&self.customer,"status":invoice_status,"billing_reason":reason,
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
            "type":"customer.subscription.updated","data":{"object":{"id":"sub_invoice1","customer":&self.customer}}});
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

    fn migration_owner(&self) -> &Client {
        self.current
            .as_ref()
            .map_or(&self.db, |fixture| &fixture.owner)
    }

    async fn cleanup(self) {
        crate::test_database::Fixture::close_connection(self.db, self.db_driver).await;
        if let Some(fixture) = self.current {
            for driver in self.peer_drivers.into_inner().unwrap() {
                tokio::time::timeout(std::time::Duration::from_secs(5), driver)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            fixture.finish().await;
        } else {
            self.setup
                .unwrap()
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .await
                .unwrap();
        }
    }

    async fn connect(&self) -> Client {
        let (db, connection) = zrotext_postgres_connection::connect(&self.url)
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        if self.current.is_some() {
            self.peer_drivers.lock().unwrap().push(driver);
        }
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
                line_label: None,
                no_fallback: false,
            })
            .await
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public database"]
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
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public database"]
async fn partial_invoice_guard_installation_cannot_bypass_the_existing_monthly_limit() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    // Fault injection is confined to this test's owned disposable database.
    case.migration_owner()
        .batch_execute("ALTER TABLE usage_ledger DISABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    // The complete current installation authenticates its catalog before the
    // invoice guard. A disabled ledger trigger invalidates that exact graph;
    // no caller may reach quota accounting through a damaged native boundary.
    assert!(!case.db.query_one(
        "SELECT graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton",
        &[],
    ).await.unwrap().get::<_, bool>(0));
    assert!(matches!(
        case.send("partial").await,
        Err(zrotext_delivery_store::StoreError::RuntimeIdentityUnavailable)
    ));
    assert_no_admission_writes(&case.db).await;
    case.migration_owner()
        .batch_execute("ALTER TABLE usage_ledger ENABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    zrotext_delivery_store::hosted_runtime_identity::require(&case.db)
        .await
        .unwrap();
    assert!(case.send("restored").await.unwrap().created);
    case.cleanup().await;
}

async fn assert_no_admission_writes(db: &Client) {
    let counts = db.query_one(
        "SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM dispatch_jobs),(SELECT count(*) FROM billing_usage_outbox),(SELECT count(*) FROM usage_ledger),(SELECT count(*) FROM billing_invoice_usage),(SELECT reserved_units FROM billing_invoice_periods),(SELECT open_units FROM billing_invoice_periods)",
        &[],
    ).await.unwrap();
    for index in 0..counts.len() {
        assert_eq!(counts.get::<_, i64>(index), 0);
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; genuine historical105 invoice contract in a disposable schema"]
async fn historical_invoice_guard_damage_refuses_quota_before_any_ledger_write() {
    let mut case = Case::pre_runtime_invoice_contract().await;
    // No hosted graph is installed: this is the supported absent-hosted legacy
    // path, not a native-identity substitute for the current public database.
    assert!(case.db.query_one(
        "SELECT to_regclass('hosted_billing_namespaces') IS NULL AND to_regprocedure('hosted_runtime_schema_ready()') IS NULL",
        &[],
    ).await.unwrap().get::<_, bool>(0));
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.db
        .batch_execute("ALTER TABLE usage_ledger DISABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    assert!(matches!(
        case.send("historical-partial").await,
        Err(zrotext_delivery_store::StoreError::QuotaNotConfigured)
    ));
    assert_no_admission_writes(&case.db).await;
    case.db
        .batch_execute("ALTER TABLE usage_ledger ENABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    assert!(case.send("historical-restored").await.unwrap().created);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public database"]
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
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public database"]
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
