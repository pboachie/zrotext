// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::sync::Arc;
use tokio::{
    sync::{Barrier, Semaphore},
    task::JoinSet,
};
use tokio_postgres::NoTls;

struct TestDb {
    admin: Client,
    client: Client,
    schema: String,
    scoped_url: String,
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}

impl TestDb {
    async fn new() -> Option<Self> {
        let root_url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL").ok()?;
        assert!(root_url.starts_with("postgres://") || root_url.starts_with("postgresql://"));
        let admin = connect(&root_url).await;
        let schema = format!("metering_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let client = connect(&scoped_url).await;
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        Some(Self {
            admin,
            client,
            schema,
            scoped_url,
        })
    }

    async fn account_and_device(&self) -> (Uuid, Uuid) {
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        self.client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        self.client.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'metering test phone')",
            &[&device_id, &account_id],
        ).await.unwrap();
        (account_id, device_id)
    }

    async fn policy(&self, account_id: Uuid, limit: i64) {
        self.client.execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',$2)",
            &[&account_id, &limit],
        ).await.unwrap();
    }

    async fn close(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn message<'a>(
    account_id: Uuid,
    device_id: Uuid,
    message_id: Uuid,
    key: &'a str,
    expiry: i64,
) -> NewMessage<'a> {
    NewMessage {
        account_id,
        client_message_id: message_id,
        device_id,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"metering test only",
        expires_at_ms: expiry,
    }
}

async fn timestamp_ms(client: &Client, value: &str) -> i64 {
    client
        .query_one(
            "SELECT (extract(epoch FROM $1::text::timestamptz)*1000)::bigint",
            &[&value],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn reservation_is_idempotent_and_refund_stays_in_original_utc_period() {
    let Some(mut db) = TestDb::new().await else {
        return;
    };
    let (account, device) = db.account_and_device().await;
    let (other_account, other_device) = db.account_and_device().await;
    let january = timestamp_ms(&db.client, "2026-01-31 23:59:59+00").await;
    let february = timestamp_ms(&db.client, "2026-02-01 00:00:00+00").await;
    let expiry = now_ms() + 3_600_000;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    {
        let mut store = DeliveryStore::new(&mut db.client);
        assert!(matches!(
            store
                .accept_metered(message(
                    other_account,
                    other_device,
                    Uuid::new_v4(),
                    "no-policy",
                    expiry
                ))
                .await,
            Err(StoreError::QuotaNotConfigured)
        ));
    }
    db.policy(account, 1).await;
    db.policy(other_account, 1).await;
    {
        let mut store = DeliveryStore::new(&mut db.client);
        let unmetered = Uuid::new_v4();
        assert!(
            store
                .accept(message(account, device, unmetered, "alpha-only", expiry))
                .await
                .unwrap()
                .created
        );
        assert!(matches!(
            store
                .accept_metered_at(
                    message(account, device, unmetered, "alpha-only", expiry),
                    february
                )
                .await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(
            store
                .accept_metered_at(message(account, device, first, "one", expiry), january)
                .await
                .unwrap()
                .created
        );
        assert!(
            !store
                .accept_metered_at(message(account, device, first, "one", expiry), february)
                .await
                .unwrap()
                .created
        );
        assert!(matches!(
            store
                .accept_metered_at(
                    message(account, device, Uuid::new_v4(), "january-full", expiry),
                    january
                )
                .await,
            Err(StoreError::QuotaExceeded)
        ));
        assert!(matches!(
            store
                .accept_metered_at(
                    message(account, device, Uuid::new_v4(), "one", expiry),
                    february
                )
                .await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(matches!(
            store
                .accept_metered_at(
                    message(account, device, first, "other-key", expiry),
                    february
                )
                .await,
            Err(StoreError::MessageIdConflict)
        ));
        assert!(
            store
                .accept_metered_at(message(account, device, second, "two", expiry), february)
                .await
                .unwrap()
                .created
        );
        assert!(!store.cancel(other_account, first).await.unwrap());
        assert!(store.cancel(account, first).await.unwrap());
        assert!(matches!(
            store.cancel(account, first).await,
            Err(StoreError::InvalidTransition)
        ));
        assert!(
            !store
                .accept_metered_at(message(account, device, first, "one", expiry), february)
                .await
                .unwrap()
                .created
        );
    }

    let periods = db.client.query(
        "SELECT period_start::text,reserved_units,refunded_units FROM usage_periods WHERE account_id=$1 ORDER BY period_start",
        &[&account],
    ).await.unwrap();
    assert_eq!(periods.len(), 2);
    assert_eq!(
        (
            periods[0].get::<_, String>(0),
            periods[0].get::<_, i64>(1),
            periods[0].get::<_, i64>(2)
        ),
        ("2026-01-01".into(), 1, 1)
    );
    assert_eq!(
        (
            periods[1].get::<_, String>(0),
            periods[1].get::<_, i64>(1),
            periods[1].get::<_, i64>(2)
        ),
        ("2026-02-01".into(), 1, 0)
    );

    db.client.execute("UPDATE messages SET expires_at=now()-interval '1 second' WHERE account_id=$1 AND id=$2", &[&account, &second]).await.unwrap();
    {
        let mut store = DeliveryStore::new(&mut db.client);
        assert_eq!(store.expire_due(10).await.unwrap(), 1);
        assert_eq!(store.expire_due(10).await.unwrap(), 0);
    }
    let periods = db.client.query(
        "SELECT period_start::text,reserved_units,refunded_units FROM usage_periods WHERE account_id=$1 ORDER BY period_start",
        &[&account],
    ).await.unwrap();
    assert_eq!(
        (periods[0].get::<_, i64>(1), periods[0].get::<_, i64>(2)),
        (1, 1)
    );
    assert_eq!(
        (periods[1].get::<_, i64>(1), periods[1].get::<_, i64>(2)),
        (1, 1)
    );
    let ledger_count: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(ledger_count, 4);
    let other_count: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE account_id=$1",
            &[&other_account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(other_count, 0);
    db.close().await;
}

#[tokio::test]
async fn one_remaining_unit_accepts_only_one_of_one_hundred_contenders() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let (account, device) = db.account_and_device().await;
    db.policy(account, 1).await;
    let expiry = now_ms() + 3_600_000;
    let barrier = Arc::new(Barrier::new(101));
    // All 100 callers start together; a bounded connection pool keeps this
    // test below PostgreSQL's default max_connections while still racing the
    // same usage_periods row in independent database transactions.
    let permits = Arc::new(Semaphore::new(32));
    let mut tasks = JoinSet::new();
    for index in 0..100 {
        let barrier = barrier.clone();
        let permits = permits.clone();
        let url = db.scoped_url.clone();
        tasks.spawn(async move {
            let message_id = Uuid::new_v4();
            let key = format!("parallel-{index}");
            barrier.wait().await;
            let _permit = permits.acquire().await.unwrap();
            let mut client = connect(&url).await;
            let result = DeliveryStore::new(&mut client)
                .accept_metered(message(account, device, message_id, &key, expiry))
                .await;
            (message_id, result)
        });
    }
    barrier.wait().await;
    let mut winner = None;
    let mut exhausted = 0;
    while let Some(task) = tasks.join_next().await {
        match task.unwrap() {
            (message_id, Ok(outcome)) => {
                assert!(outcome.created);
                assert_eq!(outcome.message_id, message_id);
                assert!(winner.replace(message_id).is_none());
            }
            (_, Err(StoreError::QuotaExceeded)) => exhausted += 1,
            (_, Err(error)) => panic!("unexpected metering error: {error:?}"),
        }
    }
    assert!(winner.is_some());
    assert_eq!(exhausted, 99);
    let period = db.client.query_one(
        "SELECT reserved_units,refunded_units FROM usage_periods WHERE account_id=$1 AND metric='outbound_message'",
        &[&account],
    ).await.unwrap();
    assert_eq!((period.get::<_, i64>(0), period.get::<_, i64>(1)), (1, 0));
    let message_count: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    let key_count: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM idempotency_keys WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    let ledger_count: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!((message_count, key_count, ledger_count), (1, 1, 1));
    db.close().await;
}
