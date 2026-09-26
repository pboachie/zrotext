// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::NoTls;

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}

struct TestDb {
    admin: Client,
    client: Client,
    schema: String,
}

impl TestDb {
    async fn new() -> Self {
        let root_url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
            .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
        assert!(root_url.starts_with("postgres://") || root_url.starts_with("postgresql://"));
        let admin = connect(&root_url).await;
        let schema = format!("recovery_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let client = connect(&format!(
            "{root_url}{separator}options=-csearch_path%3D{schema}"
        ))
        .await;
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
            include_str!("../../../deploy/compose/migrations/031_recipient_suppression.sql"),
            include_str!("../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
            include_str!("../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
            include_str!("../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        Self {
            admin,
            client,
            schema,
        }
    }

    /// Admits `accounts * devices * 16` metered messages, the most each
    /// device may hold pending, then makes every one of them expired.
    async fn expired_backlog(&mut self, accounts: usize, devices: usize) -> i64 {
        let expiry = now_ms() + 3_600_000;
        let mut admitted = 0;
        for _ in 0..accounts {
            let account_id = Uuid::new_v4();
            self.client
                .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
                .await
                .unwrap();
            self.client.execute(
                "INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',10000)",
                &[&account_id],
            ).await.unwrap();
            for _ in 0..devices {
                let device_id = Uuid::new_v4();
                self.client.execute(
                    "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'recovery test phone')",
                    &[&device_id, &account_id],
                ).await.unwrap();
                let mut store = DeliveryStore::new(&mut self.client);
                for _ in 0..MAX_PENDING_PER_DEVICE {
                    let key = Uuid::new_v4().to_string();
                    let outcome = store
                        .accept_metered(NewMessage {
                            account_id,
                            client_message_id: Uuid::new_v4(),
                            device_id,
                            idempotency_key: &key,
                            recipient_e164: "+15551234567",
                            synthetic_payload: b"recovery test only",
                            expires_at_ms: expiry,
                        })
                        .await
                        .unwrap();
                    assert!(outcome.created);
                    admitted += 1;
                }
            }
        }
        self.client
            .execute(
                "UPDATE messages SET expires_at=now()-interval '1 minute'",
                &[],
            )
            .await
            .unwrap();
        admitted
    }

    async fn refunds(&self) -> (i64, i64) {
        let ledger: i64 = self
            .client
            .query_one(
                "SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let periods: i64 = self
            .client
            .query_one(
                "SELECT coalesce(sum(refunded_units),0)::bigint FROM usage_periods",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        (ledger, periods)
    }

    async fn close(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn one_recovery_tick_expires_more_than_one_batch_and_refunds_exactly_once() {
    let mut db = TestDb::new().await;
    // 9 accounts * 8 devices * 16 pending = 1,152 expired pre-grant messages.
    let admitted = db.expired_backlog(9, 8).await;
    assert_eq!(admitted, 1_152);

    let backlog = DeliveryStore::new(&mut db.client)
        .recovery_backlog(10_000)
        .await
        .unwrap();
    assert_eq!(backlog.expired_pending, admitted);
    assert!(backlog.oldest_expired_age_seconds.unwrap() >= 59);
    assert_eq!((backlog.silent_attempts, backlog.delivery_timeouts), (0, 0));
    let capped = DeliveryStore::new(&mut db.client)
        .recovery_backlog(500)
        .await
        .unwrap();
    assert_eq!(capped.expired_pending, 500);

    let first = DeliveryStore::new(&mut db.client)
        .recover_bounded(RECOVERY_BATCH, RECOVERY_BATCHES_PER_TICK, || false)
        .await
        .unwrap();
    assert_eq!(
        first,
        RecoveryPass {
            expired: 1_000,
            silent_attempts: 0,
            delivery_timeouts: 0,
            bound_reached: true,
        }
    );
    assert_eq!(db.refunds().await, (1_000, 1_000));

    let second = DeliveryStore::new(&mut db.client)
        .recover_bounded(RECOVERY_BATCH, RECOVERY_BATCHES_PER_TICK, || false)
        .await
        .unwrap();
    assert_eq!(second.expired, 152);
    assert!(!second.bound_reached);
    let third = DeliveryStore::new(&mut db.client)
        .recover_bounded(RECOVERY_BATCH, RECOVERY_BATCHES_PER_TICK, || false)
        .await
        .unwrap();
    assert_eq!(third, RecoveryPass::default());
    assert_eq!(db.refunds().await, (admitted, admitted));

    let states = db
        .client
        .query_one(
            "SELECT count(*) FILTER (WHERE m.state='expired'), \
             count(*) FILTER (WHERE j.finished_at IS NOT NULL) \
             FROM messages m JOIN dispatch_jobs j ON j.message_id=m.id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (states.get::<_, i64>(0), states.get::<_, i64>(1)),
        (admitted, admitted)
    );
    let backlog = DeliveryStore::new(&mut db.client)
        .recovery_backlog(10_000)
        .await
        .unwrap();
    assert_eq!(backlog, RecoveryBacklog::default());
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn recovery_stops_early_when_the_process_is_draining() {
    let mut db = TestDb::new().await;
    let admitted = db.expired_backlog(1, 8).await;
    assert_eq!(admitted, 128);
    let batches = std::sync::atomic::AtomicUsize::new(0);
    let pass = DeliveryStore::new(&mut db.client)
        .recover_bounded(10, RECOVERY_BATCHES_PER_TICK, || {
            batches.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 2
        })
        .await
        .unwrap();
    assert_eq!(pass.expired, 20);
    assert!(!pass.bound_reached);
    assert_eq!(db.refunds().await, (20, 20));
    assert!(matches!(
        DeliveryStore::new(&mut db.client)
            .recover_bounded(0, 1, || false)
            .await,
        Err(StoreError::InvalidInput)
    ));
    db.close().await;
}
