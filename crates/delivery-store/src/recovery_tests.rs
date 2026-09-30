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
        crate::tests::apply_test_migrations(&client).await;
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

/// A full batch of each kind sweeps through one statement per batch, emits
/// events with the same digest the per-row loop computed, and never resweeps
/// (#508).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn full_batches_sweep_silent_attempts_and_delivery_timeouts_with_events() {
    let mut db = TestDb::new().await;
    let account_id = Uuid::new_v4();
    db.client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) \
             SELECT gen_random_uuid(),$1,'sweep fixture' FROM generate_series(1,200)",
            &[&account_id],
        )
        .await
        .unwrap();
    for (state, fence_outcome, attempt_status, grant_age, updated_age, count) in [
        (
            "claimed",
            "granted",
            "granted",
            "10 minutes",
            "0 seconds",
            100_i64,
        ),
        (
            "submitted",
            "submitted",
            "submitted",
            "1 hour",
            "25 hours",
            100,
        ),
    ] {
        db.client
            .execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
                 transport_mode,transport_payload,request_digest,state,expires_at,updated_at) \
                 SELECT gen_random_uuid(),$1,(SELECT d.id FROM devices d WHERE d.account_id=$1 \
                   ORDER BY d.id LIMIT 1 OFFSET (n-1)),'+15551234567',$2,'synthetic_alpha',$3,$4,$5, \
                 now()+interval '1 hour',now()-($6::text::interval) \
                 FROM generate_series(1,$7::bigint) n",
                &[
                    &account_id,
                    &vec![1_u8; 32],
                    &b"sweep fixture".as_slice(),
                    &vec![2_u8; 32],
                    &state,
                    &updated_age,
                    &count,
                ],
            )
            .await
            .unwrap();
        db.client
            .execute(
                "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
                 session_epoch,deployment_epoch,status,updated_at) \
                 SELECT gen_random_uuid(),$1,m.id,m.device_id,1,2,1,$2,now() \
                 FROM messages m WHERE m.account_id=$1 AND m.state=$3",
                &[&account_id, &attempt_status, &state],
            )
            .await
            .unwrap();
        db.client
            .execute(
                "INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation, \
                 session_epoch,deployment_epoch,recipient_digest,grant_expires_at,outcome) \
                 SELECT m.id,$1,m.device_id,a.id,1,2,1,$2,now()-($3::text::interval),$4 \
                 FROM messages m JOIN message_attempts a ON a.message_id=m.id \
                 WHERE m.account_id=$1 AND m.state=$5",
                &[
                    &account_id,
                    &vec![1_u8; 32],
                    &grant_age,
                    &fence_outcome,
                    &state,
                ],
            )
            .await
            .unwrap();
    }

    let silent = DeliveryStore::new(&mut db.client)
        .reconcile_silent_attempts(RECOVERY_BATCH)
        .await
        .unwrap();
    assert_eq!(silent, 100);
    let timeouts = DeliveryStore::new(&mut db.client)
        .reconcile_delivery_timeouts(RECOVERY_BATCH)
        .await
        .unwrap();
    assert_eq!(timeouts, 100);

    let events: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM message_events \
             WHERE evidence_code IN ('grant_timeout','sent_callback_timeout','delivery_timeout')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 200);
    let digest_matches: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM message_events e \
             WHERE e.event_digest=sha256(uuid_send(e.account_id)||uuid_send(e.message_id)|| \
                   uuid_send(e.attempt_id)||e.evidence_code::bytea) \
               AND e.evidence_code IN ('grant_timeout','sent_callback_timeout','delivery_timeout')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(digest_matches, 200);
    let states: Vec<(String, i64)> = db
        .client
        .query(
            "SELECT state,count(*) FROM messages WHERE account_id=$1 GROUP BY state ORDER BY state",
            &[&account_id],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        states,
        vec![
            ("delivery_unknown".to_string(), 100),
            ("unknown".to_string(), 100),
        ]
    );
    let unknown_attempts: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM message_attempts WHERE account_id=$1 AND status='unknown'",
            &[&account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(unknown_attempts, 100);

    assert_eq!(
        DeliveryStore::new(&mut db.client)
            .reconcile_silent_attempts(RECOVERY_BATCH)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        DeliveryStore::new(&mut db.client)
            .reconcile_delivery_timeouts(RECOVERY_BATCH)
            .await
            .unwrap(),
        0
    );
    db.close().await;
}
