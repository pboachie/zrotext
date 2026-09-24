// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded Stripe TEST reconciliation work per scheduler tick.

use super::{BillingError, worker::StripeTestWorker};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};

trait BillingJobs: Send + Sync + 'static {
    fn reconcile(
        &self,
        database_url: String,
        risk: bool,
    ) -> impl Future<Output = Result<bool, BillingError>> + Send;
}

impl BillingJobs for StripeTestWorker {
    async fn reconcile(&self, database_url: String, risk: bool) -> Result<bool, BillingError> {
        if risk {
            self.reconcile_risk_one(&database_url).await
        } else {
            self.reconcile_one(&database_url).await
        }
    }
}

/// Each queue has its own 10-second clock. A shared semaphore limits total
/// work, while a slow batch in either queue cannot delay the other's polling.
pub struct BillingQueueConfig<T> {
    pub worker: Arc<T>,
    pub database_url: String,
    pub batch_size: usize,
    pub concurrency: usize,
    pub risk: bool,
    pub draining: Arc<AtomicBool>,
    pub notify: Arc<Notify>,
    pub permits: Arc<Semaphore>,
}

pub async fn run_billing_queue(config: BillingQueueConfig<StripeTestWorker>) {
    run_queue(config, Duration::from_secs(10)).await
}

async fn run_queue<T: BillingJobs>(config: BillingQueueConfig<T>, interval: Duration) {
    let BillingQueueConfig {
        worker,
        database_url,
        batch_size,
        concurrency,
        risk,
        draining,
        notify,
        permits,
    } = config;
    let mut checks = tokio::time::interval(interval);
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut unavailable_logged = false;
    loop {
        if draining.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _ = checks.tick() => {
                let failed = drain_jobs(&worker, &database_url, batch_size, concurrency, risk, &draining, &permits).await;
                if failed && !unavailable_logged {
                    if risk { eprintln!("Stripe test payment-risk reconciliation unavailable"); }
                    else { eprintln!("Stripe test reconciliation unavailable"); }
                    unavailable_logged = true;
                } else if !failed {
                    unavailable_logged = false;
                }
            }
            _ = notify.notified() => break,
        }
    }
}

/// Returns whether any job failed. One false result means the queue was empty;
/// already claimed jobs still finish before the tick ends.
#[cfg(test)]
pub async fn drain_billing_batch(
    worker: &Arc<StripeTestWorker>,
    database_url: &str,
    batch_size: usize,
    concurrency: usize,
    risk: bool,
    draining: &Arc<AtomicBool>,
) -> bool {
    let permits = Arc::new(Semaphore::new(concurrency));
    drain_jobs(
        worker,
        database_url,
        batch_size,
        concurrency,
        risk,
        draining,
        &permits,
    )
    .await
}

async fn drain_jobs<T: BillingJobs>(
    worker: &Arc<T>,
    database_url: &str,
    batch_size: usize,
    concurrency: usize,
    risk: bool,
    draining: &Arc<AtomicBool>,
    permits: &Arc<Semaphore>,
) -> bool {
    let mut jobs = JoinSet::new();
    let mut started = 0;
    for _ in 0..concurrency.min(batch_size) {
        if draining.load(Ordering::Acquire) {
            break;
        }
        spawn_job(
            &mut jobs,
            worker.clone(),
            database_url.to_owned(),
            risk,
            draining.clone(),
            permits.clone(),
        );
        started += 1;
    }
    let mut failed = false;
    let mut empty = false;
    while let Some(result) = jobs.join_next().await {
        match result {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => empty = true,
            Ok(Err(_)) | Err(_) => failed = true,
        }
        if !empty && !failed && started < batch_size && !draining.load(Ordering::Acquire) {
            spawn_job(
                &mut jobs,
                worker.clone(),
                database_url.to_owned(),
                risk,
                draining.clone(),
                permits.clone(),
            );
            started += 1;
        }
    }
    failed
}

fn spawn_job<T: BillingJobs>(
    jobs: &mut JoinSet<Result<bool, BillingError>>,
    worker: Arc<T>,
    database_url: String,
    risk: bool,
    draining: Arc<AtomicBool>,
    permits: Arc<Semaphore>,
) {
    jobs.spawn(async move {
        let _permit = permits
            .acquire_owned()
            .await
            .expect("billing semaphore remains open");
        if draining.load(Ordering::Acquire) {
            return Ok(false);
        }
        worker.reconcile(database_url, risk).await
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::StatusCode,
        routing::get,
    };
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    #[tokio::test]
    async fn postgres_fake_stripe_drains_200_rows_in_eight_ticks() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_drain_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        for i in 0..200 {
            let account_id = Uuid::new_v4();
            let customer_id = format!("cus_fixture{i:03}");
            let subscription_id = format!("sub_fixture{i:03}");
            db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
                .await
                .unwrap();
            db.execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
                &[&account_id, &customer_id],
            )
            .await
            .unwrap();
            db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES($1,$2,$3)", &[&subscription_id, &account_id, &customer_id]).await.unwrap();
        }
        let app = Router::new().route("/v1/subscriptions/{subscription_id}", get(|Path(subscription_id): Path<String>| async move {
            let customer_id = subscription_id.replacen("sub_", "cus_", 1);
            Json(json!({
                "id":subscription_id,
                "object":"subscription",
                "livemode":false,
                "customer":customer_id,
                "status":"active",
                "items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_fixture1"}}]}
            }))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let worker = Arc::new(
            StripeTestWorker::new_with_quotas(
                "rk_test_fixture123456".into(),
                vec!["price_fixture1".into()],
                vec![super::super::TestQuotaPlan {
                    price_id: "price_fixture1".into(),
                    outbound_limit: 100,
                    device_limit: None,
                }],
            )
            .unwrap()
            .with_test_server(format!("http://{address}")),
        );
        let draining = Arc::new(AtomicBool::new(false));
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            for tick in 1..=8 {
                assert!(!drain_billing_batch(&worker, &scoped_url, 25, 2, false, &draining).await);
                let done: i64 = db.query_one("SELECT count(*) FROM billing_reconciliations WHERE dirty_generation=processed_generation", &[]).await.unwrap().get(0);
                assert_eq!(done, tick * 25);
            }
        }).await.unwrap();
        let projected: i64 = db.query_one("SELECT count(*) FROM usage_quota_policies WHERE source='stripe_test' AND limit_units=100", &[]).await.unwrap().get(0);
        assert_eq!(projected, 200);
        server.abort();
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[derive(Default)]
    struct ProviderProbe {
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    async fn provider_response(probe: &ProviderProbe, delay: std::time::Duration) -> StatusCode {
        let active = probe.active.fetch_add(1, Ordering::SeqCst) + 1;
        probe.peak.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(delay).await;
        probe.active.fetch_sub(1, Ordering::SeqCst);
        StatusCode::OK
    }

    struct SlowFakeJobs {
        http: reqwest::Client,
        base_url: String,
        subscriptions_done: AtomicUsize,
        risk_started_after: AtomicUsize,
        risk_available: AtomicBool,
        initial_empty: tokio::sync::Notify,
    }

    impl BillingJobs for SlowFakeJobs {
        async fn reconcile(&self, _database_url: String, risk: bool) -> Result<bool, BillingError> {
            if risk {
                if !self.risk_available.load(Ordering::SeqCst) {
                    self.initial_empty.notify_one();
                    return Ok(false);
                }
                let _ = self.risk_started_after.compare_exchange(
                    usize::MAX,
                    self.subscriptions_done.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                self.http
                    .get(format!("{}/risk", self.base_url))
                    .send()
                    .await
                    .map_err(|_| BillingError::InvalidEvent)?;
                Ok(false)
            } else {
                self.http
                    .get(format!("{}/subscription", self.base_url))
                    .send()
                    .await
                    .map_err(|_| BillingError::InvalidEvent)?;
                self.subscriptions_done.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        }
    }

    #[tokio::test]
    async fn slow_provider_does_not_starve_risk_queue() {
        let probe = Arc::new(ProviderProbe::default());
        let app = Router::new()
            .route(
                "/subscription",
                get(|State(probe): State<Arc<ProviderProbe>>| async move {
                    provider_response(&probe, std::time::Duration::from_millis(80)).await
                }),
            )
            .route(
                "/risk",
                get(|State(probe): State<Arc<ProviderProbe>>| async move {
                    provider_response(&probe, std::time::Duration::from_millis(5)).await
                }),
            )
            .with_state(probe.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let worker = Arc::new(SlowFakeJobs {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            base_url: format!("http://{address}"),
            subscriptions_done: AtomicUsize::new(0),
            risk_started_after: AtomicUsize::new(usize::MAX),
            risk_available: AtomicBool::new(false),
            initial_empty: tokio::sync::Notify::new(),
        });
        let draining = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(tokio::sync::Notify::new());
        let permits = Arc::new(Semaphore::new(1));
        let initial_empty = worker.initial_empty.notified();
        let subscriptions = tokio::spawn(run_queue(
            BillingQueueConfig {
                worker: worker.clone(),
                database_url: "unused".into(),
                batch_size: 20,
                concurrency: 1,
                risk: false,
                draining: draining.clone(),
                notify: notify.clone(),
                permits: permits.clone(),
            },
            std::time::Duration::from_millis(20),
        ));
        let risks = tokio::spawn(run_queue(
            BillingQueueConfig {
                worker: worker.clone(),
                database_url: "unused".into(),
                batch_size: 20,
                concurrency: 1,
                risk: true,
                draining: draining.clone(),
                notify: notify.clone(),
                permits,
            },
            std::time::Duration::from_millis(20),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), initial_empty)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        worker.risk_available.store(true, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while worker.risk_started_after.load(Ordering::SeqCst) == usize::MAX {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            worker.risk_started_after.load(Ordering::SeqCst) < 20,
            "risk started after the subscription batch"
        );
        draining.store(true, Ordering::SeqCst);
        notify.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            subscriptions.await.unwrap();
            risks.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            probe.peak.load(Ordering::SeqCst),
            1,
            "queues exceeded the shared concurrency cap"
        );
        server.abort();
    }
}
