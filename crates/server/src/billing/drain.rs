// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded Stripe TEST reconciliation work per scheduler tick.

#[cfg(test)]
mod failure_diagnostics;

use super::{
    BillingError,
    worker::{JobOutcome, StripeTestWorker},
};
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
    ) -> impl Future<Output = Result<JobOutcome, BillingError>> + Send;
}

impl BillingJobs for StripeTestWorker {
    async fn reconcile(
        &self,
        database_url: String,
        risk: bool,
    ) -> Result<JobOutcome, BillingError> {
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
    /// Staggers the first tick so co-periodic queues do not burst together.
    pub phase: Duration,
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
        phase,
        draining,
        notify,
        permits,
    } = config;
    let mut checks = tokio::time::interval_at(tokio::time::Instant::now() + phase, interval);
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
        #[cfg(test)]
        failure_diagnostics::emit(&result);
        match result {
            Ok(Ok(JobOutcome::WorkDone)) => {}
            Ok(Ok(JobOutcome::Empty)) => empty = true,
            // One provider-wide failure ends this queue's drain for the tick:
            // already-running jobs finish, but nothing new is spawned.
            Ok(Ok(JobOutcome::ProviderDown)) | Ok(Err(_)) | Err(_) => failed = true,
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
    jobs: &mut JoinSet<Result<JobOutcome, BillingError>>,
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
            return Ok(JobOutcome::Empty);
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
        response::IntoResponse,
        routing::get,
    };
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_fake_stripe_drains_200_rows_in_eight_ticks() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
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
            include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
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
        // A worker session's now() can trail this session's slightly (seen
        // on Docker Desktop); backdate so every row is already due.
        db.execute(
            "UPDATE billing_reconciliations SET next_attempt_at=now()-interval '1 minute'",
            &[],
        )
        .await
        .unwrap();
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

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_fake_stripe_outage_stops_fan_out_and_keeps_rows_queued() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for (status, retry_after) in [(429u16, Some(120u64)), (503, None)] {
            let schema = format!("billing_outage_{}", Uuid::new_v4().simple());
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
                include_str!(
                    "../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"
                ),
                include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
                include_str!(
                    "../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"
                ),
                include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
                include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
                include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
                // 023 adds the pointer-or-review check that a blanket
                // requeue of review rows violates; 024 widens risk states.
                include_str!(
                    "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
                ),
                include_str!(
                    "../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"
                ),
                include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
                include_str!(
                    "../../../../deploy/compose/migrations/028_billing_provider_failures.sql"
                ),
            ] {
                db.batch_execute(sql).await.unwrap();
            }
            for i in 0..10 {
                let account_id = Uuid::new_v4();
                let customer_id = format!("cus_outage{i:02}");
                let subscription_id = format!("sub_outage{i:02}");
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
            // Rows the pre-#483 worker parked for provider-wide failures
            // (class authorization/transport): recovery must sweep both back
            // into the queue without operator action. Rows parked for
            // row-level reasons, a tenant-conflict risk event and a
            // pointerless review-required dispute must keep their review
            // state and evidence.
            let parked_account = Uuid::new_v4();
            db.execute("INSERT INTO accounts(id) VALUES($1)", &[&parked_account])
                .await
                .unwrap();
            db.execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
                &[&parked_account, &"cus_outageparked"],
            )
            .await
            .unwrap();
            db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES($1,$2,$3)", &[&"sub_outageparked", &parked_account, &"cus_outageparked"]).await.unwrap();
            db.execute(
                "UPDATE billing_reconciliations SET state='needs_review',failed_attempts=10,last_failure_class='transport' WHERE stripe_subscription_id='sub_outageparked'",
                &[],
            )
            .await
            .unwrap();
            db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,state,failed_attempts,last_failure_class) VALUES('sub_rowparked',$1,'cus_outageparked','needs_review',10,'invalid_response')", &[&parked_account]).await.unwrap();
            db.execute(
                "INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES('evt_outageparked','charge.refunded',$1,$2,'queued')",
                &[&parked_account, &vec![0u8; 32]],
            )
            .await
            .unwrap();
            db.execute(
                "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES('evt_outageparked','ch_outageparked','refund',$1)",
                &[&parked_account],
            )
            .await
            .unwrap();
            db.execute(
                "UPDATE billing_risk_events SET state='needs_review',failed_attempts=10,last_failure_class='authorization' WHERE stripe_event_id='evt_outageparked'",
                &[],
            )
            .await
            .unwrap();
            for (event, kind) in [
                ("evt_rowparked", "charge.refunded"),
                ("evt_pointerless", "charge.dispute.created"),
                ("evt_queuedrisk", "charge.refunded"),
            ] {
                db.execute(
                    "INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES($1,$2,$3,$4,'queued')",
                    &[&event, &kind, &parked_account, &vec![0u8; 32]],
                )
                .await
                .unwrap();
            }
            // A tenant conflict parked by the worker, recorded as "local".
            db.execute(
                "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id,state,failed_attempts,last_failure_class) VALUES('evt_rowparked','ch_rowparked','refund',$1,'needs_review',10,'local')",
                &[&parked_account],
            )
            .await
            .unwrap();
            // Ingestion stores a signed dispute with an unusable charge as a
            // pointerless review row; migration 023 keeps it in review.
            db.execute(
                "INSERT INTO billing_risk_events(stripe_event_id,risk_kind,account_id,state) VALUES('evt_pointerless','dispute',$1,'needs_review')",
                &[&parked_account],
            )
            .await
            .unwrap();
            // A queued risk event: the shared pause must stop its queue too.
            db.execute(
                "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES('evt_queuedrisk','ch_queuedrisk','refund',$1)",
                &[&parked_account],
            )
            .await
            .unwrap();
            // A worker session's now() can trail this session's slightly
            // (seen on Docker Desktop); backdate so queued rows are due.
            db.execute("UPDATE billing_reconciliations SET next_attempt_at=now()-interval '1 minute' WHERE state='queued'", &[]).await.unwrap();
            db.execute("UPDATE billing_risk_events SET next_attempt_at=now()-interval '1 minute' WHERE state='queued'", &[]).await.unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let healthy = Arc::new(AtomicBool::new(false));
            let app = Router::new().route(
                "/v1/subscriptions/{subscription_id}",
                get(
                    move |State((counted, recovered)): State<(
                        Arc<AtomicUsize>,
                        Arc<AtomicBool>,
                    )>,
                          Path(subscription_id): Path<String>| async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if recovered.load(Ordering::SeqCst) {
                            let customer_id =
                                subscription_id.replacen("sub_", "cus_", 1);
                            return Json(json!({
                                "id": subscription_id,
                                "object": "subscription",
                                "livemode": false,
                                "customer": customer_id,
                                "status": "active",
                                "items": {"object": "list", "has_more": false, "data": [{"price": {"id": "price_fixture1"}}]}
                            }))
                            .into_response();
                        }
                        let mut headers = axum::http::HeaderMap::new();
                        if let Some(seconds) = retry_after {
                            headers.insert(
                                axum::http::header::RETRY_AFTER,
                                axum::http::HeaderValue::from_str(&seconds.to_string())
                                    .unwrap(),
                            );
                        }
                        (axum::http::StatusCode::from_u16(status).unwrap(), headers)
                            .into_response()
                    },
                ),
            )
            .route(
                "/v1/charges/{charge_id}",
                get(
                    move |State((counted, _)): State<(Arc<AtomicUsize>, Arc<AtomicBool>)>| async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::from_u16(status).unwrap()
                    },
                ),
            )
            .with_state((requests.clone(), healthy.clone()));
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
            // First tick: the initial jobs discover the outage; the drain must
            // stop refilling, so the provider sees at most `concurrency` hits.
            assert!(drain_billing_batch(&worker, &scoped_url, 25, 2, false, &draining).await);
            let first_tick = requests.load(Ordering::SeqCst);
            assert!(first_tick <= 2, "first tick sent {first_tick} requests");
            let row = db.query_one(
                "SELECT count(*) FILTER (WHERE state='queued' AND stripe_subscription_id LIKE 'sub_outage%'),count(*) FILTER (WHERE state='queued' AND failed_attempts<>0),min(next_attempt_at) FROM billing_reconciliations",
                &[],
            ).await.unwrap();
            assert_eq!(row.get::<_, i64>(0), 10, "rows must stay queued");
            assert_eq!(
                row.get::<_, i64>(1),
                0,
                "outage must not count toward review"
            );
            let deferred = db.query_one(
                "SELECT count(*) FROM billing_reconciliations WHERE next_attempt_at > now() + make_interval(secs => $1)",
                &[&if retry_after.is_some() { 110f64 } else { 20f64 }],
            ).await.unwrap().get::<_, i64>(0);
            assert_eq!(
                deferred, first_tick as i64,
                "only the failed rows defer, by the provider pause"
            );
            // Second tick while paused: no provider contact at all, from
            // either queue. The risk queue has a claimable event and shares
            // the subscription queue's pause.
            assert!(!drain_billing_batch(&worker, &scoped_url, 25, 2, false, &draining).await);
            assert!(!drain_billing_batch(&worker, &scoped_url, 25, 2, true, &draining).await);
            assert_eq!(
                requests.load(Ordering::SeqCst),
                first_tick,
                "paused queue sent more requests"
            );
            let queued_risk = db.query_one("SELECT state,failed_attempts,next_attempt_at<=now() FROM billing_risk_events WHERE stripe_event_id='evt_queuedrisk'", &[]).await.unwrap();
            assert_eq!(queued_risk.get::<_, String>(0), "queued");
            assert_eq!(queued_risk.get::<_, i32>(1), 0);
            assert!(
                queued_risk.get::<_, bool>(2),
                "paused risk queue must not claim"
            );
            // Recovery: the provider answers again; the first successful
            // request clears the pause state and sweeps parked rows back
            // into the queue without operator action.
            healthy.store(true, Ordering::SeqCst);
            worker.expire_provider_pause_for_tests();
            assert!(!drain_billing_batch(&worker, &scoped_url, 25, 2, false, &draining).await);
            // The sweep marks requeued rows due at one worker session's now();
            // another session's clock can trail it slightly, so drain a
            // bounded number of times until the requeued row is processed.
            for _ in 0..20 {
                assert!(!drain_billing_batch(&worker, &scoped_url, 25, 2, false, &draining).await);
                let done: bool = db.query_one("SELECT dirty_generation=processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_outageparked'", &[]).await.unwrap().get(0);
                if done {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let parked = db.query_one("SELECT failed_attempts,dirty_generation=processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_outageparked'", &[]).await.unwrap();
            assert_eq!(
                parked.get::<_, i32>(0),
                0,
                "parked row must requeue and drain"
            );
            assert!(
                parked.get::<_, bool>(1),
                "parked row must requeue and drain"
            );
            let parked_risk = db
                .query_one(
                    "SELECT state,failed_attempts,last_failure_class FROM billing_risk_events WHERE stripe_event_id='evt_outageparked'",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(
                parked_risk.get::<_, String>(0),
                "queued",
                "outage-parked risk event must requeue"
            );
            assert_eq!(parked_risk.get::<_, i32>(1), 0);
            assert_eq!(
                parked_risk.get::<_, Option<String>>(2).as_deref(),
                Some("authorization"),
                "requeue keeps the failure evidence"
            );
            // Row-level parking is terminal until an operator acts: state,
            // retry count and failure class all survive the recovery sweep.
            let kept = db
                .query_one(
                    "SELECT state,failed_attempts,last_failure_class FROM billing_reconciliations WHERE stripe_subscription_id='sub_rowparked'",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(kept.get::<_, String>(0), "needs_review");
            assert_eq!(kept.get::<_, i32>(1), 10);
            assert_eq!(kept.get::<_, String>(2), "invalid_response");
            let kept = db
                .query(
                    "SELECT stripe_event_id,state,failed_attempts,last_failure_class FROM billing_risk_events WHERE stripe_event_id IN ('evt_rowparked','evt_pointerless') ORDER BY stripe_event_id",
                    &[],
                )
                .await
                .unwrap();
            let kept: Vec<(String, String, i32, Option<String>)> = kept
                .iter()
                .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
                .collect();
            assert_eq!(
                kept,
                vec![
                    ("evt_pointerless".into(), "needs_review".into(), 0, None),
                    (
                        "evt_rowparked".into(),
                        "needs_review".into(),
                        10,
                        Some("local".into())
                    ),
                ]
            );
            let review: i64 = db
                .query_one(
                    "SELECT count(*) FROM billing_reconciliations WHERE state='needs_review'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(review, 1, "only the row-level review row stays parked");
            assert!(
                requests.load(Ordering::SeqCst) > first_tick,
                "recovery must contact the provider"
            );
            // Recovery resets the escalation: the next outage starts again at
            // the 30-second base instead of the grown pause. One job (batch 1,
            // concurrency 1) keeps the streak deterministic.
            healthy.store(false, Ordering::SeqCst);
            db.execute("UPDATE billing_reconciliations SET dirty_generation=dirty_generation+1,next_attempt_at=now()-interval '1 minute' WHERE stripe_subscription_id='sub_outage00'", &[]).await.unwrap();
            assert!(drain_billing_batch(&worker, &scoped_url, 1, 1, false, &draining).await);
            let (low, high) = if retry_after.is_some() {
                (110f64, 130f64)
            } else {
                (20f64, 40f64)
            };
            let deferred: bool = db.query_one(
                "SELECT next_attempt_at > now() + make_interval(secs => $1) AND next_attempt_at < now() + make_interval(secs => $2) FROM billing_reconciliations WHERE stripe_subscription_id='sub_outage00'",
                &[&low, &high],
            ).await.unwrap().get(0);
            assert!(deferred, "post-recovery pause must restart at the base");
            server.abort();
            setup
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .await
                .unwrap();
        }
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
        async fn reconcile(
            &self,
            _database_url: String,
            risk: bool,
        ) -> Result<JobOutcome, BillingError> {
            if risk {
                if !self.risk_available.load(Ordering::SeqCst) {
                    self.initial_empty.notify_one();
                    return Ok(JobOutcome::Empty);
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
                Ok(JobOutcome::Empty)
            } else {
                self.http
                    .get(format!("{}/subscription", self.base_url))
                    .send()
                    .await
                    .map_err(|_| BillingError::InvalidEvent)?;
                self.subscriptions_done.fetch_add(1, Ordering::SeqCst);
                Ok(JobOutcome::WorkDone)
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
                phase: Duration::ZERO,
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
                phase: Duration::ZERO,
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
