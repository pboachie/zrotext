// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded Stripe TEST reconciliation work per scheduler tick.

use super::{BillingError, worker::StripeTestWorker};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::task::JoinSet;

/// Returns whether any job failed. One false result means the queue was empty;
/// already claimed jobs still finish before the tick ends.
pub async fn drain_billing_batch(
    worker: &Arc<StripeTestWorker>,
    database_url: &str,
    batch_size: usize,
    concurrency: usize,
    risk: bool,
    draining: &AtomicBool,
) -> bool {
    let mut jobs = JoinSet::new();
    let mut started = 0;
    for _ in 0..concurrency.min(batch_size) {
        if draining.load(Ordering::Acquire) {
            break;
        }
        spawn_job(&mut jobs, worker.clone(), database_url.to_owned(), risk);
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
            spawn_job(&mut jobs, worker.clone(), database_url.to_owned(), risk);
            started += 1;
        }
    }
    failed
}

fn spawn_job(
    jobs: &mut JoinSet<Result<bool, BillingError>>,
    worker: Arc<StripeTestWorker>,
    database_url: String,
    risk: bool,
) {
    jobs.spawn(async move {
        if risk {
            worker.reconcile_risk_one(&database_url).await
        } else {
            worker.reconcile_one(&database_url).await
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Path, routing::get};
    use serde_json::json;
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
        let draining = AtomicBool::new(false);
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
}
