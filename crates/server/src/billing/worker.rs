// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode subscription reconciliation against Stripe's current API state.

use super::{
    BillingError, SubscriptionSnapshot, TestQuotaPlan, is_test_api_key,
    reconcile_snapshot_with_quotas, risk, valid_id,
};
use reqwest::{Client as HttpClient, redirect, retry};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio_postgres::Client;
use uuid::Uuid;

const MAX_FAILURES: i32 = 10;
static LAST_DIAGNOSTIC: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// Longest provider-wide pause, and the cap on a caller-supplied Retry-After.
const PROVIDER_PAUSE_CAP_SECS: u64 = 600;
/// Baseline provider-wide pause before consecutive-failure escalation.
const PROVIDER_PAUSE_BASE_MS: u64 = 30_000;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    #[error("HTTP {0}")]
    HttpStatus(u16),
    #[error("HTTP 429")]
    RateLimited { retry_after_secs: u64 },
    #[error("transport")]
    Transport,
    #[error("invalid response")]
    InvalidResponse,
}

impl ProviderFailure {
    fn class(self) -> (&'static str, usize) {
        match self {
            Self::HttpStatus(401 | 403) => ("authorization", 0),
            Self::HttpStatus(404) => ("missing", 1),
            // 429 stays in the persisted "http" class (the DB check constraint
            // enumerates it); the diagnostic log keeps the sharper label.
            Self::HttpStatus(429) | Self::RateLimited { .. } => ("http", 2),
            Self::HttpStatus(_) => ("http", 2),
            Self::Transport => ("transport", 4),
            Self::InvalidResponse => ("invalid_response", 5),
        }
    }
    /// Provider-wide failures affect every row alike, so they pause the whole
    /// queue instead of accumulating per-row review state.
    pub(super) fn provider_wide(self) -> Option<u64> {
        match self {
            Self::HttpStatus(401 | 403 | 429 | 500..=599) | Self::Transport => Some(0),
            Self::RateLimited { retry_after_secs } => Some(retry_after_secs),
            Self::HttpStatus(_) | Self::InvalidResponse => None,
        }
    }
}

/// Pause after a provider-wide failure: the provider's Retry-After when one
/// was supplied (capped), otherwise an exponential schedule over consecutive
/// provider-wide failures, always bounded by the cap.
fn provider_pause_ms(consecutive: u32, retry_after_secs: u64) -> u64 {
    if retry_after_secs > 0 {
        return retry_after_secs.clamp(1, PROVIDER_PAUSE_CAP_SECS) * 1_000;
    }
    let escalation = 1u64.checked_shl(consecutive.min(5)).unwrap_or(32);
    PROVIDER_PAUSE_BASE_MS
        .saturating_mul(escalation)
        .min(PROVIDER_PAUSE_CAP_SECS * 1_000)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Classify a non-success response, honouring a numeric Retry-After on 429.
/// Only the delta-seconds form is read; an HTTP-date or missing header falls
/// back to the scheduled provider-wide pause. The value is capped regardless
/// of what the provider sends.
pub(super) fn provider_failure_from_status(response: &reqwest::Response) -> ProviderFailure {
    let status = response.status().as_u16();
    if status == 429
        && let Some(retry_after) = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return ProviderFailure::RateLimited {
            retry_after_secs: retry_after.min(PROVIDER_PAUSE_CAP_SECS),
        };
    }
    ProviderFailure::HttpStatus(status)
}

fn diagnostic(failure: ProviderFailure, row: &str, job: &str) {
    let (class, slot) = failure.class();
    let status = match failure {
        ProviderFailure::HttpStatus(status) => status.to_string(),
        // The persisted class is "http"; the log keeps the sharper label.
        ProviderFailure::RateLimited { .. } => {
            diagnostic_class("rate_limited", slot, "429", row, job);
            return;
        }
        _ => "none".to_owned(),
    };
    diagnostic_class(class, slot, &status, row, job);
}

fn diagnostic_class(class: &str, slot: usize, status: &str, row: &str, job: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = &LAST_DIAGNOSTIC[slot];
    let previous = last.load(Ordering::Relaxed);
    if now.saturating_sub(previous) < 60
        || last
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let reference = opaque_ref(row);
    eprintln!(
        "Stripe test billing failure job={job} class={class} status={status} row_ref={reference}"
    );
}

fn opaque_ref(row: &str) -> String {
    Sha256::digest(row.as_bytes())[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What one reconcile job did, so the drain loop can stop feeding a queue
/// whose provider just failed everywhere at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// A row was reconciled, or a row-level failure was recorded for retry.
    WorkDone,
    /// Nothing was claimable this tick.
    Empty,
    /// A provider-wide failure (401/403/429/5xx/transport): stop this queue's
    /// drain for the rest of the tick and let the pause gate future probes.
    ProviderDown,
}

pub struct StripeTestWorker {
    http: HttpClient,
    secret_key: String,
    recognized_prices: Vec<String>,
    quota_plans: Vec<TestQuotaPlan>,
    subscription_authorized: Arc<AtomicBool>,
    risk_authorized: Arc<AtomicBool>,
    api_base: String,
    provider_paused_until_ms: AtomicU64,
    provider_wide_streak: AtomicU32,
    last_provider_pause_secs: AtomicU64,
}

impl StripeTestWorker {
    pub fn new(secret_key: String, recognized_prices: Vec<String>) -> Result<Self, &'static str> {
        Self::new_with_quotas(secret_key, recognized_prices, Vec::new())
    }

    pub fn new_with_quotas(
        secret_key: String,
        recognized_prices: Vec<String>,
        quota_plans: Vec<TestQuotaPlan>,
    ) -> Result<Self, &'static str> {
        if !is_test_api_key(&secret_key)
            || recognized_prices.is_empty()
            || recognized_prices
                .iter()
                .any(|id| valid_id(id, "price_").is_err())
            || quota_plans
                .iter()
                .any(|plan| plan.outbound_limit <= 0 || !recognized_prices.contains(&plan.price_id))
        {
            return Err("invalid Stripe test configuration");
        }
        let http = HttpClient::builder()
            .no_proxy()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "cannot configure Stripe test client")?;
        Ok(Self {
            http,
            secret_key,
            recognized_prices,
            quota_plans,
            subscription_authorized: Arc::new(AtomicBool::new(true)),
            risk_authorized: Arc::new(AtomicBool::new(true)),
            api_base: "https://api.stripe.com".into(),
            provider_paused_until_ms: AtomicU64::new(0),
            provider_wide_streak: AtomicU32::new(0),
            last_provider_pause_secs: AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_server(mut self, api_base_url: String) -> Self {
        self.http = HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("fake Stripe client");
        self.api_base = api_base_url;
        self
    }

    pub fn authorization_state(&self) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        (
            self.subscription_authorized.clone(),
            self.risk_authorized.clone(),
        )
    }

    fn provider_paused(&self) -> bool {
        unix_ms() < self.provider_paused_until_ms.load(Ordering::Acquire)
    }

    /// Test-only: expire an active provider pause so recovery can be
    /// exercised without waiting out the backoff schedule.
    #[cfg(test)]
    pub(super) fn expire_provider_pause_for_tests(&self) {
        self.provider_paused_until_ms.store(0, Ordering::Release);
    }

    /// Returns whether this success ended a provider-wide failure streak, so
    /// callers run the parked-row sweep at most once per outage.
    fn provider_recovered(&self) -> bool {
        self.provider_paused_until_ms.store(0, Ordering::Release);
        self.provider_wide_streak.swap(0, Ordering::AcqRel) > 0
    }

    fn pause_provider(&self, failure: ProviderFailure) {
        let streak = self.provider_wide_streak.fetch_add(1, Ordering::AcqRel);
        let retry_after = failure.provider_wide().unwrap_or(0);
        let pause_ms = provider_pause_ms(streak, retry_after);
        let until = unix_ms().saturating_add(pause_ms);
        self.provider_paused_until_ms
            .store(until, Ordering::Release);
        self.last_provider_pause_secs
            .store((pause_ms / 1_000).max(1), Ordering::Release);
    }

    /// Deferral applied to the failing row: the same duration as the queue
    /// pause, so rows and probes restart together after an outage.
    fn provider_wide_delay_secs(&self, error: &BillingError) -> Option<f64> {
        let BillingError::Provider(failure) = error else {
            return None;
        };
        failure.provider_wide()?;
        Some(self.last_provider_pause_secs.load(Ordering::Acquire) as f64)
    }

    fn record_failure(&self, error: &BillingError, row: &str, job: &str) -> &'static str {
        let BillingError::Provider(failure) = error else {
            diagnostic_class("local", 6, "none", row, job);
            return "local";
        };
        if matches!(failure, ProviderFailure::HttpStatus(401 | 403)) {
            if job == "subscription" {
                self.subscription_authorized.store(false, Ordering::Release);
            }
            if job == "risk" {
                self.risk_authorized.store(false, Ordering::Release);
            }
        }
        if failure.provider_wide().is_some() {
            self.pause_provider(*failure);
        }
        diagnostic(*failure, row, job);
        failure.class().0
    }

    fn outcome_for(&self, error: &BillingError) -> JobOutcome {
        if let BillingError::Provider(failure) = error
            && failure.provider_wide().is_some()
        {
            return JobOutcome::ProviderDown;
        }
        JobOutcome::WorkDone
    }

    /// A successful provider communication proves the outage ended: requeue
    /// rows parked by the outage so operators no longer clear needs_review by
    /// hand. Only the first success after a provider-wide streak pays for the
    /// sweep; rows parked by row-level failures keep their review state.
    async fn requeue_parked_rows(db: &Client) -> Result<(), BillingError> {
        db.execute(
            "UPDATE billing_reconciliations SET state='queued',failed_attempts=0,last_failure_class=NULL,next_attempt_at=now(),updated_at=now() WHERE state='needs_review'",
            &[],
        )
        .await?;
        db.execute(
            "UPDATE billing_risk_events SET state='queued',failed_attempts=0,last_failure_class=NULL,next_attempt_at=now() WHERE state='needs_review'",
            &[],
        )
        .await?;
        Ok(())
    }

    pub async fn reconcile_one(&self, database_url: &str) -> Result<JobOutcome, BillingError> {
        if self.provider_paused() {
            // One probe is allowed only once the pause elapses; until then the
            // queue claims nothing and sends nothing.
            return Ok(JobOutcome::Empty);
        }
        let mut db = crate::runtime_db::connect_worker(database_url).await?;
        let Some((account_id, subscription_id, customer_id, generation)) = claim(&mut db).await?
        else {
            return Ok(JobOutcome::Empty);
        };
        let fetched = self.fetch_subscription(&subscription_id).await;
        match fetched {
            Ok(snapshot) if snapshot.subscription_id == subscription_id => {
                self.subscription_authorized.store(true, Ordering::Release);
                if self.provider_recovered() {
                    Self::requeue_parked_rows(&db).await?;
                }
                if let Err(error) = reconcile_snapshot_with_quotas(
                    &mut db,
                    account_id,
                    &snapshot,
                    &self.recognized_prices,
                    &self.quota_plans,
                    generation,
                )
                .await
                {
                    let state = backoff(&db, &subscription_id, generation, "local").await?;
                    if state.as_deref() == Some("needs_review") {
                        diagnostic_class(
                            "needs_review",
                            7,
                            "none",
                            &subscription_id,
                            "subscription",
                        );
                    }
                    return Err(error);
                }
            }
            Err(BillingError::Provider(ProviderFailure::HttpStatus(404))) => {
                self.subscription_authorized.store(true, Ordering::Release);
                if self.provider_recovered() {
                    Self::requeue_parked_rows(&db).await?;
                }
                diagnostic(
                    ProviderFailure::HttpStatus(404),
                    &subscription_id,
                    "subscription",
                );
                let snapshot = SubscriptionSnapshot {
                    subscription_id: subscription_id.clone(),
                    customer_id,
                    status: "provider_deleted".into(),
                    price_id: None,
                    latest_invoice_id: None,
                };
                if let Err(error) = reconcile_snapshot_with_quotas(
                    &mut db,
                    account_id,
                    &snapshot,
                    &self.recognized_prices,
                    &self.quota_plans,
                    generation,
                )
                .await
                {
                    backoff(&db, &subscription_id, generation, "local").await?;
                    return Err(error);
                }
            }
            result => {
                let error = result
                    .err()
                    .unwrap_or(BillingError::Provider(ProviderFailure::InvalidResponse));
                let class = self.record_failure(&error, &subscription_id, "subscription");
                let state = if let Some(delay_secs) = self.provider_wide_delay_secs(&error) {
                    defer_provider_wide(&db, &subscription_id, generation, class, delay_secs)
                        .await?
                } else {
                    backoff(&db, &subscription_id, generation, class).await?
                };
                if state.as_deref() == Some("needs_review") {
                    diagnostic_class("needs_review", 7, "none", &subscription_id, "subscription");
                }
                return Ok(self.outcome_for(&error));
            }
        }
        Ok(JobOutcome::WorkDone)
    }

    /// One bounded payment-risk job per tick. A known customer's queued risk
    /// blocks new metered reservations while the provider chain is resolved.
    pub async fn reconcile_risk_one(&self, database_url: &str) -> Result<JobOutcome, BillingError> {
        if self.provider_paused() {
            return Ok(JobOutcome::Empty);
        }
        let mut db = crate::runtime_db::connect_worker(database_url).await?;
        let Some((event_id, charge_id, payment_intent_id, kind)) = risk::claim(&mut db).await?
        else {
            return Ok(JobOutcome::Empty);
        };
        let result = async {
            let charge = if let Some(charge_id) = &charge_id {
                risk::fetch_charge(&self.http, &self.secret_key, &self.api_base, charge_id).await?
            } else if let Some(payment_intent_id) = &payment_intent_id {
                risk::fetch_charge_for_payment_intent(
                    &self.http,
                    &self.secret_key,
                    &self.api_base,
                    payment_intent_id,
                )
                .await?
            } else {
                return Err(BillingError::InvalidEvent);
            };
            if payment_intent_id
                .as_deref()
                .is_some_and(|known| known != charge.payment_intent_id)
            {
                return Err(BillingError::InvalidEvent);
            }
            if !risk::bind_charge_customer(&mut db, &event_id, &charge.customer_id).await? {
                return Err(BillingError::InvalidEvent);
            }
            if kind == "refund" && charge.amount_refunded == 0 {
                return Err(BillingError::InvalidEvent);
            }
            let subscription = risk::fetch_invoice_subscription(
                &self.http,
                &self.secret_key,
                &self.api_base,
                &charge,
            )
            .await?;
            risk::apply_hold(
                &mut db,
                &event_id,
                &charge.id,
                Some(&charge.payment_intent_id),
                &charge.customer_id,
                &subscription,
                &kind,
            )
            .await
        }
        .await;
        match result {
            Ok(()) => {
                self.risk_authorized.store(true, Ordering::Release);
                if self.provider_recovered() {
                    Self::requeue_parked_rows(&db).await?;
                }
                Ok(JobOutcome::WorkDone)
            }
            Err(error) if matches!(error, BillingError::Database(_)) => Err(error),
            Err(error) => {
                let class = self.record_failure(&error, &event_id, "risk");
                let state = if let Some(delay_secs) = self.provider_wide_delay_secs(&error) {
                    risk::defer_provider_wide(&db, &event_id, class, delay_secs).await?
                } else {
                    risk::backoff(&db, &event_id, class).await?
                };
                if state.as_deref() == Some("needs_review") {
                    diagnostic_class("needs_review", 7, "none", &event_id, "risk");
                }
                // A provider read, unresolved binding or attribution failure
                // is retained for retry and later review.
                Ok(self.outcome_for(&error))
            }
        }
    }

    async fn fetch_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionSnapshot, BillingError> {
        valid_id(subscription_id, "sub_")?;
        let url = format!("{}/v1/subscriptions/{subscription_id}", self.api_base);
        let mut response = self
            .http
            .get(url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .map_err(|_| ProviderFailure::Transport)?;
        if !response.status().is_success() {
            return Err(provider_failure_from_status(&response).into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProviderFailure::Transport)?
        {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(ProviderFailure::InvalidResponse.into());
            }
            body.extend_from_slice(&chunk);
        }
        parse_subscription(&body).map_err(|_| ProviderFailure::InvalidResponse.into())
    }
}

pub(super) fn parse_subscription(body: &[u8]) -> Result<SubscriptionSnapshot, BillingError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| BillingError::InvalidEvent)?;
    if value["object"] != "subscription" || value["livemode"] != false {
        return Err(BillingError::InvalidEvent);
    }
    let subscription_id = valid_id(
        value["id"].as_str().ok_or(BillingError::InvalidEvent)?,
        "sub_",
    )?
    .to_owned();
    let customer_id = valid_id(
        value["customer"]
            .as_str()
            .ok_or(BillingError::InvalidEvent)?,
        "cus_",
    )?
    .to_owned();
    let status = value["status"]
        .as_str()
        .ok_or(BillingError::InvalidEvent)?
        .to_owned();
    if !matches!(
        status.as_str(),
        "incomplete"
            | "incomplete_expired"
            | "trialing"
            | "active"
            | "past_due"
            | "canceled"
            | "unpaid"
            | "paused"
    ) {
        return Err(BillingError::InvalidEvent);
    }
    // A partial or malformed list cannot prove the single-price entitlement.
    // Leave reconciliation pending so metered sends remain blocked.
    if value["items"]["object"] != "list" || value["items"]["has_more"] != false {
        return Err(BillingError::InvalidEvent);
    }
    let items = value["items"]["data"]
        .as_array()
        .ok_or(BillingError::InvalidEvent)?;
    let price_id = if items.len() == 1 {
        Some(
            valid_id(
                items[0]["price"]["id"]
                    .as_str()
                    .ok_or(BillingError::InvalidEvent)?,
                "price_",
            )?
            .to_owned(),
        )
    } else {
        None
    };
    let latest_invoice_id = value["latest_invoice"]
        .as_str()
        .or_else(|| value["latest_invoice"]["id"].as_str())
        .map(|id| valid_id(id, "in_"))
        .transpose()?
        .map(str::to_owned);
    Ok(SubscriptionSnapshot {
        subscription_id,
        customer_id,
        status,
        price_id,
        latest_invoice_id,
    })
}

pub(super) async fn claim(
    db: &mut Client,
) -> Result<Option<(Uuid, String, String, i64)>, BillingError> {
    let tx = db.transaction().await?;
    let row = tx.query_opt(
        "WITH target AS (SELECT stripe_subscription_id FROM billing_reconciliations WHERE state='queued' AND dirty_generation>processed_generation AND next_attempt_at<=now() ORDER BY next_attempt_at,stripe_subscription_id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE billing_reconciliations b SET next_attempt_at=now()+interval '30 seconds' FROM target WHERE b.stripe_subscription_id=target.stripe_subscription_id RETURNING b.account_id,b.stripe_subscription_id,b.stripe_customer_id,b.dirty_generation",
        &[],
    ).await?;
    tx.commit().await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))))
}

async fn backoff(
    db: &Client,
    subscription_id: &str,
    generation: i64,
    class: &str,
) -> Result<Option<String>, BillingError> {
    let row = db.query_opt(
        // Row-level failures back off exponentially: one minute doubling per
        // attempt, capped at one hour. Provider-wide failures never count here.
        "UPDATE billing_reconciliations SET failed_attempts=least(failed_attempts+1,$4),state=CASE WHEN failed_attempts+1 >= $4 THEN 'needs_review' ELSE 'queued' END,last_failure_class=$3,next_attempt_at=now()+make_interval(secs => least(3600, 60 * (1 << least(failed_attempts,5)))),updated_at=now() WHERE stripe_subscription_id=$1 AND dirty_generation=$2 AND processed_generation<$2 AND state='queued' RETURNING state",
        &[&subscription_id, &generation, &class, &MAX_FAILURES],
    ).await?;
    Ok(row.map(|row| row.get(0)))
}

/// Provider-wide failures defer the row without counting toward review: the
/// row stays queued and restarts with the next probe after the pause.
async fn defer_provider_wide(
    db: &Client,
    subscription_id: &str,
    generation: i64,
    class: &str,
    delay_secs: f64,
) -> Result<Option<String>, BillingError> {
    let row = db.query_opt(
        "UPDATE billing_reconciliations SET last_failure_class=$3,next_attempt_at=now()+make_interval(secs => $4),updated_at=now() WHERE stripe_subscription_id=$1 AND dirty_generation=$2 AND processed_generation<$2 AND state='queued' RETURNING state",
        &[&subscription_id, &generation, &class, &delay_secs],
    ).await?;
    Ok(row.map(|row| row.get(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_postgres::NoTls;

    async fn fake_provider(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.readable().await.unwrap();
            let mut input = [0u8; 4096];
            let _ = stream.try_read(&mut input).unwrap();
            let response = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let mut remaining = response.as_bytes();
            while !remaining.is_empty() {
                stream.writable().await.unwrap();
                let written = stream.try_write(remaining).unwrap();
                remaining = &remaining[written..];
            }
        });
        format!("http://{addr}")
    }

    fn test_worker(api_base: String) -> StripeTestWorker {
        let mut worker = StripeTestWorker::new_with_quotas(
            "rk_test_fixture123456".into(),
            vec!["price_fixture1".into()],
            vec![TestQuotaPlan {
                price_id: "price_fixture1".into(),
                outbound_limit: 5,
                device_limit: None,
            }],
        )
        .unwrap();
        worker.http = HttpClient::builder().no_proxy().build().unwrap();
        worker.api_base = api_base;
        worker
    }

    #[tokio::test]
    async fn fake_provider_preserves_status_and_never_exposes_body() {
        for status in [401, 403, 404, 429, 500] {
            let worker = test_worker(fake_provider(status, "private provider response").await);
            let error = worker.fetch_subscription("sub_fixture1").await.unwrap_err();
            assert!(
                matches!(&error, BillingError::Provider(ProviderFailure::HttpStatus(code)) if *code == status)
            );
            let message = error.to_string();
            assert!(message.contains(&status.to_string()));
            assert!(!message.contains("private provider response"));
            assert!(!message.contains("rk_test_fixture123456"));
        }
        let worker = test_worker(fake_provider(200, "private malformed response").await);
        assert!(matches!(
            worker.fetch_subscription("sub_fixture1").await,
            Err(BillingError::Provider(ProviderFailure::InvalidResponse))
        ));
        let risk_base = fake_provider(403, "private risk response").await;
        let risk_http = HttpClient::builder().no_proxy().build().unwrap();
        assert!(matches!(
            risk::fetch_charge(
                &risk_http,
                "rk_test_fixture123456",
                &risk_base,
                "ch_fixture1"
            )
            .await,
            Err(BillingError::Provider(ProviderFailure::HttpStatus(403)))
        ));
        let worker = StripeTestWorker::new(
            "rk_test_fixture123456".into(),
            vec!["price_fixture1".into()],
        )
        .unwrap();
        worker.record_failure(
            &BillingError::Provider(ProviderFailure::HttpStatus(403)),
            "evt_fixture1",
            "risk",
        );
        let (subscription, risk) = worker.authorization_state();
        assert!(subscription.load(Ordering::Acquire));
        assert!(!risk.load(Ordering::Acquire));
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_provider_403_review_and_404_deleted_projection() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_provider_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
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
            include_str!(
                "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_fixture1')", &[&account]).await.unwrap();
        db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES('sub_fixture1',$1,'cus_fixture1')", &[&account]).await.unwrap();
        let first = SubscriptionSnapshot {
            subscription_id: "sub_fixture1".into(),
            customer_id: "cus_fixture1".into(),
            status: "active".into(),
            price_id: Some("price_fixture1".into()),
            latest_invoice_id: None,
        };
        let plans = vec![TestQuotaPlan {
            price_id: "price_fixture1".into(),
            outbound_limit: 5,
            device_limit: None,
        }];
        reconcile_snapshot_with_quotas(
            &mut db,
            account,
            &first,
            &["price_fixture1".into()],
            &plans,
            1,
        )
        .await
        .unwrap();
        db.execute("UPDATE billing_reconciliations SET dirty_generation=2 WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();

        let worker = test_worker(fake_provider(403, "secret response").await);
        assert_eq!(
            worker.reconcile_one(&scoped_url).await.unwrap(),
            JobOutcome::ProviderDown
        );
        assert!(!worker.authorization_state().0.load(Ordering::Acquire));
        let row = db.query_one("SELECT failed_attempts,state,last_failure_class,next_attempt_at>now()+interval '20 seconds' AND next_attempt_at<now()+interval '40 seconds' FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        // Provider-wide failures never count toward review and defer the row.
        assert_eq!(row.get::<_, i32>(0), 0);
        assert_eq!(row.get::<_, String>(1), "queued");
        assert_eq!(row.get::<_, String>(2), "authorization");
        assert!(row.get::<_, bool>(3));
        // A paused queue claims nothing and sends nothing until it elapses.
        assert_eq!(
            worker.reconcile_one(&scoped_url).await.unwrap(),
            JobOutcome::Empty
        );
        // Row-level failures still park rows in needs_review at the cap; the
        // 403 above did not count, so all MAX_FAILURES attempts come from here.
        for _ in 0..MAX_FAILURES {
            backoff(&db, "sub_fixture1", 2, "invalid_response")
                .await
                .unwrap();
        }
        let row = db.query_one("SELECT failed_attempts,state FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), MAX_FAILURES);
        assert_eq!(row.get::<_, String>(1), "needs_review");
        assert!(claim(&mut db).await.unwrap().is_none());

        db.execute("UPDATE billing_reconciliations SET state='queued',failed_attempts=0,next_attempt_at=now() WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        let worker = test_worker(fake_provider(404, "secret response").await);
        assert_eq!(
            worker.reconcile_one(&scoped_url).await.unwrap(),
            JobOutcome::WorkDone
        );
        let row = db.query_one("SELECT dirty_generation=processed_generation,state FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert!(row.get::<_, bool>(0));
        assert_eq!(row.get::<_, String>(1), "queued");
        let row = db.query_one("SELECT stripe_status FROM billing_subscriptions WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "provider_deleted");
        let row = db.query_one("SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'", &[&account]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        let row = db.query_one("SELECT reason FROM billing_quota_audit WHERE account_id=$1 ORDER BY id DESC LIMIT 1", &[&account]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "provider_deleted");
        db.execute("INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES('evt_fixture1','charge.refunded',$1,$2,'queued')", &[&account, &vec![0u8; 32]]).await.unwrap();
        db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES('evt_fixture1','ch_fixture1','refund',$1)", &[&account]).await.unwrap();
        let worker = test_worker(fake_provider(403, "secret risk response").await);
        assert_eq!(
            worker.reconcile_risk_one(&scoped_url).await.unwrap(),
            JobOutcome::ProviderDown
        );
        assert!(!worker.authorization_state().1.load(Ordering::Acquire));
        let row = db.query_one("SELECT failed_attempts,state,last_failure_class FROM billing_risk_events WHERE stripe_event_id='evt_fixture1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), 0);
        assert_eq!(row.get::<_, String>(1), "queued");
        assert_eq!(row.get::<_, String>(2), "authorization");
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[test]
    fn worker_accepts_restricted_test_key_but_rejects_live_keys() {
        assert!(
            StripeTestWorker::new(
                "rk_test_fixture123456".into(),
                vec!["price_fixture1".into()]
            )
            .is_ok()
        );
        for key in ["rk_live_fixture123456", "sk_live_fixture123456"] {
            assert!(StripeTestWorker::new(key.into(), vec!["price_fixture1".into()]).is_err());
        }
    }

    #[test]
    fn parses_current_test_subscription_shape() {
        let fixture = br#"{"id":"sub_fixture1","object":"subscription","livemode":false,"customer":"cus_fixture1","status":"past_due","latest_invoice":"in_fixture1","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_fixture1"}}]}}"#;
        let parsed = parse_subscription(fixture).unwrap();
        assert_eq!(parsed.status, "past_due");
        assert_eq!(parsed.price_id.as_deref(), Some("price_fixture1"));
        assert_eq!(parsed.latest_invoice_id.as_deref(), Some("in_fixture1"));
        assert!(parse_subscription(&fixture.replace_bytes(b"false", b"true")).is_err());
    }

    #[test]
    fn incomplete_subscription_items_cannot_grant_a_recognized_plan() {
        let complete = serde_json::json!({
            "id": "sub_fixture1", "object": "subscription", "livemode": false,
            "customer": "cus_fixture1", "status": "active",
            "items": {"object": "list", "has_more": false,
                "data": [{"price": {"id": "price_fixture1"}}]}
        });
        assert!(parse_subscription(&serde_json::to_vec(&complete).unwrap()).is_ok());
        for invalid in [
            serde_json::json!(true),
            serde_json::Value::Null,
            serde_json::json!("false"),
        ] {
            let mut value = complete.clone();
            value["items"]["has_more"] = invalid;
            assert!(parse_subscription(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = complete;
        value["items"]["object"] = serde_json::json!("subscription_item");
        assert!(parse_subscription(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    trait ReplaceBytes {
        fn replace_bytes(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
    }
    impl ReplaceBytes for [u8] {
        fn replace_bytes(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
            let at = self.windows(from.len()).position(|w| w == from).unwrap();
            let mut bytes = self.to_vec();
            bytes.splice(at..at + from.len(), to.iter().copied());
            bytes
        }
    }
}
