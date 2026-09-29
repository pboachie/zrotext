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
/// Failure classes only a provider outage records. Since #483 those failures
/// defer rows instead of reaching `backoff`, so a review row carrying one was
/// parked by an outage under the old accounting and is safe to requeue.
const OUTAGE_PARKED_CLASSES: [&str; 2] = ["authorization", "transport"];

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

    /// A successful provider read ends the pause at once. The failure streak
    /// (which drives both escalation and the parked-row sweep) is reset only
    /// after the sweep commits, so a sweep that fails is retried by the next
    /// success instead of being skipped for the rest of the outage.
    async fn provider_recovered(&self, db: &mut Client) {
        self.provider_paused_until_ms.store(0, Ordering::Release);
        let streak = self.provider_wide_streak.load(Ordering::Acquire);
        if streak == 0 {
            return;
        }
        match Self::requeue_outage_parked_rows(db).await {
            Ok(()) => {
                // A failure recorded while the sweep ran belongs to a new
                // streak; keep it instead of overwriting it with zero.
                let _ = self.provider_wide_streak.compare_exchange(
                    streak,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            // The row that proved recovery still gets reconciled; the streak
            // stays so the next success repeats the sweep.
            Err(_) => diagnostic_class("recovery_sweep", 3, "none", "sweep", "recovery"),
        }
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

    /// Requeue only rows that a provider outage parked. Provider-wide failures
    /// now defer rows without counting toward review, so `backoff` is never
    /// handed a provider-wide class (see `OUTAGE_PARKED_CLASSES`): a
    /// needs_review row whose recorded class is `authorization` or
    /// `transport` can only have been parked by the pre-#483 worker, which
    /// counted outages toward review. `http` is excluded because that worker
    /// used it for both 429/5xx and row-level 4xx. Row-level, tenant-conflict
    /// (`local`) and ingestion review rows (class NULL) are never touched.
    /// The failure class is kept as evidence; only the retry budget, which
    /// the outage consumed, is restored. Both tables change in one
    /// transaction so a failed sweep leaves nothing half-applied.
    async fn requeue_outage_parked_rows(db: &mut Client) -> Result<(), BillingError> {
        let tx = db.transaction().await?;
        tx.execute(
            "UPDATE billing_reconciliations SET state='queued',failed_attempts=0,next_attempt_at=now(),updated_at=now() WHERE state='needs_review' AND last_failure_class = ANY($1)",
            &[&OUTAGE_PARKED_CLASSES.as_slice()],
        )
        .await?;
        // Migration 023 keeps pointerless risk events in needs_review.
        tx.execute(
            "UPDATE billing_risk_events SET state='queued',failed_attempts=0,next_attempt_at=now() WHERE state='needs_review' AND last_failure_class = ANY($1) AND (stripe_charge_id IS NOT NULL OR stripe_payment_intent_id IS NOT NULL)",
            &[&OUTAGE_PARKED_CLASSES.as_slice()],
        )
        .await?;
        tx.commit().await?;
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
        // Release the worker socket for the provider read: a slow or
        // unreachable Stripe must not hold one of the worker slots. The
        // claim's 30-second retry window keeps the row owned meanwhile.
        drop(db);
        let fetched = match self.fetch_subscription(&subscription_id).await {
            Ok(snapshot) if snapshot.subscription_id == subscription_id => Ok(snapshot),
            Err(BillingError::Provider(ProviderFailure::HttpStatus(404))) => Err(None),
            result => {
                let error = result
                    .err()
                    .unwrap_or(BillingError::Provider(ProviderFailure::InvalidResponse));
                // Record the failure, and with it any provider pause, before
                // reconnecting: a failed reconnect must not lose the pause.
                let class = self.record_failure(&error, &subscription_id, "subscription");
                Err(Some((error, class)))
            }
        };
        let mut db = crate::runtime_db::connect_worker(database_url).await?;
        match fetched {
            Ok(snapshot) => {
                self.subscription_authorized.store(true, Ordering::Release);
                self.provider_recovered(&mut db).await;
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
            Err(None) => {
                self.subscription_authorized.store(true, Ordering::Release);
                self.provider_recovered(&mut db).await;
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
            Err(Some((error, class))) => {
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
        // Fetch the charge with no worker socket held. The claim's 30-second
        // retry window keeps the event owned meanwhile.
        drop(db);
        let charge = async {
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
            Ok(charge)
        }
        .await;
        let charge = match charge {
            Ok(charge) => charge,
            Err(error) => {
                // Pause before reconnecting so a failed reconnect cannot
                // lose it.
                let class = self.record_failure(&error, &event_id, "risk");
                let db = crate::runtime_db::connect_worker(database_url).await?;
                return self
                    .risk_failure_recorded(&db, &event_id, &error, class)
                    .await;
            }
        };
        let mut db = crate::runtime_db::connect_worker(database_url).await?;
        match risk::bind_charge_customer(&mut db, &event_id, &charge.customer_id).await {
            Ok(true) => {}
            Ok(false) => {
                return self
                    .risk_failure(&db, &event_id, BillingError::InvalidEvent)
                    .await;
            }
            Err(error) if matches!(error, BillingError::Database(_)) => return Err(error),
            // A tenant conflict (or an invalid pointer) is a row-level
            // failure: back off and reach review at the cap instead of
            // being re-claimed every 30 seconds forever.
            Err(error) => return self.risk_failure(&db, &event_id, error).await,
        }
        if kind == "refund" && charge.amount_refunded == 0 {
            return self
                .risk_failure(&db, &event_id, BillingError::InvalidEvent)
                .await;
        }
        // Release the socket again for the invoice read.
        drop(db);
        let subscription = match risk::fetch_invoice_subscription(
            &self.http,
            &self.secret_key,
            &self.api_base,
            &charge,
        )
        .await
        {
            Ok(subscription) => subscription,
            Err(error) => {
                let class = self.record_failure(&error, &event_id, "risk");
                let db = crate::runtime_db::connect_worker(database_url).await?;
                return self
                    .risk_failure_recorded(&db, &event_id, &error, class)
                    .await;
            }
        };
        let mut db = crate::runtime_db::connect_worker(database_url).await?;
        let result = risk::apply_hold(
            &mut db,
            &event_id,
            &charge.id,
            Some(&charge.payment_intent_id),
            &charge.customer_id,
            &subscription,
            &kind,
        )
        .await;
        match result {
            Ok(()) => {
                self.risk_authorized.store(true, Ordering::Release);
                self.provider_recovered(&mut db).await;
                Ok(JobOutcome::WorkDone)
            }
            Err(error) if matches!(error, BillingError::Database(_)) => Err(error),
            Err(error) => self.risk_failure(&db, &event_id, error).await,
        }
    }

    /// Records one failed risk job and leaves it queued for bounded retry. A
    /// provider-wide failure defers the row by the provider pause instead of
    /// the per-row backoff and reports `ProviderDown` to end the drain.
    async fn risk_failure(
        &self,
        db: &crate::runtime_db::PooledClient,
        event_id: &str,
        error: BillingError,
    ) -> Result<JobOutcome, BillingError> {
        let class = self.record_failure(&error, event_id, "risk");
        self.risk_failure_recorded(db, event_id, &error, class)
            .await
    }

    /// The database half of `risk_failure`, for callers that already
    /// recorded the failure (and set any pause) before reconnecting.
    async fn risk_failure_recorded(
        &self,
        db: &crate::runtime_db::PooledClient,
        event_id: &str,
        error: &BillingError,
        class: &'static str,
    ) -> Result<JobOutcome, BillingError> {
        let state = if let Some(delay_secs) = self.provider_wide_delay_secs(error) {
            risk::defer_provider_wide(db, event_id, class, delay_secs).await?
        } else {
            risk::backoff(db, event_id, class).await?
        };
        if state.as_deref() == Some("needs_review") {
            diagnostic_class("needs_review", 7, "none", event_id, "risk");
        }
        // A provider read, unresolved binding or attribution failure
        // is retained for retry and later review.
        Ok(self.outcome_for(error))
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
        // Row-level failures back off exponentially from the pre-increment
        // count: 1, 2, 4, 8, 16, then 32 minutes for every later attempt (the
        // 3600-second bound is never reached). Provider-wide failures never
        // count here.
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
        fake_provider_with_headers(status, "", body).await
    }

    /// One-shot fake provider. `headers` is inserted verbatim, each line
    /// ending in CRLF.
    async fn fake_provider_with_headers(
        status: u16,
        headers: &'static str,
        body: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.readable().await.unwrap();
            let mut input = [0u8; 4096];
            let _ = stream.try_read(&mut input).unwrap();
            let response = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",
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
        // Same retry policy as production and `with_test_server`: one request
        // per job, so every fixture response maps to exactly one outcome.
        worker.http = HttpClient::builder()
            .no_proxy()
            .retry(retry::never())
            .build()
            .unwrap();
        worker.api_base = api_base;
        worker
    }

    /// A fresh schema with every migration the billing worker touches,
    /// including 023's pointer-or-review check and 024's risk states.
    async fn billing_schema(prefix: &str) -> (Client, Client, String, String) {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
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
            include_str!(
                "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
            ),
            include_str!(
                "../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        (setup, db, scoped_url, schema)
    }

    /// Account, bound customer and one queued refund risk event.
    async fn queued_risk_event(db: &Client, event: &str, charge: &str, customer: &str) {
        let account = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
            &[&account, &customer],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES($1,'charge.refunded',$2,$3,'queued')", &[&event, &account, &vec![0u8; 32]]).await.unwrap();
        // Backdated: a worker session's now() can trail this session's.
        db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id,next_attempt_at) VALUES($1,$2,'refund',$3,now()-interval '1 minute')", &[&event, &charge, &account]).await.unwrap();
    }

    #[test]
    fn provider_wide_classification_covers_every_status() {
        for status in 100..=599u16 {
            let expected = matches!(status, 401 | 403 | 429 | 500..=599).then_some(0);
            assert_eq!(
                ProviderFailure::HttpStatus(status).provider_wide(),
                expected,
                "status {status}"
            );
        }
        for status in [400u16, 402, 404, 408, 409, 422] {
            assert_eq!(ProviderFailure::HttpStatus(status).provider_wide(), None);
        }
        assert_eq!(ProviderFailure::Transport.provider_wide(), Some(0));
        assert_eq!(ProviderFailure::InvalidResponse.provider_wide(), None);
        assert_eq!(
            ProviderFailure::RateLimited {
                retry_after_secs: 7
            }
            .provider_wide(),
            Some(7)
        );
        // The recovery sweep trusts that a row-level failure (the only kind
        // that reaches `backoff`) never records an outage-only class.
        let mut failures: Vec<ProviderFailure> =
            (100..=599u16).map(ProviderFailure::HttpStatus).collect();
        failures.extend([
            ProviderFailure::Transport,
            ProviderFailure::InvalidResponse,
            ProviderFailure::RateLimited {
                retry_after_secs: 1,
            },
        ]);
        for failure in failures {
            let class = failure.class().0;
            if failure.provider_wide().is_none() {
                assert!(
                    !OUTAGE_PARKED_CLASSES.contains(&class),
                    "{failure:?} reaches backoff with outage class {class}"
                );
            }
        }
        assert!(!OUTAGE_PARKED_CLASSES.contains(&"local"));
    }

    #[test]
    fn provider_pause_escalates_and_is_capped() {
        assert_eq!(provider_pause_ms(0, 0), 30_000);
        assert_eq!(provider_pause_ms(1, 0), 60_000);
        assert_eq!(provider_pause_ms(2, 0), 120_000);
        assert_eq!(provider_pause_ms(4, 0), 480_000);
        assert_eq!(provider_pause_ms(5, 0), 600_000);
        for streak in 0..=40 {
            assert!(provider_pause_ms(streak, 0) <= 600_000, "streak {streak}");
        }
        assert_eq!(provider_pause_ms(u32::MAX, 0), 600_000);
        // A supplied Retry-After replaces escalation but never the cap.
        assert_eq!(provider_pause_ms(0, 1), 1_000);
        assert_eq!(provider_pause_ms(7, 120), 120_000);
        assert_eq!(provider_pause_ms(0, 86_400), 600_000);
        assert_eq!(provider_pause_ms(0, u64::MAX), 600_000);
    }

    #[tokio::test]
    async fn retry_after_is_capped_at_parse_and_in_the_pause() {
        let worker = test_worker(
            fake_provider_with_headers(429, "Retry-After: 86400\r\n", "slow down").await,
        );
        let error = worker.fetch_subscription("sub_fixture1").await.unwrap_err();
        assert!(matches!(
            error,
            BillingError::Provider(ProviderFailure::RateLimited {
                retry_after_secs: 600
            })
        ));
        let before = unix_ms();
        worker.record_failure(&error, "sub_fixture1", "subscription");
        let until = worker.provider_paused_until_ms.load(Ordering::Acquire);
        assert!(until <= unix_ms() + 600_000 && until >= before + 599_000);
        assert_eq!(
            worker.provider_wide_delay_secs(&error),
            Some(600.0),
            "row deferral follows the capped pause"
        );
        // Non-numeric Retry-After falls back to the scheduled pause.
        let worker = test_worker(
            fake_provider_with_headers(429, "Retry-After: soon\r\n", "slow down").await,
        );
        assert!(matches!(
            worker.fetch_subscription("sub_fixture1").await,
            Err(BillingError::Provider(ProviderFailure::HttpStatus(429)))
        ));
    }

    #[tokio::test]
    async fn paused_queues_claim_nothing_and_touch_no_database() {
        let worker = test_worker("http://127.0.0.1:9".into());
        worker.record_failure(
            &BillingError::Provider(ProviderFailure::HttpStatus(503)),
            "sub_fixture1",
            "subscription",
        );
        assert!(worker.provider_paused());
        // An unreachable database proves neither queue even connects while
        // the shared pause is active.
        let unreachable = "postgres://zrotext@127.0.0.1:9/none";
        assert_eq!(
            worker.reconcile_one(unreachable).await.unwrap(),
            JobOutcome::Empty
        );
        assert_eq!(
            worker.reconcile_risk_one(unreachable).await.unwrap(),
            JobOutcome::Empty
        );
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_risk_invoice_outage_pauses_without_counting() {
        let (setup, db, scoped_url, schema) = billing_schema("billing_risk_invoice").await;
        queued_risk_event(&db, "evt_invoice1", "ch_invoice1", "cus_invoice1").await;
        let charges = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invoices = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/v1/charges/{charge_id}",
                axum::routing::get({
                    let charges = charges.clone();
                    move || {
                        let charges = charges.clone();
                        async move {
                            charges.fetch_add(1, Ordering::SeqCst);
                            axum::Json(serde_json::json!({"id":"ch_invoice1","object":"charge","livemode":false,"customer":"cus_invoice1","payment_intent":"pi_invoice1","amount_refunded":100}))
                        }
                    }
                }),
            )
            .route(
                "/v1/invoice_payments",
                axum::routing::get({
                    let invoices = invoices.clone();
                    move || {
                        let invoices = invoices.clone();
                        async move {
                            invoices.fetch_add(1, Ordering::SeqCst);
                            axum::http::StatusCode::SERVICE_UNAVAILABLE
                        }
                    }
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let worker = test_worker(format!("http://{address}"));
        assert_eq!(
            worker.reconcile_risk_one(&scoped_url).await.unwrap(),
            JobOutcome::ProviderDown
        );
        assert_eq!(charges.load(Ordering::SeqCst), 1);
        assert_eq!(invoices.load(Ordering::SeqCst), 1);
        let row = db.query_one("SELECT failed_attempts,state,last_failure_class,next_attempt_at>now()+interval '20 seconds' AND next_attempt_at<now()+interval '40 seconds' FROM billing_risk_events WHERE stripe_event_id='evt_invoice1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), 0, "outage must not count");
        assert_eq!(row.get::<_, String>(1), "queued");
        assert_eq!(row.get::<_, String>(2), "http");
        assert!(row.get::<_, bool>(3), "row defers by the provider pause");
        assert!(worker.provider_paused());
        assert!(worker.authorization_state().1.load(Ordering::Acquire));
        server.abort();
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_risk_tenant_conflict_backs_off_to_review() {
        const CHARGE: &str = r#"{"id":"ch_conflict1","object":"charge","livemode":false,"customer":"cus_conflict1","payment_intent":"pi_conflict1","amount_refunded":100}"#;
        let (setup, db, scoped_url, schema) = billing_schema("billing_risk_conflict").await;
        queued_risk_event(&db, "evt_conflict1", "ch_conflict1", "cus_conflict1").await;
        // The signed event names another customer than the current Charge.
        db.execute(
            "UPDATE billing_events SET stripe_customer_id='cus_other1' WHERE stripe_event_id='evt_conflict1'",
            &[],
        )
        .await
        .unwrap();
        let worker = test_worker(fake_provider(200, CHARGE).await);
        assert_eq!(
            worker.reconcile_risk_one(&scoped_url).await.unwrap(),
            JobOutcome::WorkDone
        );
        assert!(!worker.provider_paused());
        let row = db.query_one("SELECT failed_attempts,state,last_failure_class,next_attempt_at>now()+interval '50 seconds' FROM billing_risk_events WHERE stripe_event_id='evt_conflict1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), 1, "tenant conflict must count");
        assert_eq!(row.get::<_, String>(1), "queued");
        assert_eq!(row.get::<_, String>(2), "local");
        assert!(row.get::<_, bool>(3), "row-level backoff, not the claim");
        db.execute("UPDATE billing_risk_events SET failed_attempts=9,next_attempt_at=now()-interval '1 minute' WHERE stripe_event_id='evt_conflict1'", &[]).await.unwrap();
        let worker = test_worker(fake_provider(200, CHARGE).await);
        assert_eq!(
            worker.reconcile_risk_one(&scoped_url).await.unwrap(),
            JobOutcome::WorkDone
        );
        let row = db.query_one("SELECT failed_attempts,state,last_failure_class FROM billing_risk_events WHERE stripe_event_id='evt_conflict1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), 10);
        assert_eq!(row.get::<_, String>(1), "needs_review");
        assert_eq!(row.get::<_, String>(2), "local");
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_risk_row_level_failures_back_off_per_row() {
        let (setup, db, scoped_url, schema) = billing_schema("billing_risk_rowlevel").await;
        // 400 and 404 are row-level: counted once, backed off one minute,
        // and no provider pause.
        for (status, event, charge, class) in [
            (400u16, "evt_rowlevel1", "ch_rowlevel1", "http"),
            (404, "evt_rowlevel2", "ch_rowlevel2", "missing"),
        ] {
            let customer = format!("cus_{}", &event[4..]);
            queued_risk_event(&db, event, charge, &customer).await;
            let worker = test_worker(fake_provider(status, "row response").await);
            assert_eq!(
                worker.reconcile_risk_one(&scoped_url).await.unwrap(),
                JobOutcome::WorkDone,
                "status {status}"
            );
            assert!(!worker.provider_paused(), "status {status} paused");
            let row = db.query_one("SELECT failed_attempts,state,last_failure_class,extract(epoch FROM next_attempt_at-now())::float8 FROM billing_risk_events WHERE stripe_event_id=$1", &[&event]).await.unwrap();
            assert_eq!(row.get::<_, i32>(0), 1, "status {status}");
            assert_eq!(row.get::<_, String>(1), "queued");
            assert_eq!(row.get::<_, String>(2), class);
            let delay = row.get::<_, f64>(3);
            assert!((50.0..70.0).contains(&delay), "delay {delay}");
        }
        // Each later failure counts exactly one and doubles the delay up to
        // 32 minutes; the tenth parks the event for review.
        for attempts in 2..=10 {
            let state = risk::backoff(&db, "evt_rowlevel1", "http").await.unwrap();
            let row = db.query_one("SELECT failed_attempts,extract(epoch FROM next_attempt_at-now())::float8 FROM billing_risk_events WHERE stripe_event_id='evt_rowlevel1'", &[]).await.unwrap();
            assert_eq!(row.get::<_, i32>(0), attempts);
            let expected = 60.0 * f64::from(1u32 << (attempts - 1).min(5));
            let delay = row.get::<_, f64>(1);
            assert!(
                (delay - expected).abs() < 10.0,
                "attempt {attempts}: {delay} vs {expected}"
            );
            let expected_state = if attempts == 10 {
                "needs_review"
            } else {
                "queued"
            };
            assert_eq!(state.as_deref(), Some(expected_state), "attempt {attempts}");
        }
        assert_eq!(
            risk::backoff(&db, "evt_rowlevel1", "http").await.unwrap(),
            None,
            "a parked event takes no further backoff"
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
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
        // Due times written by this session are backdated: a worker session's
        // now() can trail it slightly (seen on Docker Desktop), and a row due
        // "now" would then look not yet due to the claim.
        db.execute("UPDATE billing_reconciliations SET dirty_generation=2,next_attempt_at=now()-interval '1 minute' WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();

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

        db.execute("UPDATE billing_reconciliations SET state='queued',failed_attempts=0,next_attempt_at=now()-interval '1 minute' WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
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
        db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id,next_attempt_at) VALUES('evt_fixture1','ch_fixture1','refund',$1,now()-interval '1 minute')", &[&account]).await.unwrap();
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
