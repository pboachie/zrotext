// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit TEST-only HTTPS forwarding of already finalized local usage.
use reqwest::{Client, Url};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};
use zrotext_delivery_store::billable::{
    MeterRequest, MeterResponse, TestMeterTransport, TestUsageWorker,
};

const ENDPOINT: &str = "https://api.stripe.com/v1/billing/meter_events";
const MAX_BODY: usize = 16384;

pub struct StripeTestMeterTransport {
    http: Client,
    key: zeroize::Zeroizing<String>,
    endpoint: Url,
}
impl StripeTestMeterTransport {
    pub fn configured(
        enabled: bool,
        billing_test: bool,
        key: Option<String>,
    ) -> Result<Option<Self>, &'static str> {
        if !enabled {
            return Ok(None);
        }
        if !billing_test {
            return Err("TEST meter forwarding requires TEST billing");
        }
        Self::new(key.ok_or("TEST meter credential unavailable")?).map(Some)
    }
    pub fn new(key: String) -> Result<Self, &'static str> {
        if !super::is_test_api_key(&key)
            || key.len() > 256
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("invalid Stripe TEST meter credential");
        }
        let http = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .build()
            .map_err(|_| "invalid Stripe TEST meter client")?;
        Ok(Self {
            http,
            key: zeroize::Zeroizing::new(key),
            endpoint: Url::parse(ENDPOINT).expect("fixed HTTPS endpoint"),
        })
    }
    async fn send(&self, request: MeterRequest) -> MeterResponse {
        if request.identifier.is_empty()
            || request.identifier.len() > 128
            || !request
                .identifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || request.idempotency_key != request.identifier
            || request.units != 1
            || request.timestamp <= 0
            || request.api_version != "2025-07-30.basil"
            || super::valid_id(&request.customer_id, "cus_").is_err()
            || request.event_name.is_empty()
            || request.event_name.len() > 100
            || !request
                .event_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return MeterResponse::InvalidResponse;
        }
        let params = [
            ("event_name", request.event_name.clone()),
            ("identifier", request.identifier.clone()),
            ("timestamp", request.timestamp.to_string()),
            ("payload[value]", request.units.to_string()),
            ("payload[stripe_customer_id]", request.customer_id.clone()),
        ];
        let result = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(self.key.as_str())
            .header("Stripe-Version", request.api_version)
            .header("Idempotency-Key", &request.idempotency_key)
            .form(&params)
            .send()
            .await;
        let Ok(mut response) = result else {
            return MeterResponse::Unknown;
        };
        if response.url() != &self.endpoint {
            return MeterResponse::Unknown;
        }
        let status = response.status().as_u16();
        if status != 200 {
            let retry_after_seconds = response
                .headers()
                .get("Retry-After")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
                .min(600);
            return MeterResponse::Http {
                status,
                retry_after_seconds,
            };
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
        {
            return MeterResponse::Unknown;
        }
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_BODY => bytes.extend(chunk),
                Ok(None) => break,
                _ => return MeterResponse::Unknown,
            }
        }
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return MeterResponse::Unknown;
        };
        if value.get("object").and_then(Value::as_str) != Some("billing.meter_event")
            || value.get("identifier").and_then(Value::as_str) != Some(request.identifier.as_str())
            || value.get("event_name").and_then(Value::as_str) != Some(request.event_name.as_str())
            || value.get("livemode").and_then(Value::as_bool) != Some(false)
            || value.get("timestamp").and_then(Value::as_i64) != Some(request.timestamp)
            || value
                .pointer("/payload/stripe_customer_id")
                .and_then(Value::as_str)
                != Some(request.customer_id.as_str())
            || value.pointer("/payload/value").and_then(Value::as_str) != Some("1")
        {
            return MeterResponse::InvalidResponse;
        }
        MeterResponse::Acknowledged {
            identifier: request.identifier,
            livemode: false,
        }
    }
}
impl TestMeterTransport for StripeTestMeterTransport {
    async fn submit(&self, request: MeterRequest) -> MeterResponse {
        self.send(request).await
    }
}

/// One bounded claim per tick, sharing the existing worker admission budget.
/// Provider failures persist in the existing outbox; diagnostics contain no IDs.
pub async fn run_queue(
    database_url: String,
    transport: StripeTestMeterTransport,
    draining: Arc<AtomicBool>,
    notify: Arc<Notify>,
    permits: Arc<Semaphore>,
) {
    let worker = TestUsageWorker::test_candidate();
    let mut checks = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(3),
        Duration::from_secs(10),
    );
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut failed = false;
    loop {
        if draining.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _=notify.notified()=>{},
            _=checks.tick()=> {
                let Ok(_permit)=permits.clone().try_acquire_owned() else {continue};
                let Ok(mut db)=crate::runtime_db::connect_worker(&database_url).await else {continue};
                if worker.run_one(&mut db,&transport).await.is_err() && !failed {
                    eprintln!("Stripe TEST usage forwarding storage unavailable"); failed=true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
