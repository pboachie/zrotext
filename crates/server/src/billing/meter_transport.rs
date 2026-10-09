// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit TEST-only HTTPS forwarding of already finalized local usage.
use reqwest::{Client, Url};
use serde::Deserialize;
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

// Decode authority-bearing fields directly: a generic JSON map would silently
// replace a repeated identity or mode field with its last occurrence. Additional
// provider metadata is allowed, but every field used for acknowledgement is unique.
#[derive(Deserialize)]
struct MeterAcknowledgement {
    object: String,
    identifier: String,
    event_name: String,
    livemode: bool,
    timestamp: i64,
    #[serde(deserialize_with = "object_only")]
    payload: MeterPayload,
}

#[derive(Deserialize)]
struct MeterPayload {
    stripe_customer_id: String,
    value: String,
}

fn object_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

fn acknowledgement(bytes: &[u8], request: &MeterRequest) -> MeterResponse {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let parsed = object_only::<_, MeterAcknowledgement>(&mut parser)
        .and_then(|value| parser.end().map(|()| value));
    let value = match parsed {
        Ok(value) => value,
        Err(error) if error.is_data() => return MeterResponse::InvalidResponse,
        Err(_) => return MeterResponse::Unknown,
    };
    if value.object != "billing.meter_event"
        || value.identifier != request.identifier
        || value.event_name != request.event_name
        || value.livemode
        || value.timestamp != request.timestamp
        || value.payload.stripe_customer_id != request.customer_id
        || value.payload.value != "1"
    {
        return MeterResponse::InvalidResponse;
    }
    MeterResponse::Acknowledged {
        identifier: request.identifier.clone(),
        livemode: false,
    }
}

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
            || request.identifier.len() > 100
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
        acknowledgement(&bytes, &request)
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
