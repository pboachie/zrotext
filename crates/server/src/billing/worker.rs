// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode subscription reconciliation against Stripe's current API state.

use super::{
    BillingError, SubscriptionSnapshot, TestQuotaPlan, is_test_api_key,
    reconcile_snapshot_with_quotas, risk, valid_id,
};
use reqwest::{Client as HttpClient, redirect, retry};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;

pub struct StripeTestWorker {
    http: HttpClient,
    secret_key: String,
    recognized_prices: Vec<String>,
    quota_plans: Vec<TestQuotaPlan>,
    api_base_url: String,
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
            api_base_url: "https://api.stripe.com".into(),
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
        self.api_base_url = api_base_url;
        self
    }

    pub async fn reconcile_one(&self, database_url: &str) -> Result<bool, BillingError> {
        let (mut db, connection) = crate::runtime_db::connect_worker(database_url).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let Some((account_id, subscription_id, generation)) = claim(&mut db).await? else {
            return Ok(false);
        };
        let fetched = self.fetch_subscription(&subscription_id).await;
        match fetched {
            Ok(snapshot) if snapshot.subscription_id == subscription_id => {
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
                    backoff(&db, &subscription_id, generation).await?;
                    return Err(error);
                }
            }
            _ => {
                backoff(&db, &subscription_id, generation).await?;
                return Ok(true);
            }
        }
        Ok(true)
    }

    /// One bounded payment-risk job per tick. A known customer's queued risk
    /// blocks new metered reservations while the provider chain is resolved.
    pub async fn reconcile_risk_one(&self, database_url: &str) -> Result<bool, BillingError> {
        let (mut db, connection) = crate::runtime_db::connect_worker(database_url).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let Some((event_id, charge_id, kind)) = risk::claim(&mut db).await? else {
            return Ok(false);
        };
        let result = async {
            let charge = risk::fetch_charge(&self.http, &self.secret_key, &charge_id).await?;
            if !risk::bind_charge_customer(&mut db, &event_id, &charge.customer_id).await? {
                return Err(BillingError::InvalidEvent);
            }
            if kind == "refund" && charge.amount_refunded == 0 {
                return Err(BillingError::InvalidEvent);
            }
            let subscription =
                risk::fetch_invoice_subscription(&self.http, &self.secret_key, &charge).await?;
            risk::apply_hold(
                &mut db,
                &event_id,
                &charge_id,
                &charge.customer_id,
                &subscription,
                &kind,
            )
            .await
        }
        .await;
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                risk::backoff(&db, &event_id).await?;
                if matches!(error, BillingError::Database(_)) {
                    Err(error)
                } else {
                    // A provider read, unresolved binding or attribution
                    // failure is retained for retry and later review.
                    Ok(true)
                }
            }
        }
    }

    async fn fetch_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionSnapshot, BillingError> {
        valid_id(subscription_id, "sub_")?;
        let url = format!("{}/v1/subscriptions/{subscription_id}", self.api_base_url);
        let mut response = self
            .http
            .get(url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .map_err(|_| BillingError::InvalidEvent)?;
        if !response.status().is_success() {
            return Err(BillingError::InvalidEvent);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| BillingError::InvalidEvent)?
        {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(BillingError::InvalidEvent);
            }
            body.extend_from_slice(&chunk);
        }
        parse_subscription(&body)
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

pub(super) async fn claim(db: &mut Client) -> Result<Option<(Uuid, String, i64)>, BillingError> {
    let tx = db.transaction().await?;
    let row = tx.query_opt(
        "WITH target AS (SELECT stripe_subscription_id FROM billing_reconciliations WHERE dirty_generation>processed_generation AND next_attempt_at<=now() ORDER BY next_attempt_at,stripe_subscription_id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE billing_reconciliations b SET next_attempt_at=now()+interval '30 seconds' FROM target WHERE b.stripe_subscription_id=target.stripe_subscription_id RETURNING b.account_id,b.stripe_subscription_id,b.dirty_generation",
        &[],
    ).await?;
    tx.commit().await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2))))
}

async fn backoff(db: &Client, subscription_id: &str, generation: i64) -> Result<(), BillingError> {
    db.execute(
        "UPDATE billing_reconciliations SET failed_attempts=failed_attempts+1,next_attempt_at=now()+interval '1 minute' WHERE stripe_subscription_id=$1 AND dirty_generation=$2 AND processed_generation<$2",
        &[&subscription_id, &generation],
    ).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
