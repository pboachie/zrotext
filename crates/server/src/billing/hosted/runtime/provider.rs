// SPDX-License-Identifier: AGPL-3.0-only
use super::{Error, Options, mode_name};
use crate::billing::hosted::{
    namespace::{Mode, ProviderIdentity},
    policy::SubscriptionStatus,
};
use reqwest::{Client, Method};
use serde::Serialize;
use serde_json::Value;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const VERSION: &str = crate::billing::risk::STRIPE_API_VERSION;
const MAX_BYTES: usize = 256 * 1024;
pub(super) const LEASE_SECONDS: i64 = 120;
pub(super) struct Provider {
    http: Client,
    base: String,
    paused_until: AtomicU64,
    catalog: tokio::sync::Mutex<Option<(tokio::time::Instant, Catalog)>>,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Catalog {
    schema_version: u8,
    mode: &'static str,
    currency: String,
    unit_amount: i64,
    interval: String,
    interval_count: i64,
    outbound_limit: u64,
    device_cap: u64,
    tax_behavior: String,
    automatic_tax: bool,
    allowance_period: &'static str,
}
impl Provider {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            http: Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|_| Error::Configuration)?,
            base: "https://api.stripe.com".into(),
            paused_until: AtomicU64::new(0),
            catalog: tokio::sync::Mutex::new(None),
        })
    }
    #[cfg(test)]
    pub fn fake(base: String) -> Self {
        Self {
            http: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            base,
            paused_until: AtomicU64::new(0),
            catalog: tokio::sync::Mutex::new(None),
        }
    }
    #[cfg(test)]
    pub fn unpause(&self) {
        self.paused_until.store(0, Ordering::Release);
    }
    #[cfg(test)]
    pub async fn expire_catalog(&self) {
        if let Some((at, _)) = self.catalog.lock().await.as_mut() {
            *at = tokio::time::Instant::now() - Duration::from_secs(121);
        }
    }
    pub async fn request(
        &self,
        key: &str,
        method: Method,
        path: &str,
        fields: &[(&str, String)],
        operation: Option<&str>,
    ) -> Result<Value, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.paused_until.load(Ordering::Acquire) > now {
            return Err(Error::Provider);
        }
        let mut url = reqwest::Url::parse(&format!("{}{path}", self.base))
            .map_err(|_| Error::Configuration)?;
        if method == Method::GET {
            url.query_pairs_mut()
                .extend_pairs(fields.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let mut request = self
            .http
            .request(method.clone(), url)
            .bearer_auth(key)
            .header("Stripe-Version", VERSION);
        if method != Method::GET {
            request = request.form(fields)
        }
        if let Some(operation) = operation {
            request = request.header("Idempotency-Key", operation)
        }
        let result = async {
            let mut response = request.send().await.map_err(|_| Error::Provider)?;
            if !response.status().is_success() {
                let pause = if response.status().as_u16() == 429 {
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|s| s.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(30)
                        .clamp(5, 300)
                } else {
                    30
                };
                self.paused_until
                    .store(now.saturating_add(pause), Ordering::Release);
                return Err(Error::Provider);
            }
            if response
                .content_length()
                .is_some_and(|len| len > MAX_BYTES as u64)
            {
                return Err(Error::Provider);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Provider)? {
                if body.len().saturating_add(chunk.len()) > MAX_BYTES {
                    return Err(Error::Provider);
                }
                body.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&body).map_err(|_| Error::Provider)
        }
        .await;
        if result.is_err() {
            self.paused_until
                .fetch_max(now.saturating_add(5), Ordering::Release);
        }
        result
    }
    pub async fn get(&self, key: &str, path: &str) -> Result<Value, Error> {
        self.request(key, Method::GET, path, &[], None).await
    }
    pub async fn verify(&self, o: &Options, origin: &str) -> Result<ProviderIdentity, Error> {
        for key in [&o.read_key, &o.session_key] {
            // /account, not /accounts/{id}: connected-account access is not
            // proof of the credential's own provider account.
            let account = self.get(key, "/v1/account").await?;
            let balance = self.get(key, "/v1/balance").await?;
            if account["object"] != "account"
                || account["id"] != o.namespace.provider_account()
                || balance["object"] != "balance"
                || balance["livemode"] != live(o)
            {
                return Err(Error::Identity);
            }
        }
        let _ = self.catalog_current(o).await?;
        let session_price = self
            .get(&o.session_key, &format!("/v1/prices/{}", o.plan.price()))
            .await?;
        parse_catalog(&session_price, o)?;
        let portal = self
            .get(
                &o.session_key,
                &format!(
                    "/v1/billing_portal/configurations/{}",
                    o.portal_configuration
                ),
            )
            .await?;
        if portal["object"] != "billing_portal.configuration"
            || portal["id"] != o.portal_configuration
            || portal["livemode"] != live(o)
            || portal["active"] != true
            || portal["features"]["subscription_update"]["enabled"] != false
        {
            return Err(Error::Identity);
        }
        let webhook = self
            .get(
                &o.read_key,
                &format!("/v1/webhook_endpoints/{}", o.webhook_endpoint),
            )
            .await?;
        let events = webhook["enabled_events"]
            .as_array()
            .ok_or(Error::Identity)?;
        if webhook["object"] != "webhook_endpoint"
            || webhook["id"] != o.webhook_endpoint
            || webhook["livemode"] != live(o)
            || webhook["status"] != "enabled"
            || webhook["api_version"] != VERSION
            || webhook["url"] != format!("{origin}/v1/billing/stripe-events")
            || !events
                .iter()
                .any(|e| e == "*" || e == "invoice.payment_failed")
            || !events
                .iter()
                .any(|e| e == "*" || e == "customer.subscription.updated")
            || !events.iter().any(|e| e == "*" || e == "charge.refunded")
            || !events
                .iter()
                .any(|e| e == "*" || e == "charge.dispute.created")
        {
            return Err(Error::Identity);
        }
        Ok(ProviderIdentity {
            mode: o.namespace.mode(),
            provider_account: o.namespace.provider_account().into(),
        })
    }
    pub async fn catalog(&self) -> Result<Catalog, Error> {
        let cache = self.catalog.lock().await;
        if let Some((at, catalog)) = &*cache
            && at.elapsed() < Duration::from_secs(120)
        {
            return Ok(catalog.clone());
        }
        Err(Error::Provider)
    }
    pub async fn refresh_catalog(&self, o: &Options) -> Result<(), Error> {
        let mut cache = self.catalog.lock().await;
        if cache
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() < Duration::from_secs(30))
        {
            return Ok(());
        }
        let catalog = self.fetch_catalog(o).await?;
        *cache = Some((tokio::time::Instant::now(), catalog));
        Ok(())
    }
    pub async fn catalog_current(&self, o: &Options) -> Result<Catalog, Error> {
        let catalog = self.fetch_catalog(o).await?;
        *self.catalog.lock().await = Some((tokio::time::Instant::now(), catalog.clone()));
        Ok(catalog)
    }
    async fn fetch_catalog(&self, o: &Options) -> Result<Catalog, Error> {
        parse_catalog(
            &self
                .get(&o.read_key, &format!("/v1/prices/{}", o.plan.price()))
                .await?,
            o,
        )
    }
    pub async fn subscriptions(&self, o: &Options, customer: &str) -> Result<Subscriptions, Error> {
        if !id(customer, "cus_") {
            return Err(Error::Identity);
        }
        let v = self
            .request(
                &o.read_key,
                Method::GET,
                "/v1/subscriptions",
                &[
                    ("customer", customer.into()),
                    ("status", "all".into()),
                    ("limit", "20".into()),
                ],
                None,
            )
            .await?;
        parse_subscriptions(&v, o, customer)
    }
    pub async fn invoice(&self, o: &Options, id: &str) -> Result<Value, Error> {
        if !self::id(id, "in_") {
            return Err(Error::Identity);
        }
        self.get(&o.read_key, &format!("/v1/invoices/{id}")).await
    }
    pub async fn current_portal(&self, o: &Options) -> Result<(), Error> {
        let portal = self
            .get(
                &o.session_key,
                &format!(
                    "/v1/billing_portal/configurations/{}",
                    o.portal_configuration
                ),
            )
            .await?;
        if portal["object"] != "billing_portal.configuration"
            || portal["id"] != o.portal_configuration
            || portal["livemode"] != live(o)
            || portal["active"] != true
            || portal["features"]["subscription_update"]["enabled"] != false
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
pub(super) fn id(value: &str, prefix: &str) -> bool {
    value.len() > prefix.len()
        && value.len() <= 128
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub(super) fn live(o: &Options) -> bool {
    o.namespace.mode() == Mode::Live
}
pub(super) fn canonical_origin(value: &str) -> Result<(), Error> {
    let u = reqwest::Url::parse(value).map_err(|_| Error::Configuration)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
        || u.as_str().trim_end_matches('/') != value
    {
        return Err(Error::Configuration);
    }
    Ok(())
}
fn parse_catalog(v: &Value, o: &Options) -> Result<Catalog, Error> {
    let currency = v["currency"].as_str().ok_or(Error::Provider)?;
    let amount = v["unit_amount"].as_i64().ok_or(Error::Provider)?;
    let interval = v["recurring"]["interval"].as_str().ok_or(Error::Provider)?;
    let count = v["recurring"]["interval_count"]
        .as_i64()
        .ok_or(Error::Provider)?;
    let tax = v["tax_behavior"].as_str().ok_or(Error::Provider)?;
    if v["object"] != "price"
        || v["id"] != o.plan.price()
        || v["livemode"] != live(o)
        || v["active"] != true
        || v["type"] != "recurring"
        || v["billing_scheme"] != "per_unit"
        || v["recurring"]["usage_type"] != "licensed"
        || !matches!(interval, "day" | "week" | "month" | "year")
        || !(1..=365).contains(&count)
        || !(1..=9_007_199_254_740_991).contains(&amount)
        || currency.len() != 3
        || !currency.bytes().all(|b| b.is_ascii_lowercase())
        || !matches!(tax, "inclusive" | "exclusive")
        || !v["transform_quantity"].is_null()
        || !v["tiers"].is_null()
        || !v["currency_options"].is_null()
    {
        return Err(Error::Provider);
    }
    Ok(Catalog {
        schema_version: 1,
        mode: mode_name(o.namespace.mode()),
        currency: currency.into(),
        unit_amount: amount,
        interval: interval.into(),
        interval_count: count,
        outbound_limit: o.plan.outbound_limit(),
        device_cap: o.plan.device_limit(),
        tax_behavior: tax.into(),
        automatic_tax: o.automatic_tax,
        allowance_period: "subscription_invoice",
    })
}
#[derive(Clone, Debug)]
pub(super) struct Subscription {
    pub id: String,
    pub item: String,
    pub status: SubscriptionStatus,
    pub price: String,
    pub invoice: String,
    pub start: i64,
    pub end: i64,
}
pub(super) struct Subscriptions {
    pub complete: bool,
    pub current: Vec<Subscription>,
}
fn parse_subscriptions(v: &Value, o: &Options, customer: &str) -> Result<Subscriptions, Error> {
    let rows = v["data"].as_array().ok_or(Error::Provider)?;
    if v["object"] != "list" || rows.len() > 20 || !v["has_more"].is_boolean() {
        return Err(Error::Provider);
    }
    let mut result = Subscriptions {
        complete: v["has_more"] == false,
        current: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for s in rows {
        let sid = s["id"]
            .as_str()
            .filter(|x| id(x, "sub_"))
            .ok_or(Error::Provider)?;
        if !seen.insert(sid)
            || s["object"] != "subscription"
            || s["livemode"] != live(o)
            || s["customer"] != customer
        {
            return Err(Error::Identity);
        }
        let status = match s["status"].as_str() {
            Some("active") => SubscriptionStatus::Active,
            Some("past_due") => SubscriptionStatus::PastDue,
            Some("incomplete") => SubscriptionStatus::Incomplete,
            Some("unpaid") => SubscriptionStatus::Unpaid,
            Some("paused") => SubscriptionStatus::Paused,
            Some("canceled" | "incomplete_expired") => continue,
            _ => {
                result.complete = false;
                continue;
            }
        };
        let items = s["items"]["data"].as_array().ok_or(Error::Provider)?;
        if s["items"]["object"] != "list" || s["items"]["has_more"] != false || items.len() != 1 {
            result.complete = false;
            continue;
        }
        let item = &items[0];
        let item_id = item["id"]
            .as_str()
            .filter(|v| id(v, "si_"))
            .ok_or(Error::Provider)?;
        let price = item["price"]["id"]
            .as_str()
            .filter(|x| id(x, "price_"))
            .ok_or(Error::Provider)?;
        if item["quantity"] != 1 || item["price"]["livemode"] != live(o) {
            result.complete = false;
            continue;
        }
        let invoice = s["latest_invoice"]
            .as_str()
            .filter(|x| id(x, "in_"))
            .unwrap_or("");
        let start = item["current_period_start"].as_i64().unwrap_or(0);
        let end = item["current_period_end"].as_i64().unwrap_or(0);
        result.current.push(Subscription {
            id: sid.into(),
            item: item_id.into(),
            status,
            price: price.into(),
            invoice: invoice.into(),
            start,
            end,
        });
    }
    Ok(result)
}
pub(super) fn validate_invoice(
    v: &Value,
    o: &Options,
    customer: &str,
    s: &Subscription,
) -> Result<(), Error> {
    if v["object"] != "invoice"
        || v["id"] != s.invoice
        || v["livemode"] != live(o)
        || v["customer"] != customer
        || v["parent"]["subscription_details"]["subscription"] != s.id
    {
        return Err(Error::Identity);
    }
    // Invoice collection windows are not service-period authority. The one
    // complete, non-prorated subscription-item line binds the exact service
    // period, price, item, subscription, mode and customer obligation.
    let lines = v["lines"]["data"].as_array().ok_or(Error::Pending)?;
    if v["lines"]["object"] != "list" || v["lines"]["has_more"] != false || lines.len() != 1 {
        return Err(Error::Pending);
    }
    let line = &lines[0];
    let details = &line["parent"]["subscription_item_details"];
    if line["object"] != "line_item"
        || line["livemode"] != live(o)
        || (!line["invoice"].is_null() && line["invoice"] != s.invoice)
        || line["quantity"] != 1
        || line["parent"]["type"] != "subscription_item_details"
        || details["subscription_item"] != s.item
        || details["subscription"] != s.id
        || details["proration"] != false
        || line["pricing"]["type"] != "price_details"
        || line["pricing"]["price_details"]["price"] != s.price
        || line["period"]["start"] != s.start
        || line["period"]["end"] != s.end
    {
        return Err(Error::Identity);
    }
    if s.status == SubscriptionStatus::Active && v["status"] != "paid" {
        return Err(Error::Pending);
    }
    if s.status == SubscriptionStatus::PastDue
        && !matches!(v["status"].as_str(), Some("open" | "uncollectible"))
    {
        return Err(Error::Pending);
    }
    Ok(())
}

pub(super) struct RiskResolution {
    pub customer: Option<String>,
    pub invoice: Option<String>,
    pub subscription: Option<String>,
    pub attributed: bool,
}
pub(super) async fn resolve_risk(
    r: &super::Runtime,
    kind: &str,
    object: &Value,
) -> Result<RiskResolution, Error> {
    let mut result = RiskResolution {
        customer: object["customer"]
            .as_str()
            .filter(|s| id(s, "cus_"))
            .map(String::from),
        invoice: None,
        subscription: None,
        attributed: false,
    };
    let expected = match kind {
        "charge.refunded" => "charge",
        "refund.created" => "refund",
        _ => "dispute",
    };
    if object["object"] != expected || object["livemode"] != live(&r.options) {
        return Ok(result);
    }
    let mut charge = if kind == "charge.refunded" {
        object["id"]
            .as_str()
            .filter(|s| id(s, "ch_") || id(s, "py_"))
            .map(String::from)
    } else {
        object["charge"]
            .as_str()
            .filter(|s| id(s, "ch_") || id(s, "py_"))
            .map(String::from)
    };
    if charge.is_none()
        && kind == "refund.created"
        && let Some(pi) = object["payment_intent"].as_str().filter(|s| id(s, "pi_"))
    {
        let list = r
            .provider
            .request(
                &r.options.read_key,
                Method::GET,
                "/v1/charges",
                &[("payment_intent", pi.into()), ("limit", "20".into())],
                None,
            )
            .await?;
        if list["object"] != "list" || list["has_more"] != false {
            return Ok(result);
        }
        let Some(rows) = list["data"].as_array() else {
            return Ok(result);
        };
        let matching: Vec<_> = rows
            .iter()
            .filter(|c| {
                c["object"] == "charge"
                    && c["livemode"] == live(&r.options)
                    && c["payment_intent"] == pi
                    && c["amount_refunded"].as_i64().is_some_and(|n| n > 0)
            })
            .collect();
        if matching.len() != 1 {
            return Ok(result);
        }
        charge = matching[0]["id"]
            .as_str()
            .filter(|s| id(s, "ch_") || id(s, "py_"))
            .map(String::from);
    }
    let Some(charge) = charge else {
        return Ok(result);
    };
    let value = r
        .provider
        .get(&r.options.read_key, &format!("/v1/charges/{charge}"))
        .await?;
    if value["object"] != "charge" || value["id"] != charge || value["livemode"] != live(&r.options)
    {
        return Ok(result);
    }
    result.customer = value["customer"]
        .as_str()
        .filter(|s| id(s, "cus_"))
        .map(String::from);
    if kind != "charge.dispute.created" && value["amount_refunded"].as_i64().is_none_or(|n| n <= 0)
    {
        return Ok(result);
    }
    let Some(pi) = value["payment_intent"].as_str().filter(|s| id(s, "pi_")) else {
        return Ok(result);
    };
    if result.customer.is_none() {
        return Ok(result);
    }
    let payments = r
        .provider
        .request(
            &r.options.read_key,
            Method::GET,
            "/v1/invoice_payments",
            &[
                ("payment[type]", "payment_intent".into()),
                ("payment[payment_intent]", pi.into()),
                ("limit", "2".into()),
            ],
            None,
        )
        .await?;
    let Some(rows) = payments["data"].as_array() else {
        return Ok(result);
    };
    if payments["object"] != "list" || payments["has_more"] != false || rows.len() != 1 {
        return Ok(result);
    }
    let p = &rows[0];
    if p["object"] != "invoice_payment"
        || p["livemode"] != live(&r.options)
        || p["status"] != "paid"
        || p["payment"]["type"] != "payment_intent"
        || p["payment"]["payment_intent"] != pi
    {
        return Ok(result);
    }
    let Some(invoice) = p["invoice"].as_str().filter(|s| id(s, "in_")) else {
        return Ok(result);
    };
    let v = r.provider.invoice(&r.options, invoice).await?;
    if v["object"] != "invoice"
        || v["id"] != invoice
        || v["livemode"] != live(&r.options)
        || v["customer"].as_str() != result.customer.as_deref()
        || v["status"] != "paid"
    {
        return Ok(result);
    }
    let Some(subscription) = v["parent"]["subscription_details"]["subscription"]
        .as_str()
        .filter(|s| id(s, "sub_"))
    else {
        return Ok(result);
    };
    result.invoice = Some(invoice.into());
    result.subscription = Some(subscription.into());
    result.attributed = true;
    Ok(result)
}
