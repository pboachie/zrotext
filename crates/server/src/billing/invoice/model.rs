// SPDX-License-Identifier: AGPL-3.0-only
//! Strict TEST provider observations. Invoice totals and webhook ordering are
//! never period authority; only a current single subscription item and its
//! exact non-prorated renewal line can establish a budget period.

use super::super::{BillingError, SubscriptionSnapshot, valid_id, worker};
use serde_json::Value;

pub(super) const MAX_PERIOD_MS: i64 = 370 * 24 * 60 * 60 * 1000;
pub(super) const GRACE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Period {
    pub start_ms: i64,
    pub end_ms: i64,
}

impl Period {
    pub fn new(start_ms: i64, end_ms: i64) -> Result<Self, BillingError> {
        if start_ms <= 0
            || end_ms <= start_ms
            || end_ms
                .checked_sub(start_ms)
                .is_none_or(|n| n > MAX_PERIOD_MS)
        {
            return Err(BillingError::InvalidEvent);
        }
        Ok(Self { start_ms, end_ms })
    }
    pub fn contains(self, now_ms: i64) -> bool {
        self.start_ms <= now_ms && now_ms < self.end_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reason {
    Create,
    Renewal,
    Adjustment,
    Other,
}

#[derive(Clone, Debug)]
pub(super) struct Observation {
    pub subscription: SubscriptionSnapshot,
    pub item_id: String,
    pub period: Period,
    pub invoice_id: String,
    pub invoice_status: String,
    pub reason: Reason,
    pub renewal_line_id: Option<String>,
    pub cancel_at_ms: Option<i64>,
    pub cancel_at_period_end: bool,
}

fn id(value: &Value, prefix: &str) -> Result<String, BillingError> {
    valid_id(value.as_str().ok_or(BillingError::InvalidEvent)?, prefix).map(str::to_owned)
}

fn milliseconds(value: &Value) -> Result<i64, BillingError> {
    value
        .as_i64()
        .filter(|n| *n > 0)
        .and_then(|n| n.checked_mul(1000))
        .ok_or(BillingError::InvalidEvent)
}

fn optional_time(value: &Value) -> Result<Option<i64>, BillingError> {
    if value.is_null() {
        Ok(None)
    } else {
        milliseconds(value).map(Some)
    }
}

/// Both byte strings must come from the configured pinned-version TEST reader,
/// not from a webhook, owner request, or cached subscription projection.
pub(super) fn parse(subscription: &[u8], invoice: &[u8]) -> Result<Observation, BillingError> {
    let snapshot = worker::parse_subscription(subscription)?;
    let sub: Value =
        serde_json::from_slice(subscription).map_err(|_| BillingError::InvalidEvent)?;
    let inv: Value = serde_json::from_slice(invoice).map_err(|_| BillingError::InvalidEvent)?;
    let items = sub["items"]["data"]
        .as_array()
        .ok_or(BillingError::InvalidEvent)?;
    if items.len() != 1 || sub["items"]["has_more"] != false {
        return Err(BillingError::InvalidEvent);
    }
    let item = &items[0];
    let item_id = id(&item["id"], "si_")?;
    if item["quantity"] != 1 {
        return Err(BillingError::InvalidEvent);
    }
    let period = Period::new(
        milliseconds(&item["current_period_start"])?,
        milliseconds(&item["current_period_end"])?,
    )?;
    let invoice_id = id(&inv["id"], "in_")?;
    if inv["object"] != "invoice"
        || inv["livemode"] != false
        || snapshot.latest_invoice_id.as_deref() != Some(invoice_id.as_str())
        || id(&inv["customer"], "cus_")? != snapshot.customer_id
        || inv["parent"]["type"] != "subscription_details"
        || id(
            &inv["parent"]["subscription_details"]["subscription"],
            "sub_",
        )? != snapshot.subscription_id
    {
        return Err(BillingError::TenantConflict);
    }
    let invoice_status = inv["status"]
        .as_str()
        .ok_or(BillingError::InvalidEvent)?
        .to_owned();
    if !matches!(
        invoice_status.as_str(),
        "draft" | "open" | "paid" | "void" | "uncollectible"
    ) {
        return Err(BillingError::InvalidEvent);
    }
    let reason = match inv["billing_reason"].as_str() {
        Some("subscription_create") => Reason::Create,
        Some("subscription_cycle") => Reason::Renewal,
        Some("subscription_update") => Reason::Adjustment,
        Some("manual" | "subscription_threshold") => Reason::Other,
        _ => return Err(BillingError::InvalidEvent),
    };
    let lines = inv["lines"]["data"]
        .as_array()
        .ok_or(BillingError::InvalidEvent)?;
    if inv["lines"]["object"] != "list" || inv["lines"]["has_more"] != false || lines.len() > 32 {
        return Err(BillingError::InvalidEvent);
    }
    let mut renewal_line_id = None;
    for line in lines {
        let line_id = id(&line["id"], "il_")?;
        let details = &line["parent"]["subscription_item_details"];
        if line["parent"]["type"] != "subscription_item_details"
            || id(&details["subscription_item"], "si_")? != item_id
        {
            return Err(BillingError::InvalidEvent);
        }
        let prorated = details["proration"]
            .as_bool()
            .ok_or(BillingError::InvalidEvent)?;
        let line_period = Period::new(
            milliseconds(&line["period"]["start"])?,
            milliseconds(&line["period"]["end"])?,
        )?;
        let price = id(&line["pricing"]["price_details"]["price"], "price_")?;
        if matches!(reason, Reason::Create | Reason::Renewal) {
            if prorated
                || line_period != period
                || snapshot.price_id.as_deref() != Some(price.as_str())
                || renewal_line_id.is_some()
            {
                return Err(BillingError::InvalidEvent);
            }
            renewal_line_id = Some(line_id);
        }
    }
    if matches!(reason, Reason::Create | Reason::Renewal) && renewal_line_id.is_none() {
        return Err(BillingError::InvalidEvent);
    }
    Ok(Observation {
        subscription: snapshot,
        item_id,
        period,
        invoice_id,
        invoice_status,
        reason,
        renewal_line_id,
        cancel_at_ms: optional_time(&sub["cancel_at"])?,
        cancel_at_period_end: sub["cancel_at_period_end"]
            .as_bool()
            .ok_or(BillingError::InvalidEvent)?,
    })
}

impl Observation {
    pub fn can_establish_period(&self) -> bool {
        self.invoice_status == "paid"
            && self.subscription.status == "active"
            && self.renewal_line_id.is_some()
            && matches!(self.reason, Reason::Create | Reason::Renewal)
    }
    pub fn same_current_state(&self, other: &Self) -> bool {
        self.subscription.subscription_id == other.subscription.subscription_id
            && self.subscription.customer_id == other.subscription.customer_id
            && self.subscription.status == other.subscription.status
            && self.subscription.price_id == other.subscription.price_id
            && self.item_id == other.item_id
            && self.period == other.period
            && self.invoice_id == other.invoice_id
            && self.invoice_status == other.invoice_status
            && self.reason == other.reason
            && self.renewal_line_id == other.renewal_line_id
            && self.cancel_at_ms == other.cancel_at_ms
            && self.cancel_at_period_end == other.cancel_at_period_end
    }
}

#[cfg(test)]
mod tests;
