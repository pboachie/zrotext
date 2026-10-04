// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::collections::{HashMap, HashSet};

impl TestUsageReconciler {
    async fn read(&self, path: &str, query: &[(&str, String)]) -> Result<Value, Error> {
        let mut url = self.base.join(path).map_err(|_| Error::Unavailable)?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let mut response = self
            .http
            .get(url.clone())
            .bearer_auth(self.key.as_str())
            .header("Stripe-Version", "2025-07-30.basil")
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status().as_u16() != 200
            || response.url() != &url
            || response.content_length().is_some_and(|n| n > 65536)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_none_or(|v| v.split(';').next() != Some("application/json"))
        {
            return refused();
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len().saturating_add(chunk.len()) > 65536 {
                return refused();
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)
    }

    async fn summaries(&self, scope: &Scope) -> Result<i64, Error> {
        let response = self
            .read(
                &format!("v1/billing/meters/{}/event_summaries", scope.meter),
                &[
                    ("customer", scope.customer.clone()),
                    ("start_time", scope.start.to_string()),
                    ("end_time", scope.end.to_string()),
                    ("limit", "2".into()),
                ],
            )
            .await?;
        parse_summary(&response, scope)
    }

    async fn invoice_quantity(&self, scope: &Scope) -> Result<Option<i64>, Error> {
        let Some(invoice) = scope.invoice.as_ref() else {
            return Ok(None);
        };
        let subscription = scope.subscription.as_ref().ok_or(Error::Unavailable)?;
        if !identifier(invoice, "in_") || !identifier(subscription, "sub_") {
            return refused();
        }
        let response = self.read(&format!("v1/invoices/{invoice}"), &[]).await?;
        invoice_identity(&response, scope)?;
        let mut lines = Vec::new();
        let mut seen = HashSet::new();
        let mut page = response.get("lines").cloned().ok_or(Error::Unavailable)?;
        for number in 0..4 {
            if page.get("object").and_then(Value::as_str) != Some("list") {
                return refused();
            }
            let rows = page
                .get("data")
                .and_then(Value::as_array)
                .ok_or(Error::Unavailable)?;
            if rows.len() > 100 {
                return refused();
            }
            for row in rows {
                let id = row
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(Error::Unavailable)?;
                if !identifier(id, "il_") || !seen.insert(id.to_owned()) {
                    return refused();
                }
                lines.push(row.clone());
            }
            match page.get("has_more").and_then(Value::as_bool) {
                Some(false) => break,
                Some(true) if number < 3 && !rows.is_empty() => {
                    let cursor = rows
                        .last()
                        .and_then(|r| r.get("id"))
                        .and_then(Value::as_str)
                        .ok_or(Error::Unavailable)?;
                    page = self
                        .read(
                            &format!("v1/invoices/{invoice}/lines"),
                            &[("limit", "100".into()), ("starting_after", cursor.into())],
                        )
                        .await?;
                }
                _ => return refused(),
            }
        }
        let mut selected = None;
        let mut prices = HashMap::new();
        // A bounded complete invoice is required. Fixed subscription charges,
        // prorations and unrelated meters never substitute for usage quantity.
        for line in &lines {
            if line.get("object").and_then(Value::as_str) != Some("line_item")
                || line.get("livemode").and_then(Value::as_bool) != Some(false)
            {
                return refused();
            }
            let price = line
                .pointer("/pricing/price_details/price")
                .and_then(Value::as_str)
                .ok_or(Error::Unavailable)?;
            if !identifier(price, "price_") {
                return refused();
            }
            let price_object = if let Some(cached) = prices.get(price) {
                Value::clone(cached)
            } else {
                if prices.len() >= 8 {
                    return refused();
                }
                let value = self.read(&format!("v1/prices/{price}"), &[]).await?;
                prices.insert(price.to_owned(), value.clone());
                value
            };
            if price_object.get("id").and_then(Value::as_str) != Some(price)
                || price_object.get("object").and_then(Value::as_str) != Some("price")
                || price_object.get("livemode").and_then(Value::as_bool) != Some(false)
            {
                return refused();
            }
            if price_object
                .pointer("/recurring/meter")
                .and_then(Value::as_str)
                != Some(&scope.meter)
            {
                continue;
            }
            if selected.is_some()
                || scope.invoice_binding.as_ref().is_some_and(
                    |(expected_price, expected_line, expected_item)| {
                        price != expected_price
                            || line.get("id").and_then(Value::as_str)
                                != Some(expected_line.as_str())
                            || line
                                .pointer("/parent/subscription_item_details/subscription_item")
                                .and_then(Value::as_str)
                                != Some(expected_item.as_str())
                    },
                )
                || price_object
                    .pointer("/recurring/usage_type")
                    .and_then(Value::as_str)
                    != Some("metered")
                || price_object.get("billing_scheme").and_then(Value::as_str) != Some("per_unit")
                || !price_object
                    .get("transform_quantity")
                    .is_some_and(Value::is_null)
                || !price_object.get("tiers_mode").is_some_and(Value::is_null)
                || line.pointer("/parent/type").and_then(Value::as_str)
                    != Some("subscription_item_details")
                || line
                    .pointer("/parent/subscription_item_details/subscription")
                    .and_then(Value::as_str)
                    != Some(subscription)
                || line
                    .pointer("/parent/subscription_item_details/proration")
                    .and_then(Value::as_bool)
                    != Some(false)
                || line.pointer("/period/start").and_then(Value::as_i64) != Some(scope.start)
                || line.pointer("/period/end").and_then(Value::as_i64) != Some(scope.end)
            {
                return refused();
            }
            let quantity = line
                .get("quantity")
                .and_then(Value::as_i64)
                .filter(|n| *n >= 0)
                .ok_or(Error::Unavailable)?;
            selected = Some(quantity);
        }
        let final_invoice = self.read(&format!("v1/invoices/{invoice}"), &[]).await?;
        invoice_identity(&final_invoice, scope)?;
        if response != final_invoice {
            return refused();
        }
        Ok(selected)
    }

    pub(super) async fn observe(&self, scope: &Scope) -> Result<(i64, Option<i64>), Error> {
        if !identifier(&scope.customer, "cus_")
            || !identifier(&scope.meter, "mtr_")
            || scope.start <= 0
            || scope.end <= scope.start
            || scope.end - scope.start > 2678400
            || scope.start % 60 != 0
            || scope.end % 60 != 0
        {
            return refused();
        }
        let meter = self
            .read(&format!("v1/billing/meters/{}", scope.meter), &[])
            .await?;
        if meter.get("object").and_then(Value::as_str) != Some("billing.meter")
            || meter.get("id").and_then(Value::as_str) != Some(&scope.meter)
            || meter.get("livemode").and_then(Value::as_bool) != Some(false)
            || meter.get("event_name").and_then(Value::as_str) != Some(&scope.event_name)
            || meter.get("status").and_then(Value::as_str) != Some("active")
            || meter
                .pointer("/default_aggregation/formula")
                .and_then(Value::as_str)
                != Some("sum")
            || meter
                .pointer("/customer_mapping/type")
                .and_then(Value::as_str)
                != Some("by_id")
            || meter
                .pointer("/customer_mapping/event_payload_key")
                .and_then(Value::as_str)
                != Some("stripe_customer_id")
            || meter
                .pointer("/value_settings/event_payload_key")
                .and_then(Value::as_str)
                != Some("value")
        {
            return refused();
        }
        let aggregate = self.summaries(scope).await?;
        let invoice = self.invoice_quantity(scope).await?;
        if self.summaries(scope).await? != aggregate {
            return refused();
        }
        Ok((aggregate, invoice))
    }
}

fn parse_summary(value: &Value, scope: &Scope) -> Result<i64, Error> {
    if value.get("object").and_then(Value::as_str) != Some("list")
        || value.get("has_more").and_then(Value::as_bool) != Some(false)
    {
        return refused();
    }
    let rows = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?;
    if rows.is_empty() {
        return Ok(0);
    }
    if rows.len() != 1 {
        return refused();
    }
    let row = &rows[0];
    if row.get("object").and_then(Value::as_str) != Some("billing.meter_event_summary")
        || row.get("livemode").and_then(Value::as_bool) != Some(false)
        || row.get("meter").and_then(Value::as_str) != Some(&scope.meter)
        || row.get("start_time").and_then(Value::as_i64) != Some(scope.start)
        || row.get("end_time").and_then(Value::as_i64) != Some(scope.end)
        || row
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| !identifier(id, "mtrusg_"))
    {
        return refused();
    }
    row.get("aggregated_value")
        .and_then(Value::as_i64)
        .filter(|n| *n >= 0)
        .ok_or(Error::Unavailable)
}

fn invoice_identity(value: &Value, scope: &Scope) -> Result<(), Error> {
    if value.get("object").and_then(Value::as_str) != Some("invoice")
        || value.get("id").and_then(Value::as_str) != scope.invoice.as_deref()
        || value.get("customer").and_then(Value::as_str) != Some(&scope.customer)
        || value.get("livemode").and_then(Value::as_bool) != Some(false)
        || value.pointer("/parent/type").and_then(Value::as_str) != Some("subscription_details")
        || value
            .pointer("/parent/subscription_details/subscription")
            .and_then(Value::as_str)
            != scope.subscription.as_deref()
        || !matches!(
            value.get("status").and_then(Value::as_str),
            Some("open" | "paid")
        )
    {
        return refused();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
