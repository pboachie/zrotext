// SPDX-License-Identifier: AGPL-3.0-only
//! Privileged, explicit review of signed TEST-mode payment risks. Provider
//! reads are bounded and validated; no provider response body is persisted.

use super::{
    BillingError, is_test_api_key, lock_customer, queue_subscription, risk, valid_charge_id,
    valid_id,
};
use reqwest::{Client as HttpClient, redirect, retry};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewResult {
    Held,
    AttributedUnbound,
    ClosedFailedRefund,
    ClosureNeedsApproval,
    AlreadyResolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSummary {
    pub event_id: String,
    pub event_type: String,
    pub customer_attributed: bool,
    pub account_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPage {
    pub items: Vec<ReviewSummary>,
    pub next_after: Option<String>,
}

/// Stable keyset paging keeps a large review backlog completely enumerable.
/// A closed cursor still works because its row remains in the risk table.
pub async fn list_review_required(
    client: &Client,
    after: Option<&str>,
) -> Result<ReviewPage, BillingError> {
    if let Some(cursor) = after {
        valid_id(cursor, "evt_")?;
        if client
            .query_opt(
                "SELECT 1 FROM billing_risk_events WHERE stripe_event_id=$1",
                &[&cursor],
            )
            .await?
            .is_none()
        {
            return Err(BillingError::InvalidEvent);
        }
    }
    let rows = client.query(
        "SELECT e.stripe_event_id,e.event_type,e.stripe_customer_id IS NOT NULL,r.account_id IS NOT NULL \
         FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) \
         LEFT JOIN billing_risk_events after_row ON after_row.stripe_event_id=$1 \
         WHERE r.state='needs_review' AND ($1::text IS NULL OR \
             (after_row.stripe_event_id IS NOT NULL AND \
              (r.created_at,r.stripe_event_id)>(after_row.created_at,after_row.stripe_event_id))) \
         ORDER BY r.created_at,r.stripe_event_id LIMIT 101",
        &[&after],
    ).await?;
    let has_more = rows.len() > 100;
    let items = rows
        .into_iter()
        .take(100)
        .map(|row| ReviewSummary {
            event_id: row.get(0),
            event_type: row.get(1),
            customer_attributed: row.get(2),
            account_bound: row.get(3),
        })
        .collect::<Vec<_>>();
    let next_after = if has_more {
        items.last().map(|item| item.event_id.clone())
    } else {
        None
    };
    Ok(ReviewPage { items, next_after })
}

/// The only production provider is a fixed-host, GET-only Stripe TEST reader.
/// Its key is never included in an error, log or audit row.
pub async fn review_with_stripe(
    client: &mut Client,
    secret_key: &str,
    event_id: &str,
    operator_id: &str,
    allow_close_failed_refund: bool,
) -> Result<ReviewResult, BillingError> {
    if !is_test_api_key(secret_key) {
        return Err(BillingError::InvalidEvent);
    }
    let http = HttpClient::builder()
        .no_proxy()
        .https_only(true)
        .redirect(redirect::Policy::none())
        .retry(retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| BillingError::InvalidEvent)?;
    review_one(
        client,
        &StripeProvider { http, secret_key },
        event_id,
        operator_id,
        allow_close_failed_refund,
    )
    .await
}

trait ReviewProvider {
    async fn get(&self, path: &str) -> Result<Value, BillingError>;
}

struct StripeProvider<'a> {
    http: HttpClient,
    secret_key: &'a str,
}

impl ReviewProvider for StripeProvider<'_> {
    async fn get(&self, path: &str) -> Result<Value, BillingError> {
        // Every path is assembled below from a validated provider ID.
        risk::fetch_json(
            &self.http,
            self.secret_key,
            &format!("https://api.stripe.com{path}"),
        )
        .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewRow {
    event_type: String,
    object_id: Option<String>,
    customer_id: Option<String>,
    event_account_id: Option<Uuid>,
    charge_id: Option<String>,
    payment_intent_id: Option<String>,
    kind: String,
    state: String,
    risk_account_id: Option<Uuid>,
}

async fn load_review(client: &Client, event_id: &str) -> Result<ReviewRow, BillingError> {
    let row = client.query_one(
        "SELECT e.event_type,e.object_id,e.stripe_customer_id,e.account_id, \
         r.stripe_charge_id,r.stripe_payment_intent_id,r.risk_kind,r.state,r.account_id \
         FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) WHERE r.stripe_event_id=$1",
        &[&event_id],
    ).await?;
    Ok(ReviewRow {
        event_type: row.get(0),
        object_id: row.get(1),
        customer_id: row.get(2),
        event_account_id: row.get(3),
        charge_id: row.get(4),
        payment_intent_id: row.get(5),
        kind: row.get(6),
        state: row.get(7),
        risk_account_id: row.get(8),
    })
}

fn valid_operator(id: &str) -> bool {
    (2..=64).contains(&id.len())
        && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

async fn review_one<P: ReviewProvider>(
    client: &mut Client,
    provider: &P,
    event_id: &str,
    operator_id: &str,
    allow_close_failed_refund: bool,
) -> Result<ReviewResult, BillingError> {
    valid_id(event_id, "evt_")?;
    if !valid_operator(operator_id) {
        return Err(BillingError::InvalidEvent);
    }
    let prior = load_review(client, event_id).await?;
    if matches!(prior.state.as_str(), "held" | "closed_failed_refund") {
        return Ok(ReviewResult::AlreadyResolved);
    }
    if prior.state != "needs_review" {
        return Err(BillingError::InvalidEvent);
    }
    let evidence = fetch_evidence(provider, event_id, &prior).await?;
    if evidence.failed_refund && !allow_close_failed_refund {
        return Ok(ReviewResult::ClosureNeedsApproval);
    }
    persist_decision(client, event_id, operator_id, &prior, &evidence).await
}

struct Evidence {
    object_id: String,
    charge: risk::Charge,
    subscription_id: Option<String>,
    failed_refund: bool,
}

fn optional_id(value: &Value, prefix: &str) -> Result<Option<String>, BillingError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(
        valid_id(value.as_str().ok_or(BillingError::InvalidEvent)?, prefix)?.to_owned(),
    ))
}

fn optional_charge(value: &Value) -> Result<Option<String>, BillingError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(
        valid_charge_id(value.as_str().ok_or(BillingError::InvalidEvent)?)?.to_owned(),
    ))
}

fn risk_object_id(value: &Value, event_type: &str) -> Result<String, BillingError> {
    let id = value["id"].as_str().ok_or(BillingError::InvalidEvent)?;
    match event_type {
        "charge.refunded" => valid_charge_id(id),
        "refund.created" => valid_id(id, "re_"),
        "charge.dispute.created" => valid_id(id, "du_").or_else(|_| valid_id(id, "dp_")),
        _ => Err(BillingError::InvalidEvent),
    }
    .map(str::to_owned)
}

async fn fetch_evidence<P: ReviewProvider>(
    provider: &P,
    event_id: &str,
    prior: &ReviewRow,
) -> Result<Evidence, BillingError> {
    let event = provider.get(&format!("/v1/events/{event_id}")).await?;
    if event["id"] != event_id
        || event["object"] != "event"
        || event["livemode"] != false
        || event["type"] != prior.event_type
    {
        return Err(BillingError::InvalidEvent);
    }
    let event_object = &event["data"]["object"];
    let object_id = risk_object_id(event_object, &prior.event_type)?;
    if prior
        .object_id
        .as_deref()
        .is_some_and(|known| known != object_id)
    {
        return Err(BillingError::TenantConflict);
    }
    let (charge_id, payment_intent_id, failed_refund, event_customer) = match prior
        .event_type
        .as_str()
    {
        "charge.refunded" => {
            if event_object["object"] != "charge" {
                return Err(BillingError::InvalidEvent);
            }
            let customer = optional_id(&event_object["customer"], "cus_")?;
            (
                Some(object_id.clone()),
                optional_id(&event_object["payment_intent"], "pi_")?,
                false,
                customer,
            )
        }
        "refund.created" => {
            if event_object["object"] != "refund" {
                return Err(BillingError::InvalidEvent);
            }
            let event_charge = optional_charge(&event_object["charge"])?;
            let event_pi = optional_id(&event_object["payment_intent"], "pi_")?;
            let fresh = provider.get(&format!("/v1/refunds/{object_id}")).await?;
            if fresh["id"] != object_id || fresh["object"] != "refund" || fresh["livemode"] != false
            {
                return Err(BillingError::InvalidEvent);
            }
            let fresh_charge = optional_charge(&fresh["charge"])?;
            let fresh_pi = optional_id(&fresh["payment_intent"], "pi_")?;
            if event_charge
                .as_ref()
                .is_some_and(|known| Some(known) != fresh_charge.as_ref())
                || event_pi
                    .as_ref()
                    .is_some_and(|known| Some(known) != fresh_pi.as_ref())
            {
                return Err(BillingError::TenantConflict);
            }
            let status = fresh["status"].as_str().ok_or(BillingError::InvalidEvent)?;
            if !matches!(
                status,
                "pending" | "requires_action" | "succeeded" | "failed" | "canceled"
            ) {
                return Err(BillingError::InvalidEvent);
            }
            (
                fresh_charge,
                fresh_pi,
                matches!(status, "failed" | "canceled"),
                None,
            )
        }
        "charge.dispute.created" => {
            if event_object["object"] != "dispute" {
                return Err(BillingError::InvalidEvent);
            }
            let event_charge = optional_charge(&event_object["charge"])?;
            let event_pi = optional_id(&event_object["payment_intent"], "pi_")?;
            let fresh = provider.get(&format!("/v1/disputes/{object_id}")).await?;
            if fresh["id"] != object_id
                || fresh["object"] != "dispute"
                || fresh["livemode"] != false
            {
                return Err(BillingError::InvalidEvent);
            }
            let fresh_charge = optional_charge(&fresh["charge"])?;
            let fresh_pi = optional_id(&fresh["payment_intent"], "pi_")?;
            if event_charge
                .as_ref()
                .is_some_and(|known| Some(known) != fresh_charge.as_ref())
                || event_pi
                    .as_ref()
                    .is_some_and(|known| Some(known) != fresh_pi.as_ref())
            {
                return Err(BillingError::TenantConflict);
            }
            (fresh_charge, fresh_pi, false, None)
        }
        _ => return Err(BillingError::InvalidEvent),
    };
    if prior.kind
        != if prior.event_type == "charge.dispute.created" {
            "dispute"
        } else {
            "refund"
        }
    {
        return Err(BillingError::TenantConflict);
    }
    if prior
        .charge_id
        .as_ref()
        .is_some_and(|known| Some(known) != charge_id.as_ref())
        || prior
            .payment_intent_id
            .as_ref()
            .is_some_and(|known| Some(known) != payment_intent_id.as_ref())
    {
        return Err(BillingError::TenantConflict);
    }
    let charge = if let Some(charge_id) = &charge_id {
        let value = provider.get(&format!("/v1/charges/{charge_id}")).await?;
        risk::parse_charge(&value, charge_id)?
    } else if let Some(pi_id) = &payment_intent_id {
        let value = provider
            .get(&format!("/v1/charges?payment_intent={pi_id}&limit=100"))
            .await?;
        risk::parse_charge_for_payment_intent(&value, pi_id)?
    } else {
        return Err(BillingError::InvalidEvent);
    };
    if payment_intent_id
        .as_deref()
        .is_some_and(|known| known != charge.payment_intent_id)
        || event_customer
            .as_deref()
            .is_some_and(|known| known != charge.customer_id)
        || prior
            .customer_id
            .as_deref()
            .is_some_and(|known| known != charge.customer_id)
    {
        return Err(BillingError::TenantConflict);
    }
    if failed_refund {
        return Ok(Evidence {
            object_id,
            charge,
            subscription_id: None,
            failed_refund,
        });
    }
    if prior.kind == "refund" && charge.amount_refunded == 0 {
        return Err(BillingError::InvalidEvent);
    }
    let pi_id = &charge.payment_intent_id;
    let payments = provider.get(&format!("/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D={pi_id}&limit=2")).await?;
    let invoice_id = risk::parse_invoice_payment(&payments, pi_id)?;
    let invoice = provider.get(&format!("/v1/invoices/{invoice_id}")).await?;
    let subscription_id =
        risk::parse_invoice_subscription(&invoice, &invoice_id, &charge.customer_id)?;
    Ok(Evidence {
        object_id,
        charge,
        subscription_id: Some(subscription_id),
        failed_refund,
    })
}

async fn persist_decision(
    client: &mut Client,
    event_id: &str,
    operator_id: &str,
    prior: &ReviewRow,
    evidence: &Evidence,
) -> Result<ReviewResult, BillingError> {
    let tx = client.transaction().await?;
    lock_customer(&tx, &evidence.charge.customer_id).await?;
    let bound = tx
        .query_opt(
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR UPDATE",
            &[&evidence.charge.customer_id],
        )
        .await?
        .map(|row| row.get::<_, Uuid>(0));
    let row = tx
        .query_one(
            "SELECT e.event_type,e.object_id,e.stripe_customer_id,e.account_id, \
         r.stripe_charge_id,r.stripe_payment_intent_id,r.risk_kind,r.state,r.account_id \
         FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) \
         WHERE r.stripe_event_id=$1 FOR UPDATE OF r,e",
            &[&event_id],
        )
        .await?;
    let current = ReviewRow {
        event_type: row.get(0),
        object_id: row.get(1),
        customer_id: row.get(2),
        event_account_id: row.get(3),
        charge_id: row.get(4),
        payment_intent_id: row.get(5),
        kind: row.get(6),
        state: row.get(7),
        risk_account_id: row.get(8),
    };
    if matches!(current.state.as_str(), "held" | "closed_failed_refund") {
        tx.commit().await?;
        return Ok(ReviewResult::AlreadyResolved);
    }
    if current != *prior
        || prior
            .customer_id
            .as_deref()
            .is_some_and(|known| known != evidence.charge.customer_id)
        || prior
            .risk_account_id
            .is_some_and(|known| Some(known) != bound)
        || prior
            .event_account_id
            .is_some_and(|known| Some(known) != bound)
    {
        return Err(BillingError::TenantConflict);
    }
    let action;
    let result;
    if evidence.failed_refund {
        action = "closed_failed_refund";
        result = ReviewResult::ClosedFailedRefund;
        tx.execute(
            "UPDATE billing_risk_events SET state='closed_failed_refund',stripe_charge_id=$2, \
             stripe_payment_intent_id=$3,account_id=COALESCE(account_id,$4),processed_at=now() WHERE stripe_event_id=$1",
            &[&event_id, &evidence.charge.id, &evidence.charge.payment_intent_id, &bound],
        ).await?;
    } else if let Some(account_id) = bound {
        let subscription_id = evidence
            .subscription_id
            .as_deref()
            .ok_or(BillingError::InvalidEvent)?;
        if !queue_subscription(
            &tx,
            account_id,
            &evidence.charge.customer_id,
            subscription_id,
        )
        .await?
        {
            return Err(BillingError::TenantConflict);
        }
        tx.execute(
            "INSERT INTO billing_payment_holds(stripe_event_id,account_id,stripe_subscription_id,stripe_charge_id,reason) VALUES($1,$2,$3,$4,$5)",
            &[&event_id, &account_id, &subscription_id, &evidence.charge.id, &prior.kind],
        ).await?;
        tx.execute(
            "UPDATE billing_risk_events SET state='held',stripe_charge_id=$2, \
             stripe_payment_intent_id=$3,account_id=$4,stripe_subscription_id=$5,processed_at=now() WHERE stripe_event_id=$1",
            &[&event_id, &evidence.charge.id, &evidence.charge.payment_intent_id, &account_id, &subscription_id],
        ).await?;
        action = "held";
        result = ReviewResult::Held;
    } else {
        tx.execute(
            "UPDATE billing_risk_events SET stripe_charge_id=$2,stripe_payment_intent_id=$3 WHERE stripe_event_id=$1",
            &[&event_id, &evidence.charge.id, &evidence.charge.payment_intent_id],
        ).await?;
        action = "attributed_unbound";
        result = ReviewResult::AttributedUnbound;
    }
    tx.execute(
        "UPDATE billing_events SET stripe_customer_id=$2,account_id=COALESCE(account_id,$3), \
         object_id=COALESCE(object_id,$4) WHERE stripe_event_id=$1",
        &[
            &event_id,
            &evidence.charge.customer_id,
            &bound,
            &evidence.object_id,
        ],
    )
    .await?;
    let recorded = tx.execute(
        "INSERT INTO billing_risk_review_actions(stripe_event_id,operator_id,action,stripe_object_id, \
         stripe_charge_id,stripe_payment_intent_id,stripe_customer_id,stripe_subscription_id) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(stripe_event_id,action) DO NOTHING",
        &[&event_id, &operator_id, &action, &evidence.object_id, &evidence.charge.id,
          &evidence.charge.payment_intent_id, &evidence.charge.customer_id, &evidence.subscription_id],
    ).await?;
    if action != "attributed_unbound" && recorded != 1 {
        return Err(BillingError::TenantConflict);
    }
    tx.commit().await?;
    Ok(result)
}

#[cfg(test)]
mod tests;
