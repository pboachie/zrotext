// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode refund/dispute holds. A verified event first enters a durable
//! queue; provider reads then attribute its charge to a paid subscription
//! invoice. No event body grants access or clears a hold.

use super::{BillingError, lock_customer, queue_subscription, valid_charge_id, valid_id};
use reqwest::Client as HttpClient;
use serde_json::Value;
use tokio_postgres::Client;
use uuid::Uuid;

const STRIPE_API_VERSION: &str = "2025-07-30.basil";

#[derive(Debug)]
pub(super) struct Charge {
    pub customer_id: String,
    pub payment_intent_id: String,
    pub amount_refunded: i64,
}

pub(super) async fn fetch_charge(
    http: &HttpClient,
    secret_key: &str,
    charge_id: &str,
) -> Result<Charge, BillingError> {
    valid_charge_id(charge_id)?;
    let value = fetch_json(
        http,
        secret_key,
        &format!("https://api.stripe.com/v1/charges/{charge_id}"),
    )
    .await?;
    parse_charge(&value, charge_id)
}

fn parse_charge(value: &Value, expected_id: &str) -> Result<Charge, BillingError> {
    if value["object"] != "charge" || value["livemode"] != false || value["id"] != expected_id {
        return Err(BillingError::InvalidEvent);
    }
    let customer_id = valid_id(
        value["customer"]
            .as_str()
            .ok_or(BillingError::InvalidEvent)?,
        "cus_",
    )?
    .to_owned();
    let payment_intent_id = valid_id(
        value["payment_intent"]
            .as_str()
            .ok_or(BillingError::InvalidEvent)?,
        "pi_",
    )?
    .to_owned();
    let amount_refunded = value["amount_refunded"]
        .as_i64()
        .filter(|amount| *amount >= 0)
        .ok_or(BillingError::InvalidEvent)?;
    Ok(Charge {
        customer_id,
        payment_intent_id,
        amount_refunded,
    })
}

/// Resolve the PaymentIntent through Stripe's invoice-payments API. Requiring
/// one paid payment and a subscription invoice avoids attributing an unrelated
/// one-time charge to an account's subscription.
pub(super) async fn fetch_invoice_subscription(
    http: &HttpClient,
    secret_key: &str,
    charge: &Charge,
) -> Result<String, BillingError> {
    // The PI is validated to ASCII alphanumerics above, so interpolation
    // cannot change the fixed Stripe host or query structure.
    let payments = fetch_json(
        http,
        secret_key,
        &format!("https://api.stripe.com/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D={}&limit=2", charge.payment_intent_id),
    )
    .await?;
    let invoice_id = parse_invoice_payment(&payments, &charge.payment_intent_id)?;
    let invoice = fetch_json(
        http,
        secret_key,
        &format!("https://api.stripe.com/v1/invoices/{invoice_id}"),
    )
    .await?;
    parse_invoice_subscription(&invoice, &invoice_id, &charge.customer_id)
}

fn parse_invoice_payment(value: &Value, payment_intent_id: &str) -> Result<String, BillingError> {
    if value["object"] != "list" || value["has_more"] != false {
        return Err(BillingError::InvalidEvent);
    }
    let rows = value["data"].as_array().ok_or(BillingError::InvalidEvent)?;
    if rows.len() != 1 {
        return Err(BillingError::InvalidEvent);
    }
    let row = &rows[0];
    if row["object"] != "invoice_payment"
        || row["livemode"] != false
        || row["status"] != "paid"
        || row["payment"]["type"] != "payment_intent"
        || row["payment"]["payment_intent"] != payment_intent_id
    {
        return Err(BillingError::InvalidEvent);
    }
    Ok(valid_id(
        row["invoice"].as_str().ok_or(BillingError::InvalidEvent)?,
        "in_",
    )?
    .to_owned())
}

fn parse_invoice_subscription(
    value: &Value,
    invoice_id: &str,
    customer_id: &str,
) -> Result<String, BillingError> {
    if value["object"] != "invoice"
        || value["livemode"] != false
        || value["id"] != invoice_id
        || value["customer"] != customer_id
        || value["status"] != "paid"
    {
        return Err(BillingError::InvalidEvent);
    }
    let subscription = value["subscription"]
        .as_str()
        .or_else(|| value["parent"]["subscription_details"]["subscription"].as_str())
        .ok_or(BillingError::InvalidEvent)?;
    Ok(valid_id(subscription, "sub_")?.to_owned())
}

async fn fetch_json(http: &HttpClient, secret_key: &str, url: &str) -> Result<Value, BillingError> {
    let mut response = http
        .get(url)
        .header("Stripe-Version", STRIPE_API_VERSION)
        .bearer_auth(secret_key)
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
    serde_json::from_slice(&body).map_err(|_| BillingError::InvalidEvent)
}

/// Bind a verified risk event to the customer returned by the current Charge.
/// The customer row lock serializes the first hold with metered reservations.
pub(super) async fn bind_charge_customer(
    client: &mut Client,
    event_id: &str,
    customer_id: &str,
) -> Result<bool, BillingError> {
    valid_id(event_id, "evt_")?;
    valid_id(customer_id, "cus_")?;
    let tx = client.transaction().await?;
    lock_customer(&tx, customer_id).await?;
    let bound = tx
        .query_opt(
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR UPDATE",
            &[&customer_id],
        )
        .await?;
    let previous = tx.query_one(
        "SELECT e.stripe_customer_id,r.account_id FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) WHERE r.stripe_event_id=$1 FOR UPDATE OF r,e",
        &[&event_id],
    ).await?;
    let event_customer: Option<String> = previous.get(0);
    if event_customer
        .as_deref()
        .is_some_and(|known| known != customer_id)
    {
        return Err(BillingError::TenantConflict);
    }
    let Some(bound) = bound else {
        // Persist the current Charge's customer even before Checkout creates
        // the trusted local binding. A later bind_customer can then attach a
        // review-required event after this worker's retries are exhausted.
        tx.execute(
            "UPDATE billing_events SET stripe_customer_id=$2 WHERE stripe_event_id=$1 AND stripe_customer_id IS NULL",
            &[&event_id, &customer_id],
        )
        .await?;
        tx.commit().await?;
        return Ok(false);
    };
    let account_id: Uuid = bound.get(0);
    let prior_account: Option<Uuid> = previous.get(1);
    if prior_account.is_some_and(|known| known != account_id) {
        return Err(BillingError::TenantConflict);
    }
    tx.execute(
        "UPDATE billing_risk_events SET account_id=$2 WHERE stripe_event_id=$1 AND account_id IS NULL",
        &[&event_id, &account_id],
    ).await?;
    tx.execute(
        "UPDATE billing_events SET account_id=$2,stripe_customer_id=$3,disposition='queued' WHERE stripe_event_id=$1 AND account_id IS NULL",
        &[&event_id, &account_id, &customer_id],
    ).await?;
    tx.commit().await?;
    Ok(true)
}

/// Append a hold only after the Charge -> InvoicePayment -> paid subscription
/// invoice chain has been fetched and tenant-bound. A later active subscription
/// reconciliation cannot remove this record.
pub(super) async fn apply_hold(
    client: &mut Client,
    event_id: &str,
    charge_id: &str,
    customer_id: &str,
    subscription_id: &str,
    kind: &str,
) -> Result<(), BillingError> {
    valid_id(event_id, "evt_")?;
    valid_charge_id(charge_id)?;
    valid_id(customer_id, "cus_")?;
    valid_id(subscription_id, "sub_")?;
    if !matches!(kind, "refund" | "dispute") {
        return Err(BillingError::InvalidEvent);
    }
    let tx = client.transaction().await?;
    lock_customer(&tx, customer_id).await?;
    let bound = tx
        .query_one(
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR UPDATE",
            &[&customer_id],
        )
        .await?;
    let account_id: Uuid = bound.get(0);
    let risk = tx.query_one(
        "SELECT stripe_charge_id,risk_kind,state,account_id FROM billing_risk_events WHERE stripe_event_id=$1 FOR UPDATE",
        &[&event_id],
    ).await?;
    let prior_account: Option<Uuid> = risk.get(3);
    if risk.get::<_, String>(0) != charge_id
        || risk.get::<_, String>(1) != kind
        || prior_account.is_some_and(|known| known != account_id)
    {
        return Err(BillingError::TenantConflict);
    }
    if risk.get::<_, String>(2) == "held" {
        tx.commit().await?;
        return Ok(());
    }
    if !queue_subscription(&tx, account_id, customer_id, subscription_id).await? {
        return Err(BillingError::TenantConflict);
    }
    tx.execute(
        "INSERT INTO billing_payment_holds(stripe_event_id,account_id,stripe_subscription_id,stripe_charge_id,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT(stripe_event_id) DO NOTHING",
        &[&event_id, &account_id, &subscription_id, &charge_id, &kind],
    ).await?;
    tx.execute(
        "UPDATE billing_risk_events SET state='held',account_id=$2,stripe_subscription_id=$3,processed_at=now() WHERE stripe_event_id=$1",
        &[&event_id, &account_id, &subscription_id],
    ).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn claim(
    client: &mut Client,
) -> Result<Option<(String, String, String)>, BillingError> {
    let tx = client.transaction().await?;
    let row = tx.query_opt(
        "WITH target AS (SELECT stripe_event_id FROM billing_risk_events WHERE state='queued' AND next_attempt_at<=now() ORDER BY next_attempt_at,stripe_event_id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE billing_risk_events r SET next_attempt_at=now()+interval '30 seconds' FROM target WHERE r.stripe_event_id=target.stripe_event_id RETURNING r.stripe_event_id,r.stripe_charge_id,r.risk_kind",
        &[],
    ).await?;
    tx.commit().await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2))))
}

pub(super) async fn backoff(client: &Client, event_id: &str) -> Result<(), BillingError> {
    client.execute(
        "UPDATE billing_risk_events SET failed_attempts=failed_attempts+1,state=CASE WHEN failed_attempts>=9 THEN 'needs_review' ELSE 'queued' END,next_attempt_at=now()+interval '1 minute' WHERE stripe_event_id=$1 AND state='queued'",
        &[&event_id],
    ).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn current_test_payment_chain_requires_unique_paid_subscription_invoice() {
        let charge = json!({"id":"ch_risk1","object":"charge","livemode":false,"customer":"cus_risk1","payment_intent":"pi_risk1","amount_refunded":1});
        let parsed = parse_charge(&charge, "ch_risk1").unwrap();
        assert_eq!(parsed.amount_refunded, 1);
        assert!(parse_charge(&charge, "ch_other1").is_err());
        let payments = json!({"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"status":"paid","payment":{"type":"payment_intent","payment_intent":"pi_risk1"},"invoice":"in_risk1"}]});
        assert_eq!(
            parse_invoice_payment(&payments, &parsed.payment_intent_id).unwrap(),
            "in_risk1"
        );
        assert!(parse_invoice_payment(&payments, "pi_other1").is_err());
        let invoice = json!({"id":"in_risk1","object":"invoice","livemode":false,"status":"paid","customer":"cus_risk1","parent":{"subscription_details":{"subscription":"sub_risk1"}}});
        assert_eq!(
            parse_invoice_subscription(&invoice, "in_risk1", "cus_risk1").unwrap(),
            "sub_risk1"
        );
        assert!(parse_invoice_subscription(&invoice, "in_risk1", "cus_other1").is_err());
    }
}
