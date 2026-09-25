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
mod tests {
    use super::*;
    use crate::billing::{HmacSha256, IngestResult, bind_customer, ingest, verify_event};
    use hmac::Mac;
    use serde_json::json;
    use std::{collections::HashMap, env, sync::Mutex};
    use tokio_postgres::NoTls;

    struct FakeProvider {
        answers: HashMap<String, Value>,
        requested: Mutex<Vec<String>>,
    }

    impl FakeProvider {
        fn new(answers: impl IntoIterator<Item = (String, Value)>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                requested: Mutex::new(Vec::new()),
            }
        }
    }

    impl ReviewProvider for FakeProvider {
        async fn get(&self, path: &str) -> Result<Value, BillingError> {
            self.requested.lock().unwrap().push(path.to_owned());
            self.answers
                .get(path)
                .cloned()
                .ok_or(BillingError::InvalidEvent)
        }
    }

    fn signed(body: &[u8]) -> crate::billing::VerifiedEvent {
        let secret = format!("whsec_{}", Uuid::new_v4().simple());
        let now = 1_750_000_000;
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{now}.").as_bytes());
        mac.update(body);
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        verify_event(body, &format!("t={now},v1={signature}"), &secret, now).unwrap()
    }

    fn refund_provider(
        event_id: &str,
        refund_id: &str,
        charge_id: &str,
        customer_id: &str,
        status: &str,
    ) -> FakeProvider {
        let suffix = refund_id.strip_prefix("re_").unwrap();
        let pi_id = format!("pi_{suffix}");
        let invoice_id = format!("in_{suffix}");
        let subscription_id = format!("sub_{suffix}");
        FakeProvider::new([
            (
                format!("/v1/events/{event_id}"),
                json!({"id":event_id,"object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":refund_id,"object":"refund","charge":charge_id,"payment_intent":pi_id}}}),
            ),
            (
                format!("/v1/refunds/{refund_id}"),
                json!({"id":refund_id,"object":"refund","livemode":false,"charge":charge_id,"payment_intent":pi_id,"status":status}),
            ),
            (
                format!("/v1/charges/{charge_id}"),
                json!({"id":charge_id,"object":"charge","livemode":false,"customer":customer_id,"payment_intent":pi_id,"amount_refunded":if status == "failed" { 0 } else { 50 }}),
            ),
            (
                format!(
                    "/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D={pi_id}&limit=2"
                ),
                json!({"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"status":"paid","payment":{"type":"payment_intent","payment_intent":pi_id},"invoice":invoice_id}]}),
            ),
            (
                format!("/v1/invoices/{invoice_id}"),
                json!({"id":invoice_id,"object":"invoice","livemode":false,"customer":customer_id,"status":"paid","subscription":subscription_id}),
            ),
        ])
    }

    #[tokio::test]
    async fn provider_evidence_rejects_live_mismatched_and_incomplete_objects() {
        let event_id = "evt_reviewshape1";
        let prior = ReviewRow {
            event_type: "refund.created".into(),
            object_id: Some("re_reviewshape1".into()),
            customer_id: None,
            event_account_id: None,
            charge_id: Some("ch_reviewshape1".into()),
            payment_intent_id: None,
            kind: "refund".into(),
            state: "needs_review".into(),
            risk_account_id: None,
        };
        let mut provider = refund_provider(
            event_id,
            "re_reviewshape1",
            "ch_reviewshape1",
            "cus_reviewshape1",
            "succeeded",
        );
        let evidence = fetch_evidence(&provider, event_id, &prior)
            .await
            .unwrap_or_else(|error| panic!("{error:?}; {:?}", provider.requested.lock().unwrap()));
        assert_eq!(evidence.charge.customer_id, "cus_reviewshape1");
        assert_eq!(
            evidence.subscription_id.as_deref(),
            Some("sub_reviewshape1")
        );
        assert_eq!(provider.requested.lock().unwrap().len(), 5);
        provider
            .answers
            .get_mut(&format!("/v1/events/{event_id}"))
            .unwrap()["livemode"] = json!(true);
        assert!(fetch_evidence(&provider, event_id, &prior).await.is_err());
        provider
            .answers
            .get_mut(&format!("/v1/events/{event_id}"))
            .unwrap()["livemode"] = json!(false);
        provider
            .answers
            .get_mut("/v1/charges/ch_reviewshape1")
            .unwrap()["customer"] = json!("cus_other1");
        provider
            .answers
            .get_mut("/v1/invoices/in_reviewshape1")
            .unwrap()["customer"] = json!("cus_reviewshape1");
        assert!(fetch_evidence(&provider, event_id, &prior).await.is_err());
        provider
            .answers
            .get_mut("/v1/charges/ch_reviewshape1")
            .unwrap()["customer"] = json!("cus_reviewshape1");
        provider
            .answers
            .get_mut("/v1/refunds/re_reviewshape1")
            .unwrap()["charge"] = json!("ch_other1");
        assert!(fetch_evidence(&provider, event_id, &prior).await.is_err());
    }

    #[tokio::test]
    async fn payment_intent_only_refund_and_dispute_need_a_complete_consistent_provider_chain() {
        let refund_id = "evt_reviewpi1";
        let refund_row = ReviewRow {
            event_type: "refund.created".into(),
            object_id: Some("re_reviewpi1".into()),
            customer_id: None,
            event_account_id: None,
            charge_id: None,
            payment_intent_id: Some("pi_reviewpi1".into()),
            kind: "refund".into(),
            state: "needs_review".into(),
            risk_account_id: None,
        };
        let mut refund = FakeProvider::new([
            (format!("/v1/events/{refund_id}"), json!({"id":refund_id,"object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewpi1","object":"refund","charge":null,"payment_intent":"pi_reviewpi1"}}})),
            ("/v1/refunds/re_reviewpi1".into(), json!({"id":"re_reviewpi1","object":"refund","livemode":false,"charge":null,"payment_intent":"pi_reviewpi1","status":"succeeded"})),
            ("/v1/charges?payment_intent=pi_reviewpi1&limit=100".into(), json!({"object":"list","has_more":false,"data":[{"id":"ch_reviewfailedattempt1","object":"charge","livemode":false,"payment_intent":"pi_reviewpi1","amount_refunded":0},{"id":"py_reviewpi1","object":"charge","livemode":false,"customer":"cus_reviewpi1","payment_intent":"pi_reviewpi1","amount_refunded":50}]})),
            ("/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D=pi_reviewpi1&limit=2".into(), json!({"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"status":"paid","payment":{"type":"payment_intent","payment_intent":"pi_reviewpi1"},"invoice":"in_reviewpi1"}]})),
            ("/v1/invoices/in_reviewpi1".into(), json!({"id":"in_reviewpi1","object":"invoice","livemode":false,"customer":"cus_reviewpi1","status":"paid","subscription":"sub_reviewpi1"})),
        ]);
        assert_eq!(
            fetch_evidence(&refund, refund_id, &refund_row)
                .await
                .unwrap()
                .charge
                .id,
            "py_reviewpi1"
        );
        refund
            .answers
            .get_mut("/v1/charges?payment_intent=pi_reviewpi1&limit=100")
            .unwrap()["has_more"] = json!(true);
        assert!(
            fetch_evidence(&refund, refund_id, &refund_row)
                .await
                .is_err()
        );

        let dispute_id = "evt_reviewdispute1";
        let dispute_row = ReviewRow {
            event_type: "charge.dispute.created".into(),
            object_id: Some("du_reviewdispute1".into()),
            customer_id: None,
            event_account_id: None,
            charge_id: Some("ch_reviewdispute1".into()),
            payment_intent_id: None,
            kind: "dispute".into(),
            state: "needs_review".into(),
            risk_account_id: None,
        };
        let mut dispute = FakeProvider::new([
            (format!("/v1/events/{dispute_id}"), json!({"id":dispute_id,"object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_reviewdispute1","object":"dispute","charge":"ch_reviewdispute1"}}})),
            ("/v1/disputes/du_reviewdispute1".into(), json!({"id":"du_reviewdispute1","object":"dispute","livemode":false,"charge":"ch_reviewdispute1","payment_intent":"pi_reviewdispute1","status":"needs_response"})),
            ("/v1/charges/ch_reviewdispute1".into(), json!({"id":"ch_reviewdispute1","object":"charge","livemode":false,"customer":"cus_reviewdispute1","payment_intent":"pi_reviewdispute1","amount_refunded":0})),
            ("/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D=pi_reviewdispute1&limit=2".into(), json!({"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"status":"paid","payment":{"type":"payment_intent","payment_intent":"pi_reviewdispute1"},"invoice":"in_reviewdispute1"}]})),
            ("/v1/invoices/in_reviewdispute1".into(), json!({"id":"in_reviewdispute1","object":"invoice","livemode":false,"customer":"cus_reviewdispute1","status":"paid","subscription":"sub_reviewdispute1"})),
        ]);
        assert_eq!(
            fetch_evidence(&dispute, dispute_id, &dispute_row)
                .await
                .unwrap()
                .subscription_id
                .as_deref(),
            Some("sub_reviewdispute1")
        );
        dispute
            .answers
            .get_mut("/v1/disputes/du_reviewdispute1")
            .unwrap()["charge"] = json!("ch_other1");
        assert!(
            fetch_evidence(&dispute, dispute_id, &dispute_row)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a disposable PostgreSQL schema and fake provider"]
    async fn operator_review_holds_attributed_risks_and_closes_only_failed_refunds() {
        let base_url =
            env::var("ZT_AUTH_TEST_DATABASE_URL").expect("set ZT_AUTH_TEST_DATABASE_URL");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let schema = format!("billing_review_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
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
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();

        // A signed refund with a Charge pointer can time out in the normal
        // queue before its customer is known locally. Review fetches Event,
        // Refund, Charge and paid invoice from a fake provider, then retains
        // the review hold until a trusted customer binding appears.
        let event = signed(br#"{"id":"evt_reviewunknown1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewunknown1","object":"refund","charge":"ch_reviewunknown1"}}}"#);
        assert_eq!(
            ingest(&mut db, &event).await.unwrap(),
            IngestResult::Unbound
        );
        db.execute(
            "UPDATE billing_risk_events SET state='needs_review' WHERE stripe_event_id=$1",
            &[&event.event_id],
        )
        .await
        .unwrap();
        let provider = refund_provider(
            "evt_reviewunknown1",
            "re_reviewunknown1",
            "ch_reviewunknown1",
            "cus_reviewunknown1",
            "succeeded",
        );
        assert_eq!(
            review_one(&mut db, &provider, &event.event_id, "operator.test", false)
                .await
                .unwrap(),
            ReviewResult::AttributedUnbound
        );
        let attribution = db.query_one("SELECT e.stripe_customer_id,r.state FROM billing_events e JOIN billing_risk_events r USING(stripe_event_id) WHERE e.stripe_event_id=$1", &[&event.event_id]).await.unwrap();
        assert_eq!(attribution.get::<_, String>(0), "cus_reviewunknown1");
        assert_eq!(attribution.get::<_, String>(1), "needs_review");
        assert_eq!(
            review_one(&mut db, &provider, &event.event_id, "operator.test", false)
                .await
                .unwrap(),
            ReviewResult::AttributedUnbound
        );
        let action_count: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_review_actions WHERE stripe_event_id=$1",
                &[&event.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(action_count, 1);
        bind_customer(&mut db, account, "cus_reviewunknown1")
            .await
            .unwrap();
        assert_eq!(
            review_one(&mut db, &provider, &event.event_id, "operator.test", false)
                .await
                .unwrap(),
            ReviewResult::Held
        );
        assert_eq!(
            review_one(&mut db, &provider, &event.event_id, "operator.test", false)
                .await
                .unwrap(),
            ReviewResult::AlreadyResolved
        );
        let hold = db.query_one("SELECT account_id,stripe_subscription_id,stripe_charge_id FROM billing_payment_holds WHERE stripe_event_id=$1", &[&event.event_id]).await.unwrap();
        assert_eq!(hold.get::<_, Uuid>(0), account);
        assert_eq!(hold.get::<_, String>(1), "sub_reviewunknown1");
        assert_eq!(hold.get::<_, String>(2), "ch_reviewunknown1");
        let decisions: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_review_actions WHERE stripe_event_id=$1",
                &[&event.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(decisions, 2);

        let failed = signed(br#"{"id":"evt_reviewfailed1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewfailed1","object":"refund","charge":"ch_reviewfailed1"}}}"#);
        ingest(&mut db, &failed).await.unwrap();
        db.execute(
            "UPDATE billing_risk_events SET state='needs_review' WHERE stripe_event_id=$1",
            &[&failed.event_id],
        )
        .await
        .unwrap();
        let failed_provider = refund_provider(
            "evt_reviewfailed1",
            "re_reviewfailed1",
            "ch_reviewfailed1",
            "cus_reviewunknown1",
            "failed",
        );
        assert_eq!(
            review_one(
                &mut db,
                &failed_provider,
                &failed.event_id,
                "operator.test",
                false
            )
            .await
            .unwrap(),
            ReviewResult::ClosureNeedsApproval
        );
        let open: String = db
            .query_one(
                "SELECT state FROM billing_risk_events WHERE stripe_event_id=$1",
                &[&failed.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(open, "needs_review");
        assert_eq!(
            review_one(
                &mut db,
                &failed_provider,
                &failed.event_id,
                "operator.test",
                true
            )
            .await
            .unwrap(),
            ReviewResult::ClosedFailedRefund
        );
        let closed: String = db
            .query_one(
                "SELECT state FROM billing_risk_events WHERE stripe_event_id=$1",
                &[&failed.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(closed, "closed_failed_refund");
        let final_action: String = db
            .query_one(
                "SELECT action FROM billing_risk_review_actions WHERE stripe_event_id=$1",
                &[&failed.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(final_action, "closed_failed_refund");
        let failed_holds: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_payment_holds WHERE stripe_event_id=$1",
                &[&failed.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(failed_holds, 0);

        // This shape was acknowledged as unsupported by #184 itself: its
        // signed Charge snapshot reports zero refunded, while a fresh TEST
        // Charge read can later prove the refund and paid invoice link.
        let unsupported = signed(br#"{"id":"evt_reviewshape2","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_reviewshape2","object":"charge","customer":"cus_reviewunknown1","payment_intent":"pi_reviewshape2","amount_refunded":0}}}"#);
        assert!(unsupported.unsupported && unsupported.risk_review_required);
        assert_eq!(
            ingest(&mut db, &unsupported).await.unwrap(),
            IngestResult::Unsupported
        );
        let provider = FakeProvider::new([
            ("/v1/events/evt_reviewshape2".into(), json!({"id":"evt_reviewshape2","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_reviewshape2","object":"charge","customer":"cus_reviewunknown1","payment_intent":"pi_reviewshape2","amount_refunded":0}}})),
            ("/v1/charges/ch_reviewshape2".into(), json!({"id":"ch_reviewshape2","object":"charge","livemode":false,"customer":"cus_reviewunknown1","payment_intent":"pi_reviewshape2","amount_refunded":50})),
            ("/v1/invoice_payments?payment%5Btype%5D=payment_intent&payment%5Bpayment_intent%5D=pi_reviewshape2&limit=2".into(), json!({"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"status":"paid","payment":{"type":"payment_intent","payment_intent":"pi_reviewshape2"},"invoice":"in_reviewshape2"}]})),
            ("/v1/invoices/in_reviewshape2".into(), json!({"id":"in_reviewshape2","object":"invoice","livemode":false,"customer":"cus_reviewunknown1","status":"paid","subscription":"sub_reviewshape2"})),
        ]);
        assert_eq!(
            review_one(
                &mut db,
                &provider,
                &unsupported.event_id,
                "operator.test",
                false
            )
            .await
            .unwrap(),
            ReviewResult::Held
        );
        let state: String = db
            .query_one(
                "SELECT state FROM billing_risk_events WHERE stripe_event_id=$1",
                &[&unsupported.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "held");

        // A signed event and fresh Refund that both lack usable pointers
        // cannot be closed or attributed; no audit decision is invented.
        let unknown = signed(br#"{"id":"evt_reviewmissing1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewmissing1","object":"refund","charge":null,"payment_intent":null}}}"#);
        assert_eq!(
            ingest(&mut db, &unknown).await.unwrap(),
            IngestResult::Unsupported
        );
        let missing_provider = FakeProvider::new([
            (
                "/v1/events/evt_reviewmissing1".into(),
                json!({"id":"evt_reviewmissing1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewmissing1","object":"refund","charge":null,"payment_intent":null}}}),
            ),
            (
                "/v1/refunds/re_reviewmissing1".into(),
                json!({"id":"re_reviewmissing1","object":"refund","livemode":false,"charge":null,"payment_intent":null,"status":"pending"}),
            ),
        ]);
        assert!(
            review_one(
                &mut db,
                &missing_provider,
                &unknown.event_id,
                "operator.test",
                true
            )
            .await
            .is_err()
        );
        let unresolved: String = db
            .query_one(
                "SELECT state FROM billing_risk_events WHERE stripe_event_id=$1",
                &[&unknown.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(unresolved, "needs_review");
        let no_action: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_review_actions WHERE stripe_event_id=$1",
                &[&unknown.event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(no_action, 0);

        // Two operators can validate the same event concurrently, but the
        // customer/risk locks admit only one hold and one final audit action.
        let concurrent = signed(br#"{"id":"evt_reviewconcurrent1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_reviewconcurrent1","object":"refund","charge":"ch_reviewconcurrent1"}}}"#);
        ingest(&mut db, &concurrent).await.unwrap();
        db.execute(
            "UPDATE billing_risk_events SET state='needs_review' WHERE stripe_event_id=$1",
            &[&concurrent.event_id],
        )
        .await
        .unwrap();
        let provider = refund_provider(
            "evt_reviewconcurrent1",
            "re_reviewconcurrent1",
            "ch_reviewconcurrent1",
            "cus_reviewunknown1",
            "succeeded",
        );
        let (mut reviewer_a, connection_a) =
            tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection_a.await;
        });
        let (mut reviewer_b, connection_b) =
            tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection_b.await;
        });
        let (a, b) = tokio::join!(
            review_one(
                &mut reviewer_a,
                &provider,
                &concurrent.event_id,
                "operator.a",
                false
            ),
            review_one(
                &mut reviewer_b,
                &provider,
                &concurrent.event_id,
                "operator.b",
                false
            ),
        );
        let outcomes = [a.unwrap(), b.unwrap()];
        assert!(outcomes.contains(&ReviewResult::Held));
        assert!(outcomes.contains(&ReviewResult::AlreadyResolved));
        let hold_count: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_payment_holds WHERE stripe_event_id=$1",
                &[&concurrent.event_id],
            )
            .await
            .unwrap()
            .get(0);
        let audit_count: i64 = db.query_one("SELECT count(*) FROM billing_risk_review_actions WHERE stripe_event_id=$1 AND action='held'", &[&concurrent.event_id]).await.unwrap().get(0);
        assert_eq!((hold_count, audit_count), (1, 1));

        // A full first page must not hide later risks. The cursor is the
        // immutable (created_at, event_id) position, so closed rows can also
        // be used as an `--after` anchor without changing review state.
        db.batch_execute(
            "INSERT INTO billing_events(stripe_event_id,event_type,body_sha256,disposition) \
             SELECT 'evt_reviewpage' || gs::text,'refund.created',decode(repeat('00',32),'hex'),'unsupported' \
             FROM generate_series(1,205) gs; \
             INSERT INTO billing_risk_events(stripe_event_id,risk_kind,state) \
             SELECT 'evt_reviewpage' || gs::text,'refund','needs_review' \
             FROM generate_series(1,205) gs",
        ).await.unwrap();
        let expected: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_events WHERE state='needs_review'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let mut seen = std::collections::HashSet::new();
        let mut after = None;
        let mut pages = 0;
        loop {
            let page = list_review_required(&db, after.as_deref()).await.unwrap();
            pages += 1;
            assert!(page.items.len() <= 100);
            for row in page.items {
                assert!(seen.insert(row.event_id));
            }
            after = page.next_after;
            if after.is_none() {
                break;
            }
        }
        assert_eq!(pages, 3);
        assert_eq!(seen.len() as i64, expected);
        assert!(
            !list_review_required(&db, Some(&failed.event_id))
                .await
                .unwrap()
                .items
                .is_empty()
        );
        assert!(
            list_review_required(&db, Some("evt_nonexistentcursor1"))
                .await
                .is_err()
        );
        let still_open: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_events WHERE state='needs_review'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(still_open, expected);

        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
