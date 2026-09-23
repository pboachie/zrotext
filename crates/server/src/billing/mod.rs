// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode Stripe event inbox. Events only request reconciliation; they never
//! directly grant a plan or change a quota.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod http;
pub mod risk;
pub mod worker;

type HmacSha256 = Hmac<Sha256>;
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER: usize = 1024;
const TOLERANCE_SECONDS: i64 = 300;

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("invalid Stripe signature")]
    InvalidSignature,
    #[error("invalid Stripe event")]
    InvalidEvent,
    #[error("Stripe event ID was previously recorded with different bytes")]
    EventConflict,
    #[error("billing storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("Stripe customer or subscription belongs to another tenant")]
    TenantConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    pub event_id: String,
    pub event_type: String,
    pub object_id: Option<String>,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    /// Only populated for verified test-mode refund or chargeback events.
    pub risk_charge_id: Option<String>,
    pub body_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestResult {
    Queued,
    Unbound,
    Ignored,
    Conflict,
    Duplicate,
}

/// Verify the exact raw request bytes before JSON parsing. The endpoint secret
/// is used literally as the HMAC key, including its `whsec_` prefix.
pub fn verify_event(
    body: &[u8],
    signature_header: &str,
    endpoint_secret: &str,
    now_unix_seconds: i64,
) -> Result<VerifiedEvent, BillingError> {
    if body.is_empty()
        || body.len() > MAX_BODY
        || signature_header.len() > MAX_HEADER
        || !endpoint_secret.starts_with("whsec_")
        || endpoint_secret.len() < 16
    {
        return Err(BillingError::InvalidSignature);
    }
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for field in signature_header.split(',') {
        let Some((kind, value)) = field.trim().split_once('=') else {
            continue;
        };
        match kind {
            "t" => {
                if timestamp.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(BillingError::InvalidSignature);
                }
                timestamp = value.parse::<i64>().ok();
            }
            "v1" if value.len() == 64 => {
                if let Some(bytes) = decode_hex_32(value) {
                    signatures.push(bytes);
                }
            }
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or(BillingError::InvalidSignature)?;
    if now_unix_seconds.abs_diff(timestamp) > TOLERANCE_SECONDS as u64 || signatures.is_empty() {
        return Err(BillingError::InvalidSignature);
    }
    let mut mac = HmacSha256::new_from_slice(endpoint_secret.as_bytes())
        .expect("HMAC accepts all key lengths");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    if !signatures
        .iter()
        .any(|candidate| mac.clone().verify_slice(candidate).is_ok())
    {
        return Err(BillingError::InvalidSignature);
    }
    let json: Value = serde_json::from_slice(body).map_err(|_| BillingError::InvalidEvent)?;
    if json["object"] != "event" || json["livemode"] != false {
        return Err(BillingError::InvalidEvent);
    }
    let event_id = stripe_id(&json["id"], "evt_")?.to_owned();
    let event_type = json["type"].as_str().ok_or(BillingError::InvalidEvent)?;
    if event_type.len() > 100 || event_type.is_empty() {
        return Err(BillingError::InvalidEvent);
    }
    let object = &json["data"]["object"];
    let (object_id, customer_id, subscription_id, risk_charge_id) = match event_type {
        "checkout.session.completed" => (
            Some(stripe_id(&object["id"], "cs_test_")?.to_owned()),
            Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
            Some(stripe_id(&object["subscription"], "sub_")?.to_owned()),
            None,
        ),
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted"
        | "customer.subscription.paused"
        | "customer.subscription.resumed" => {
            let subscription = stripe_id(&object["id"], "sub_")?.to_owned();
            (
                Some(subscription.clone()),
                Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
                Some(subscription),
                None,
            )
        }
        "invoice.paid" | "invoice.payment_failed" => {
            // Invoice subscription pointers differ across Stripe API versions.
            // A missing pointer is durably recorded but grants no entitlement.
            let subscription = object["subscription"]
                .as_str()
                .or_else(|| object["parent"]["subscription_details"]["subscription"].as_str())
                .map(|id| valid_id(id, "sub_"))
                .transpose()?;
            (
                Some(stripe_id(&object["id"], "in_")?.to_owned()),
                Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
                subscription.map(str::to_owned),
                None,
            )
        }
        "charge.refunded" => {
            if object["object"] != "charge"
                || object["amount_refunded"]
                    .as_i64()
                    .is_none_or(|amount| amount <= 0)
            {
                return Err(BillingError::InvalidEvent);
            }
            let charge = stripe_id(&object["id"], "ch_")?.to_owned();
            let customer = object["customer"]
                .as_str()
                .map(|id| valid_id(id, "cus_"))
                .transpose()?
                .map(str::to_owned);
            (Some(charge.clone()), customer, None, Some(charge))
        }
        "refund.created" => {
            if object["object"] != "refund" {
                return Err(BillingError::InvalidEvent);
            }
            let charge = object["charge"]
                .as_str()
                .map(|id| valid_id(id, "ch_"))
                .transpose()?
                .map(str::to_owned);
            (
                Some(stripe_id(&object["id"], "re_")?.to_owned()),
                None,
                None,
                charge,
            )
        }
        "charge.dispute.created" => {
            if object["object"] != "dispute" {
                return Err(BillingError::InvalidEvent);
            }
            let dispute = object["id"].as_str().ok_or(BillingError::InvalidEvent)?;
            if valid_id(dispute, "du_").is_err() {
                valid_id(dispute, "dp_")?;
            }
            (
                Some(dispute.to_owned()),
                None,
                None,
                Some(stripe_id(&object["charge"], "ch_")?.to_owned()),
            )
        }
        _ => (None, None, None, None),
    };
    Ok(VerifiedEvent {
        event_id,
        event_type: event_type.to_owned(),
        object_id,
        customer_id,
        subscription_id,
        risk_charge_id,
        body_sha256: Sha256::digest(body).into(),
    })
}

fn stripe_id<'a>(value: &'a Value, prefix: &str) -> Result<&'a str, BillingError> {
    valid_id(value.as_str().ok_or(BillingError::InvalidEvent)?, prefix)
}

fn valid_id<'a>(id: &'a str, prefix: &str) -> Result<&'a str, BillingError> {
    if id.len() <= prefix.len()
        || id.len() > 255
        || !id.starts_with(prefix)
        || !id[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(BillingError::InvalidEvent);
    }
    Ok(id)
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let mut result = [0u8; 32];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *slot = ((high << 4) | low) as u8;
    }
    Some(result)
}

/// Insert the event and mark its subscription dirty in one transaction. A
/// duplicate event ID never increments the generation. Unknown customers are
/// retained for an operator to resolve, but cannot affect another account.
pub async fn ingest(
    client: &mut Client,
    event: &VerifiedEvent,
) -> Result<IngestResult, BillingError> {
    let tx = client.transaction().await?;
    let account_id: Option<Uuid> = if let Some(customer_id) = &event.customer_id {
        lock_customer(&tx, customer_id).await?;
        tx.query_opt(
            if event.risk_charge_id.is_some() {
                "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR UPDATE"
            } else {
                "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR SHARE"
            },
            &[customer_id],
        )
        .await?
        .map(|row| row.get(0))
    } else {
        None
    };
    let initial = if event.subscription_id.is_none() && event.risk_charge_id.is_none() {
        IngestResult::Ignored
    } else if account_id.is_none() {
        IngestResult::Unbound
    } else {
        IngestResult::Queued
    };
    let disposition = match initial {
        IngestResult::Ignored => "ignored",
        IngestResult::Unbound => "unbound",
        _ => "queued",
    };
    let inserted = tx.execute(
        "INSERT INTO billing_events(stripe_event_id,event_type,object_id,stripe_customer_id,stripe_subscription_id,account_id,body_sha256,disposition) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(stripe_event_id) DO NOTHING",
        &[&event.event_id, &event.event_type, &event.object_id, &event.customer_id,
            &event.subscription_id, &account_id, &event.body_sha256.as_slice(), &disposition],
    ).await?;
    if inserted == 0 {
        let existing: Vec<u8> = tx
            .query_one(
                "SELECT body_sha256 FROM billing_events WHERE stripe_event_id=$1",
                &[&event.event_id],
            )
            .await?
            .get(0);
        if existing != event.body_sha256 {
            return Err(BillingError::EventConflict);
        }
        tx.commit().await?;
        return Ok(IngestResult::Duplicate);
    }
    if let Some(charge_id) = &event.risk_charge_id {
        let kind = if event.event_type == "charge.dispute.created" {
            "dispute"
        } else {
            "refund"
        };
        tx.execute(
            "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES($1,$2,$3,$4)",
            &[&event.event_id, &charge_id, &kind, &account_id],
        )
        .await?;
    }
    let mut result = initial;
    if let (Some(account_id), Some(customer_id), Some(subscription_id)) =
        (account_id, &event.customer_id, &event.subscription_id)
    {
        if !queue_subscription(&tx, account_id, customer_id, subscription_id).await? {
            result = IngestResult::Conflict;
        }
        if result == IngestResult::Conflict {
            tx.execute(
                "UPDATE billing_events SET disposition='conflict' WHERE stripe_event_id=$1",
                &[&event.event_id],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(result)
}

async fn lock_customer(tx: &Transaction<'_>, customer_id: &str) -> Result<(), BillingError> {
    // This also protects the absence of a binding row during concurrent setup.
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&customer_id],
    )
    .await?;
    Ok(())
}

async fn queue_subscription(
    tx: &Transaction<'_>,
    account_id: Uuid,
    customer_id: &str,
    subscription_id: &str,
) -> Result<bool, BillingError> {
    let owned_elsewhere = tx.query_opt(
        "SELECT 1 FROM billing_subscriptions WHERE stripe_subscription_id=$1 AND (account_id<>$2 OR stripe_customer_id<>$3) UNION ALL SELECT 1 FROM billing_reconciliations WHERE stripe_subscription_id=$1 AND (account_id<>$2 OR stripe_customer_id<>$3) LIMIT 1",
        &[&subscription_id, &account_id, &customer_id],
    ).await?.is_some();
    if owned_elsewhere {
        return Ok(false);
    }
    let changed = tx.execute(
        "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES($1,$2,$3) ON CONFLICT(stripe_subscription_id) DO UPDATE SET dirty_generation=billing_reconciliations.dirty_generation+1,next_attempt_at=now(),updated_at=now() WHERE billing_reconciliations.account_id=EXCLUDED.account_id AND billing_reconciliations.stripe_customer_id=EXCLUDED.stripe_customer_id",
        &[&subscription_id, &account_id, &customer_id],
    ).await?;
    Ok(changed == 1)
}

/// Establish a customer binding from a trusted Checkout flow, then queue any
/// previously unbound verified events. This is not an owner-facing route.
pub async fn bind_customer(
    client: &mut Client,
    account_id: Uuid,
    customer_id: &str,
) -> Result<(), BillingError> {
    valid_id(customer_id, "cus_")?;
    let tx = client.transaction().await?;
    lock_customer(&tx, customer_id).await?;
    tx.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
        &[&account_id, &customer_id],
    ).await?;
    let binding = tx
        .query_opt(
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR UPDATE",
            &[&customer_id],
        )
        .await?;
    if binding.map(|row| row.get::<_, Uuid>(0)) != Some(account_id) {
        return Err(BillingError::TenantConflict);
    }
    let rows = tx.query(
        "SELECT stripe_event_id,stripe_subscription_id FROM billing_events WHERE stripe_customer_id=$1 AND stripe_subscription_id IS NOT NULL AND disposition='unbound' ORDER BY received_at,stripe_event_id FOR UPDATE",
        &[&customer_id],
    ).await?;
    for row in rows {
        let event_id: String = row.get(0);
        let subscription_id: String = row.get(1);
        let disposition =
            if queue_subscription(&tx, account_id, customer_id, &subscription_id).await? {
                "queued"
            } else {
                "conflict"
            };
        tx.execute(
            "UPDATE billing_events SET account_id=$2,disposition=$3 WHERE stripe_event_id=$1",
            &[&event_id, &account_id, &disposition],
        )
        .await?;
    }
    // A verified refund can precede the trusted Checkout/customer binding.
    // Once bound, pending risk blocks fresh metered reservations immediately.
    tx.execute(
        "UPDATE billing_risk_events r SET account_id=$2 FROM billing_events e WHERE r.stripe_event_id=e.stripe_event_id AND e.stripe_customer_id=$1 AND r.account_id IS NULL",
        &[&customer_id, &account_id],
    )
    .await?;
    tx.execute(
        "UPDATE billing_events SET account_id=$2,disposition='queued' WHERE stripe_customer_id=$1 AND stripe_subscription_id IS NULL AND event_type IN ('charge.refunded','refund.created','charge.dispute.created') AND disposition='unbound'",
        &[&customer_id, &account_id],
    ).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SubscriptionSnapshot {
    pub subscription_id: String,
    pub customer_id: String,
    pub status: String,
    pub price_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestQuotaPlan {
    pub price_id: String,
    pub outbound_limit: i64,
}

/// Explicit test-mode price mapping. No price ID or limit comes from Checkout
/// request data or a webhook body.
pub fn parse_test_quota_plans(
    value: &str,
    recognized_prices: &[String],
) -> Result<Vec<TestQuotaPlan>, &'static str> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut plans = Vec::new();
    for entry in value.split(',') {
        let (price_id, limit) = entry
            .trim()
            .split_once(':')
            .ok_or("invalid Stripe test quota plan")?;
        valid_id(price_id, "price_").map_err(|_| "invalid Stripe test quota plan")?;
        if !recognized_prices.iter().any(|known| known == price_id)
            || plans
                .iter()
                .any(|plan: &TestQuotaPlan| plan.price_id == price_id)
        {
            return Err("invalid Stripe test quota plan");
        }
        let outbound_limit: i64 = limit
            .parse()
            .map_err(|_| "invalid Stripe test quota plan")?;
        if outbound_limit <= 0 {
            return Err("invalid Stripe test quota plan");
        }
        plans.push(TestQuotaPlan {
            price_id: price_id.to_owned(),
            outbound_limit,
        });
    }
    Ok(plans)
}

/// Startup always drops previously projected test allowances and requests a
/// fresh provider read. A changed or removed local price mapping cannot keep
/// granting the old limit after restart.
pub async fn reset_test_quotas_on_start(
    database_url: &str,
    require_schema: bool,
) -> Result<(), BillingError> {
    let (mut db, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = db
        .query_one(
            "SELECT to_regclass('billing_quota_audit') IS NOT NULL, to_regclass('billing_risk_events') IS NOT NULL AND to_regclass('billing_payment_holds') IS NOT NULL",
            &[],
        )
        .await?;
    let quota_available: bool = schema.get(0);
    let risk_available: bool = schema.get(1);
    if !quota_available {
        return if require_schema {
            Err(BillingError::InvalidEvent)
        } else {
            Ok(())
        };
    }
    // Disabling test billing must still clear old allowances when only the
    // entitlement migration has run; enabling requires the hold schema too.
    if require_schema && !risk_available {
        return Err(BillingError::InvalidEvent);
    }
    let tx = db.transaction().await?;
    tx.execute(
        "UPDATE billing_reconciliations SET dirty_generation=dirty_generation+1,next_attempt_at=now(),updated_at=now()",
        &[],
    ).await?;
    tx.execute(
        "INSERT INTO billing_quota_audit(account_id,reconciliation_generation,previous_limit_units,limit_units,reason) SELECT account_id,0,limit_units,0,'startup_reset' FROM usage_quota_policies WHERE source='stripe_test' AND limit_units<>0",
        &[],
    ).await?;
    tx.execute(
        "UPDATE usage_quota_policies SET limit_units=0,updated_at=now() WHERE source='stripe_test' AND limit_units<>0",
        &[],
    ).await?;
    tx.execute(
        "UPDATE usage_periods u SET limit_units=0 FROM usage_quota_policies p WHERE u.account_id=p.account_id AND u.metric='outbound_message' AND p.metric='outbound_message' AND p.source='stripe_test' AND u.period_start=date_trunc('month',transaction_timestamp() AT TIME ZONE 'UTC')::date",
        &[],
    ).await?;
    tx.commit().await?;
    Ok(())
}

/// Apply a freshly fetched Stripe subscription after checking both provider
/// IDs against the tenant binding. Event payloads never enter this path.
pub async fn reconcile_snapshot(
    client: &mut Client,
    account_id: Uuid,
    snapshot: &SubscriptionSnapshot,
    recognized_prices: &[String],
    expected_generation: i64,
) -> Result<(), BillingError> {
    reconcile_snapshot_with_quotas(
        client,
        account_id,
        snapshot,
        recognized_prices,
        &[],
        expected_generation,
    )
    .await
}

pub async fn reconcile_snapshot_with_quotas(
    client: &mut Client,
    account_id: Uuid,
    snapshot: &SubscriptionSnapshot,
    recognized_prices: &[String],
    quota_plans: &[TestQuotaPlan],
    expected_generation: i64,
) -> Result<(), BillingError> {
    valid_id(&snapshot.subscription_id, "sub_")?;
    valid_id(&snapshot.customer_id, "cus_")?;
    if let Some(price_id) = &snapshot.price_id {
        valid_id(price_id, "price_")?;
    }
    let tx = client.transaction().await?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 2))",
        &[&account_id.to_string()],
    )
    .await?;
    let row = tx.query_opt(
        "SELECT stripe_customer_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id=$1 AND account_id=$2 FOR UPDATE",
        &[&snapshot.subscription_id, &account_id],
    ).await?.ok_or(BillingError::TenantConflict)?;
    let bound_customer: String = row.get(0);
    if bound_customer != snapshot.customer_id {
        return Err(BillingError::TenantConflict);
    }
    let generation: i64 = row.get(1);
    let processed: i64 = row.get(2);
    if expected_generation <= processed || expected_generation > generation {
        tx.commit().await?;
        return Ok(());
    }
    if !matches!(
        snapshot.status.as_str(),
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
    let recognized = snapshot
        .price_id
        .as_ref()
        .is_some_and(|price| recognized_prices.contains(price));
    tx.execute(
        "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(stripe_subscription_id) DO UPDATE SET stripe_status=EXCLUDED.stripe_status,stripe_price_id=EXCLUDED.stripe_price_id,recognized_price=EXCLUDED.recognized_price,reconciled_at=now() WHERE billing_subscriptions.account_id=EXCLUDED.account_id AND billing_subscriptions.stripe_customer_id=EXCLUDED.stripe_customer_id",
        &[&snapshot.subscription_id, &account_id, &snapshot.customer_id, &snapshot.status, &snapshot.price_id, &recognized],
    ).await?;
    tx.execute(
        "UPDATE billing_reconciliations SET processed_generation=$3,failed_attempts=0,updated_at=now() WHERE stripe_subscription_id=$1 AND account_id=$2",
        &[&snapshot.subscription_id, &account_id, &expected_generation],
    ).await?;
    if !quota_plans.is_empty() {
        project_test_quota(
            &tx,
            account_id,
            &snapshot.subscription_id,
            expected_generation,
            quota_plans,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn project_test_quota(
    tx: &Transaction<'_>,
    account_id: Uuid,
    changed_subscription: &str,
    generation: i64,
    plans: &[TestQuotaPlan],
) -> Result<(), BillingError> {
    let rows = tx.query(
        "SELECT stripe_status,stripe_price_id,recognized_price FROM billing_subscriptions WHERE account_id=$1",
        &[&account_id],
    ).await?;
    // Other nonterminal subscriptions make the account ambiguous. Terminal
    // historical subscriptions do not block a newly active one.
    let nonterminal: Vec<_> = rows
        .iter()
        .filter(|row| {
            let status: String = row.get(0);
            !matches!(status.as_str(), "canceled" | "incomplete_expired")
        })
        .collect();
    let (limit, reason) = if nonterminal.len() == 1 {
        let row = nonterminal[0];
        let status: String = row.get(0);
        let price: Option<String> = row.get(1);
        let recognized: bool = row.get(2);
        if status == "active" && recognized {
            if let Some(plan) = plans
                .iter()
                .find(|plan| price.as_deref() == Some(&plan.price_id))
            {
                (plan.outbound_limit, "active")
            } else {
                (0, "unmapped")
            }
        } else {
            (0, "inactive")
        }
    } else if nonterminal.is_empty() {
        (0, "inactive")
    } else {
        (0, "ambiguous")
    };
    let previous = tx.query_opt(
        "SELECT limit_units,source FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' FOR UPDATE",
        &[&account_id],
    ).await?;
    let changed = previous.as_ref().is_none_or(|row| {
        row.get::<_, i64>(0) != limit || row.get::<_, String>(1) != "stripe_test"
    });
    if changed {
        tx.execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',$2,'stripe_test') ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=EXCLUDED.limit_units,source='stripe_test',updated_at=now()",
            &[&account_id, &limit],
        ).await?;
        tx.execute(
            "UPDATE usage_periods SET limit_units=$2 WHERE account_id=$1 AND metric='outbound_message' AND period_start=date_trunc('month',transaction_timestamp() AT TIME ZONE 'UTC')::date",
            &[&account_id, &limit],
        ).await?;
        let prior: Option<i64> = previous.map(|row| row.get(0));
        tx.execute(
            "INSERT INTO billing_quota_audit(account_id,stripe_subscription_id,reconciliation_generation,previous_limit_units,limit_units,reason) VALUES($1,$2,$3,$4,$5,$6)",
            &[&account_id, &changed_subscription, &generation, &prior, &limit, &reason],
        ).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio_postgres::NoTls;
    use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};

    const BODY: &[u8] = br#"{"id":"evt_fixture1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_fixture1","object":"subscription","customer":"cus_fixture1","status":"active"}}}"#;
    const HEADER: &str =
        "t=1750000000,v0=0000,v1=17db9d23bf1f46a7db28382296af063cf65b36c77d80f154712e9f0803633536";
    const SECRET: &str = "whsec_testfixture1234567890";

    fn signed_header(timestamp: i64, mac: HmacSha256) -> String {
        let digest = mac.finalize().into_bytes();
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("t={timestamp},v1={hex}")
    }

    #[test]
    fn stripe_signature_uses_exact_raw_body_and_recency() {
        let event = verify_event(BODY, HEADER, SECRET, 1_750_000_000).unwrap();
        assert_eq!(event.event_id, "evt_fixture1");
        assert_eq!(event.customer_id.as_deref(), Some("cus_fixture1"));
        assert_eq!(event.subscription_id.as_deref(), Some("sub_fixture1"));
        assert!(verify_event(BODY, HEADER, SECRET, 1_750_000_300).is_ok());
        assert!(verify_event(BODY, HEADER, SECRET, 1_750_000_301).is_err());
        assert!(verify_event(BODY, HEADER, SECRET, 1_749_999_699).is_err());
        assert!(
            verify_event(
                BODY,
                "t=1750000000,v0=17db9d23bf1f46a7db28382296af063cf65b36c77d80f154712e9f0803633536",
                SECRET,
                1_750_000_000
            )
            .is_err()
        );
        assert!(verify_event(BODY, "t=1750000000,t=1750000000,v1=17db9d23bf1f46a7db28382296af063cf65b36c77d80f154712e9f0803633536", SECRET, 1_750_000_000).is_err());
        let mut edited = BODY.to_vec();
        edited.push(b' ');
        assert!(verify_event(&edited, HEADER, SECRET, 1_750_000_000).is_err());
        assert!(verify_event(BODY, HEADER, "whsec_wrongfixture123456", 1_750_000_000).is_err());
    }

    #[test]
    fn test_mode_rejects_live_event_even_with_valid_signature() {
        let mut body = BODY.to_vec();
        let at = body
            .windows(5)
            .position(|window| window == b"false")
            .unwrap();
        body.splice(at..at + 5, b"true".iter().copied());
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(&body);
        let signed = signed_header(1_750_000_000, mac);
        assert!(matches!(
            verify_event(&body, &signed, SECRET, 1_750_000_000),
            Err(BillingError::InvalidEvent)
        ));
    }

    #[test]
    fn test_mode_checkout_completion_accepts_stripe_test_id_shape() {
        let body = br#"{"id":"evt_checkout1","object":"event","livemode":false,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_fixture1","customer":"cus_fixture1","subscription":"sub_fixture1"}}}"#;
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(body);
        let signature = signed_header(1_750_000_000, mac);
        let event = verify_event(body, &signature, SECRET, 1_750_000_000).unwrap();
        assert_eq!(event.object_id.as_deref(), Some("cs_test_fixture1"));
        assert_eq!(event.customer_id.as_deref(), Some("cus_fixture1"));
    }

    #[test]
    fn test_quota_plan_config_is_explicit_and_bounded() {
        let prices = vec!["price_basic1".to_owned(), "price_plus1".to_owned()];
        assert_eq!(
            parse_test_quota_plans("price_basic1:2,price_plus1:10", &prices).unwrap(),
            vec![
                TestQuotaPlan {
                    price_id: prices[0].clone(),
                    outbound_limit: 2
                },
                TestQuotaPlan {
                    price_id: prices[1].clone(),
                    outbound_limit: 10
                },
            ]
        );
        for invalid in [
            "price_unknown1:2",
            "price_basic1:0",
            "price_basic1:-1",
            "price_basic1:2,price_basic1:3",
            "price_basic1:18446744073709551616",
            "price_basic1:x",
        ] {
            assert!(parse_test_quota_plans(invalid, &prices).is_err());
        }
    }

    fn signed_test_event(body: &[u8]) -> VerifiedEvent {
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(body);
        let signature = signed_header(1_750_000_000, mac);
        verify_event(body, &signature, SECRET, 1_750_000_000).unwrap()
    }

    #[test]
    fn verified_test_payment_risk_shapes_are_strict() {
        let refund = signed_test_event(br#"{"id":"evt_riskrefund1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_risk1","object":"refund","charge":"ch_risk1"}}}"#);
        assert_eq!(refund.risk_charge_id.as_deref(), Some("ch_risk1"));
        let unsupported = signed_test_event(br#"{"id":"evt_riskrefund2","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_risk2","object":"refund","charge":null}}}"#);
        assert!(unsupported.risk_charge_id.is_none());
        let zero = br#"{"id":"evt_riskzero1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_risk1","object":"charge","customer":"cus_risk1","amount_refunded":0}}}"#;
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(zero);
        let signature = signed_header(1_750_000_000, mac);
        assert!(matches!(
            verify_event(zero, &signature, SECRET, 1_750_000_000),
            Err(BillingError::InvalidEvent)
        ));
    }

    #[tokio::test]
    async fn verified_refund_and_dispute_hold_active_metered_accounts() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_hold_test_{}", Uuid::new_v4().simple());
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
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1),($2)", &[&a, &b])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'phone a'),($3,$4,'phone b')",
            &[&device_a, &a, &device_b, &b],
        )
        .await
        .unwrap();
        bind_customer(&mut db, a, "cus_holda1").await.unwrap();
        bind_customer(&mut db, b, "cus_holdb1").await.unwrap();
        let prices = vec!["price_hold1".to_owned()];
        let plans = parse_test_quota_plans("price_hold1:10", &prices).unwrap();
        for (event_id, account, customer, subscription) in [
            ("evt_holda1", a, "cus_holda1", "sub_holda1"),
            ("evt_holdb1", b, "cus_holdb1", "sub_holdb1"),
        ] {
            let event = signed_test_event(
                format!("{{\"id\":\"{event_id}\",\"object\":\"event\",\"livemode\":false,\"type\":\"customer.subscription.updated\",\"data\":{{\"object\":{{\"id\":\"{subscription}\",\"customer\":\"{customer}\"}}}}}}")
                    .as_bytes(),
            );
            assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
            reconcile_snapshot_with_quotas(
                &mut db,
                account,
                &SubscriptionSnapshot {
                    subscription_id: subscription.into(),
                    customer_id: customer.into(),
                    status: "active".into(),
                    price_id: Some("price_hold1".into()),
                },
                &prices,
                &plans,
                1,
            )
            .await
            .unwrap();
        }
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 3_600_000;
        let send = |account_id: Uuid, device_id: Uuid, id: Uuid, key: &'static str| NewMessage {
            account_id,
            device_id,
            client_message_id: id,
            idempotency_key: key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic test",
            expires_at_ms: expiry,
        };
        let first = Uuid::new_v4();
        assert!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(a, device_a, first, "a-first"))
                .await
                .unwrap()
                .created
        );

        let refund = signed_test_event(br#"{"id":"evt_refund1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_refund1","object":"charge","customer":"cus_holda1","amount_refunded":50}}}"#);
        assert_eq!(refund.risk_charge_id.as_deref(), Some("ch_refund1"));
        assert_eq!(
            ingest(&mut db, &refund).await.unwrap(),
            IngestResult::Queued
        );
        assert_eq!(
            ingest(&mut db, &refund).await.unwrap(),
            IngestResult::Duplicate
        );
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(a, device_a, Uuid::new_v4(), "a-pending"))
                .await,
            Err(StoreError::PaymentHold)
        ));
        // The other tenant still has its own active allowance.
        assert!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(b, device_b, Uuid::new_v4(), "b-before"))
                .await
                .unwrap()
                .created
        );
        assert!(matches!(
            risk::apply_hold(
                &mut db,
                "evt_refund1",
                "ch_refund1",
                "cus_holdb1",
                "sub_holdb1",
                "refund"
            )
            .await,
            Err(BillingError::TenantConflict)
        ));
        risk::bind_charge_customer(&mut db, "evt_refund1", "cus_holda1")
            .await
            .unwrap();
        risk::apply_hold(
            &mut db,
            "evt_refund1",
            "ch_refund1",
            "cus_holda1",
            "sub_holda1",
            "refund",
        )
        .await
        .unwrap();
        risk::apply_hold(
            &mut db,
            "evt_refund1",
            "ch_refund1",
            "cus_holda1",
            "sub_holda1",
            "refund",
        )
        .await
        .unwrap();
        let count: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_payment_holds WHERE account_id=$1",
                &[&a],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        let active_a = SubscriptionSnapshot {
            subscription_id: "sub_holda1".into(),
            customer_id: "cus_holda1".into(),
            status: "active".into(),
            price_id: Some("price_hold1".into()),
        };
        reconcile_snapshot_with_quotas(&mut db, a, &active_a, &prices, &plans, 2)
            .await
            .unwrap();
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(a, device_a, Uuid::new_v4(), "a-still-held"))
                .await,
            Err(StoreError::PaymentHold)
        ));
        assert!(
            !DeliveryStore::new(&mut db)
                .accept_metered(send(a, device_a, first, "a-first"))
                .await
                .unwrap()
                .created
        );

        // A closed dispute received first cannot clear or suppress a later
        // creation event. The creation event carries no customer until the
        // current Charge is fetched and bound by the worker.
        let closed = signed_test_event(br#"{"id":"evt_disputeclosed1","object":"event","livemode":false,"type":"charge.dispute.closed","data":{"object":{"id":"du_holdb1","object":"dispute","charge":"ch_dispute1"}}}"#);
        assert_eq!(
            ingest(&mut db, &closed).await.unwrap(),
            IngestResult::Ignored
        );
        let dispute = signed_test_event(br#"{"id":"evt_dispute1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_holdb1","object":"dispute","charge":"ch_dispute1"}}}"#);
        assert_eq!(
            ingest(&mut db, &dispute).await.unwrap(),
            IngestResult::Unbound
        );
        assert!(
            risk::bind_charge_customer(&mut db, "evt_dispute1", "cus_holdb1")
                .await
                .unwrap()
        );
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(b, device_b, Uuid::new_v4(), "b-pending"))
                .await,
            Err(StoreError::PaymentHold)
        ));
        risk::apply_hold(
            &mut db,
            "evt_dispute1",
            "ch_dispute1",
            "cus_holdb1",
            "sub_holdb1",
            "dispute",
        )
        .await
        .unwrap();
        let count: i64 = db
            .query_one("SELECT count(*) FROM billing_payment_holds", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 2);
        let late = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&late])
            .await
            .unwrap();
        let unbound = signed_test_event(br#"{"id":"evt_disputelate1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_late1","object":"dispute","charge":"ch_late1"}}}"#);
        assert_eq!(
            ingest(&mut db, &unbound).await.unwrap(),
            IngestResult::Unbound
        );
        assert!(
            !risk::bind_charge_customer(&mut db, "evt_disputelate1", "cus_late1")
                .await
                .unwrap()
        );
        db.execute(
            "UPDATE billing_risk_events SET state='needs_review',failed_attempts=10 WHERE stripe_event_id='evt_disputelate1'",
            &[],
        )
        .await
        .unwrap();
        bind_customer(&mut db, late, "cus_late1").await.unwrap();
        let late_risk = db
            .query_one(
                "SELECT r.account_id,r.state,e.stripe_customer_id FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) WHERE r.stripe_event_id='evt_disputelate1'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(late_risk.get::<_, Option<Uuid>>(0), Some(late));
        assert_eq!(late_risk.get::<_, String>(1), "needs_review");
        assert_eq!(
            late_risk.get::<_, Option<String>>(2).as_deref(),
            Some("cus_late1")
        );
        let live = br#"{"id":"evt_live1","object":"event","livemode":true,"type":"charge.refunded","data":{"object":{"id":"ch_live1","object":"charge","customer":"cus_holda1","amount_refunded":50}}}"#;
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(live);
        let signed = signed_header(1_750_000_000, mac);
        assert!(matches!(
            verify_event(live, &signed, SECRET, 1_750_000_000),
            Err(BillingError::InvalidEvent)
        ));
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reconciled_test_subscription_controls_metered_reservations() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_quota_test_{}", Uuid::new_v4().simple());
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
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        let other = Uuid::new_v4();
        let device = Uuid::new_v4();
        db.execute(
            "INSERT INTO accounts(id) VALUES($1),($2)",
            &[&account, &other],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',99)", &[&account]).await.unwrap();
        bind_customer(&mut db, account, "cus_entitlement1")
            .await
            .unwrap();
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 3_600_000;
        let first = Uuid::new_v4();
        let send = |message_id: Uuid, key: &'static str| NewMessage {
            account_id: account,
            client_message_id: message_id,
            device_id: device,
            idempotency_key: key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic test",
            expires_at_ms: expiry,
        };
        {
            let mut store = DeliveryStore::new(&mut db);
            assert!(matches!(
                store.accept_metered(send(first, "first")).await,
                Err(StoreError::QuotaNotConfigured)
            ));
        }
        let event = VerifiedEvent {
            event_id: "evt_entitlement1".into(),
            event_type: "customer.subscription.updated".into(),
            object_id: Some("sub_entitlement1".into()),
            customer_id: Some("cus_entitlement1".into()),
            subscription_id: Some("sub_entitlement1".into()),
            risk_charge_id: None,
            body_sha256: [1; 32],
        };
        assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
        let plans = parse_test_quota_plans(
            "price_basic1:2,price_plus1:1",
            &["price_basic1".into(), "price_plus1".into()],
        )
        .unwrap();
        let prices = vec!["price_basic1".into(), "price_plus1".into()];
        let active = SubscriptionSnapshot {
            subscription_id: "sub_entitlement1".into(),
            customer_id: "cus_entitlement1".into(),
            status: "active".into(),
            price_id: Some("price_basic1".into()),
        };
        reconcile_snapshot_with_quotas(&mut db, other, &active, &prices, &plans, 1)
            .await
            .expect_err("wrong tenant");
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
            .await
            .unwrap();
        assert_eq!(
            ingest(&mut db, &event).await.unwrap(),
            IngestResult::Duplicate
        );
        let second = Uuid::new_v4();
        {
            let mut store = DeliveryStore::new(&mut db);
            assert!(
                store
                    .accept_metered(send(first, "first"))
                    .await
                    .unwrap()
                    .created
            );
            assert!(
                !store
                    .accept_metered(send(first, "first"))
                    .await
                    .unwrap()
                    .created
            );
            assert!(
                store
                    .accept_metered(send(second, "second"))
                    .await
                    .unwrap()
                    .created
            );
            assert!(matches!(
                store.accept_metered(send(Uuid::new_v4(), "third")).await,
                Err(StoreError::QuotaExceeded)
            ));
        }
        reset_test_quotas_on_start(&scoped_url, true).await.unwrap();
        {
            let mut store = DeliveryStore::new(&mut db);
            assert!(matches!(
                store
                    .accept_metered(send(Uuid::new_v4(), "after-restart"))
                    .await,
                Err(StoreError::QuotaNotConfigured)
            ));
        }
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 2)
            .await
            .unwrap();
        let mut next = event.clone();
        next.event_id = "evt_entitlement2".into();
        assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
        {
            let mut store = DeliveryStore::new(&mut db);
            assert!(matches!(
                store.accept_metered(send(Uuid::new_v4(), "pending")).await,
                Err(StoreError::QuotaNotConfigured)
            ));
        }
        let downgraded = SubscriptionSnapshot {
            price_id: Some("price_plus1".into()),
            ..active.clone()
        };
        reconcile_snapshot_with_quotas(&mut db, account, &downgraded, &prices, &plans, 3)
            .await
            .unwrap();
        let row = db.query_one("SELECT p.limit_units,p.source,u.limit_units,u.reserved_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1", &[&account]).await.unwrap();
        assert_eq!(
            (
                row.get::<_, i64>(0),
                row.get::<_, String>(1),
                row.get::<_, i64>(2),
                row.get::<_, i64>(3)
            ),
            (1, "stripe_test".into(), 1, 2)
        );
        next.event_id = "evt_entitlement3".into();
        assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
        let canceled = SubscriptionSnapshot {
            status: "canceled".into(),
            ..downgraded.clone()
        };
        reconcile_snapshot_with_quotas(&mut db, account, &canceled, &prices, &plans, 4)
            .await
            .unwrap();
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 3)
            .await
            .unwrap();
        let row = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        {
            let mut store = DeliveryStore::new(&mut db);
            assert!(matches!(
                store
                    .accept_metered(send(Uuid::new_v4(), "after-cancel"))
                    .await,
                Err(StoreError::QuotaExceeded)
            ));
            assert!(
                !store
                    .accept_metered(send(first, "first"))
                    .await
                    .unwrap()
                    .created
            );
        }
        let mut generation = 4;
        for (event_id, snapshot, expected_limit) in [
            (
                "evt_entitlement4",
                SubscriptionSnapshot {
                    status: "past_due".into(),
                    ..active.clone()
                },
                0_i64,
            ),
            (
                "evt_entitlement5",
                SubscriptionSnapshot {
                    price_id: Some("price_unknown1".into()),
                    ..active.clone()
                },
                0_i64,
            ),
            ("evt_entitlement6", active.clone(), 2_i64),
        ] {
            next.event_id = event_id.into();
            assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
            generation += 1;
            reconcile_snapshot_with_quotas(
                &mut db, account, &snapshot, &prices, &plans, generation,
            )
            .await
            .unwrap();
            let row = db
                .query_one(
                    "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                    &[&account],
                )
                .await
                .unwrap();
            assert_eq!(row.get::<_, i64>(0), expected_limit);
        }
        let mut another = event.clone();
        another.event_id = "evt_entitlement7".into();
        another.subscription_id = Some("sub_entitlement2".into());
        another.object_id = another.subscription_id.clone();
        assert_eq!(
            ingest(&mut db, &another).await.unwrap(),
            IngestResult::Queued
        );
        let second_active = SubscriptionSnapshot {
            subscription_id: "sub_entitlement2".into(),
            ..active.clone()
        };
        reconcile_snapshot_with_quotas(&mut db, account, &second_active, &prices, &plans, 1)
            .await
            .unwrap();
        let row = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap();
        assert_eq!(
            row.get::<_, i64>(0),
            0,
            "two active subscriptions are ambiguous"
        );
        another.event_id = "evt_entitlement8".into();
        assert_eq!(
            ingest(&mut db, &another).await.unwrap(),
            IngestResult::Queued
        );
        let second_canceled = SubscriptionSnapshot {
            status: "canceled".into(),
            ..second_active
        };
        reconcile_snapshot_with_quotas(&mut db, account, &second_canceled, &prices, &plans, 2)
            .await
            .unwrap();
        let row = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        let row = db
            .query_one(
                "SELECT count(*) FROM billing_quota_audit WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 8);
        // A rolling upgrade can temporarily have entitlement migration 010
        // without risk migration 011. Disabling billing still clears its old
        // allowance, while enabling billing requires both schemas.
        db.batch_execute("DROP TABLE billing_payment_holds,billing_risk_events")
            .await
            .unwrap();
        assert!(reset_test_quotas_on_start(&scoped_url, true).await.is_err());
        reset_test_quotas_on_start(&scoped_url, false)
            .await
            .unwrap();
        let limit: i64 = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(limit, 0);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dedupe_tenant_binding_and_stale_reconciliation() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let database_url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
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
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1),($2)", &[&a, &b])
            .await
            .unwrap();
        db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_fixture2')", &[&b]).await.unwrap();
        let event = verify_event(BODY, HEADER, SECRET, 1_750_000_000).unwrap();
        assert_eq!(
            ingest(&mut db, &event).await.unwrap(),
            IngestResult::Unbound
        );
        bind_customer(&mut db, a, "cus_fixture1").await.unwrap();
        assert!(matches!(
            bind_customer(&mut db, b, "cus_fixture1").await,
            Err(BillingError::TenantConflict)
        ));
        assert_eq!(
            ingest(&mut db, &event).await.unwrap(),
            IngestResult::Duplicate
        );
        let mut changed_body = event.clone();
        changed_body.body_sha256[0] ^= 1;
        assert!(matches!(
            ingest(&mut db, &changed_body).await,
            Err(BillingError::EventConflict)
        ));
        let row = db.query_one("SELECT dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 0));
        assert_eq!(
            worker::claim(&mut db).await.unwrap(),
            Some((a, "sub_fixture1".into(), 1))
        );
        assert!(worker::claim(&mut db).await.unwrap().is_none());
        let mut newer = event.clone();
        newer.event_id = "evt_fixture2".into();
        assert_eq!(ingest(&mut db, &newer).await.unwrap(), IngestResult::Queued);
        let active = SubscriptionSnapshot {
            subscription_id: "sub_fixture1".into(),
            customer_id: "cus_fixture1".into(),
            status: "active".into(),
            price_id: Some("price_known1".into()),
        };
        let prices = vec!["price_known1".into()];
        reconcile_snapshot(&mut db, a, &active, &prices, 1)
            .await
            .unwrap();
        let row = db.query_one("SELECT dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (2, 1));
        let canceled = SubscriptionSnapshot {
            status: "canceled".into(),
            ..active.clone()
        };
        reconcile_snapshot(&mut db, a, &canceled, &prices, 2)
            .await
            .unwrap();
        reconcile_snapshot(&mut db, a, &active, &prices, 1)
            .await
            .unwrap();
        let row = db.query_one("SELECT stripe_status,recognized_price FROM billing_subscriptions WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "canceled");
        assert!(row.get::<_, bool>(1));
        let mut late_old_event = event.clone();
        late_old_event.event_id = "evt_fixture4".into();
        assert_eq!(
            ingest(&mut db, &late_old_event).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot(&mut db, a, &canceled, &prices, 3)
            .await
            .unwrap();
        let row = db.query_one("SELECT stripe_status FROM billing_subscriptions WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "canceled");
        let wrong_customer = SubscriptionSnapshot {
            customer_id: "cus_fixture2".into(),
            ..active
        };
        assert!(matches!(
            reconcile_snapshot(&mut db, a, &wrong_customer, &prices, 2).await,
            Err(BillingError::TenantConflict)
        ));
        let mut cross = newer;
        cross.event_id = "evt_fixture3".into();
        cross.customer_id = Some("cus_fixture2".into());
        assert_eq!(
            ingest(&mut db, &cross).await.unwrap(),
            IngestResult::Conflict
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "reads two real Stripe test events and reconciles their current subscriptions; run explicitly"]
    async fn real_stripe_test_events_reconcile_current_state() {
        let database_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set a disposable PostgreSQL test database URL");
        let secret_key = env::var("ZT_STRIPE_TEST_SECRET_KEY")
            .expect("set a Stripe test secret in the process environment");
        let price_id = env::var("ZT_STRIPE_TEST_PRICE_ID").expect("set the test price ID");
        let cases = [
            (
                env::var("ZT_STRIPE_TEST_PAID_EVENT_ID").expect("set the paid event ID"),
                env::var("ZT_STRIPE_TEST_PAID_CUSTOMER_ID").expect("set the paid test customer ID"),
                "invoice.paid",
                "canceled",
            ),
            (
                env::var("ZT_STRIPE_TEST_FAILED_EVENT_ID").expect("set the failed event ID"),
                env::var("ZT_STRIPE_TEST_FAILED_CUSTOMER_ID")
                    .expect("set the failed test customer ID"),
                "invoice.payment_failed",
                "incomplete_expired",
            ),
        ];
        assert!(secret_key.starts_with("sk_test_"));
        valid_id(&price_id, "price_").unwrap();
        let (setup, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_real_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if database_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{database_url}{separator}options=-csearch_path%3D{schema}");
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
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let signing_secret = "whsec_local_test_event_fixture_20260923";
        for (event_id, customer_id, expected_type, _) in &cases {
            valid_id(event_id, "evt_").unwrap();
            valid_id(customer_id, "cus_").unwrap();
            let account_id = Uuid::new_v4();
            db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
                .await
                .unwrap();
            bind_customer(&mut db, account_id, customer_id)
                .await
                .unwrap();
            let response = http
                .get(format!("https://api.stripe.com/v1/events/{event_id}"))
                .bearer_auth(&secret_key)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let body = response.bytes().await.unwrap();
            assert!(body.len() <= MAX_BODY);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes()).unwrap();
            mac.update(timestamp.to_string().as_bytes());
            mac.update(b".");
            mac.update(&body);
            let signature = signed_header(timestamp, mac);
            let event = verify_event(&body, &signature, signing_secret, timestamp).unwrap();
            assert_eq!(event.event_type, *expected_type);
            assert_eq!(event.customer_id.as_deref(), Some(customer_id.as_str()));
            assert!(event.subscription_id.is_some());
            assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
            assert_eq!(
                ingest(&mut db, &event).await.unwrap(),
                IngestResult::Duplicate
            );
        }
        let worker = worker::StripeTestWorker::new(secret_key, vec![price_id]).unwrap();
        assert!(worker.reconcile_one(&scoped_url).await.unwrap());
        assert!(worker.reconcile_one(&scoped_url).await.unwrap());
        assert!(!worker.reconcile_one(&scoped_url).await.unwrap());
        for (_, customer_id, _, expected_status) in &cases {
            let row = db
                .query_one(
                    "SELECT stripe_status,recognized_price FROM billing_subscriptions WHERE stripe_customer_id=$1",
                    &[customer_id],
                )
                .await
                .unwrap();
            assert_eq!(row.get::<_, String>(0), *expected_status);
            assert!(row.get::<_, bool>(1));
        }
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
