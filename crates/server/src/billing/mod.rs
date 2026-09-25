// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode Stripe event inbox. Events only request reconciliation; they never
//! directly grant a plan or change a quota.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod drain;
pub mod http;
pub mod owner;
pub mod review;
pub mod risk;
pub mod sessions;
pub mod worker;

type HmacSha256 = Hmac<Sha256>;
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER: usize = 1024;
const TOLERANCE_SECONDS: i64 = 300;

fn is_test_api_key(key: &str) -> bool {
    (key.starts_with("sk_test_") || key.starts_with("rk_test_")) && key.len() >= 16
}

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("runtime database unavailable")]
    RuntimeDatabase(#[from] crate::runtime_db::ConnectError),
    #[error("invalid Stripe signature")]
    InvalidSignature,
    #[error("invalid Stripe event")]
    InvalidEvent,
    #[error("Stripe test provider read failed: {0}")]
    Provider(#[from] worker::ProviderFailure),
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
    /// A refund can identify its payment by PaymentIntent when `charge` is null.
    pub risk_payment_intent_id: Option<String>,
    /// Creation time on a signed invoice.payment_failed event, in Unix seconds.
    pub payment_failed_at_unix: Option<i64>,
    pub body_sha256: [u8; 32],
    /// True when the signed test-mode event's object shape is not one this
    /// build acts on. The event is still acknowledged and durably recorded.
    pub unsupported: bool,
    /// A recognized risk event with an unexpected shape needs owner review.
    pub risk_review_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestResult {
    Queued,
    Unbound,
    Ignored,
    Unsupported,
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
    // Beyond this point the signature and envelope are trusted. An unexpected
    // object shape is acknowledged and durably recorded instead of being
    // answered with 4xx, so a legitimate provider event is never dropped and
    // retried until Stripe gives up on it.
    let mut unsupported = false;
    let payment_failed_at_unix = if event_type == "invoice.payment_failed" {
        match json["created"]
            .as_i64()
            .filter(|created| (946_684_800..=253_402_300_799).contains(created))
        {
            Some(created) => Some(created),
            None => {
                unsupported = true;
                None
            }
        }
    } else {
        None
    };
    let risk_type = matches!(
        event_type,
        "charge.refunded" | "refund.created" | "charge.dispute.created"
    );
    let object = &json["data"]["object"];
    let mut risk_review_required = false;
    let mut shape = match parse_event_shape(event_type, object) {
        Ok(shape) => shape,
        Err(BillingError::InvalidEvent) => {
            unsupported = true;
            risk_review_required = risk_type;
            EventShape {
                // Preserve only syntactically valid provider pointers for
                // owner review. They never grant entitlement or create a
                // final payment hold without provider attribution.
                object_id: match event_type {
                    "charge.refunded" => stripe_charge_id(&object["id"]).ok(),
                    "refund.created" => stripe_id(&object["id"], "re_").ok(),
                    "charge.dispute.created" => object["id"]
                        .as_str()
                        .filter(|id| valid_id(id, "du_").is_ok() || valid_id(id, "dp_").is_ok()),
                    _ => None,
                }
                .map(str::to_owned),
                // A signed Charge can still name a valid customer even if its
                // risk shape is unusable. Hold that account for review.
                customer_id: if event_type == "charge.refunded" {
                    object["customer"]
                        .as_str()
                        .and_then(|id| valid_id(id, "cus_").ok())
                        .map(str::to_owned)
                } else {
                    None
                },
                risk_charge_id: match event_type {
                    "charge.refunded" => stripe_charge_id(&object["id"]).ok(),
                    "refund.created" | "charge.dispute.created" => {
                        stripe_charge_id(&object["charge"]).ok()
                    }
                    _ => None,
                }
                .map(str::to_owned),
                risk_payment_intent_id: if event_type == "refund.created" {
                    stripe_id(&object["payment_intent"], "pi_")
                        .ok()
                        .map(str::to_owned)
                } else {
                    None
                },
                ..EventShape::default()
            }
        }
        Err(other) => return Err(other),
    };
    if unsupported && !risk_review_required {
        // An invoice failure without a usable creation time cannot anchor
        // grace; do not queue it under an unsupported disposition.
        shape = EventShape::default();
    }
    Ok(VerifiedEvent {
        event_id,
        event_type: event_type.to_owned(),
        object_id: shape.object_id,
        customer_id: shape.customer_id,
        subscription_id: shape.subscription_id,
        risk_charge_id: shape.risk_charge_id,
        risk_payment_intent_id: shape.risk_payment_intent_id,
        payment_failed_at_unix,
        body_sha256: Sha256::digest(body).into(),
        unsupported,
        risk_review_required,
    })
}

/// Provider pointers extracted from one recognized event's object.
#[derive(Default)]
struct EventShape {
    object_id: Option<String>,
    customer_id: Option<String>,
    subscription_id: Option<String>,
    risk_charge_id: Option<String>,
    risk_payment_intent_id: Option<String>,
}

/// Extract the pointers one recognized event type acts on. A recognized type
/// whose object does not match the expected shape yields InvalidEvent, which
/// `verify_event` downgrades to the unsupported disposition.
fn parse_event_shape(event_type: &str, object: &Value) -> Result<EventShape, BillingError> {
    Ok(match event_type {
        "checkout.session.completed" => EventShape {
            object_id: Some(stripe_id(&object["id"], "cs_test_")?.to_owned()),
            customer_id: Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
            subscription_id: Some(stripe_id(&object["subscription"], "sub_")?.to_owned()),
            risk_charge_id: None,
            risk_payment_intent_id: None,
        },
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted"
        | "customer.subscription.paused"
        | "customer.subscription.resumed" => {
            let subscription = stripe_id(&object["id"], "sub_")?.to_owned();
            EventShape {
                object_id: Some(subscription.clone()),
                customer_id: Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
                subscription_id: Some(subscription),
                risk_charge_id: None,
                risk_payment_intent_id: None,
            }
        }
        "invoice.paid" | "invoice.payment_failed" => {
            // Invoice subscription pointers differ across Stripe API versions.
            // A missing pointer is durably recorded but grants no entitlement.
            let subscription = object["subscription"]
                .as_str()
                .or_else(|| object["parent"]["subscription_details"]["subscription"].as_str())
                .map(|id| valid_id(id, "sub_"))
                .transpose()?
                .map(str::to_owned);
            EventShape {
                object_id: Some(stripe_id(&object["id"], "in_")?.to_owned()),
                customer_id: Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
                subscription_id: subscription,
                risk_charge_id: None,
                risk_payment_intent_id: None,
            }
        }
        "charge.refunded" => {
            if object["object"] != "charge"
                || object["amount_refunded"]
                    .as_i64()
                    .is_none_or(|amount| amount <= 0)
            {
                return Err(BillingError::InvalidEvent);
            }
            let charge = stripe_charge_id(&object["id"])?.to_owned();
            let customer = object["customer"]
                .as_str()
                .map(|id| valid_id(id, "cus_"))
                .transpose()?
                .map(str::to_owned);
            EventShape {
                object_id: Some(charge.clone()),
                customer_id: customer,
                subscription_id: None,
                risk_charge_id: Some(charge),
                risk_payment_intent_id: None,
            }
        }
        "refund.created" => {
            if object["object"] != "refund" {
                return Err(BillingError::InvalidEvent);
            }
            let charge = object["charge"]
                .as_str()
                .map(valid_charge_id)
                .transpose()?
                .map(str::to_owned);
            let payment_intent = object["payment_intent"]
                .as_str()
                .map(|id| valid_id(id, "pi_"))
                .transpose()?
                .map(str::to_owned);
            if charge.is_none() && payment_intent.is_none() {
                return Err(BillingError::InvalidEvent);
            }
            EventShape {
                object_id: Some(stripe_id(&object["id"], "re_")?.to_owned()),
                customer_id: None,
                subscription_id: None,
                risk_charge_id: charge,
                risk_payment_intent_id: payment_intent,
            }
        }
        "charge.dispute.created" => {
            if object["object"] != "dispute" {
                return Err(BillingError::InvalidEvent);
            }
            let dispute = object["id"].as_str().ok_or(BillingError::InvalidEvent)?;
            if valid_id(dispute, "du_").is_err() {
                valid_id(dispute, "dp_")?;
            }
            EventShape {
                object_id: Some(dispute.to_owned()),
                customer_id: None,
                subscription_id: None,
                risk_charge_id: Some(stripe_charge_id(&object["charge"])?.to_owned()),
                risk_payment_intent_id: None,
            }
        }
        _ => EventShape::default(),
    })
}

fn stripe_id<'a>(value: &'a Value, prefix: &str) -> Result<&'a str, BillingError> {
    valid_id(value.as_str().ok_or(BillingError::InvalidEvent)?, prefix)
}

fn stripe_charge_id(value: &Value) -> Result<&str, BillingError> {
    valid_charge_id(value.as_str().ok_or(BillingError::InvalidEvent)?)
}

/// Card charges use `ch_`, but non-card payment methods such as SEPA Direct
/// Debit, ACH and Bacs create PaymentIntent-scoped charges with `py_` IDs.
/// Both can carry refunds and disputes.
fn valid_charge_id(id: &str) -> Result<&str, BillingError> {
    valid_id(id, "ch_").or_else(|_| valid_id(id, "py_"))
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
            if event.risk_charge_id.is_some()
                || event.risk_payment_intent_id.is_some()
                || event.risk_review_required
            {
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
    let initial = if event.unsupported {
        IngestResult::Unsupported
    } else if event.subscription_id.is_none()
        && event.risk_charge_id.is_none()
        && event.risk_payment_intent_id.is_none()
    {
        IngestResult::Ignored
    } else if account_id.is_none() {
        IngestResult::Unbound
    } else {
        IngestResult::Queued
    };
    let disposition = match initial {
        IngestResult::Ignored => "ignored",
        IngestResult::Unbound => "unbound",
        IngestResult::Unsupported => "unsupported",
        _ => "queued",
    };
    let inserted = tx.execute(
        "INSERT INTO billing_events(stripe_event_id,event_type,object_id,stripe_customer_id,stripe_subscription_id,account_id,body_sha256,disposition,payment_failed_at,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9::bigint IS NULL THEN NULL ELSE LEAST(to_timestamp($9::bigint::double precision),clock_timestamp()) END,clock_timestamp()) ON CONFLICT(stripe_event_id) DO NOTHING",
        &[&event.event_id, &event.event_type, &event.object_id, &event.customer_id,
            &event.subscription_id, &account_id, &event.body_sha256.as_slice(), &disposition,
            &event.payment_failed_at_unix],
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
    if event.risk_charge_id.is_some()
        || event.risk_payment_intent_id.is_some()
        || event.risk_review_required
    {
        let kind = if event.event_type == "charge.dispute.created" {
            "dispute"
        } else {
            "refund"
        };
        tx.execute(
            "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,stripe_payment_intent_id,risk_kind,account_id,state) VALUES($1,$2,$3,$4,$5,$6)",
            &[&event.event_id, &event.risk_charge_id, &event.risk_payment_intent_id,
                &kind, &account_id, &if event.risk_review_required { "needs_review" } else { "queued" }],
        )
        .await?;
    }
    let mut result = initial;
    if let (false, Some(account_id), Some(customer_id), Some(subscription_id)) = (
        event.unsupported,
        account_id,
        &event.customer_id,
        &event.subscription_id,
    ) {
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
        "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES($1,$2,$3) ON CONFLICT(stripe_subscription_id) DO UPDATE SET dirty_generation=billing_reconciliations.dirty_generation+1,state='queued',failed_attempts=0,last_failure_class=NULL,next_attempt_at=now(),updated_at=now() WHERE billing_reconciliations.account_id=EXCLUDED.account_id AND billing_reconciliations.stripe_customer_id=EXCLUDED.stripe_customer_id",
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
    /// Current provider invoice; grace never uses a failure from another bill.
    pub latest_invoice_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestQuotaPlan {
    pub price_id: String,
    pub outbound_limit: i64,
    pub device_limit: Option<i64>,
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
        let mut fields = entry.trim().split(':');
        let price_id = fields.next().ok_or("invalid Stripe test quota plan")?;
        let limit = fields.next().ok_or("invalid Stripe test quota plan")?;
        let device_limit = fields
            .next()
            .map(|value| {
                value
                    .parse::<i64>()
                    .map_err(|_| "invalid Stripe test quota plan")
            })
            .transpose()?;
        if fields.next().is_some() || device_limit.is_some_and(|limit| limit < 0) {
            return Err("invalid Stripe test quota plan");
        }
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
            device_limit,
        });
    }
    if plans.iter().any(|plan| plan.device_limit.is_some())
        && plans.iter().any(|plan| plan.device_limit.is_none())
    {
        return Err("every mapped test price needs an explicit device cap");
    }
    Ok(plans)
}

/// Hash the effective entitlement configuration, independent of input order.
pub fn quota_configuration_fingerprint(
    prices: &[String],
    plans: &[TestQuotaPlan],
    reader_key: &str,
) -> [u8; 32] {
    let mut prices = prices.to_vec();
    prices.sort();
    let mut plans = plans.to_vec();
    plans.sort_by(|left, right| left.price_id.cmp(&right.price_id));
    let mut hash = Sha256::new();
    hash.update(b"stripe-test-entitlements-v1\0");
    for price in prices {
        hash.update((price.len() as u64).to_be_bytes());
        hash.update(price.as_bytes());
    }
    hash.update(b"\0plans\0");
    for plan in plans {
        hash.update((plan.price_id.len() as u64).to_be_bytes());
        hash.update(plan.price_id.as_bytes());
        hash.update(plan.outbound_limit.to_be_bytes());
        hash.update(plan.device_limit.unwrap_or(-1).to_be_bytes());
    }
    // Test keys are high-entropy credentials. A changed reader key must force
    // a new provider read; only this one-way digest is stored in PostgreSQL.
    hash.update(b"\0reader-key\0");
    hash.update(reader_key.as_bytes());
    hash.finalize().into()
}

/// Only a changed test entitlement configuration invalidates prior projections.
/// The singleton row serializes rolling starts across server instances.
pub async fn reset_test_quotas_on_start(
    database_url: &str,
    require_schema: bool,
    device_caps_enabled: bool,
    config_fingerprint: Option<&[u8; 32]>,
) -> Result<(), BillingError> {
    let (mut db, connection) = crate::runtime_db::connect_worker(database_url).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = db
        .query_one(
            "SELECT to_regclass('billing_quota_audit') IS NOT NULL, to_regclass('billing_risk_events') IS NOT NULL AND to_regclass('billing_payment_holds') IS NOT NULL, to_regclass('billing_device_cap_config') IS NOT NULL AND to_regclass('billing_device_caps') IS NOT NULL AND to_regclass('billing_device_cap_audit') IS NOT NULL, EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='billing_subscriptions' AND column_name='payment_grace_started_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='billing_subscriptions' AND column_name='last_non_past_due_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='billing_subscriptions' AND column_name='latest_invoice_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='billing_subscriptions' AND column_name='payment_grace_invoice_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='billing_events' AND column_name='payment_failed_at')",
            &[],
        )
        .await?;
    let quota_available: bool = schema.get(0);
    let risk_available: bool = schema.get(1);
    let device_caps_available: bool = schema.get(2);
    let payment_grace_available: bool = schema.get(3);
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
    if require_schema && !device_caps_available {
        return Err(BillingError::InvalidEvent);
    }
    if require_schema && !payment_grace_available {
        return Err(BillingError::InvalidEvent);
    }
    if require_schema && config_fingerprint.is_none() {
        return Err(BillingError::InvalidEvent);
    }
    let config_available: bool = db
        .query_one("SELECT to_regclass('billing_test_config') IS NOT NULL", &[])
        .await?
        .get(0);
    if require_schema && !config_available {
        return Err(BillingError::InvalidEvent);
    }
    let tx = db.transaction().await?;
    // Use one database lock for startup across all sites, including the first
    // start when the singleton row does not exist yet.
    if config_available {
        tx.query_one("SELECT pg_advisory_xact_lock(139025)", &[])
            .await?;
    }
    if device_caps_available {
        let enabled: bool = tx.query_one(
            "UPDATE billing_device_cap_config SET enabled=enabled OR $1,updated_at=now() WHERE singleton=true RETURNING enabled",
            &[&device_caps_enabled],
        )
        .await?.get(0);
        if enabled && !device_caps_enabled {
            return Err(BillingError::InvalidEvent);
        }
    }
    if let Some(fingerprint) = config_fingerprint {
        let current = tx
            .query_opt(
                "SELECT configuration_sha256 FROM billing_test_config WHERE singleton=true",
                &[],
            )
            .await?;
        if current.is_some_and(|row| row.get::<_, Vec<u8>>(0) == fingerprint) {
            tx.commit().await?;
            return Ok(());
        }
        tx.execute("INSERT INTO billing_test_config(singleton,configuration_sha256) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET configuration_sha256=EXCLUDED.configuration_sha256,updated_at=clock_timestamp()", &[&fingerprint.as_slice()]).await?;
    } else if config_available {
        tx.execute("DELETE FROM billing_test_config WHERE singleton=true", &[])
            .await?;
    }
    if config_fingerprint.is_some() {
        tx.execute(
            "UPDATE billing_reconciliations r SET dirty_generation=r.dirty_generation+1,state='queued',failed_attempts=0,last_failure_class=NULL,next_attempt_at=now(),updated_at=now() WHERE NOT EXISTS (SELECT 1 FROM billing_subscriptions s WHERE s.stripe_subscription_id=r.stripe_subscription_id AND s.stripe_status IN ('canceled','incomplete_expired','provider_deleted'))",
            &[],
        ).await?;
        tx.execute(
            "UPDATE billing_risk_events SET state='queued',failed_attempts=0,last_failure_class=NULL,next_attempt_at=now() WHERE state='needs_review'",
            &[],
        ).await?;
    }
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
    if device_caps_available {
        tx.execute(
            "INSERT INTO billing_device_cap_audit(account_id,reconciliation_generation,previous_limit_devices,limit_devices,reason) SELECT account_id,0,limit_devices,0,'startup_reset' FROM billing_device_caps WHERE limit_devices<>0",
            &[],
        ).await?;
        tx.execute(
            "UPDATE billing_device_caps SET limit_devices=0,updated_at=now() WHERE limit_devices<>0",
            &[],
        ).await?;
    }
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
    // Pairing approval takes a conflicting account lock before counting devices.
    // NO KEY UPDATE still serializes cap changes without blocking the account
    // FK KEY SHARE acquired by verified billing ingress.
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account_id],
    )
    .await?;
    let device_caps_enabled: bool = tx
        .query_one(
            "SELECT enabled FROM billing_device_cap_config WHERE singleton=true",
            &[],
        )
        .await?
        .get(0);
    if device_caps_enabled
        && (quota_plans.is_empty() || quota_plans.iter().any(|plan| plan.device_limit.is_none()))
    {
        return Err(BillingError::InvalidEvent);
    }
    // Ingress, risk holds, and customer binding lock the customer before they
    // queue a reconciliation. Take the same order before locking its row.
    let binding = tx.query_opt(
        "SELECT 1 FROM billing_customers WHERE account_id=$1 AND stripe_customer_id=$2 FOR SHARE",
        &[&account_id, &snapshot.customer_id],
    ).await?;
    if binding.is_none() {
        return Err(BillingError::TenantConflict);
    }
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
            | "provider_deleted"
    ) {
        return Err(BillingError::InvalidEvent);
    }
    let recognized = snapshot
        .price_id
        .as_ref()
        .is_some_and(|price| recognized_prices.contains(price));
    let prior = tx.query_opt(
        "SELECT stripe_status,extract(epoch FROM payment_grace_started_at)::bigint,payment_grace_invoice_id FROM billing_subscriptions WHERE stripe_subscription_id=$1 AND account_id=$2 FOR UPDATE",
        &[&snapshot.subscription_id, &account_id],
    ).await?;
    let prior_past_due = prior
        .as_ref()
        .is_some_and(|row| row.get::<_, String>(0) == "past_due");
    let prior_start: Option<i64> = prior.as_ref().and_then(|row| row.get(1));
    let prior_invoice: Option<String> = prior.as_ref().and_then(|row| row.get(2));
    let (grace_started_at, grace_invoice_id) = if snapshot.status == "past_due" {
        if prior_past_due
            && prior_start.is_some()
            && prior_invoice.as_ref() == snapshot.latest_invoice_id.as_ref()
        {
            (prior_start, prior_invoice)
        } else {
            let candidate: Option<i64> = if let Some(invoice_id) = &snapshot.latest_invoice_id {
                // The fetched current invoice binds the failure. After a
                // provider-confirmed recovery, both creation and receipt must
                // be later than that boundary; an old event delivered late is
                // ambiguous and must fail closed even if its invoice is reused.
                tx.query_one(
                    "SELECT extract(epoch FROM min(e.payment_failed_at))::bigint FROM billing_events e LEFT JOIN billing_subscriptions s ON s.stripe_subscription_id=e.stripe_subscription_id AND s.account_id=e.account_id WHERE e.account_id=$1 AND e.stripe_subscription_id=$2 AND e.object_id=$3 AND e.payment_failed_at IS NOT NULL AND (s.last_non_past_due_at IS NULL OR (e.payment_failed_at > s.last_non_past_due_at AND e.received_at > s.last_non_past_due_at))",
                    &[&account_id, &snapshot.subscription_id, &invoice_id],
                ).await?.get(0)
            } else {
                None
            };
            if let (Some(candidate), Some(invoice_id)) = (candidate, &snapshot.latest_invoice_id) {
                // Rebinding within one continuous delinquency never extends
                // its original deadline to a later invoice's failure date.
                (
                    Some(if prior_past_due {
                        prior_start.map_or(candidate, |start| start.min(candidate))
                    } else {
                        candidate
                    }),
                    Some(invoice_id.clone()),
                )
            } else if prior_past_due {
                // Keep the old anchor but close admission while the provider's
                // current invoice differs or is absent. A later matching event
                // may rebind without resetting the original deadline.
                (prior_start, prior_invoice)
            } else {
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    tx.execute(
        "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price,payment_grace_started_at,last_non_past_due_at,latest_invoice_id,payment_grace_invoice_id) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $7::bigint IS NULL THEN NULL ELSE to_timestamp($7::bigint::double precision) END,CASE WHEN $4='past_due' THEN NULL ELSE clock_timestamp() END,$8,$9) ON CONFLICT(stripe_subscription_id) DO UPDATE SET stripe_status=EXCLUDED.stripe_status,stripe_price_id=EXCLUDED.stripe_price_id,recognized_price=EXCLUDED.recognized_price,payment_grace_started_at=EXCLUDED.payment_grace_started_at,last_non_past_due_at=CASE WHEN EXCLUDED.stripe_status='past_due' THEN billing_subscriptions.last_non_past_due_at ELSE clock_timestamp() END,latest_invoice_id=EXCLUDED.latest_invoice_id,payment_grace_invoice_id=EXCLUDED.payment_grace_invoice_id,reconciled_at=clock_timestamp() WHERE billing_subscriptions.account_id=EXCLUDED.account_id AND billing_subscriptions.stripe_customer_id=EXCLUDED.stripe_customer_id",
        &[&snapshot.subscription_id, &account_id, &snapshot.customer_id, &snapshot.status, &snapshot.price_id, &recognized, &grace_started_at, &snapshot.latest_invoice_id, &grace_invoice_id],
    ).await?;
    tx.execute(
        "UPDATE billing_reconciliations SET processed_generation=$3,failed_attempts=0,state='queued',last_failure_class=NULL,updated_at=now() WHERE stripe_subscription_id=$1 AND account_id=$2",
        &[&snapshot.subscription_id, &account_id, &expected_generation],
    ).await?;
    if !quota_plans.is_empty() {
        project_test_quota(
            &tx,
            account_id,
            &snapshot.subscription_id,
            expected_generation,
            quota_plans,
            snapshot.status == "provider_deleted",
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
    provider_deleted: bool,
) -> Result<(), BillingError> {
    let rows = tx.query(
        "SELECT stripe_status,stripe_price_id,recognized_price,payment_grace_started_at IS NOT NULL AND payment_grace_invoice_id IS NOT DISTINCT FROM latest_invoice_id AND payment_grace_started_at+interval '7 days'>clock_timestamp() FROM billing_subscriptions WHERE account_id=$1",
        &[&account_id],
    ).await?;
    // Other nonterminal subscriptions make the account ambiguous. Terminal
    // historical subscriptions do not block a newly active one.
    let nonterminal: Vec<_> = rows
        .iter()
        .filter(|row| {
            let status: String = row.get(0);
            !matches!(
                status.as_str(),
                "canceled" | "incomplete_expired" | "provider_deleted"
            )
        })
        .collect();
    let (limit, reason) = if nonterminal.len() == 1 {
        let row = nonterminal[0];
        let status: String = row.get(0);
        let price: Option<String> = row.get(1);
        let recognized: bool = row.get(2);
        let grace_active: bool = row.get(3);
        if (status == "active" || (status == "past_due" && grace_active)) && recognized {
            if let Some(plan) = plans
                .iter()
                .find(|plan| price.as_deref() == Some(&plan.price_id))
            {
                (
                    plan.outbound_limit,
                    if status == "active" {
                        "active"
                    } else {
                        "grace"
                    },
                )
            } else {
                (0, "unmapped")
            }
        } else {
            (0, "inactive")
        }
    } else if nonterminal.is_empty() {
        (
            0,
            if provider_deleted {
                "provider_deleted"
            } else {
                "inactive"
            },
        )
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
    if changed || reason == "provider_deleted" {
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
    if plans.iter().any(|plan| plan.device_limit.is_some()) {
        let device_limit = if matches!(reason, "active" | "grace") {
            let price: Option<String> = nonterminal[0].get(1);
            plans
                .iter()
                .find(|plan| price.as_deref() == Some(&plan.price_id))
                .and_then(|plan| plan.device_limit)
                .unwrap_or(0)
        } else {
            0
        };
        let prior = tx
            .query_opt(
                "SELECT limit_devices FROM billing_device_caps WHERE account_id=$1 FOR UPDATE",
                &[&account_id],
            )
            .await?;
        if prior
            .as_ref()
            .is_none_or(|row| row.get::<_, i64>(0) != device_limit)
        {
            tx.execute(
                "INSERT INTO billing_device_caps(account_id,limit_devices) VALUES($1,$2) ON CONFLICT(account_id) DO UPDATE SET limit_devices=EXCLUDED.limit_devices,updated_at=now()",
                &[&account_id, &device_limit],
            ).await?;
            let previous: Option<i64> = prior.map(|row| row.get(0));
            tx.execute(
                "INSERT INTO billing_device_cap_audit(account_id,stripe_subscription_id,reconciliation_generation,previous_limit_devices,limit_devices,reason) VALUES($1,$2,$3,$4,$5,$6)",
                &[&account_id, &changed_subscription, &generation, &previous, &device_limit, &reason],
            ).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
