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
    /// Creation time on a signed invoice.payment_failed event, in Unix seconds.
    pub payment_failed_at_unix: Option<i64>,
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
    let payment_failed_at_unix = if event_type == "invoice.payment_failed" {
        Some(
            json["created"]
                .as_i64()
                .filter(|created| (946_684_800..=253_402_300_799).contains(created))
                .ok_or(BillingError::InvalidEvent)?,
        )
    } else {
        None
    };
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
        payment_failed_at_unix,
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
mod tests {
    use super::*;
    use std::env;
    use tokio_postgres::NoTls;
    use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};

    const BODY: &[u8] = br#"{"id":"evt_fixture1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_fixture1","object":"subscription","customer":"cus_fixture1","status":"active"}}}"#;
    const HEADER: &str =
        "t=1750000000,v0=0000,v1=17db9d23bf1f46a7db28382296af063cf65b36c77d80f154712e9f0803633536";
    const SECRET: &str = "whsec_testfixture1234567890";

    #[test]
    fn api_key_gate_accepts_only_test_secret_or_restricted_keys() {
        assert!(is_test_api_key("sk_test_fixture123456"));
        assert!(is_test_api_key("rk_test_fixture123456"));
        for key in [
            "sk_live_fixture123456",
            "rk_live_fixture123456",
            "pk_test_fixture123456",
            "rk_test_",
            "sk_test_",
        ] {
            assert!(!is_test_api_key(key));
        }
    }

    #[test]
    fn quota_configuration_fingerprint_tracks_effective_mapping() {
        let prices = vec!["price_a".into(), "price_b".into()];
        let plans = vec![
            TestQuotaPlan {
                price_id: "price_a".into(),
                outbound_limit: 100,
                device_limit: Some(2),
            },
            TestQuotaPlan {
                price_id: "price_b".into(),
                outbound_limit: 200,
                device_limit: Some(4),
            },
        ];
        let original = quota_configuration_fingerprint(&prices, &plans, "rk_test_fixture123456");
        let mut reordered_prices = prices.clone();
        reordered_prices.reverse();
        let mut reordered_plans = plans.clone();
        reordered_plans.reverse();
        assert_eq!(
            original,
            quota_configuration_fingerprint(
                &reordered_prices,
                &reordered_plans,
                "rk_test_fixture123456"
            )
        );
        reordered_plans[0].outbound_limit += 1;
        assert_ne!(
            original,
            quota_configuration_fingerprint(&prices, &reordered_plans, "rk_test_fixture123456")
        );
        assert_ne!(
            original,
            quota_configuration_fingerprint(&prices, &plans, "rk_test_fixture654321")
        );
    }

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
                    outbound_limit: 2,
                    device_limit: None,
                },
                TestQuotaPlan {
                    price_id: prices[1].clone(),
                    outbound_limit: 10,
                    device_limit: None,
                },
            ]
        );
        assert_eq!(
            parse_test_quota_plans("price_basic1:2:1,price_plus1:10:3", &prices)
                .unwrap()
                .iter()
                .map(|plan| plan.device_limit)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(3)]
        );
        for invalid in [
            "price_unknown1:2",
            "price_basic1:0",
            "price_basic1:-1",
            "price_basic1:2,price_basic1:3",
            "price_basic1:18446744073709551616",
            "price_basic1:x",
            "price_basic1:2:-1",
            "price_basic1:2:1:4",
            "price_basic1:2:1,price_plus1:10",
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
    async fn failed_payment_and_late_paid_event_follow_current_test_subscription() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_lifecycle_{}", Uuid::new_v4().simple());
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
            include_str!("../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'billing fixture')",
            &[&device, &account],
        )
        .await
        .unwrap();
        bind_customer(&mut db, account, "cus_lifecycle1")
            .await
            .unwrap();
        let prices = vec!["price_lifecycle1".into(), "price_lifecycle2".into()];
        let plans =
            parse_test_quota_plans("price_lifecycle1:2,price_lifecycle2:1", &prices).unwrap();
        let active = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"active","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle1"}}]}}"#).unwrap();
        let past_due = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"past_due","latest_invoice":"in_lifecyclefailed1","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle1"}}]}}"#).unwrap();
        let downgraded = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"active","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle2"}}]}}"#).unwrap();
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 3_600_000;
        let send = |id: Uuid, key: &'static str| NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: id,
            idempotency_key: key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic billing fixture",
            expires_at_ms: expiry,
        };

        // These are locally signed virtual Stripe TEST fixtures. Only the
        // subscription snapshots, as parsed from a provider response, project
        // entitlements; invoice event payloads merely dirty the queue.
        let paid = signed_test_event(br#"{"id":"evt_lifecyclepaid1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclepaid1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
        assert_eq!(ingest(&mut db, &paid).await.unwrap(), IngestResult::Queued);
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
            .await
            .unwrap();
        let first = Uuid::new_v4();
        assert!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(first, "first"))
                .await
                .unwrap()
                .created
        );
        // Model an active provider read before the later failed attempt.
        db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '2 minutes' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();

        // The nested subscription pointer covers the newer Invoice shape.
        let failure_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 60;
        let failed_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclefailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": failure_created,
            "data": {"object": {"id": "in_lifecyclefailed1", "customer": "cus_lifecycle1", "parent": {"subscription_details": {"subscription": "sub_lifecycle1"}}}}
        })).unwrap();
        let failed = signed_test_event(&failed_body);
        assert_eq!(
            ingest(&mut db, &failed).await.unwrap(),
            IngestResult::Queued
        );
        assert_eq!(
            ingest(&mut db, &failed).await.unwrap(),
            IngestResult::Duplicate
        );
        let generation: i64 = db.query_one(
            "SELECT dirty_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert_eq!(
            generation, 2,
            "duplicate delivery must not queue a second read"
        );
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(Uuid::new_v4(), "pending-failure"))
                .await,
            Err(StoreError::QuotaNotConfigured)
        ));
        reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 2)
            .await
            .unwrap();
        let grace_start: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert_eq!(grace_start, failure_created);
        let grace_message = Uuid::new_v4();
        assert!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(grace_message, "within-grace"))
                .await
                .unwrap()
                .created
        );
        assert!(
            DeliveryStore::new(&mut db)
                .cancel(account, grace_message)
                .await
                .unwrap()
        );
        // This contender begins before expiry but waits on the account lock
        // until afterward. Admission must use the post-wait DB clock.
        db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=clock_timestamp()-interval '7 days'+interval '1 second' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
        let (mut locker, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let lock = locker.transaction().await.unwrap();
        lock.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[&account],
        )
        .await
        .unwrap();
        let contender_url = scoped_url.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let contender = tokio::spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&contender_url, NoTls)
                .await
                .unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            started_tx.send(()).unwrap();
            DeliveryStore::new(&mut client)
                .accept_metered(NewMessage {
                    account_id: account,
                    device_id: device,
                    client_message_id: Uuid::new_v4(),
                    idempotency_key: "after-lock-expiry",
                    recipient_e164: "+15551234567",
                    synthetic_payload: b"synthetic billing fixture",
                    expires_at_ms: expiry,
                })
                .await
        });
        started_rx.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        lock.commit().await.unwrap();
        assert!(matches!(
            contender.await.unwrap(),
            Err(StoreError::QuotaExceeded)
        ));
        db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=transaction_timestamp()-interval '7 days 1 second' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(Uuid::new_v4(), "after-grace"))
                .await,
            Err(StoreError::QuotaExceeded)
        ));
        assert!(
            !DeliveryStore::new(&mut db)
                .accept_metered(send(first, "first"))
                .await
                .unwrap()
                .created
        );

        // A delayed paid webhook must read the current past_due state. Its
        // old invoice payload cannot restore an allowance by itself.
        let late_paid = signed_test_event(br#"{"id":"evt_lifecyclelate1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecycleold1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
        assert_eq!(
            ingest(&mut db, &late_paid).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 3)
            .await
            .unwrap();
        let row = db.query_one(
            "SELECT p.limit_units,u.reserved_units,u.refunded_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1",
            &[&account],
        ).await.unwrap();
        assert_eq!(
            (
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, i64>(2)
            ),
            (0, 2, 1)
        );
        let replayed_start: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert!(replayed_start < grace_start);

        let recovered = signed_test_event(br#"{"id":"evt_lifecyclerecovered1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclerecovered1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
        assert_eq!(
            ingest(&mut db, &recovered).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 4)
            .await
            .unwrap();
        let cleared: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert!(cleared);
        assert!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(Uuid::new_v4(), "recovered"))
                .await
                .unwrap()
                .created
        );

        // A delayed failure for the recovered invoice reads the current
        // active subscription and cannot reopen its old grace interval.
        let stale_failure_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclestalefailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": failure_created,
            "data": {"object": {"id": "in_lifecyclefailed1", "customer": "cus_lifecycle1", "subscription": "sub_lifecycle1"}}
        })).unwrap();
        let stale_failure = signed_test_event(&stale_failure_body);
        assert_eq!(
            ingest(&mut db, &stale_failure).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 5)
            .await
            .unwrap();
        let cleared: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert!(cleared);

        // The old failure is for a different invoice and cannot grant grace
        // when the current provider snapshot becomes past_due again.
        let next_past_due = SubscriptionSnapshot {
            latest_invoice_id: Some("in_lifecyclenew1".into()),
            ..past_due.clone()
        };
        let next_update = signed_test_event(br#"{"id":"evt_lifecyclenextdue1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_lifecycle1","customer":"cus_lifecycle1"}}}"#);
        assert_eq!(
            ingest(&mut db, &next_update).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &next_past_due, &prices, &plans, 6)
            .await
            .unwrap();
        let no_grace: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
        assert!(no_grace);
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(Uuid::new_v4(), "unmatched-invoice"))
                .await,
            Err(StoreError::QuotaExceeded)
        ));

        // A matching signed failure starts a new interval. A future provider
        // timestamp is capped at database receipt time before persistence.
        let future_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3_600;
        let next_failure_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclenewfailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": future_created,
            "data": {"object": {"id": "in_lifecyclenew1", "customer": "cus_lifecycle1", "subscription": "sub_lifecycle1"}}
        })).unwrap();
        let next_failure = signed_test_event(&next_failure_body);
        assert_eq!(
            ingest(&mut db, &next_failure).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &next_past_due, &prices, &plans, 7)
            .await
            .unwrap();
        let clock = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint,extract(epoch FROM transaction_timestamp())::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
        let new_start: i64 = clock.get(0);
        let observed_now: i64 = clock.get(1);
        assert!((observed_now - 5..=observed_now).contains(&new_start));
        assert!(new_start < future_created);
        let new_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
        assert_eq!(new_limit, 2);
        let next_recovered = signed_test_event(br#"{"id":"evt_lifecyclenewpaid1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclenew1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
        assert_eq!(
            ingest(&mut db, &next_recovered).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 8)
            .await
            .unwrap();

        let downgrade = signed_test_event(br#"{"id":"evt_lifecycledowngrade1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_lifecycle1","customer":"cus_lifecycle1"}}}"#);
        assert_eq!(
            ingest(&mut db, &downgrade).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &downgraded, &prices, &plans, 9)
            .await
            .unwrap();
        let row = db.query_one(
            "SELECT p.limit_units,u.limit_units,u.reserved_units,u.refunded_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1",
            &[&account],
        ).await.unwrap();
        assert_eq!(
            (
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, i64>(2),
                row.get::<_, i64>(3)
            ),
            (1, 1, 3, 1),
            "downgrade preserves existing reservations"
        );
        assert!(matches!(
            DeliveryStore::new(&mut db)
                .accept_metered(send(Uuid::new_v4(), "after-downgrade"))
                .await,
            Err(StoreError::QuotaExceeded)
        ));
        let audit = db.query(
            "SELECT reconciliation_generation,previous_limit_units,limit_units,reason FROM billing_quota_audit WHERE account_id=$1 ORDER BY id",
            &[&account],
        ).await.unwrap();
        assert_eq!(
            audit.len(),
            6,
            "duplicate and late events must not add policy changes"
        );
        assert_eq!(
            (
                audit[1].get::<_, i64>(0),
                audit[1].get::<_, i64>(2),
                audit[1].get::<_, String>(3)
            ),
            (3, 0, "inactive".into())
        );
        assert_eq!(
            (
                audit[5].get::<_, i64>(0),
                audit[5].get::<_, i64>(1),
                audit[5].get::<_, i64>(2)
            ),
            (9, 2, 1)
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delayed_failure_keeps_last_active_boundary_and_recovery_excludes_old_cycle() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_delayed_grace_{}", Uuid::new_v4().simple());
        admin
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        bind_customer(&mut db, account, "cus_delayedgrace1")
            .await
            .unwrap();
        let prices = vec!["price_delayedgrace1".into()];
        let plans = parse_test_quota_plans("price_delayedgrace1:3", &prices).unwrap();
        let active = SubscriptionSnapshot {
            subscription_id: "sub_delayedgrace1".into(),
            customer_id: "cus_delayedgrace1".into(),
            status: "active".into(),
            price_id: Some("price_delayedgrace1".into()),
            latest_invoice_id: None,
        };
        let past_due = SubscriptionSnapshot {
            status: "past_due".into(),
            latest_invoice_id: Some("in_delayedgrace1".into()),
            ..active.clone()
        };
        let update =
            |id: &str| {
                signed_test_event(&serde_json::to_vec(&serde_json::json!({
            "id": id,
            "object": "event",
            "livemode": false,
            "type": "customer.subscription.updated",
            "data": {"object": {"id": "sub_delayedgrace1", "customer": "cus_delayedgrace1"}}
        })).unwrap())
            };
        assert_eq!(
            ingest(&mut db, &update("evt_delayedactive1"))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
            .await
            .unwrap();
        db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '1 hour' WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
        assert_eq!(
            ingest(&mut db, &update("evt_delayedpastdue1"))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 2)
            .await
            .unwrap();
        let no_anchor: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
        assert!(no_anchor);

        // Delivery arrives more than five minutes after its signed creation.
        // Repeated past_due reads must not move the last active boundary.
        let delayed_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 600;
        let failed_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedfailure1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": delayed_created,
            "data": {"object": {"id": "in_delayedgrace1", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
        let delayed = signed_test_event(&failed_body);
        assert_eq!(
            ingest(&mut db, &delayed).await.unwrap(),
            IngestResult::Queued
        );
        assert_eq!(
            ingest(&mut db, &delayed).await.unwrap(),
            IngestResult::Duplicate
        );
        reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 3)
            .await
            .unwrap();
        let started: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
        assert_eq!(started, delayed_created);
        let limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
        assert_eq!(limit, 3);

        // A newer current invoice invalidates the old binding immediately.
        // A matching failure can rebind without extending the first deadline.
        let swapped = SubscriptionSnapshot {
            latest_invoice_id: Some("in_delayedgrace2".into()),
            ..past_due.clone()
        };
        assert_eq!(
            ingest(&mut db, &update("evt_delayedswap1")).await.unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 4)
            .await
            .unwrap();
        let mismatch = db.query_one(
            "SELECT payment_grace_invoice_id,latest_invoice_id,extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
        assert_eq!(mismatch.get::<_, String>(0), "in_delayedgrace1");
        assert_eq!(mismatch.get::<_, String>(1), "in_delayedgrace2");
        assert_eq!(mismatch.get::<_, i64>(2), started);
        let blocked_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
        assert_eq!(blocked_limit, 0);
        let swapped_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 30;
        let swapped_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedswapfailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": swapped_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
        assert_eq!(
            ingest(&mut db, &signed_test_event(&swapped_body))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 5)
            .await
            .unwrap();
        let rebound = db.query_one(
            "SELECT payment_grace_invoice_id,extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
        assert_eq!(rebound.get::<_, String>(0), "in_delayedgrace2");
        assert_eq!(rebound.get::<_, i64>(1), started);
        let restored_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
        assert_eq!(restored_limit, 3);

        // This failure was created and received before recovery, but lies
        // within five minutes. It cannot be reused after recovery.
        let near_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 60;
        let near_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayednear1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": near_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
        assert_eq!(
            ingest(&mut db, &signed_test_event(&near_body))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 6)
            .await
            .unwrap();

        assert_eq!(
            ingest(&mut db, &update("evt_delayedrecovery1"))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 7)
            .await
            .unwrap();
        let stale_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedstale1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": near_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
        assert_eq!(
            ingest(&mut db, &signed_test_event(&stale_body))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 8)
            .await
            .unwrap();
        db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '2 seconds' WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
        assert_eq!(
            ingest(&mut db, &update("evt_delayedpastdue2"))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 9)
            .await
            .unwrap();
        let no_replay: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
        assert!(
            no_replay,
            "the prior cycle's failed invoice must not restart grace"
        );

        let fresh_created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let fresh_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedfailure2",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": fresh_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
        assert_eq!(
            ingest(&mut db, &signed_test_event(&fresh_body))
                .await
                .unwrap(),
            IngestResult::Queued
        );
        reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 10)
            .await
            .unwrap();
        let restarted: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
        assert!(restarted > started);
        assert!((fresh_created - 1..=fresh_created).contains(&restarted));
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reconciliation_locks_customer_before_queue_row_without_blocking_account_fk() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_lock_order_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut blocker_db, connection) =
            tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (mut reconcile_db, connection) =
            tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (probe, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
        ] {
            probe.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        probe
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        probe.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_lockorder1')",
            &[&account],
        ).await.unwrap();
        probe.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES('sub_lockorder1',$1,'cus_lockorder1')",
            &[&account],
        ).await.unwrap();
        let reconcile_pid: i32 = reconcile_db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let blocker = blocker_db.transaction().await.unwrap();
        let blocker_pid: i32 = blocker
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        blocker
            .query_one(
                "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR UPDATE",
                &[&account],
            )
            .await
            .unwrap();

        let task = tokio::spawn(async move {
            reconcile_snapshot(
                &mut reconcile_db,
                account,
                &SubscriptionSnapshot {
                    subscription_id: "sub_lockorder1".into(),
                    customer_id: "cus_lockorder1".into(),
                    status: "active".into(),
                    price_id: None,
                    latest_invoice_id: None,
                },
                &[],
                1,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blockers: Vec<i32> = setup
                    .query_one("SELECT pg_blocking_pids($1)", &[&reconcile_pid])
                    .await
                    .unwrap()
                    .get(0);
                if blockers.contains(&blocker_pid) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reconciliation must wait on the held customer row");

        // Both probes succeed only if reconciliation holds neither the old
        // account UPDATE lock nor the queue row before the customer lock.
        probe
            .query_one(
                "SELECT id FROM accounts WHERE id=$1 FOR KEY SHARE NOWAIT",
                &[&account],
            )
            .await
            .unwrap();
        probe.query_one(
            "SELECT stripe_subscription_id FROM billing_reconciliations WHERE stripe_subscription_id='sub_lockorder1' FOR UPDATE NOWAIT",
            &[],
        ).await.unwrap();
        // The recovery boundary must be recorded after the blocked lock is
        // released. transaction_timestamp() would still be the earlier start
        // of the reconciliation transaction here.
        let released_after: f64 = probe
            .query_one(
                "SELECT extract(epoch FROM clock_timestamp())::double precision",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        blocker.commit().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("reconciliation should resume")
            .unwrap()
            .unwrap();
        let processed: i64 = probe.query_one(
            "SELECT processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_lockorder1'",
            &[],
        ).await.unwrap().get(0);
        assert_eq!(processed, 1);
        let status: String = probe.query_one(
            "SELECT stripe_status FROM billing_subscriptions WHERE stripe_subscription_id='sub_lockorder1'",
            &[],
        ).await.unwrap().get(0);
        assert_eq!(status, "active");
        let recovery_boundary: f64 = probe
            .query_one(
                "SELECT extract(epoch FROM last_non_past_due_at)::double precision FROM billing_subscriptions WHERE stripe_subscription_id='sub_lockorder1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(recovery_boundary >= released_after);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
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
                    latest_invoice_id: None,
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
            latest_invoice_id: None,
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
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
            payment_failed_at_unix: None,
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
            latest_invoice_id: None,
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
        reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
            .await
            .unwrap();
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
        let before = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
        reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
            .await
            .unwrap();
        let unchanged = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
        for (old, new) in before.iter().zip(&unchanged) {
            assert_eq!(old.get::<_, i64>(1), new.get::<_, i64>(1));
            assert_eq!(old.get::<_, i64>(2), new.get::<_, i64>(2));
        }
        let preserved: i64 = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(preserved, 2, "same config must preserve active quota");
        reset_test_quotas_on_start(&scoped_url, true, false, Some(&[2; 32]))
            .await
            .unwrap();
        let changed = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
        for (old, new) in before.iter().zip(&changed) {
            let subscription: String = new.get(0);
            let expected = old.get::<_, i64>(1) + i64::from(subscription != "sub_entitlement2");
            assert_eq!(
                new.get::<_, i64>(1),
                expected,
                "terminal subscription must not be redirtied"
            );
        }
        // A rolling upgrade can temporarily have entitlement migration 010
        // without risk migration 011. Disabling billing still clears its old
        // allowance, while enabling billing requires both schemas.
        db.batch_execute("DROP TABLE billing_payment_holds,billing_risk_events")
            .await
            .unwrap();
        assert!(
            reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
                .await
                .is_err()
        );
        reset_test_quotas_on_start(&scoped_url, false, false, None)
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
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
            Some((a, "sub_fixture1".into(), "cus_fixture1".into(), 1))
        );
        assert!(worker::claim(&mut db).await.unwrap().is_none());
        let mut newer = event.clone();
        newer.event_id = "evt_fixture2".into();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
        let mut replays = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let event = newer.clone();
            let url = database_url.clone();
            let barrier = barrier.clone();
            replays.spawn(async move {
                let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
                tokio::spawn(async move { connection.await.unwrap() });
                barrier.wait().await;
                ingest(&mut client, &event).await.unwrap()
            });
        }
        let mut queued = 0;
        let mut duplicate = 0;
        while let Some(result) = replays.join_next().await {
            match result.unwrap() {
                IngestResult::Queued => queued += 1,
                IngestResult::Duplicate => duplicate += 1,
                other => panic!("unexpected replay disposition: {other:?}"),
            }
        }
        assert_eq!((queued, duplicate), (1, 15));
        let active = SubscriptionSnapshot {
            subscription_id: "sub_fixture1".into(),
            customer_id: "cus_fixture1".into(),
            status: "active".into(),
            price_id: Some("price_known1".into()),
            latest_invoice_id: None,
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
        assert!(is_test_api_key(&secret_key));
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
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/025_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/026_billing_provider_failures.sql"),
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
