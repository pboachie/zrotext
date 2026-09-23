// SPDX-License-Identifier: AGPL-3.0-only
//! Test-mode Stripe event inbox. Events only request reconciliation; they never
//! directly grant a plan or change a quota.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod http;
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
    let (object_id, customer_id, subscription_id) = match event_type {
        "checkout.session.completed" => (
            Some(stripe_id(&object["id"], "cs_")?.to_owned()),
            Some(stripe_id(&object["customer"], "cus_")?.to_owned()),
            Some(stripe_id(&object["subscription"], "sub_")?.to_owned()),
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
            )
        }
        _ => (None, None, None),
    };
    Ok(VerifiedEvent {
        event_id,
        event_type: event_type.to_owned(),
        object_id,
        customer_id,
        subscription_id,
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
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1 FOR SHARE",
            &[customer_id],
        )
        .await?
        .map(|row| row.get(0))
    } else {
        None
    };
    let initial = if event.subscription_id.is_none() {
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
            "SELECT account_id FROM billing_customers WHERE stripe_customer_id=$1",
            &[&customer_id],
        )
        .await?;
    if binding.map(|row| row.get::<_, Uuid>(0)) != Some(account_id) {
        return Err(BillingError::TenantConflict);
    }
    let rows = tx.query(
        "SELECT stripe_event_id,stripe_subscription_id FROM billing_events WHERE stripe_customer_id=$1 AND disposition='unbound' ORDER BY received_at,stripe_event_id FOR UPDATE",
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

/// Apply a freshly fetched Stripe subscription after checking both provider
/// IDs against the tenant binding. Event payloads never enter this path.
pub async fn reconcile_snapshot(
    client: &mut Client,
    account_id: Uuid,
    snapshot: &SubscriptionSnapshot,
    recognized_prices: &[String],
    expected_generation: i64,
) -> Result<(), BillingError> {
    valid_id(&snapshot.subscription_id, "sub_")?;
    valid_id(&snapshot.customer_id, "cus_")?;
    let tx = client.transaction().await?;
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
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio_postgres::NoTls;

    const BODY: &[u8] = br#"{"id":"evt_fixture1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_fixture1","object":"subscription","customer":"cus_fixture1","status":"active"}}}"#;
    const HEADER: &str =
        "t=1750000000,v0=0000,v1=17db9d23bf1f46a7db28382296af063cf65b36c77d80f154712e9f0803633536";
    const SECRET: &str = "whsec_testfixture1234567890";

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
        let signed = format!("t=1750000000,v1={:x}", mac.finalize().into_bytes());
        assert!(matches!(
            verify_event(&body, &signed, SECRET, 1_750_000_000),
            Err(BillingError::InvalidEvent)
        ));
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
}
