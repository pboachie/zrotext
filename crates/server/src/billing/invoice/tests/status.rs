// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_auth::{AuthHttpState, DisabledVerificationDispatcher};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

async fn owner_status(case: &Case) -> serde_json::Value {
    let hasher = Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(77)).unwrap());
    let session = crate::auth::login(
        &case.db,
        &hasher,
        "invoice-owner@example.test",
        &crate::test_keys::password(77),
    )
    .await
    .unwrap();
    let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{}", case.schema);
    let state = AuthHttpState::new(
        url,
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let response = billing::owner::status_router(state)
        .oneshot(
            Request::builder()
                .uri("/status")
                .header(
                    "Cookie",
                    format!("__Host-zrotext_session={}", session.token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

async fn ingest_signed(case: &mut Case, payload: serde_json::Value) {
    let body = serde_json::to_vec(&payload).unwrap();
    let secret = format!("whsec_{}", Uuid::new_v4().simple());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(&body);
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let verified = billing::verify_event(
        &body,
        &format!("t=1750000000,v1={signature}"),
        &secret,
        1_750_000_000,
    )
    .unwrap();
    billing::ingest(&mut case.db, &verified).await.unwrap();
}

fn assert_current(view: &serde_json::Value, eligible: bool, limit: i64) {
    assert_eq!(view["invoicePeriod"]["currentPeriodEligible"], eligible);
    assert_eq!(view["invoicePeriod"]["effectiveLimit"], limit);
    assert_eq!(view["projectedEntitlement"]["outboundLimit"], limit);
    assert_eq!(
        view["projectedEntitlement"]["reason"],
        if eligible {
            "invoice_current"
        } else {
            "invoice_restricted"
        }
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn owner_projection_rechecks_missing_dirty_cancelled_and_held_invoice_authority() {
    let mut case = Case::new().await;
    let missing = owner_status(&case).await;
    assert_current(&missing, false, 0);
    assert!(missing["invoicePeriod"]["lastObservedPhase"].is_null());
    assert!(missing["invoicePeriod"]["consumedUnits"].is_null());
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("status-unknown").await.unwrap();
    let active = owner_status(&case).await;
    assert_current(&active, true, 2);
    assert_eq!(active["invoicePeriod"]["consumedUnits"], 1);
    case.db
        .execute(
            "UPDATE billing_reconciliations SET dirty_generation=processed_generation+1",
            &[],
        )
        .await
        .unwrap();
    let dirty = owner_status(&case).await;
    assert_current(&dirty, false, 0);
    assert_eq!(dirty["invoicePeriod"]["lastObservedPhase"], "active");
    assert_eq!(dirty["invoicePeriod"]["lastObservedEffectiveLimit"], 2);
    case.db
        .execute(
            "UPDATE billing_reconciliations SET dirty_generation=processed_generation",
            &[],
        )
        .await
        .unwrap();
    case.db
        .execute(
            "UPDATE billing_invoice_entitlements SET cancel_at_ms=0",
            &[],
        )
        .await
        .unwrap();
    assert_current(&owner_status(&case).await, false, 0);
    case.db
        .execute(
            "UPDATE billing_invoice_entitlements SET cancel_at_ms=NULL",
            &[],
        )
        .await
        .unwrap();
    assert_current(&owner_status(&case).await, true, 2);
    let event = json!({"id":"evt_statusrefund","object":"event","livemode":false,
        "type":"charge.refunded","data":{"object":{"id":"ch_statusrefund","object":"charge","customer":&case.customer,"amount_refunded":1}}});
    ingest_signed(&mut case, event).await;
    assert_current(&owner_status(&case).await, false, 0);
    assert_eq!(
        owner_status(&case).await["invoicePeriod"]["consumedUnits"],
        1
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn unpaid_upgrade_status_uses_original_grace_ceiling_and_rechecks_its_deadline() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("before-unpaid-upgrade").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let now: i64 = case
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let event = json!({"id":"evt_statusfailed","object":"event","livemode":false,"created":now,
        "type":"invoice.payment_failed","data":{"object":{"id":"in_invoice2","customer":&case.customer,"parent":{"subscription_details":{"subscription":"sub_invoice1"}}}}});
    ingest_signed(&mut case, event).await;
    case.generation += 1;
    let failed = case.observation_for_price(
        "past_due",
        "open",
        "subscription_update",
        "price_invoice2",
        "in_invoice2",
    );
    billing::reconcile_with_invoice(
        &mut case.db,
        case.account,
        failed.subscription(),
        &["price_invoice2".into()],
        &[TestQuotaPlan {
            price_id: "price_invoice2".into(),
            outbound_limit: 20,
            device_limit: None,
        }],
        case.generation,
        Some(&failed),
    )
    .await
    .unwrap();
    let legacy: i64 = case
        .db
        .query_one("SELECT limit_units FROM usage_quota_policies", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        legacy, 20,
        "the legacy projection exposes the larger configured plan"
    );
    let view = owner_status(&case).await;
    assert_current(&view, true, 2);
    assert_eq!(view["invoicePeriod"]["lastObservedPhase"], "grace");
    assert_eq!(view["invoicePeriod"]["consumedUnits"], 1);
    case.db
        .execute(
            "UPDATE billing_invoice_entitlements SET grace_until_ms=0",
            &[],
        )
        .await
        .unwrap();
    let expired = owner_status(&case).await;
    assert_current(&expired, false, 0);
    assert_eq!(expired["invoicePeriod"]["lastObservedPhase"], "grace");
    assert_eq!(expired["invoicePeriod"]["lastObservedEffectiveLimit"], 2);
    assert!(case.send("expired-grace").await.is_err());
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn owner_invoice_status_does_not_label_expired_period_as_current_authority() {
    let mut case = Case::new().await;
    let now: i64 = case
        .db
        .query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .unwrap()
        .get(0);
    case.end = now + 1;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let expired = owner_status(&case).await;
    assert_current(&expired, false, 0);
    assert_eq!(expired["invoicePeriod"]["lastObservedPhase"], "active");
    assert_eq!(expired["invoicePeriod"]["lastObservedEffectiveLimit"], 2);
    case.cleanup().await;
}
