// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-only view of locally reconciled Stripe test records. These snapshots
//! are informational and never grant an entitlement.

use crate::http_auth::{self, AuthHttpError, AuthHttpState};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::sync::Arc;
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BillingStatus {
    mode: &'static str,
    customer_bound: bool,
    pending_reconciliations: i64,
    review_reconciliations: i64,
    review_risk_events: i64,
    nonterminal_subscriptions: i64,
    subscriptions: Vec<SubscriptionView>,
    more_subscriptions: bool,
    device_capacity: DeviceCapacityView,
    projected_entitlement: ProjectedEntitlementView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceCapacityView {
    limit: Option<i64>,
    active: i64,
    over_limit: bool,
    enrollment_blocked: bool,
}

/// The entitlement projection reconciliation would apply today, from the
/// latest audited change and current risk state. Informational only: only
/// reconciled provider reads ever grant or revoke an entitlement.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectedEntitlementView {
    reason: Option<String>,
    outbound_limit: Option<i64>,
    device_cap: Option<i64>,
    payment_hold: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionView {
    stripe_status: String,
    recognized_test_price: bool,
    reconciliation_pending: bool,
    needs_review: bool,
    reconciled_at_unix: i64,
    payment_grace_ends_at_unix: Option<i64>,
}

pub fn page_router(auth: AuthHttpState) -> Router {
    let state = Arc::new(auth);
    Router::new()
        .route("/billing", get(dashboard))
        .route("/billing/dashboard.js", get(script))
        .layer(middleware::from_fn(no_store_response))
        .with_state(state)
}

pub fn status_router(auth: AuthHttpState) -> Router {
    Router::new()
        .route("/status", get(status))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(auth))
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn connect(database_url: &str) -> Result<Client, AuthHttpError> {
    let (db, connection) = crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(db)
}

async fn owner_id(state: &AuthHttpState, headers: &HeaderMap) -> Result<Uuid, AuthHttpError> {
    let db = connect(&state.database_url).await?;
    Ok(
        http_auth::require_owner(&db, &state.hasher, &state.canonical_origin, headers, false)
            .await?
            .tenant
            .account_id(),
    )
}

async fn status(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<BillingStatus>, AuthHttpError> {
    let db = connect(&state.database_url).await?;
    let owner =
        http_auth::require_owner(&db, &state.hasher, &state.canonical_origin, &headers, false)
            .await?;
    let account_id = owner.tenant.account_id();
    let customer_bound = db
        .query_opt(
            "SELECT 1 FROM billing_customers WHERE account_id=$1",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .is_some();
    let pending_reconciliations: i64 = db
        .query_one(
            "SELECT count(*) FROM billing_reconciliations WHERE account_id=$1 AND dirty_generation>processed_generation",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .get(0);
    let review_reconciliations: i64 = db
        .query_one("SELECT count(*) FROM billing_reconciliations WHERE account_id=$1 AND state='needs_review' AND dirty_generation>processed_generation", &[&account_id])
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .get(0);
    let review_risk_events: i64 = db
        .query_one(
            "SELECT count(*) FROM billing_risk_events WHERE account_id=$1 AND state='needs_review'",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .get(0);
    let capacity = db
        .query_one(
            "SELECT (SELECT limit_devices FROM billing_device_caps WHERE account_id=$1), (SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL), (SELECT enabled FROM billing_device_cap_config WHERE singleton=true)",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let cap_policy_enabled: bool = capacity.get(2);
    let limit: Option<i64> = if cap_policy_enabled {
        capacity.get(0)
    } else {
        None
    };
    let active: i64 = capacity.get(1);
    let projection = db
        .query_one(
            "SELECT (SELECT count(*) FROM billing_subscriptions WHERE account_id=$1 AND stripe_status NOT IN ('canceled','incomplete_expired','provider_deleted')), (SELECT reason FROM billing_quota_audit WHERE account_id=$1 ORDER BY changed_at DESC, id DESC LIMIT 1), (SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' AND source='stripe_test'), (SELECT EXISTS(SELECT 1 FROM billing_payment_holds WHERE account_id=$1))",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let nonterminal_subscriptions: i64 = projection.get(0);
    let rows = db
        .query(
            "SELECT s.stripe_status,s.recognized_price,r.dirty_generation>r.processed_generation,extract(epoch from s.reconciled_at)::bigint,CASE WHEN s.stripe_status='past_due' AND s.payment_grace_invoice_id=s.latest_invoice_id THEN extract(epoch from s.payment_grace_started_at+interval '7 days')::bigint ELSE NULL END,r.state='needs_review' FROM billing_subscriptions s JOIN billing_reconciliations r ON r.stripe_subscription_id=s.stripe_subscription_id AND r.account_id=s.account_id WHERE s.account_id=$1 ORDER BY s.reconciled_at DESC,s.stripe_subscription_id LIMIT 21",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let more_subscriptions = rows.len() > 20;
    let subscriptions = rows
        .into_iter()
        .take(20)
        .map(|row| SubscriptionView {
            stripe_status: row.get(0),
            recognized_test_price: row.get(1),
            reconciliation_pending: row.get(2),
            needs_review: row.get(5),
            reconciled_at_unix: row.get(3),
            payment_grace_ends_at_unix: row.get(4),
        })
        .collect();
    Ok(Json(BillingStatus {
        mode: "test",
        customer_bound,
        pending_reconciliations,
        review_reconciliations,
        review_risk_events,
        nonterminal_subscriptions,
        subscriptions,
        more_subscriptions,
        device_capacity: DeviceCapacityView {
            limit,
            active,
            over_limit: limit.is_some_and(|value| active > value),
            enrollment_blocked: limit.is_some_and(|value| active >= value)
                || (limit.is_some() && pending_reconciliations > 0)
                || (limit.is_none() && cap_policy_enabled),
        },
        projected_entitlement: ProjectedEntitlementView {
            reason: projection.get(1),
            outbound_limit: projection.get(2),
            device_cap: limit,
            payment_hold: projection
                .get::<_, Option<bool>>(3)
                .is_some_and(|held| held),
        },
    }))
}

async fn dashboard(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    owner_id(&state, &headers).await?;
    Ok((
        [
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains"),
        ],
        Html(include_str!("../../static/billing-dashboard.html")),
    ).into_response())
}

async fn script() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        include_str!("../../static/billing-dashboard.js"),
    )
}

#[cfg(test)]
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests;
