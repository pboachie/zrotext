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
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BillingStatus {
    mode: &'static str,
    customer_bound: bool,
    pending_reconciliations: i64,
    subscriptions: Vec<SubscriptionView>,
    more_subscriptions: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionView {
    stripe_status: String,
    recognized_test_price: bool,
    reconciliation_pending: bool,
    reconciled_at_unix: i64,
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
    let (db, connection) = tokio_postgres::connect(database_url, NoTls)
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
    let rows = db
        .query(
            "SELECT s.stripe_status,s.recognized_price,r.dirty_generation>r.processed_generation,extract(epoch from s.reconciled_at)::bigint FROM billing_subscriptions s JOIN billing_reconciliations r ON r.stripe_subscription_id=s.stripe_subscription_id AND r.account_id=s.account_id WHERE s.account_id=$1 ORDER BY s.reconciled_at DESC,s.stripe_subscription_id LIMIT 21",
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
            reconciled_at_unix: row.get(3),
        })
        .collect();
    Ok(Json(BillingStatus {
        mode: "test",
        customer_bound,
        pending_reconciliations,
        subscriptions,
        more_subscriptions,
    }))
}

async fn dashboard(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    owner_id(&state, &headers).await?;
    Ok((
        [
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
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
mod tests {
    use super::*;
    use crate::{auth, http_auth::DisabledVerificationDispatcher};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    fn get(path: &str, token: Option<&str>) -> Request<Body> {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
        }
        request.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn owner_status_omits_provider_ids_and_foreign_tenant_rows() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("billing_owner_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let db_url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&db_url, NoTls).await.unwrap();
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
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let password_a = Uuid::new_v4().to_string();
        let password_b = Uuid::new_v4().to_string();
        let first = auth::register(&mut db, &hasher, "billing-view-a@example.test", &password_a)
            .await
            .unwrap();
        auth::verify_email(&mut db, &hasher, &first.verification_token)
            .await
            .unwrap();
        let owner_a = auth::login(&db, &hasher, "billing-view-a@example.test", &password_a)
            .await
            .unwrap();
        let second = auth::register(&mut db, &hasher, "billing-view-b@example.test", &password_b)
            .await
            .unwrap();
        auth::verify_email(&mut db, &hasher, &second.verification_token)
            .await
            .unwrap();
        let owner_b = auth::login(&db, &hasher, "billing-view-b@example.test", &password_b)
            .await
            .unwrap();
        let auth_state = AuthHttpState::new(
            db_url,
            hasher,
            "https://zrotext.example".into(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let app = page_router(auth_state.clone()).nest("/v1/billing", status_router(auth_state));

        assert_eq!(
            app.clone()
                .oneshot(get("/billing", None))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(get("/v1/billing/status", None))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let empty = app
            .clone()
            .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
            .await
            .unwrap();
        assert_eq!(empty.status(), StatusCode::OK);
        assert_eq!(empty.headers()[header::CACHE_CONTROL], "no-store");
        let empty: Value =
            serde_json::from_slice(&to_bytes(empty.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(empty["customerBound"], false);
        assert_eq!(empty["pendingReconciliations"], 0);
        assert_eq!(empty["subscriptions"].as_array().unwrap().len(), 0);

        for (account, customer, subscription, status, recognized, dirty, processed) in [
            (
                first.account_id,
                "cus_OwnerA",
                "sub_OwnerA",
                "past_due",
                false,
                2_i64,
                1_i64,
            ),
            (
                second.account_id,
                "cus_OwnerB",
                "sub_OwnerB",
                "active",
                true,
                1_i64,
                1_i64,
            ),
        ] {
            db.execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
                &[&account, &customer],
            )
            .await
            .unwrap();
            db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES($1,$2,$3,$4,$5)", &[&subscription, &account, &customer, &dirty, &processed]).await.unwrap();
            db.execute("INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price) VALUES($1,$2,$3,$4,$5,$6)", &[&subscription, &account, &customer, &status, &"price_Private", &recognized]).await.unwrap();
        }
        let response = app
            .clone()
            .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let status: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status["mode"], "test");
        assert_eq!(status["customerBound"], true);
        assert_eq!(status["pendingReconciliations"], 1);
        assert_eq!(status["subscriptions"].as_array().unwrap().len(), 1);
        assert_eq!(status["subscriptions"][0]["stripeStatus"], "past_due");
        assert_eq!(status["subscriptions"][0]["recognizedTestPrice"], false);
        assert_eq!(status["subscriptions"][0]["reconciliationPending"], true);
        for secret in [
            "cus_OwnerA",
            "sub_OwnerA",
            "cus_OwnerB",
            "sub_OwnerB",
            "price_Private",
            "active",
            &first.account_id.to_string(),
            &second.account_id.to_string(),
        ] {
            assert!(
                !text.contains(secret),
                "billing status exposed a provider identifier"
            );
        }
        let other = app
            .clone()
            .oneshot(get("/v1/billing/status", Some(&owner_b.token)))
            .await
            .unwrap();
        let other: Value =
            serde_json::from_slice(&to_bytes(other.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(other["subscriptions"][0]["stripeStatus"], "active");
        assert_eq!(other["pendingReconciliations"], 0);

        let page = app
            .clone()
            .oneshot(get("/billing", Some(&owner_a.token)))
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            page.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        let page = to_bytes(page.into_body(), 4096).await.unwrap();
        assert!(
            std::str::from_utf8(&page)
                .unwrap()
                .contains("/billing/dashboard.js")
        );
        let asset = app
            .clone()
            .oneshot(get("/billing/dashboard.js", None))
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );

        db.execute(
            "UPDATE sessions SET revoked_at=now() WHERE account_id=$1",
            &[&first.account_id],
        )
        .await
        .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(get("/billing", Some(&owner_a.token)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
