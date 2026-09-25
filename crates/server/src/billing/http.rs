// SPDX-License-Identifier: AGPL-3.0-only
//! Raw-body Stripe webhook ingress. Route is only mounted by explicit test mode.

use super::{BillingError, ingest, verify_event};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct BillingHttpState {
    pub database_url: String,
    pub endpoint_secret: String,
}

pub fn router(state: BillingHttpState) -> Router {
    Router::new()
        .route("/stripe-events", post(receive))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(state))
}

async fn receive(
    State(state): State<Arc<BillingHttpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let event = match verify_event(
        &body,
        signature,
        &state.endpoint_secret,
        now.as_secs() as i64,
    ) {
        Ok(event) => event,
        Err(BillingError::InvalidSignature | BillingError::InvalidEvent) => {
            return StatusCode::BAD_REQUEST;
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match ingest(&mut client, &event).await {
        Ok(_) => StatusCode::OK,
        Err(BillingError::EventConflict) => StatusCode::CONFLICT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::env;
    use tokio_postgres::NoTls;
    use tower::ServiceExt;
    use uuid::Uuid;

    const SECRET: &str = "whsec_testfixture1234567890";
    type HmacSha256 = Hmac<Sha256>;

    fn signed_header(timestamp: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let hex = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("t={timestamp},v1={hex}")
    }

    async fn post(app: Router, body: &[u8], signature: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/stripe-events")
                .header("stripe-signature", signature)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn correctly_signed_events_are_never_answered_with_client_errors() {
        let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let schema = format!("billing_http_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
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
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let app = router(BillingHttpState {
            database_url: scoped_url,
            endpoint_secret: SECRET.to_owned(),
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // A payment-mode Checkout completion has no subscription pointer. It
        // is acknowledged with 2xx and durably recorded as unsupported.
        let unsupported = br#"{"id":"evt_httpunsupported1","object":"event","livemode":false,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_http1","customer":"cus_http1","subscription":null}}}"#;
        assert_eq!(
            post(app.clone(), unsupported, &signed_header(now, unsupported)).await,
            StatusCode::OK
        );
        let disposition: String = db
            .query_one(
                "SELECT disposition FROM billing_events WHERE stripe_event_id='evt_httpunsupported1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(disposition, "unsupported");

        // A non-card py_ refund is a queued risk event, not a bad request.
        let refunded = br#"{"id":"evt_httprefund1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"py_httprefund1","object":"charge","customer":"cus_http1","amount_refunded":50}}}"#;
        assert_eq!(
            post(app.clone(), refunded, &signed_header(now, refunded)).await,
            StatusCode::OK
        );
        let risk: String = db
            .query_one(
                "SELECT stripe_charge_id FROM billing_risk_events WHERE stripe_event_id='evt_httprefund1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(risk, "py_httprefund1");
        let pi_refund = br#"{"id":"evt_httprefundpi1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_httprefundpi1","object":"refund","charge":null,"payment_intent":"pi_httprefundpi1"}}}"#;
        assert_eq!(
            post(app.clone(), pi_refund, &signed_header(now, pi_refund)).await,
            StatusCode::OK
        );
        let queued_pi: String = db
            .query_one(
                "SELECT stripe_payment_intent_id FROM billing_risk_events WHERE stripe_event_id='evt_httprefundpi1' AND state='queued'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(queued_pi, "pi_httprefundpi1");

        // A signed but unusable risk shape is a durable review task before
        // 2xx, rather than a silently ignored payment-risk event.
        let review = br#"{"id":"evt_httpreview1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"py_httpreview1","object":"charge","customer":"cus_http1","amount_refunded":0}}}"#;
        assert_eq!(
            post(app.clone(), review, &signed_header(now, review)).await,
            StatusCode::OK
        );
        let review_row = db
            .query_one(
                "SELECT e.disposition,r.state,e.stripe_customer_id FROM billing_events e JOIN billing_risk_events r USING(stripe_event_id) WHERE e.stripe_event_id='evt_httpreview1'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(review_row.get::<_, String>(0), "unsupported");
        assert_eq!(review_row.get::<_, String>(1), "needs_review");
        assert_eq!(
            review_row.get::<_, Option<String>>(2).as_deref(),
            Some("cus_http1")
        );
        assert_eq!(
            post(app.clone(), review, &signed_header(now, review)).await,
            StatusCode::OK
        );
        let review_count: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_risk_events WHERE stripe_event_id='evt_httpreview1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(review_count, 1);

        // Bad signatures and live-mode events remain client errors. This
        // signature covers other bytes than the delivered body.
        let mismatched = signed_header(now, unsupported);
        assert_eq!(
            post(app.clone(), refunded, &mismatched).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(app.clone(), refunded, "t=1750000000").await,
            StatusCode::BAD_REQUEST
        );
        let live = br#"{"id":"evt_httplive1","object":"event","livemode":true,"type":"charge.refunded","data":{"object":{"id":"py_httplive1","object":"charge","customer":"cus_http1","amount_refunded":50}}}"#;
        assert_eq!(
            post(app, live, &signed_header(now, live)).await,
            StatusCode::BAD_REQUEST
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
