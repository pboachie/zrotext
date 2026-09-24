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
    let Ok((mut client, connection)) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });
    match ingest(&mut client, &event).await {
        Ok(_) => StatusCode::OK,
        Err(BillingError::EventConflict) => StatusCode::CONFLICT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
