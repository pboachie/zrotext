// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only device status for observer seats. The single route serves the
//! same account-scoped status page the owner dashboard reads, to any live
//! membership role; it performs no device management and returns no message
//! content, recipients, or credentials.

use crate::auth::TokenHasher;
use crate::enrollment;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub struct ObserverState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
}

pub fn router(state: ObserverState) -> Router {
    Router::new()
        .route("/devices", get(devices))
        .with_state(Arc::new(state))
}

async fn connect(database_url: &str) -> Result<crate::runtime_db::PooledClient, StatusCode> {
    crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[derive(Serialize)]
struct ObserverDeviceBody {
    device_id: Uuid,
    display_name: String,
    revoked: bool,
    active_socket_lease: bool,
    pending_messages: i64,
    in_flight_messages: i64,
    status_observed_at_ms: i64,
    reported_preconditions: Option<enrollment::ReportedPreconditions>,
}

#[derive(Deserialize)]
struct DevicesQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct DevicesBody {
    devices: Vec<ObserverDeviceBody>,
    next_cursor: Option<Uuid>,
}

async fn devices(
    State(state): State<Arc<ObserverState>>,
    Query(query): Query<DevicesQuery>,
    headers: HeaderMap,
) -> Response {
    // The same header precheck as owner content reads: no cookie is a 401 and
    // a missing CSRF proof is a 403 before any pooled connection is taken.
    if let Err(error) = crate::http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let Ok(client) = connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal =
        match crate::http_auth::require_member_read(&client, &state.auth_hasher, &headers).await {
            Ok(principal) => principal,
            Err(error) => return error.into_response(),
        };
    match enrollment::list_account_devices(&client, &principal, query.before).await {
        Ok(page) => {
            let mut response = Json(DevicesBody {
                devices: page
                    .devices
                    .into_iter()
                    .map(|device| ObserverDeviceBody {
                        device_id: device.id,
                        display_name: device.display_name,
                        revoked: device.revoked,
                        active_socket_lease: device.active_socket_lease,
                        pending_messages: device.pending_messages,
                        in_flight_messages: device.in_flight_messages,
                        status_observed_at_ms: device.status_observed_at_ms,
                        reported_preconditions: device.reported_preconditions,
                    })
                    .collect(),
                next_cursor: page.next_cursor,
            })
            .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn observer_routes_reject_cookieless_reads_without_database_work() {
        let state = ObserverState {
            database_url: "postgres://observer-unreachable".into(),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(41)).unwrap()),
        };
        let response = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
