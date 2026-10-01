// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded metadata snapshots. Counts are writer evidence, never delivery proof.
use crate::{
    auth::{self, Scope},
    http_owner_messages::OwnerMessagesState,
};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) const COUNT_BOUND: i64 = 1_000;
const MAX_AGE_MS: i64 = 30_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryQuery {
    device_id: Option<Uuid>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Count {
    value: i64,
    capped: bool,
}
impl Count {
    fn from_probe(value: i64) -> Self {
        Self {
            value: value.min(COUNT_BOUND),
            capped: value > COUNT_BOUND,
        }
    }
}

#[derive(Serialize)]
struct Summary {
    scope: &'static str,
    device_id: Option<Uuid>,
    timezone: &'static str,
    day_start_ms: i64,
    day_end_ms: i64,
    observed_at_ms: i64,
    max_age_ms: i64,
    count_bound: i64,
    submitted_today: Count,
    pending: Count,
    in_flight: Count,
}

pub fn router(state: OwnerMessagesState) -> Router {
    Router::new()
        .route("/v1/owner/message-summary", get(owner_summary))
        .route("/v1/message-summary", get(device_summary))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn owner_summary(
    State(state): State<Arc<OwnerMessagesState>>,
    Query(query): Query<SummaryQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = crate::http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal =
        match crate::http_auth::require_owner_read(&client, &state.auth_hasher, &headers).await {
            Ok(principal) => principal,
            Err(error) => return error.into_response(),
        };
    respond(&client, principal.tenant.account_id(), query.device_id).await
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values.next()?.to_str().ok()?.strip_prefix("Bearer ")?;
    (values.next().is_none() && !token.is_empty() && !token.contains(' ')).then_some(token)
}

/// Existing messages:read keys can read only the explicitly selected device;
/// a device-bound key cannot request an account total or another device.
async fn device_summary(
    State(state): State<Arc<OwnerMessagesState>>,
    Query(query): Query<SummaryQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(device) = query.device_id else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match auth::authenticate_api_key(&client, &state.auth_hasher, token).await {
        Ok(principal) => principal,
        Err(auth::AuthError::Database(_)) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if principal
        .require(Scope::MessagesRead, Some(device))
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    respond(&client, principal.tenant.account_id(), Some(device)).await
}

async fn respond(client: &Client, account: Uuid, device: Option<Uuid>) -> Response {
    if let Some(device) = device {
        match client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE account_id=$1 AND id=$2)",
                &[&account, &device],
            )
            .await
        {
            Ok(row) if row.get::<_, bool>(0) => {}
            Ok(_) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    match client
        .query_one(
            "SELECT message_summary_metadata_ready(current_schema())",
            &[],
        )
        .await
    {
        Ok(row) if row.get::<_, bool>(0) => {}
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    match read_summary(client, account, device).await {
        Ok(summary) => Json(summary).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn summary_sql(device: bool) -> String {
    let selected = if device { "AND m.device_id=$2" } else { "" };
    format!(
        "WITH clock AS MATERIALIZED (SELECT statement_timestamp() AS observed,$2::uuid AS device), \
        snapshot AS MATERIALIZED (SELECT observed, \
          date_trunc('day',observed AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS day_start FROM clock) \
        SELECT floor(extract(epoch FROM observed)*1000)::bigint, \
          floor(extract(epoch FROM day_start)*1000)::bigint, \
          floor(extract(epoch FROM day_start+interval '24 hours')*1000)::bigint, \
          (SELECT count(*) FROM (SELECT 1 FROM message_submission_receipts m \
            WHERE m.account_id=$1 {selected} AND m.first_submitted_at>=snapshot.day_start \
              AND m.first_submitted_at<snapshot.day_start+interval '24 hours' \
            ORDER BY m.first_submitted_at LIMIT $3) submitted), \
          (SELECT count(*) FROM (SELECT 1 FROM messages m WHERE m.account_id=$1 {selected} \
            AND m.state IN ('accepted','queued','claimed') ORDER BY m.state,m.created_at LIMIT $3) pending), \
          (SELECT count(*) FROM (SELECT 1 FROM messages m WHERE m.account_id=$1 {selected} \
            AND m.state IN ('submitting','submitted') ORDER BY m.state,m.created_at LIMIT $3) in_flight) \
        FROM snapshot"
    )
}

async fn read_summary(
    client: &Client,
    account: Uuid,
    device: Option<Uuid>,
) -> Result<Summary, tokio_postgres::Error> {
    let row = client
        .query_one(
            &summary_sql(device.is_some()),
            &[&account, &device, &(COUNT_BOUND + 1)],
        )
        .await?;
    Ok(Summary {
        scope: if device.is_some() {
            "device"
        } else {
            "account"
        },
        device_id: device,
        timezone: "UTC",
        observed_at_ms: row.get(0),
        day_start_ms: row.get(1),
        day_end_ms: row.get(2),
        max_age_ms: MAX_AGE_MS,
        count_bound: COUNT_BOUND,
        submitted_today: Count::from_probe(row.get(3)),
        pending: Count::from_probe(row.get(4)),
        in_flight: Count::from_probe(row.get(5)),
    })
}

#[cfg(test)]
mod tests;
