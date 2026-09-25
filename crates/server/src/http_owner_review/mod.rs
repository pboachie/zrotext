// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-only read view of active, ambiguous SMS withdrawal holds.
//! No SMS content, credentials, or review mutations are served here.

use crate::{auth::TokenHasher, http_auth::require_owner};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::SystemTime};
use uuid::Uuid;

const PAGE_SIZE: usize = 20;

#[derive(Clone)]
pub struct OwnerReviewState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerReviewState) -> Router {
    Router::new()
        .route("/v1/owner/opt-out-review", get(list_review_holds))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    /// An event UUID, rather than a recipient number, keeps phone numbers out
    /// of request URLs and access logs. The lookup is scoped to this account.
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct ReviewHold {
    recipient_e164: String,
    source: String,
    observed_at_ms: i64,
    changed_at_ms: i64,
}

#[derive(Serialize)]
struct ListResponse {
    holds: Vec<ReviewHold>,
    next_cursor: Option<Uuid>,
}

async fn list_review_holds(
    State(state): State<Arc<OwnerReviewState>>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok((client, connection)) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let before_point: Option<(SystemTime, String)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT changed_at,recipient_e164 FROM recipient_suppressions \
                 WHERE account_id=$1 AND active \
                 AND source IN ('sms_review','sms_unsolicited_review') \
                 AND COALESCE(source_event_id,source_unsolicited_event_id)=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), row.get(1))),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let before_at = before_point.as_ref().map(|point| point.0);
    let before_recipient = before_point.as_ref().map(|point| point.1.as_str());
    let rows = match client
        .query(
            "SELECT recipient_e164,source, \
             (extract(epoch FROM source_observed_at)*1000)::bigint, \
             (extract(epoch FROM changed_at)*1000)::bigint, \
             COALESCE(source_event_id,source_unsolicited_event_id) \
             FROM recipient_suppressions \
             WHERE account_id=$1 AND active \
             AND source IN ('sms_review','sms_unsolicited_review') \
             AND ($2::timestamptz IS NULL OR (changed_at,recipient_e164)<($2,$3::text)) \
             ORDER BY changed_at DESC,recipient_e164 DESC LIMIT 21",
            &[&account_id, &before_at, &before_recipient],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let has_more = rows.len() > PAGE_SIZE;
    let page: Vec<_> = rows.into_iter().take(PAGE_SIZE).collect();
    let next_cursor = if has_more {
        page.last().map(|row| row.get::<_, Uuid>(4))
    } else {
        None
    };
    let holds = page
        .into_iter()
        .map(|row| ReviewHold {
            recipient_e164: row.get(0),
            source: row.get(1),
            observed_at_ms: row.get(2),
            changed_at_ms: row.get(3),
        })
        .collect();
    Json(ListResponse { holds, next_cursor }).into_response()
}

#[cfg(test)]
mod tests;
