// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit default-off TEST budget preflight and cleanup. No HTTP request can
//! create an execution intent, supply rates, or settle an external effect.
use super::{Error, TestExposure};
use crate::{
    api_json::ApiJson,
    http_auth::preauth::OwnerMutation,
    http_owner_conversations::{OwnerConversationsState, context::decisions::ActionKey},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reserve {
    action: ActionKey,
    route_policy_id: Uuid,
    reservation_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    reservation_id: Uuid,
}

pub fn router(state: OwnerConversationsState, enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/owner/exposure/test/reserve", post(reserve))
        .route("/v1/owner/exposure/test/cancel", post(cancel))
        .route("/v1/owner/exposure/test/{id}", get(status))
        .layer(DefaultBodyLimit::max(2048))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = if request.headers().contains_key(header::AUTHORIZATION) {
        StatusCode::UNAUTHORIZED.into_response()
    } else if request.uri().query().is_some() {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"code":"invalid_request"})),
        )
            .into_response()
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}
fn refusal(error: Error) -> Response {
    let (status, code) = match error {
        Error::Conflict => (StatusCode::CONFLICT, "conflict"),
        Error::Policy(zrotext_delivery_store::exposure::ExposureError::Limit) => {
            (StatusCode::TOO_MANY_REQUESTS, "exposure_limit")
        }
        Error::Database(_)
        | Error::Authority(crate::http_owner_conversations::ConversationError::Database(_))
        | Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        _ => (StatusCode::FORBIDDEN, "refused"),
    };
    (status, Json(json!({"code":code}))).into_response()
}
async fn bounded<T>(
    operation: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(Duration::from_secs(10), operation)
        .await
        .map_err(|_| Error::Unavailable)?
}
async fn reserve(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(request): ApiJson<Reserve>,
) -> Response {
    let result = bounded(async {
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| Error::Unavailable)?;
        TestExposure::synthetic_candidate()
            .reserve(
                &mut db,
                &owner,
                request.action,
                request.route_policy_id,
                request.reservation_id,
            )
            .await
    })
    .await;
    match result {
        Ok(value) => Json(json!({
            "reservation_id":value.id,"maximum_units":value.maximum_units.to_string(),
            "soft_warning":value.created.then_some(value.soft_warning),"state":value.state,"created":value.created,
            "execution_authorized":false,
        }))
        .into_response(),
        Err(error) => refusal(error),
    }
}
async fn cancel(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(request): ApiJson<Cancel>,
) -> Response {
    let result = bounded(async {
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| Error::Unavailable)?;
        TestExposure::synthetic_candidate()
            .cancel_unstarted(&mut db, &owner, request.reservation_id)
            .await
    })
    .await;
    match result {
        Ok(changed) => Json(json!({"changed":changed})).into_response(),
        Err(error) => refusal(error),
    }
}
async fn status(
    State(state): State<Arc<OwnerConversationsState>>,
    headers: HeaderMap,
    Path(reservation): Path<Uuid>,
) -> Response {
    let result = bounded(async {
        let (mut db, owner) =
            crate::http_owner_conversations::context::http::reader(&state, &headers).await?;
        TestExposure::synthetic_candidate()
            .status(&mut db, &owner, reservation)
            .await
    })
    .await;
    match result {
        Ok(Some(value)) => Json(json!({
            "reservation_id":value.id,"maximum_units":value.maximum_units.to_string(),
            "actual_units":value.actual_units.map(|units|units.to_string()),
            "policy_version":value.policy_version.to_string(),"state":value.state,
            "intent_issued":value.intent_issued,"execution_authorized":false,
        }))
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"code":"not_found"}))).into_response(),
        Err(error) => refusal(error),
    }
}
