// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate owner router. Main does not mount these routes.
use super::*;
use crate::{
    api_json::ApiJson,
    auth::TokenHasher,
    http_auth::{
        self,
        preauth::{OwnerAuthState, OwnerMutation},
    },
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct StateConfig {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}
impl OwnerAuthState for StateConfig {
    fn database_url(&self) -> &str {
        &self.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.auth_hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }
    fn unavailable_response(&self) -> Response {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}
pub fn router(state: StateConfig) -> Router {
    Router::new()
        .route(
            "/v1/owner/provider-configurations",
            post(create_route).get(list_route),
        )
        .route("/v1/owner/provider-configurations/{id}", get(read_route))
        .route(
            "/v1/owner/provider-configurations/{id}/revise",
            post(revise_route),
        )
        .route(
            "/v1/owner/provider-configurations/{id}/withdraw",
            post(withdraw_route),
        )
        .layer(DefaultBodyLimit::max(model::BODY))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = if request.headers().contains_key(header::AUTHORIZATION) {
        StatusCode::UNAUTHORIZED.into_response()
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
async fn connection(state: &StateConfig) -> Result<crate::runtime_db::PooledClient> {
    crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)
}
async fn read_owner(
    state: &StateConfig,
    headers: &HeaderMap,
) -> std::result::Result<
    (
        crate::runtime_db::PooledClient,
        crate::auth::SessionPrincipal,
    ),
    Response,
> {
    http_auth::require_owner_read_headers(headers).map_err(IntoResponse::into_response)?;
    let client = connection(state)
        .await
        .map_err(IntoResponse::into_response)?;
    let owner = http_auth::require_owner_read(&client, &state.auth_hasher, headers)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((client, owner))
}
async fn create_route(
    State(state): State<Arc<StateConfig>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Mutation>,
) -> Result<Json<Acknowledgment>> {
    let mut client = connection(&state).await?;
    Ok(Json(create(&mut client, &owner, input).await?))
}
async fn revise_route(
    State(state): State<Arc<StateConfig>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Mutation>,
) -> Result<Json<Acknowledgment>> {
    model::identity(&id)?;
    if id != input.config_id {
        return Err(ConversationError::Invalid);
    }
    let mut client = connection(&state).await?;
    Ok(Json(revise(&mut client, &owner, input).await?))
}
async fn withdraw_route(
    State(state): State<Arc<StateConfig>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Withdrawal>,
) -> Result<Json<Acknowledgment>> {
    model::identity(&id)?;
    if id != input.config_id {
        return Err(ConversationError::Invalid);
    }
    let mut client = connection(&state).await?;
    Ok(Json(withdraw(&mut client, &owner, input).await?))
}
async fn read_route(
    State(state): State<Arc<StateConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let config = match model::identity(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let (mut client, owner) = match read_owner(&state, &headers).await {
        Ok(value) => value,
        Err(e) => return e,
    };
    match read(&mut client, &owner, config).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => e.into_response(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    after: Option<String>,
}
async fn list_route(
    State(state): State<Arc<StateConfig>>,
    Query(query): Query<List>,
    headers: HeaderMap,
) -> Response {
    let after = match query.after.as_deref().map(model::identity).transpose() {
        Ok(value) => value,
        Err(e) => return e.into_response(),
    };
    let (mut client, owner) = match read_owner(&state, &headers).await {
        Ok(value) => value,
        Err(e) => return e,
    };
    match lifecycle::heads(&mut client, &owner, after, false).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => e.into_response(),
    }
}
