// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant owner-only service. Main deliberately does not mount this router.
use super::super::{ConversationError, http::connection};
use super::{ActionKey, ActionState, Correlation, CorrelationResult, Descriptor, TakeoverResult};
use crate::{
    api_json::ApiJson, http_auth::preauth::OwnerMutation,
    http_owner_conversations::OwnerConversationsState,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware,
    routing::post,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/workflow/actions", post(propose))
        .route("/v1/owner/workflow/actions/status", post(status))
        .route("/v1/owner/workflow/actions/decide", post(decide))
        .route("/v1/owner/workflow/actions/edit", post(edit))
        .route("/v1/owner/workflow/actions/bind", post(bind))
        .route("/v1/owner/workflow/responses/correlate", post(correlate))
        .route("/v1/owner/workflow/takeover", post(takeover))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(super::super::super::no_store))
        .with_state(Arc::new(state))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    request_id: Uuid,
    descriptor: Descriptor,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    key: ActionKey,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Choice {
    Approve,
    Cancel,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    request_id: Uuid,
    expected_record_version: i64,
    key: ActionKey,
    decision: Choice,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    request_id: Uuid,
    expected_record_version: i64,
    previous: ActionKey,
    descriptor: Descriptor,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    request_id: Uuid,
    expected_record_version: i64,
    key: ActionKey,
    message: super::store::RenderedBinding,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    request_id: Uuid,
    correlation: Correlation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Takeover {
    request_id: Uuid,
    context_id: Uuid,
}

async fn propose(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Proposal>,
) -> Result<Json<ActionState>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(
        super::register(&mut client, &owner, input.request_id, input.descriptor).await?,
    ))
}
async fn status(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Status>,
) -> Result<Json<ActionState>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(super::read(&mut client, &owner, input.key).await?))
}
async fn decide(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Decision>,
) -> Result<Json<ActionState>, ConversationError> {
    let mut client = connection(&state).await?;
    let decision = match input.decision {
        Choice::Approve => super::model::Decision::Approve,
        Choice::Cancel => super::model::Decision::Cancel,
    };
    Ok(Json(
        super::decide(
            &mut client,
            &owner,
            input.request_id,
            input.expected_record_version,
            input.key,
            decision,
        )
        .await?,
    ))
}
async fn edit(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Edit>,
) -> Result<Json<ActionState>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(
        super::edit(
            &mut client,
            &owner,
            input.request_id,
            input.expected_record_version,
            input.previous,
            input.descriptor,
        )
        .await?,
    ))
}
async fn bind(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Binding>,
) -> Result<Json<ActionState>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(
        super::bind_message(
            &mut client,
            &owner,
            input.request_id,
            input.expected_record_version,
            input.key,
            input.message,
        )
        .await?,
    ))
}
async fn correlate(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Response>,
) -> Result<Json<CorrelationResult>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(
        super::correlate_reply(&mut client, &owner, input.request_id, input.correlation).await?,
    ))
}
async fn takeover(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Takeover>,
) -> Result<Json<TakeoverResult>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(
        super::takeover(&mut client, &owner, input.request_id, input.context_id).await?,
    ))
}
