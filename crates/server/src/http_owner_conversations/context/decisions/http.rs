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
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::header,
    middleware,
    response::{IntoResponse, Response as HttpResponse},
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
    request: Request,
) -> Result<HttpResponse, ConversationError> {
    // Only this explicit JSON media profile enters the new raw-wire path.
    // Every other header goes through the original legacy extractor on the
    // untouched Request, including its reject-before-body MIME handling.
    let provider_media = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
    if !provider_media {
        let ApiJson(input) = match ApiJson::<Proposal>::from_request(request, &state).await {
            Ok(input) => input,
            Err(error) => return Ok(error.into_response()),
        };
        let mut client = connection(&state).await?;
        return Ok(Json(
            super::register(&mut client, &owner, input.request_id, input.descriptor).await?,
        )
        .into_response());
    }
    let (mut parts, body) = request.into_parts();
    let mut body_request = Request::new(body);
    // Move the router body-limit extension into the one actual body read.
    // ApiJson's later legacy decode sees only these already bounded bytes.
    *body_request.extensions_mut() = std::mem::take(&mut parts.extensions);
    let bytes = match Bytes::from_request(body_request, &state).await {
        Ok(bytes) => bytes,
        Err(error) => return Ok(error.into_response()),
    };
    // The exact raw provider parser is tried without normalizing or replacing
    // original bytes. Legacy01 still uses the original ApiJson<Proposal> path.
    if let Ok((request_id, descriptor)) = super::action_profile::ProviderAction::proposal(&bytes) {
        let mut client = connection(&state).await?;
        return Ok(Json(
            super::store::register_provider(&mut client, &owner, request_id, descriptor).await?,
        )
        .into_response());
    }
    let ApiJson(input) = match ApiJson::<Proposal>::from_request(
        Request::from_parts(parts, Body::from(bytes)),
        &state,
    )
    .await
    {
        Ok(input) => input,
        Err(error) => return Ok(error.into_response()),
    };
    let mut client = connection(&state).await?;
    Ok(
        Json(super::register(&mut client, &owner, input.request_id, input.descriptor).await?)
            .into_response(),
    )
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
