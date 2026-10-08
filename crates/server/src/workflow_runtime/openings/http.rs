// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-only create and mutation-authenticated metadata status. Startup keeps
//! the existing customer-routines gate; this router does not install the SQL candidate.
use crate::{
    api_json::ApiJson,
    http_auth::preauth::OwnerMutation,
    http_owner_conversations::{
        ConversationError, OwnerConversationsState, context::http::connection,
    },
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, Path, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;

mod wire;

const ACCOUNT_HEADER: &str = "x-zrotext-opening-account";

pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/workflow/openings", post(create))
        .route("/v1/owner/workflow/openings/{id}/status", post(status))
        .route("/v1/owner/workflow/openings/offers", post(offer))
        .route("/v1/owner/workflow/openings/reservations", post(reserve))
        .route("/v1/owner/workflow/openings/confirmations", post(confirm))
        .route("/v1/owner/workflow/openings/releases", post(release))
        .route("/v1/owner/workflow/openings/closures", post(close))
        .route("/v1/owner/workflow/openings/cancellations", post(cancel))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(owner_response))
        .with_state(Arc::new(state))
}

async fn owner_response(request: Request, next: Next) -> Response {
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

/// The header asserts independently intended account, never an alternative
/// principal or database selector. Retain the genuine account slot until return.
struct OpeningOwner(OwnerMutation);

impl FromRequestParts<Arc<OwnerConversationsState>> for OpeningOwner {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<OwnerConversationsState>,
    ) -> Result<Self, Response> {
        let owner = OwnerMutation::from_request_parts(parts, state).await?;
        let mut values = parts.headers.get_all(ACCOUNT_HEADER).iter();
        let intended = values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| wire::canonical_uuid(value).ok());
        if values.next().is_some() || intended != Some(owner.0.tenant.account_id()) {
            return Err(ConversationError::Forbidden.into_response());
        }
        if parts.uri.query().is_some() {
            return Err(ConversationError::Invalid.into_response());
        }
        Ok(Self(owner))
    }
}

async fn create(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::CreateInput>,
) -> Result<Json<wire::Created>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::create(&mut client, &owner, request).await?;
    Ok(Json(wire::created(
        account, request_id, opening_id, outcome,
    )?))
}

async fn status(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    Path(id): Path<String>,
    ApiJson(_input): ApiJson<wire::StatusInput>,
) -> Result<Json<wire::Status>, ConversationError> {
    let opening = wire::canonical_uuid(&id)?;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let receipt = super::status(&mut client, &owner, opening).await?;
    Ok(Json(wire::status(account, opening, receipt)?))
}

async fn offer(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::OfferInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::offer(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

async fn reserve(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::ReserveInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::reserve(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

async fn confirm(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::AllocationMutationInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::confirm(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

async fn release(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::AllocationMutationInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::release(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

async fn close(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::OpeningMutationInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::close(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

async fn cancel(
    State(state): State<Arc<OwnerConversationsState>>,
    OpeningOwner(OwnerMutation(owner, _slot)): OpeningOwner,
    ApiJson(input): ApiJson<wire::OpeningMutationInput>,
) -> Result<Json<wire::Mutated>, ConversationError> {
    let request = input.into_request()?;
    let request_id = request.request_id;
    let opening_id = request.opening.opening_id;
    let account = owner.tenant.account_id();
    let mut client = connection(&state).await?;
    let outcome = super::cancel(&mut client, &owner, request).await?;
    Ok(Json(wire::mutated(
        account, request_id, opening_id, outcome,
    )?))
}

#[cfg(test)]
mod tests;
