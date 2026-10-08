// SPDX-License-Identifier: AGPL-3.0-only
//! Default-off owner HTTP boundary; mounting does not enable grant issuance.
use crate::{
    api_json::ApiJson,
    auth::{AuthError, TokenHasher, mfa::MfaCipher},
    http_auth::{
        AuthHttpError,
        preauth::{OwnerAuthState, OwnerMutation},
    },
    http_owner_conversations::{ConversationError, OwnerConversationsState},
    managed_ai::{Error, ManagedGrants, OwnerCeremony},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use std::{sync::Arc, time::Duration};

mod requests;
use requests::{Create, GrantVersion, Narrow, Replace, Revoke, grant_id};

const BODY_LIMIT: usize = 16_384;
const DEADLINE: Duration = Duration::from_secs(10);

struct GrantHttpState {
    owner: OwnerConversationsState,
    cipher: Option<Arc<MfaCipher>>,
}
impl OwnerAuthState for GrantHttpState {
    fn database_url(&self) -> &str {
        &self.owner.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.owner.auth_hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.owner.canonical_origin
    }
}

/// Only mounts an owner boundary. Default ManagedGrants still refuses issuance.
pub fn router(
    owner: OwnerConversationsState,
    cipher: Option<Arc<MfaCipher>>,
    enabled: bool,
) -> Router {
    if !enabled {
        return Router::new();
    }
    routed(Arc::new(GrantHttpState { owner, cipher }), DEADLINE)
}

fn routed(state: Arc<GrantHttpState>, deadline: Duration) -> Router {
    Router::new()
        .route("/v1/owner/managed-ai/grants", post(create))
        .route("/v1/owner/managed-ai/grants/{id}/replace", post(replace))
        .route("/v1/owner/managed-ai/grants/{id}/narrow", post(narrow))
        .route("/v1/owner/managed-ai/grants/{id}/revoke", post(revoke))
        .method_not_allowed_fallback(|| async {
            failure(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(deadline, boundary))
        .with_state(state)
}

async fn boundary(State(deadline): State<Duration>, request: Request, next: Next) -> Response {
    let mut response = if request.headers().contains_key(header::AUTHORIZATION)
        || request.uri().query().is_some()
    {
        failure(StatusCode::FORBIDDEN, "refused")
    } else {
        match tokio::time::timeout(deadline, next.run(request)).await {
            Ok(response) => response,
            Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}

fn failure(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "code": code }))).into_response()
}

// The maintained mapper is private: preserve its public status variants locally.
fn authentication(error: AuthError) -> Response {
    let public = match error {
        AuthError::InvalidInput => AuthHttpError::BadRequest,
        AuthError::InvalidCredentials | AuthError::Unauthorized | AuthError::MfaRequired { .. } => {
            AuthHttpError::Unauthorized
        }
        AuthError::EmailNotVerified | AuthError::Forbidden => AuthHttpError::Forbidden,
        AuthError::Conflict => AuthHttpError::Conflict,
        AuthError::SmsOwnerKeyActive => AuthHttpError::SmsOwnerKeyActive,
        AuthError::Database(_) | AuthError::Crypto => AuthHttpError::Unavailable,
        AuthError::Password => AuthHttpError::Internal,
        AuthError::RateLimited => AuthHttpError::TooManyRequests,
    };
    public.into_response()
}

fn error(error: Error) -> Response {
    match error {
        Error::Authentication(auth) => authentication(auth),
        Error::Invalid | Error::Archive(ConversationError::Invalid) => {
            failure(StatusCode::BAD_REQUEST, "invalid_request")
        }
        Error::Conflict | Error::Archive(ConversationError::Conflict) => {
            failure(StatusCode::CONFLICT, "conflict")
        }
        Error::Forbidden | Error::Archive(ConversationError::Forbidden) => {
            failure(StatusCode::FORBIDDEN, "refused")
        }
        Error::NotFound | Error::Archive(ConversationError::NotFound) => {
            failure(StatusCode::NOT_FOUND, "not_found")
        }
        Error::Unavailable
        | Error::Database(_)
        | Error::Archive(ConversationError::Unavailable | ConversationError::Database(_)) => {
            failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

async fn create(
    State(s): State<Arc<GrantHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<Create>,
) -> Response {
    let Some(cipher) = s.cipher.as_deref() else {
        return error(Error::Unavailable);
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return error(Error::Unavailable);
    };
    let ceremony = OwnerCeremony {
        owner: &owner,
        hasher: &s.owner.auth_hasher,
        cipher,
        password: &body.password.0,
        factor: &body.factor.0,
    };
    match ManagedGrants::default()
        .create(&mut db, &ceremony, &body.request)
        .await
    {
        Ok(grant_id) => (
            StatusCode::CREATED,
            Json(GrantVersion {
                grant_id,
                current_version: 1,
            }),
        )
            .into_response(),
        Err(e) => error(e),
    }
}

async fn replace(
    State(s): State<Arc<GrantHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Replace>,
) -> Response {
    let Ok(id) = grant_id(&id) else {
        return error(Error::Invalid);
    };
    let Some(cipher) = s.cipher.as_deref() else {
        return error(Error::Unavailable);
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return error(Error::Unavailable);
    };
    let ceremony = OwnerCeremony {
        owner: &owner,
        hasher: &s.owner.auth_hasher,
        cipher,
        password: &body.password.0,
        factor: &body.factor.0,
    };
    match ManagedGrants::default()
        .replace(
            &mut db,
            &ceremony,
            id,
            body.expected_version.0,
            &body.request,
        )
        .await
    {
        Ok(()) => Json(GrantVersion {
            grant_id: id,
            current_version: body.expected_version.0 + 1,
        })
        .into_response(),
        Err(e) => error(e),
    }
}

async fn narrow(
    State(s): State<Arc<GrantHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Narrow>,
) -> Response {
    let Ok(id) = grant_id(&id) else {
        return error(Error::Invalid);
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return error(Error::Unavailable);
    };
    match ManagedGrants::default()
        .narrow(&mut db, &owner, id, body.expected_version.0, &body.request)
        .await
    {
        Ok(current_version) => Json(GrantVersion {
            grant_id: id,
            current_version,
        })
        .into_response(),
        Err(e) => error(e),
    }
}

async fn revoke(
    State(s): State<Arc<GrantHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<Revoke>,
) -> Response {
    let Ok(id) = grant_id(&id) else {
        return error(Error::Invalid);
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return error(Error::Unavailable);
    };
    match ManagedGrants::default().revoke(&mut db, &owner, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error(e),
    }
}

#[cfg(test)]
mod tests;
