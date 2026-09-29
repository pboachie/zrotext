// SPDX-License-Identifier: AGPL-3.0-only
//! HTTP surface for owner-managed observer seats: issue, list, cancel, and
//! remove for owners; single-use token acceptance for the invitee. The raw
//! invitation token appears exactly once, in the creation response.

use super::preauth::OwnerMutation;
use super::{
    AuthHttpError, AuthHttpState, connect, csrf_double_submit, map_auth, require_owner,
    require_session_cookie,
};
use crate::api_json::ApiJson;
use crate::auth::{
    AuthError,
    abuse_limits::{self, Limit},
    seats,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
pub(crate) struct CreateInvitationBody {
    email: String,
    /// Step-up proof, exactly as for API-key creation: an invitation grants a
    /// persistent read seat, so a session cookie alone cannot mint one.
    current_password: String,
    code: Option<String>,
}

#[derive(Serialize)]
struct CreatedInvitationBody {
    id: Uuid,
    email: String,
    expires_at_ms: i64,
    /// Secret: shown once, never stored server-side in the clear.
    token: String,
}

pub(crate) async fn create(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<CreateInvitationBody>,
) -> Result<Response, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    // Charge the account before the password is hashed, as API-key creation
    // does: re-issuing after cancel or removal must not reset the database
    // growth budget by signing in again, and every attempt, including a wrong
    // password, spends it, so it also bounds password guesses on this route.
    // A wrong authenticator code additionally spends the MFA step-up budget.
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::SeatInvite,
        Some(&owner.tenant.account_id().to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state.hash_permit().await?;
    let invitation = match seats::create_invitation_with_proof(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        &body.current_password,
        body.code.as_deref(),
        &body.email,
    )
    .await
    {
        Ok(invitation) => invitation,
        Err(AuthError::InvalidCredentials) => return Err(AuthHttpError::BadRequest),
        Err(error) => return Err(map_auth(error)),
    };
    let mut response = (
        StatusCode::CREATED,
        Json(CreatedInvitationBody {
            id: invitation.id,
            email: invitation.email,
            expires_at_ms: invitation.expires_at_ms,
            token: invitation.token,
        }),
    )
        .into_response();
    super::no_store(&mut response);
    Ok(response)
}

#[derive(Serialize)]
struct SeatBody {
    user_id: Uuid,
    email: String,
    email_verified: bool,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
    status: &'static str,
}

#[derive(Serialize)]
struct InvitationBody {
    id: Uuid,
    email: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    accepted_at_ms: Option<i64>,
    canceled_at_ms: Option<i64>,
    accepted_user_id: Option<Uuid>,
    status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct SeatsBody {
    seats: Vec<SeatBody>,
    invitations: Vec<InvitationBody>,
}

pub(crate) async fn list(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<SeatsBody>, AuthHttpError> {
    require_session_cookie(&headers)?;
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    // Seat metadata is account content: require the CSRF proof even though
    // this is a GET, exactly like the API-key inventory.
    let (csrf_cookie, csrf_header) = csrf_double_submit(&headers)?;
    owner
        .require_csrf_token(&state.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let page = seats::list_seats(&client, &owner).await.map_err(map_auth)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthHttpError::Internal)?
        .as_millis() as i64;
    Ok(Json(SeatsBody {
        seats: page
            .seats
            .into_iter()
            .map(|seat| {
                let status = if seat.revoked_at_ms.is_some() {
                    "removed"
                } else if seat.email_verified {
                    "active"
                } else {
                    "pending_verification"
                };
                SeatBody {
                    user_id: seat.user_id,
                    email: seat.email,
                    email_verified: seat.email_verified,
                    created_at_ms: seat.created_at_ms,
                    revoked_at_ms: seat.revoked_at_ms,
                    status,
                }
            })
            .collect(),
        invitations: page
            .invitations
            .into_iter()
            .map(|invitation| {
                let status = if invitation.accepted_at_ms.is_some() {
                    "accepted"
                } else if invitation.canceled_at_ms.is_some() {
                    "canceled"
                } else if invitation.expires_at_ms <= now_ms {
                    "expired"
                } else {
                    "open"
                };
                InvitationBody {
                    id: invitation.id,
                    email: invitation.email,
                    created_at_ms: invitation.created_at_ms,
                    expires_at_ms: invitation.expires_at_ms,
                    accepted_at_ms: invitation.accepted_at_ms,
                    canceled_at_ms: invitation.canceled_at_ms,
                    accepted_user_id: invitation.accepted_user_id,
                    status,
                }
            })
            .collect(),
    }))
}

pub(crate) async fn cancel(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(invitation_id): Path<Uuid>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    if seats::cancel_invitation(&mut client, &owner, invitation_id)
        .await
        .map_err(map_auth)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthHttpError::NotFound)
    }
}

pub(crate) async fn remove(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    if seats::remove_observer(&mut client, &owner, user_id)
        .await
        .map_err(map_auth)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthHttpError::NotFound)
    }
}

#[derive(Deserialize)]
pub(crate) struct AcceptBody {
    token: String,
    password: String,
}

pub(crate) async fn accept(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<AcceptBody>,
) -> Result<StatusCode, AuthHttpError> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        != Some(state.canonical_origin.as_str())
    {
        return Err(AuthHttpError::Forbidden);
    }
    let mut client = connect(&state.database_url).await?;
    let admitted = abuse_limits::consume_or_verify(
        &client,
        &state.hasher,
        Limit::SeatAccept,
        &body.token,
        seats::invitation_token_is_live(&client, &state.hasher, &body.token),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?;
    if !admitted {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state.hash_permit().await?;
    match seats::accept_invitation(&mut client, &state.hasher, &body.token, &body.password).await {
        Ok(_acceptance) => Ok(StatusCode::NO_CONTENT),
        // Unknown, expired, canceled, and replayed tokens share one response;
        // the address stays secret and the token stays useless.
        Err(AuthError::InvalidCredentials) => Err(AuthHttpError::BadRequest),
        Err(error) => Err(map_auth(error)),
    }
}
