// SPDX-License-Identifier: AGPL-3.0-only
//! Original-browser email verification. No verification response writes an auth,
//! CSRF, or intent cookie; another tab's newer sign-in/registration is preserved.

use super::{
    AuthHttpError, AuthHttpState, SESSION_COOKIE, connect, map_auth, no_store, require_origin,
};
use crate::{
    api_json::ApiJson,
    auth::{
        self, AuthError,
        abuse_limits::{self, Limit},
        registration_intent::{self as intent, Credentials},
    },
};
use axum::{
    extract::{FromRequestParts, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Checked before a body is read. No database connection survives body ingress.
pub(super) struct IntentMutation(Credentials);

fn unique_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, AuthHttpError> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header.to_str().map_err(|_| AuthHttpError::Forbidden)?;
        for part in header.split(';').map(str::trim) {
            if let Some((key, value)) = part.split_once('=')
                && key == name
            {
                if found.is_some() {
                    return Err(AuthHttpError::Forbidden);
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
}

fn header_proof(headers: &HeaderMap, origin: &str) -> Result<Credentials, AuthHttpError> {
    if headers.get_all(header::ORIGIN).iter().count() != 1 {
        return Err(AuthHttpError::Forbidden);
    }
    require_origin(headers, origin)?;
    let token = unique_cookie(headers, intent::INTENT_COOKIE)?.ok_or(AuthHttpError::Forbidden)?;
    let csrf = unique_cookie(headers, intent::CSRF_COOKIE)?.ok_or(AuthHttpError::Forbidden)?;
    if headers.get_all(intent::CSRF_HEADER).iter().count() != 1 {
        return Err(AuthHttpError::Forbidden);
    }
    let proof = headers
        .get(intent::CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    if !bool::from(csrf.as_bytes().ct_eq(proof.as_bytes())) {
        return Err(AuthHttpError::Forbidden);
    }
    let credentials = Credentials {
        token: Zeroizing::new(token.to_owned()),
        csrf: Zeroizing::new(csrf.to_owned()),
    };
    if !credentials.valid() {
        return Err(AuthHttpError::Forbidden);
    }
    Ok(credentials)
}

impl FromRequestParts<Arc<AuthHttpState>> for IntentMutation {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AuthHttpState>,
    ) -> Result<Self, Response> {
        header_proof(&parts.headers, &state.canonical_origin)
            .map(Self)
            .map_err(IntoResponse::into_response)
    }
}

pub(super) fn opaque_registration(credentials: &Credentials) -> Result<Response, AuthHttpError> {
    let mut response = StatusCode::ACCEPTED.into_response();
    for value in credentials.cookies() {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&value).map_err(|_| AuthHttpError::Internal)?,
        );
    }
    no_store(&mut response);
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyBody {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResendBody {}

async fn refuse_existing_session(
    client: &tokio_postgres::Client,
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(), AuthHttpError> {
    if let Some(token) = unique_cookie(headers, SESSION_COOKIE)? {
        match auth::authenticate_session(client, &state.hasher, token).await {
            Ok(_) => return Err(AuthHttpError::Conflict),
            Err(AuthError::InvalidCredentials | AuthError::Unauthorized) => {}
            Err(error) => return Err(map_auth(error)),
        }
    }
    Ok(())
}

pub(super) async fn verify(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    IntentMutation(credentials): IntentMutation,
    ApiJson(body): ApiJson<VerifyBody>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    refuse_existing_session(&client, &state, &headers).await?;
    let admitted = abuse_limits::consume(&client, &state.hasher, Limit::Verify, None)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    if !admitted
        && (!intent::live_code_for_budget(&client, &state.hasher, &credentials, &body.token)
            .await
            .map_err(map_auth)?
            || !abuse_limits::consume_verified(
                &client,
                &state.hasher,
                Limit::Verify,
                &credentials.token,
            )
            .await
            .map_err(|_| AuthHttpError::Unavailable)?)
    {
        return Err(AuthHttpError::TooManyRequests);
    }

    match intent::verify(&mut client, &state.hasher, &credentials, &body.token).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(AuthHttpError::BadRequest),
        Err(AuthError::Database(ref error))
            if error.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE) =>
        {
            Err(AuthHttpError::BadRequest)
        }
        Err(error) => Err(map_auth(error)),
    }
}

pub(super) async fn resend(
    State(state): State<Arc<AuthHttpState>>,
    IntentMutation(credentials): IntentMutation,
    ApiJson(_body): ApiJson<ResendBody>,
) -> Result<StatusCode, AuthHttpError> {
    if !state.dispatcher.ready() {
        return Ok(StatusCode::ACCEPTED);
    }
    let mut client = connect(&state.database_url).await?;
    let admitted = abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::Resend,
        Some(&credentials.token),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?;
    if admitted {
        // Do not turn row validity, contention or a declined mutation into an
        // account-existence signal. Delivery remains the durable outbox's job.
        let _ = intent::resend(&mut client, &state.hasher, &credentials).await;
    }
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests;
