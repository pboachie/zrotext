// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted owner-only public contact record observation. No issuance or effects.
//! Owner/session checks are point-in-time; returned records are not a lease.

use crate::{
    auth::{self, SessionPrincipal, TokenHasher},
    http_auth::{
        AuthHttpError, preauth::AccountSlot, require_owner_read, require_owner_read_headers,
    },
    sealed_manifest::AccountArchiveStatementRecords,
    sealed_manifest_store::{
        AdmissionError,
        outbound::{PublicCandidate, lock_current},
    },
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;

const PATH: &str = "/v1/owner/contact-reader-observation";
const READER_HEADER: &str = "x-zrotext-contact-reader";
const ROOT_HEADER: &str = "x-zrotext-root-fingerprint";
const OUTWARD_LIMIT: Duration = Duration::from_secs(10);
const BODY_LIMIT: Duration = Duration::from_secs(1);
const MAX_RESPONSE: usize = 20 * 1024;
const MAX_MANIFEST: usize = 11_223;

/// State for an isolated library router. The ordinary server does not mount it.
pub struct OwnerContactObservationState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
}

pub fn router(state: OwnerContactObservationState) -> Router {
    Router::new()
        .route(
            PATH,
            get(observe).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

struct Selection {
    reader: [u8; 32],
    fingerprint: [u8; 32],
}

fn selected(headers: &HeaderMap, name: &'static str) -> Result<[u8; 32], AuthHttpError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(AuthHttpError::BadRequest)?;
    if values.next().is_some() || value.as_bytes().len() != 44 {
        return Err(AuthHttpError::BadRequest);
    }
    let text = value.to_str().map_err(|_| AuthHttpError::BadRequest)?;
    let bytes: [u8; 32] = STANDARD
        .decode(text)
        .map_err(|_| AuthHttpError::BadRequest)?
        .try_into()
        .map_err(|_| AuthHttpError::BadRequest)?;
    if bytes == [0; 32] || STANDARD.encode(bytes) != text {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(bytes)
}

fn ingress(headers: &HeaderMap, query: Option<&str>) -> Result<Selection, AuthHttpError> {
    require_owner_read_headers(headers)?;
    if query.is_some()
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err(AuthHttpError::BadRequest);
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next()
        && (length.as_bytes() != b"0" || lengths.next().is_some())
    {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(Selection {
        reader: selected(headers, READER_HEADER)?,
        fingerprint: selected(headers, ROOT_HEADER)?,
    })
}

async fn empty_body(body: Body) -> Result<(), AuthHttpError> {
    timeout(BODY_LIMIT, to_bytes(body, 0))
        .await
        .map_err(|_| AuthHttpError::BadRequest)?
        .map_err(|_| AuthHttpError::BadRequest)?;
    Ok(())
}

async fn observe(
    State(state): State<Arc<OwnerContactObservationState>>,
    request: Request,
) -> Response {
    let deadline = Instant::now() + OUTWARD_LIMIT;
    bounded_response(deadline, request_response(&state, request, deadline)).await
}

async fn bounded_response(
    deadline: Instant,
    operation: impl Future<Output = Result<Response, AuthHttpError>>,
) -> Response {
    match timeout_at(deadline, operation).await {
        Ok(Ok(response)) if Instant::now() < deadline => response,
        Ok(Err(error)) => error.into_response(),
        _ => AuthHttpError::Unavailable.into_response(),
    }
}

async fn request_response(
    state: &OwnerContactObservationState,
    request: Request,
    deadline: Instant,
) -> Result<Response, AuthHttpError> {
    let (parts, body) = request.into_parts();
    let selection = ingress(&parts.headers, parts.uri.query())?;
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let owner = require_owner_read(&client, &state.auth_hasher, &parts.headers).await?;
    // Request-only cap: fallback pool cleanup can outlive this named guard.
    let _account_slot =
        AccountSlot::try_acquire(owner.tenant.account_id()).ok_or(AuthHttpError::Busy)?;
    empty_body(body).await?;
    let bytes = store(&mut client, &owner, &selection).await?;
    if Instant::now() >= deadline {
        return Err(AuthHttpError::Unavailable);
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

fn authority_error(error: AdmissionError) -> AuthHttpError {
    match error {
        AdmissionError::Database(_) => AuthHttpError::Unavailable,
        AdmissionError::Rejected(_) => AuthHttpError::Forbidden,
    }
}

fn owner_error(error: auth::AuthError) -> AuthHttpError {
    match error {
        auth::AuthError::Database(_) => AuthHttpError::Unavailable,
        _ => AuthHttpError::Unauthorized,
    }
}

async fn store(
    client: &mut Client,
    owner: &SessionPrincipal,
    selection: &Selection,
) -> Result<Vec<u8>, AuthHttpError> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let result = project(&tx, owner, selection).await;
    match result {
        Ok(bytes) => {
            tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
            Ok(bytes)
        }
        Err(error) => {
            // Only Ok acknowledges rollback; cancellation/error uses maintained
            // asynchronous Transaction/PooledClient Drop, with no settlement claim.
            tx.rollback()
                .await
                .map_err(|_| AuthHttpError::Unavailable)?;
            Err(error)
        }
    }
}

async fn project(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    selection: &Selection,
) -> Result<Vec<u8>, AuthHttpError> {
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let account = owner.tenant.account_id();
    let mut authority = lock_current(tx, account).await.map_err(authority_error)?;
    auth::require_current_owner(tx, owner)
        .await
        .map_err(owner_error)?;
    let (candidate, records) = authority
        .account_contact_observation(&selection.reader, &selection.fingerprint)
        .await
        .map_err(authority_error)?;
    // Bound/copy before the final actual current-record and owner checks.
    encode(&view(account, &selection.reader, candidate, records)?)?;
    let (candidate, records) = authority
        .account_contact_observation(&selection.reader, &selection.fingerprint)
        .await
        .map_err(authority_error)?;
    let bytes = encode(&view(account, &selection.reader, candidate, records)?)?;
    auth::require_current_owner(tx, owner)
        .await
        .map_err(owner_error)?;
    Ok(bytes)
}

#[derive(Serialize)]
struct KeyView {
    key_id_b64: String,
    public_point_b64: String,
    from_ms: String,
    until_ms: String,
}

#[derive(Serialize)]
struct ObservationView {
    account_id: Uuid,
    root_pin_b64: String,
    root_fingerprint_b64: String,
    trust_generation: &'static str,
    manifest_version: String,
    manifest_digest_b64: String,
    manifest_b64: String,
    observed_ms: String,
    manifest_issued_ms: String,
    manifest_expires_ms: String,
    signed_until_ms: String,
    reader: KeyView,
    root_writer: KeyView,
}

fn positive(value: u64) -> Result<String, AuthHttpError> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(AuthHttpError::Forbidden);
    }
    Ok(value.to_string())
}

fn view(
    account: Uuid,
    reader: &[u8; 32],
    candidate: PublicCandidate,
    records: AccountArchiveStatementRecords,
) -> Result<ObservationView, AuthHttpError> {
    let s = candidate.snapshot;
    if records.account != *account.as_bytes()
        || records.generation != 1
        || s.generation != 1
        || s.version <= 0
        || s.version as u64 != records.version
        || s.digest != records.digest
        || s.accepted_ms <= 0
        || candidate.pin.len() != 94
        || s.bytes.len() > MAX_MANIFEST
    {
        return Err(AuthHttpError::Forbidden);
    }
    let until = records
        .expires
        .min(records.reader_until)
        .min(records.root_until);
    let now = s.accepted_ms as u64;
    if now >= until || now < records.reader_from || now < records.root_from {
        return Err(AuthHttpError::Forbidden);
    }
    Ok(ObservationView {
        account_id: account,
        root_pin_b64: STANDARD.encode(candidate.pin),
        root_fingerprint_b64: STANDARD.encode(candidate.fingerprint),
        trust_generation: "1",
        manifest_version: positive(records.version)?,
        manifest_digest_b64: STANDARD.encode(s.digest),
        manifest_b64: STANDARD.encode(s.bytes),
        observed_ms: positive(now)?,
        manifest_issued_ms: positive(records.issued)?,
        manifest_expires_ms: positive(records.expires)?,
        signed_until_ms: positive(until)?,
        reader: KeyView {
            key_id_b64: STANDARD.encode(reader),
            public_point_b64: STANDARD.encode(records.reader_point),
            from_ms: records.reader_from.to_string(),
            until_ms: positive(records.reader_until)?,
        },
        root_writer: KeyView {
            key_id_b64: STANDARD.encode(records.root_id),
            public_point_b64: STANDARD.encode(records.root_point),
            from_ms: records.root_from.to_string(),
            until_ms: positive(records.root_until)?,
        },
    })
}

fn encode(view: &ObservationView) -> Result<Vec<u8>, AuthHttpError> {
    let bytes = serde_json::to_vec(view).map_err(|_| AuthHttpError::Internal)?;
    if bytes.len() > MAX_RESPONSE {
        return Err(AuthHttpError::Unavailable);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
