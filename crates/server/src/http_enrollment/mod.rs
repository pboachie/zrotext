// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded HTTP transport for one-use device enrollment.
//!
//! The challenge proof acknowledges a device key. It does not issue a socket
//! credential or authenticate the M0 heartbeat socket.

use crate::{
    auth::{
        TokenHasher,
        abuse_limits::{self, Limit},
    },
    enrollment::{self, DeviceChallenge, EnrollmentError, EnrollmentHasher},
    http_auth::require_owner,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc};
use tokio_postgres::Client;
use uuid::Uuid;

const MAX_BODY_BYTES: usize = 4096;

pub struct EnrollmentHttpState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub enrollment_hasher: Arc<EnrollmentHasher>,
    pub canonical_origin: String,
}

impl EnrollmentHttpState {
    pub fn new(
        database_url: String,
        auth_hasher: Arc<TokenHasher>,
        enrollment_hasher: Arc<EnrollmentHasher>,
        canonical_origin: String,
    ) -> Self {
        Self {
            database_url,
            auth_hasher,
            enrollment_hasher,
            canonical_origin,
        }
    }
}

/// Mount at `/v1/enrollment`. Public routes only accept one-use challenge
/// material in bounded POST bodies; owner mutations additionally require the
/// session cookie, exact Origin and CSRF double submit proof.
pub fn router(state: EnrollmentHttpState) -> Router {
    Router::new()
        .route("/pairings", post(create_pairing))
        .route("/pairings/{pairing_id}", get(view_pairing))
        .route("/pairings/{pairing_id}/claim", post(claim_pairing))
        .route("/pairings/{pairing_id}/prove", post(prove_pairing))
        .route("/pairings/{pairing_id}/approve", post(approve_pairing))
        .route("/pairings/{pairing_id}/cancel", post(cancel_pairing))
        .route("/devices/{device_id}/challenge", post(device_challenge))
        .route("/devices/authenticate", post(device_authenticate))
        .route("/devices", get(list_devices))
        .route("/devices/{device_id}", delete(revoke_device))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn connect(state: &EnrollmentHttpState) -> Result<Client, Response> {
    let (client, connection) = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// `live` runs only after anonymous callers exhaust the route budget, so junk
/// identifiers cannot lock out a phone that holds a real device or pairing.
async fn public_admission(
    state: &EnrollmentHttpState,
    client: &Client,
    limit: Limit,
    subject: &str,
    live: impl Future<Output = Result<bool, EnrollmentError>>,
) -> Result<(), Response> {
    match abuse_limits::consume_or_verify(client, &state.auth_hasher, limit, subject, live).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(StatusCode::TOO_MANY_REQUESTS.into_response()),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
    }
}

fn owner_error(error: EnrollmentError) -> Response {
    match error {
        EnrollmentError::InvalidInput => StatusCode::BAD_REQUEST,
        EnrollmentError::Unavailable => StatusCode::NOT_FOUND,
        EnrollmentError::Unauthorized => StatusCode::UNAUTHORIZED,
        EnrollmentError::DeviceLimitReached => StatusCode::CONFLICT,
        EnrollmentError::AuthorityUnavailable | EnrollmentError::Database(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
    .into_response()
}

fn public_error(error: EnrollmentError) -> Response {
    match error {
        EnrollmentError::InvalidInput => StatusCode::BAD_REQUEST,
        EnrollmentError::AuthorityUnavailable | EnrollmentError::Database(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        EnrollmentError::Unavailable
        | EnrollmentError::Unauthorized
        | EnrollmentError::DeviceLimitReached => StatusCode::NOT_FOUND,
    }
    .into_response()
}

fn decode_bounded(
    value: &str,
    max_encoded: usize,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, StatusCode> {
    if value.len() > max_encoded || value.contains('=') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !(min_bytes..=max_bytes).contains(&decoded.len()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(decoded)
}

fn decode_nonce(value: &str) -> Result<[u8; 32], StatusCode> {
    decode_bounded(value, 43, 32, 32)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePairingBody {
    display_name: String,
}

#[derive(Serialize)]
struct CreatePairingResponse {
    pairing_id: Uuid,
    token: String,
}

async fn create_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    headers: HeaderMap,
    Json(body): Json<CreatePairingBody>,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    match enrollment::create_pairing(
        &client,
        &state.enrollment_hasher,
        &principal,
        &body.display_name,
    )
    .await
    {
        Ok(ticket) => (
            StatusCode::CREATED,
            Json(CreatePairingResponse {
                pairing_id: ticket.id,
                token: ticket.token,
            }),
        )
            .into_response(),
        Err(error) => owner_error(error),
    }
}

#[derive(Serialize)]
struct PairingViewResponse {
    claimed: bool,
    proof_verified: bool,
    approved_device_id: Option<Uuid>,
    comparison_code: Option<String>,
    key_fingerprint: Option<String>,
}

async fn view_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(pairing_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
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
    match enrollment::pairing_view(&client, &principal, pairing_id).await {
        Ok(Some(view)) => Json(PairingViewResponse {
            claimed: view.claimed,
            proof_verified: view.proof_verified,
            approved_device_id: view.approved_device_id,
            comparison_code: view.comparison_code,
            key_fingerprint: view.key_fingerprint,
        })
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => owner_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    token: String,
    public_key_spki: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    pairing_id: Uuid,
    account_id: Uuid,
    challenge_nonce: String,
    comparison_code: String,
    key_fingerprint: String,
}

async fn claim_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(pairing_id): Path<Uuid>,
    Json(body): Json<ClaimBody>,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(response) = public_admission(
        &state,
        &client,
        Limit::PairClaim,
        &pairing_id.to_string(),
        enrollment::pairing_claim_is_live(
            &client,
            &state.enrollment_hasher,
            pairing_id,
            &body.token,
        ),
    )
    .await
    {
        return response;
    }
    if body.token.len() != 47 {
        return StatusCode::NOT_FOUND.into_response();
    }
    let public_key = match decode_bounded(&body.public_key_spki, 214, 80, 160) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    match enrollment::claim_pairing(
        &mut client,
        &state.enrollment_hasher,
        pairing_id,
        &body.token,
        &public_key,
    )
    .await
    {
        Ok(claim) => Json(ClaimResponse {
            pairing_id: claim.id,
            account_id: claim.account_id,
            challenge_nonce: URL_SAFE_NO_PAD.encode(claim.challenge_nonce),
            comparison_code: claim.comparison_code,
            key_fingerprint: claim.key_fingerprint,
        })
        .into_response(),
        Err(error) => public_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveBody {
    challenge_nonce: String,
    signature_der: String,
}

#[derive(Serialize)]
struct ProveResponse {
    proof_verified: bool,
}

async fn prove_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(pairing_id): Path<Uuid>,
    Json(body): Json<ProveBody>,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let live = async {
        match decode_nonce(&body.challenge_nonce) {
            Ok(nonce) => {
                enrollment::pairing_proof_is_live(
                    &client,
                    &state.enrollment_hasher,
                    pairing_id,
                    &nonce,
                )
                .await
            }
            Err(_) => Ok(false),
        }
    };
    if let Err(response) = public_admission(
        &state,
        &client,
        Limit::PairProof,
        &pairing_id.to_string(),
        live,
    )
    .await
    {
        return response;
    }
    let nonce = match decode_nonce(&body.challenge_nonce) {
        Ok(nonce) => nonce,
        Err(status) => return status.into_response(),
    };
    let signature = match decode_bounded(&body.signature_der, 107, 8, 80) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    match enrollment::prove_pairing_key(
        &mut client,
        &state.enrollment_hasher,
        pairing_id,
        &nonce,
        &signature,
    )
    .await
    {
        Ok(proof_verified) => Json(ProveResponse { proof_verified }).into_response(),
        Err(error) => public_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    comparison_code: String,
    key_fingerprint: String,
}

#[derive(Serialize)]
struct ApprovedResponse {
    device_id: Uuid,
}

async fn approve_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(pairing_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ApproveBody>,
) -> Response {
    if body.comparison_code.len() > 8 || body.key_fingerprint.len() > 64 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(mut client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    match enrollment::approve_pairing(
        &mut client,
        &principal,
        pairing_id,
        &body.comparison_code,
        &body.key_fingerprint,
    )
    .await
    {
        Ok(device_id) => {
            (StatusCode::CREATED, Json(ApprovedResponse { device_id })).into_response()
        }
        Err(error) => owner_error(error),
    }
}

async fn cancel_pairing(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(pairing_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    match enrollment::cancel_pairing(&client, &principal, pairing_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => owner_error(error),
    }
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge_id: Uuid,
    account_id: Uuid,
    device_id: Uuid,
    nonce: String,
}

async fn device_challenge(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(device_id): Path<Uuid>,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(response) = public_admission(
        &state,
        &client,
        Limit::DeviceChallenge,
        &device_id.to_string(),
        enrollment::device_is_live(&client, device_id),
    )
    .await
    {
        return response;
    }
    match enrollment::issue_device_challenge(&client, &state.enrollment_hasher, device_id).await {
        Ok(challenge) => Json(ChallengeResponse {
            challenge_id: challenge.id,
            account_id: challenge.account_id,
            device_id: challenge.device_id,
            nonce: URL_SAFE_NO_PAD.encode(challenge.nonce),
        })
        .into_response(),
        Err(error) => public_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticateBody {
    challenge_id: Uuid,
    account_id: Uuid,
    device_id: Uuid,
    nonce: String,
    signature_der: String,
}

async fn device_authenticate(
    State(state): State<Arc<EnrollmentHttpState>>,
    Json(body): Json<AuthenticateBody>,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let live = async {
        match decode_nonce(&body.nonce) {
            Ok(nonce) => {
                let challenge = DeviceChallenge {
                    id: body.challenge_id,
                    account_id: body.account_id,
                    device_id: body.device_id,
                    nonce,
                };
                enrollment::device_challenge_is_live(&client, &state.enrollment_hasher, &challenge)
                    .await
            }
            Err(_) => Ok(false),
        }
    };
    if let Err(response) = public_admission(
        &state,
        &client,
        Limit::DeviceAuthenticate,
        &body.device_id.to_string(),
        live,
    )
    .await
    {
        return response;
    }
    let nonce = match decode_nonce(&body.nonce) {
        Ok(nonce) => nonce,
        Err(status) => return status.into_response(),
    };
    let signature = match decode_bounded(&body.signature_der, 107, 8, 80) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let challenge = DeviceChallenge {
        id: body.challenge_id,
        account_id: body.account_id,
        device_id: body.device_id,
        nonce,
    };
    match enrollment::authenticate_device_challenge(
        &mut client,
        &state.enrollment_hasher,
        &challenge,
        &signature,
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => public_error(error),
    }
}

async fn revoke_device(
    State(state): State<Arc<EnrollmentHttpState>>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    match enrollment::revoke_device(&mut client, &principal, device_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => owner_error(error),
    }
}

#[derive(Serialize)]
struct OwnerDeviceResponse {
    device_id: Uuid,
    display_name: String,
    revoked: bool,
    active_socket_lease: bool,
}

#[derive(Deserialize)]
struct ListDevicesQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct OwnerDevicePageResponse {
    devices: Vec<OwnerDeviceResponse>,
    next_cursor: Option<Uuid>,
}

async fn list_devices(
    State(state): State<Arc<EnrollmentHttpState>>,
    Query(query): Query<ListDevicesQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
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
    match enrollment::list_owner_devices(&client, &principal, query.before).await {
        Ok(page) => Json(OwnerDevicePageResponse {
            devices: page
                .devices
                .into_iter()
                .map(|device| OwnerDeviceResponse {
                    device_id: device.id,
                    display_name: device.display_name,
                    revoked: device.revoked,
                    active_socket_lease: device.active_socket_lease,
                })
                .collect::<Vec<_>>(),
            next_cursor: page.next_cursor,
        })
        .into_response(),
        Err(error) => owner_error(error),
    }
}

#[cfg(test)]
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests;
