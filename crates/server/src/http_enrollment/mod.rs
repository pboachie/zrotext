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
use std::sync::Arc;
use tokio_postgres::{Client, NoTls};
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
    let (client, connection) = tokio_postgres::connect(&state.database_url, NoTls)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn public_admission(
    state: &EnrollmentHttpState,
    client: &Client,
    limit: Limit,
    subject: &str,
) -> Result<(), Response> {
    match abuse_limits::consume(client, &state.auth_hasher, limit, Some(subject)).await {
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
    if let Err(response) =
        public_admission(&state, &client, Limit::PairClaim, &pairing_id.to_string()).await
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
    if let Err(response) =
        public_admission(&state, &client, Limit::PairProof, &pairing_id.to_string()).await
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
    if let Err(response) = public_admission(
        &state,
        &client,
        Limit::DeviceAuthenticate,
        &body.device_id.to_string(),
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
mod tests {
    use super::*;
    use crate::{
        auth::{TokenHasher, login, register, verify_email},
        enrollment::{device_challenge_bytes, enrollment_challenge_bytes},
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer},
        pkcs8::EncodePublicKey,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn request(
        method: Method,
        uri: &str,
        body: Value,
        session: Option<(&str, &str)>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((token, csrf)) = session {
            builder = builder
                .header(
                    header::COOKIE,
                    format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
                )
                .header(header::ORIGIN, "https://test.example")
                .header("x-zrotext-csrf", csrf);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn json_response(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn binary_fields_have_strict_bounds() {
        assert!(decode_nonce(&URL_SAFE_NO_PAD.encode([0u8; 32])).is_ok());
        assert!(decode_nonce(&URL_SAFE_NO_PAD.encode([0u8; 31])).is_err());
        assert!(decode_nonce(&format!("{}=", URL_SAFE_NO_PAD.encode([0u8; 32]))).is_err());
        assert!(decode_bounded(&"A".repeat(215), 214, 80, 160).is_err());
    }

    #[tokio::test]
    async fn http_pairing_requires_csrf_proves_key_and_revokes_device() {
        let Ok(root_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        assert!(root_url.starts_with("postgres://") || root_url.starts_with("postgresql://"));
        let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_enroll_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        ] {
            admin.batch_execute(sql).await.unwrap();
        }
        let auth_hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let enrollment_hasher =
            Arc::new(EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let a = register(
            &mut admin,
            &auth_hasher,
            "http-a@example.test",
            "correct horse 123",
        )
        .await
        .unwrap();
        let b = register(
            &mut admin,
            &auth_hasher,
            "http-b@example.test",
            "correct horse 456",
        )
        .await
        .unwrap();
        verify_email(&mut admin, &auth_hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut admin, &auth_hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(
            &admin,
            &auth_hasher,
            "http-a@example.test",
            "correct horse 123",
        )
        .await
        .unwrap();
        let sb = login(
            &admin,
            &auth_hasher,
            "http-b@example.test",
            "correct horse 456",
        )
        .await
        .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let app = router(EnrollmentHttpState::new(
            scoped_url,
            auth_hasher.clone(),
            enrollment_hasher,
            "https://test.example".into(),
        ));

        let unauthenticated_list = app
            .clone()
            .oneshot(request(Method::GET, "/devices", json!({}), None))
            .await
            .unwrap();
        assert_eq!(unauthenticated_list.status(), StatusCode::UNAUTHORIZED);
        let empty_list = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(empty_list.status(), StatusCode::OK);
        assert_eq!(
            json_response(empty_list).await,
            json!({"devices":[],"next_cursor":null})
        );

        let oversized = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{}/claim", Uuid::new_v4()),
                json!({"token":"A".repeat(MAX_BODY_BYTES)}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let forged = Request::builder()
            .method(Method::POST)
            .uri("/pairings")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("__Host-zrotext_session={}", sa.token),
            )
            .body(Body::from(r#"{"display_name":"Phone"}"#))
            .unwrap();
        let response = app.clone().oneshot(forged).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/pairings",
                json!({"display_name":"Phone"}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let created = json_response(response).await;
        let pairing_id: Uuid = created["pairing_id"].as_str().unwrap().parse().unwrap();
        let token = created["token"].as_str().unwrap();

        let signing = SigningKey::random(&mut OsRng);
        let spki = signing.verifying_key().to_public_key_der().unwrap();
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/claim"),
                json!({"token":token,"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let claim = json_response(response).await;
        assert_eq!(claim["account_id"], a.account_id.to_string());
        let nonce = decode_nonce(claim["challenge_nonce"].as_str().unwrap()).unwrap();
        let fingerprint: [u8; 32] =
            Sha256::digest(signing.verifying_key().to_encoded_point(false).as_bytes()).into();
        let payload = enrollment_challenge_bytes(a.account_id, pairing_id, &fingerprint, &nonce);
        let signature: Signature = signing.sign(&payload);
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/prove"),
                json!({"challenge_nonce":claim["challenge_nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await["proof_verified"], true);

        let response = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/pairings/{pairing_id}"),
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/approve"),
                json!({"comparison_code":claim["comparison_code"],"key_fingerprint":claim["key_fingerprint"]}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let device_id: Uuid = json_response(response).await["device_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let owner_devices = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(owner_devices.headers()[header::CACHE_CONTROL], "no-store");
        let owner_devices = json_response(owner_devices).await;
        assert_eq!(owner_devices["devices"].as_array().unwrap().len(), 1);
        assert_eq!(
            owner_devices["devices"][0]["device_id"],
            device_id.to_string()
        );
        assert_eq!(owner_devices["devices"][0]["display_name"], "Phone");
        assert_eq!(owner_devices["devices"][0]["revoked"], false);
        assert_eq!(owner_devices["devices"][0]["active_socket_lease"], false);
        assert_eq!(owner_devices["next_cursor"], Value::Null);
        // A lease is written only after device proof. Its owner view follows
        // the writer's site and deployment fences, without asserting radio.
        admin
            .batch_execute("INSERT INTO sites(site_id) VALUES('hub-a'),('hub-b')")
            .await
            .unwrap();
        admin.execute(
            "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,'hub-a','instance-a',1,now()+interval '90 seconds',1)",
            &[&device_id, &a.account_id],
        ).await.unwrap();
        let status = |token: &str, csrf: &str| {
            request(Method::GET, "/devices", json!({}), Some((token, csrf)))
        };
        let active = json_response(
            app.clone()
                .oneshot(status(&sa.token, &sa.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(active["devices"][0]["active_socket_lease"], true);
        for readiness in ["sms_ready", "sim_ready", "radio_ready"] {
            assert!(active["devices"][0].get(readiness).is_none());
        }
        let other_tenant_active = json_response(
            app.clone()
                .oneshot(status(&sb.token, &sb.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            other_tenant_active,
            json!({"devices":[],"next_cursor":null})
        );
        admin.execute("UPDATE device_sessions SET lease_until=now()-interval '1 second' WHERE device_id=$1", &[&device_id]).await.unwrap();
        let expired = json_response(
            app.clone()
                .oneshot(status(&sa.token, &sa.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(expired["devices"][0]["active_socket_lease"], false);
        admin.execute("UPDATE device_sessions SET site_id='hub-b',instance_id='instance-b',connection_epoch=2,lease_until=now()+interval '90 seconds' WHERE device_id=$1", &[&device_id]).await.unwrap();
        let reconnected = json_response(
            app.clone()
                .oneshot(status(&sa.token, &sa.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(reconnected["devices"][0]["active_socket_lease"], true);
        admin
            .batch_execute("UPDATE deployment_authority SET epoch=2")
            .await
            .unwrap();
        let stale_epoch = json_response(
            app.clone()
                .oneshot(status(&sa.token, &sa.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(stale_epoch["devices"][0]["active_socket_lease"], false);
        admin.batch_execute("UPDATE deployment_authority SET epoch=1; UPDATE sites SET draining=TRUE WHERE site_id='hub-b'").await.unwrap();
        let draining = json_response(
            app.clone()
                .oneshot(status(&sa.token, &sa.csrf_token))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(draining["devices"][0]["active_socket_lease"], false);
        admin
            .batch_execute("UPDATE sites SET draining=FALSE WHERE site_id='hub-b'")
            .await
            .unwrap();
        let other_tenant_devices = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(
            json_response(other_tenant_devices).await,
            json!({"devices":[],"next_cursor":null})
        );

        let forbidden_revoke = app
            .clone()
            .oneshot(request(
                Method::DELETE,
                &format!("/devices/{device_id}"),
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(forbidden_revoke.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/devices/{device_id}/challenge"),
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge = json_response(response).await;
        let device_challenge = DeviceChallenge {
            id: challenge["challenge_id"].as_str().unwrap().parse().unwrap(),
            account_id: a.account_id,
            device_id,
            nonce: decode_nonce(challenge["nonce"].as_str().unwrap()).unwrap(),
        };
        let signature: Signature = signing.sign(&device_challenge_bytes(&device_challenge));
        let auth_body = json!({
            "challenge_id":device_challenge.id,
            "account_id":device_challenge.account_id,
            "device_id":device_challenge.device_id,
            "nonce":challenge["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        });
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/devices/authenticate",
                auth_body.clone(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/devices/authenticate",
                auth_body,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(request(
                Method::DELETE,
                &format!("/devices/{device_id}"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let revoked_list = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        let revoked_device = json_response(revoked_list).await;
        assert_eq!(revoked_device["devices"][0]["revoked"], true);
        assert_eq!(revoked_device["devices"][0]["active_socket_lease"], false);

        // Listing stays bounded and the cursor cannot cross tenant scope.
        let sec1 = signing.verifying_key().to_encoded_point(false);
        for index in 0..51 {
            let extra_id = Uuid::new_v4();
            admin
                .execute(
                    "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,$3)",
                    &[&extra_id, &a.account_id, &format!("Extra {index}")],
                )
                .await
                .unwrap();
            admin
                .execute(
                    "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
                    &[&extra_id, &a.account_id, &sec1.as_bytes(), &&fingerprint[..]],
                )
                .await
                .unwrap();
        }
        let first_page = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        let first_page = json_response(first_page).await;
        assert_eq!(first_page["devices"].as_array().unwrap().len(), 50);
        let cursor = first_page["next_cursor"].as_str().unwrap();
        let second_page = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/devices?before={cursor}"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
            ))
            .await
            .unwrap();
        let second_page = json_response(second_page).await;
        assert_eq!(second_page["devices"].as_array().unwrap().len(), 2);
        assert_eq!(second_page["next_cursor"], Value::Null);
        let tenant_b_cursor = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/devices?before={cursor}"),
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
            ))
            .await
            .unwrap();
        assert_eq!(json_response(tenant_b_cursor).await["devices"], json!([]));
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/devices/{device_id}/challenge"),
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let gate_hasher = auth_hasher.clone();
        for _ in 0..19 {
            assert!(
                abuse_limits::consume(
                    &admin,
                    &gate_hasher,
                    Limit::PairClaim,
                    Some(&pairing_id.to_string()),
                )
                .await
                .unwrap()
            );
        }
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{pairing_id}/claim"),
                json!({"token":"x".repeat(47),"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let other_pairing = Uuid::new_v4();
        let response = app
            .oneshot(request(
                Method::POST,
                &format!("/pairings/{other_pairing}/claim"),
                json!({"token":"x".repeat(47),"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        admin
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
