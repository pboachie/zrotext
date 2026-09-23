// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-only webhook endpoint lifecycle. Plaintext signing secrets leave this
//! module only in the create and rotate responses, once per generated secret.

use crate::{
    auth::{SessionPrincipal, TokenHasher},
    http_auth::require_owner,
    webhook_egress,
    webhook_worker::WebhookSecretVault,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio_postgres::{Client, NoTls, error::SqlState};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 4096;
const MAX_ENDPOINTS_PER_ACCOUNT: i64 = 8;
const MAX_HISTORY_PAGE: u8 = 20;

pub struct WebhookHttpState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    pub vault: Arc<WebhookSecretVault>,
}

pub fn router(state: WebhookHttpState) -> Router {
    Router::new()
        .route("/v1/webhooks", get(list_endpoints).post(create_endpoint))
        .route(
            "/v1/webhooks/{endpoint_id}/deliveries",
            get(list_deliveries),
        )
        .route(
            "/v1/webhooks/{endpoint_id}/deliveries/{delivery_id}/replay",
            post(replay_delivery),
        )
        .route("/v1/webhooks/{endpoint_id}/enable", post(enable_endpoint))
        .route("/v1/webhooks/{endpoint_id}/disable", post(disable_endpoint))
        .route("/v1/webhooks/{endpoint_id}/rotate", post(rotate_endpoint))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Debug)]
enum EndpointError {
    BadRequest,
    NotFound,
    Limit,
    ReplayConflict,
    ReplayLimit,
    Unavailable,
}

impl IntoResponse for EndpointError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_webhook_endpoint"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Limit => (StatusCode::CONFLICT, "endpoint_limit"),
            Self::ReplayConflict => (StatusCode::CONFLICT, "replay_not_eligible"),
            Self::ReplayLimit => (StatusCode::CONFLICT, "replay_limit"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        (status, Json(serde_json::json!({"code": code}))).into_response()
    }
}

async fn connect(state: &WebhookHttpState) -> Result<Client, EndpointError> {
    let (client, connection) = tokio_postgres::connect(&state.database_url, NoTls)
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn owner(
    client: &Client,
    state: &WebhookHttpState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<SessionPrincipal, Response> {
    require_owner(
        client,
        &state.auth_hasher,
        &state.canonical_origin,
        headers,
        mutation,
    )
    .await
    .map_err(IntoResponse::into_response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    callback_url: String,
}

#[derive(Serialize)]
struct SecretResponse {
    endpoint_id: Uuid,
    callback_url: String,
    enabled: bool,
    signing_secret_b64url: String,
}

#[derive(Serialize)]
struct EndpointView {
    endpoint_id: Uuid,
    callback_url: String,
    enabled: bool,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct ListResponse {
    endpoints: Vec<EndpointView>,
}

async fn list_endpoints(
    State(state): State<Arc<WebhookHttpState>>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, false).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match client
        .query(
            "SELECT id,callback_url,enabled,(extract(epoch FROM created_at)*1000)::bigint \
             FROM webhook_endpoints WHERE account_id=$1 ORDER BY created_at,id",
            &[&principal.tenant.account_id()],
        )
        .await
    {
        Ok(rows) => Json(ListResponse {
            endpoints: rows
                .into_iter()
                .map(|row| EndpointView {
                    endpoint_id: row.get(0),
                    callback_url: row.get(1),
                    enabled: row.get(2),
                    created_at_ms: row.get(3),
                })
                .collect(),
        })
        .into_response(),
        Err(_) => EndpointError::Unavailable.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    limit: Option<u8>,
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct AttemptView {
    generation: i16,
    attempt_number: i16,
    started_at_ms: i64,
    completed_at_ms: Option<i64>,
    outcome: Option<String>,
    http_status: Option<i16>,
}

#[derive(Serialize)]
struct DeliveryView {
    delivery_id: Uuid,
    event_id: Uuid,
    status: String,
    generation: i16,
    terminal_reason: Option<String>,
    attempt_count: i16,
    next_attempt_at_ms: Option<i64>,
    created_at_ms: i64,
    updated_at_ms: i64,
    attempts: Vec<AttemptView>,
}

#[derive(Serialize)]
struct HistoryResponse {
    deliveries: Vec<DeliveryView>,
    next_before: Option<Uuid>,
}

async fn list_deliveries(
    State(state): State<Arc<WebhookHttpState>>,
    Path(endpoint_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, false).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match history(&client, principal.tenant.account_id(), endpoint_id, query).await {
        Ok(page) => Json(page).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn history(
    client: &Client,
    account_id: Uuid,
    endpoint_id: Uuid,
    query: HistoryQuery,
) -> Result<HistoryResponse, EndpointError> {
    let limit = query.limit.unwrap_or(MAX_HISTORY_PAGE);
    if !(1..=MAX_HISTORY_PAGE).contains(&limit) {
        return Err(EndpointError::BadRequest);
    }
    let endpoint = client
        .query_opt(
            "SELECT id FROM webhook_endpoints WHERE account_id=$1 AND id=$2",
            &[&account_id, &endpoint_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    if endpoint.is_none() {
        return Err(EndpointError::NotFound);
    }
    let anchor: Option<(std::time::SystemTime, Uuid)> = match query.before {
        Some(before) => {
            let row = client
                .query_opt(
                    "SELECT created_at,id FROM webhook_deliveries \
                     WHERE account_id=$1 AND endpoint_id=$2 AND id=$3",
                    &[&account_id, &endpoint_id, &before],
                )
                .await
                .map_err(|_| EndpointError::Unavailable)?
                .ok_or(EndpointError::NotFound)?;
            Some((row.get(0), row.get(1)))
        }
        None => None,
    };
    let anchor_time = anchor.as_ref().map(|(time, _)| *time);
    let anchor_id = anchor.map(|(_, id)| id);
    let rows = client
        .query(
            "SELECT id,event_id,status,generation,terminal_reason,attempt_count, \
             CASE WHEN status='pending' THEN (extract(epoch FROM next_attempt_at)*1000)::bigint END, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint \
             FROM webhook_deliveries WHERE account_id=$1 AND endpoint_id=$2 \
             AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4)) \
             ORDER BY created_at DESC,id DESC LIMIT $5",
            &[&account_id, &endpoint_id, &anchor_time, &anchor_id, &(i64::from(limit) + 1)],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    let has_more = rows.len() > usize::from(limit);
    let mut deliveries: Vec<DeliveryView> = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| DeliveryView {
            delivery_id: row.get(0),
            event_id: row.get(1),
            status: row.get(2),
            generation: row.get(3),
            terminal_reason: row.get(4),
            attempt_count: row.get(5),
            next_attempt_at_ms: row.get(6),
            created_at_ms: row.get(7),
            updated_at_ms: row.get(8),
            attempts: Vec::new(),
        })
        .collect();
    let next_before = if has_more {
        deliveries.last().map(|delivery| delivery.delivery_id)
    } else {
        None
    };
    if !deliveries.is_empty() {
        let ids: Vec<Uuid> = deliveries
            .iter()
            .map(|delivery| delivery.delivery_id)
            .collect();
        let by_id: HashMap<Uuid, usize> = deliveries
            .iter()
            .enumerate()
            .map(|(index, delivery)| (delivery.delivery_id, index))
            .collect();
        let attempts = client
            .query(
                "SELECT a.delivery_id,a.generation,a.attempt_number, \
                 (extract(epoch FROM a.started_at)*1000)::bigint, \
                 (extract(epoch FROM a.completed_at)*1000)::bigint,a.outcome,a.http_status \
                 FROM webhook_attempts a JOIN webhook_deliveries d ON d.id=a.delivery_id \
                 WHERE d.account_id=$1 AND d.endpoint_id=$2 AND a.delivery_id=ANY($3) \
                 ORDER BY a.delivery_id,a.generation,a.attempt_number",
                &[&account_id, &endpoint_id, &ids],
            )
            .await
            .map_err(|_| EndpointError::Unavailable)?;
        for row in attempts {
            let id: Uuid = row.get(0);
            if let Some(&index) = by_id.get(&id) {
                deliveries[index].attempts.push(AttemptView {
                    generation: row.get(1),
                    attempt_number: row.get(2),
                    started_at_ms: row.get(3),
                    completed_at_ms: row.get(4),
                    outcome: row.get(5),
                    http_status: row.get(6),
                });
            }
        }
    }
    Ok(HistoryResponse {
        deliveries,
        next_before,
    })
}

#[derive(Serialize)]
struct ReplayResponse {
    delivery_id: Uuid,
    generation: i16,
    created: bool,
}

async fn replay_delivery(
    State(state): State<Arc<WebhookHttpState>>,
    Path((endpoint_id, delivery_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    // A random request UUID is durable across HTTP retries and is never
    // generated by the server on behalf of an ambiguous browser retry.
    let request_id = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok());
    let Some(request_id) = request_id.filter(|id| id.get_version_num() == 4) else {
        return EndpointError::BadRequest.into_response();
    };
    match replay(
        &mut client,
        principal.tenant.account_id(),
        endpoint_id,
        delivery_id,
        request_id,
    )
    .await
    {
        Ok(result) => (StatusCode::ACCEPTED, Json(result)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn replay(
    client: &mut Client,
    account_id: Uuid,
    endpoint_id: Uuid,
    delivery_id: Uuid,
    request_id: Uuid,
) -> Result<ReplayResponse, EndpointError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    // Match disable/rotation's lock order. A retired endpoint cannot gain a
    // new queue item while one of those mutations is committing.
    let endpoint = tx
        .query_opt(
            "SELECT enabled FROM webhook_endpoints WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&account_id, &endpoint_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?
        .ok_or(EndpointError::NotFound)?;
    let enabled: bool = endpoint.get(0);
    let delivery = tx
        .query_opt(
            "SELECT status,terminal_reason,generation,attempt_count,lease_owner,lease_until \
             FROM webhook_deliveries WHERE account_id=$1 AND endpoint_id=$2 AND id=$3 FOR UPDATE",
            &[&account_id, &endpoint_id, &delivery_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?
        .ok_or(EndpointError::NotFound)?;
    let prior = tx
        .query_opt(
            "SELECT delivery_id,generation FROM webhook_replay_requests \
             WHERE account_id=$1 AND request_id=$2",
            &[&account_id, &request_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    if let Some(prior) = prior {
        let prior_delivery: Uuid = prior.get(0);
        if prior_delivery != delivery_id {
            return Err(EndpointError::ReplayConflict);
        }
        let generation = prior.get(1);
        tx.commit().await.map_err(|_| EndpointError::Unavailable)?;
        return Ok(ReplayResponse {
            delivery_id,
            generation,
            created: false,
        });
    }
    let status: String = delivery.get(0);
    let reason: Option<String> = delivery.get(1);
    let generation: i16 = delivery.get(2);
    let attempt_count: i16 = delivery.get(3);
    let lease_owner: Option<String> = delivery.get(4);
    let lease_until: Option<std::time::SystemTime> = delivery.get(5);
    if !enabled
        || status != "dead"
        || reason.as_deref() != Some("failed")
        || attempt_count != 7
        || lease_owner.is_some()
        || lease_until.is_some()
    {
        return Err(EndpointError::ReplayConflict);
    }
    if generation >= 3 {
        return Err(EndpointError::ReplayLimit);
    }
    // Require all seven prior attempts to be completed failures. The status
    // flag alone is insufficient to authorize a replay after manual repair.
    let evidence = tx
        .query_one(
            "SELECT count(*),coalesce(bool_and(completed_at IS NOT NULL AND \
             outcome IN ('timeout','http_error','network_error')),false) \
             FROM webhook_attempts WHERE delivery_id=$1 AND generation=$2",
            &[&delivery_id, &generation],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    let count: i64 = evidence.get(0);
    let all_failed: bool = evidence.get(1);
    if count != 7 || !all_failed {
        return Err(EndpointError::ReplayConflict);
    }
    let new_generation = generation + 1;
    let inserted = tx
        .execute(
            "INSERT INTO webhook_replay_requests(account_id,request_id,delivery_id,generation) \
             VALUES($1,$2,$3,$4)",
            &[&account_id, &request_id, &delivery_id, &new_generation],
        )
        .await;
    match inserted {
        Ok(1) => {}
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            return Err(EndpointError::ReplayConflict);
        }
        _ => return Err(EndpointError::Unavailable),
    }
    tx.execute(
        "UPDATE webhook_deliveries SET status='pending',terminal_reason=NULL, \
         generation=$4,attempt_count=0,next_attempt_at=now(),updated_at=now() \
         WHERE account_id=$1 AND endpoint_id=$2 AND id=$3",
        &[&account_id, &endpoint_id, &delivery_id, &new_generation],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.commit().await.map_err(|_| EndpointError::Unavailable)?;
    Ok(ReplayResponse {
        delivery_id,
        generation: new_generation,
        created: true,
    })
}

async fn create_endpoint(
    State(state): State<Arc<WebhookHttpState>>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match create(&mut client, &state.vault, &principal, &body.callback_url).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn create(
    client: &mut Client,
    vault: &WebhookSecretVault,
    principal: &SessionPrincipal,
    callback_url: &str,
) -> Result<SecretResponse, EndpointError> {
    let callback_url = webhook_egress::validate_target(callback_url)
        .map_err(|_| EndpointError::BadRequest)?
        .to_string();
    let endpoint_id = Uuid::new_v4();
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    let ciphertext = vault
        .seal(principal.tenant.account_id(), endpoint_id, secret.as_ref())
        .map_err(|_| EndpointError::Unavailable)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    // Serialize endpoint creation for this account without blocking FK key-share
    // checks by other writers. The finite cap avoids unbounded fan-out.
    let locked = tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[&principal.tenant.account_id()],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    if locked.is_none() {
        return Err(EndpointError::NotFound);
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM webhook_endpoints WHERE account_id=$1",
            &[&principal.tenant.account_id()],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?
        .get(0);
    if count >= MAX_ENDPOINTS_PER_ACCOUNT {
        return Err(EndpointError::Limit);
    }
    tx.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
         signing_secret_key_version,enabled) VALUES($1,$2,$3,$4,$5,false)",
        &[
            &endpoint_id,
            &principal.tenant.account_id(),
            &callback_url,
            &ciphertext,
            &vault.version(),
        ],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.commit().await.map_err(|_| EndpointError::Unavailable)?;
    Ok(SecretResponse {
        endpoint_id,
        callback_url,
        enabled: false,
        signing_secret_b64url: URL_SAFE_NO_PAD.encode(secret.as_ref()),
    })
}

async fn enable_endpoint(
    State(state): State<Arc<WebhookHttpState>>,
    Path(endpoint_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match enable(&mut client, &principal, &state.vault, endpoint_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn enable(
    client: &mut Client,
    principal: &SessionPrincipal,
    vault: &WebhookSecretVault,
    endpoint_id: Uuid,
) -> Result<(), EndpointError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    let row = tx
        .query_opt(
            "SELECT callback_url,signing_secret_ciphertext,signing_secret_key_version \
             FROM webhook_endpoints WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&principal.tenant.account_id(), &endpoint_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?
        .ok_or(EndpointError::NotFound)?;
    let callback_url: String = row.get(0);
    webhook_egress::validate_target(&callback_url).map_err(|_| EndpointError::BadRequest)?;
    let ciphertext: Vec<u8> = row.get(1);
    let version: i32 = row.get(2);
    vault
        .open(
            principal.tenant.account_id(),
            endpoint_id,
            version,
            &ciphertext,
        )
        .map_err(|_| EndpointError::Unavailable)?;
    tx.execute(
        "UPDATE webhook_endpoints SET enabled=true WHERE account_id=$1 AND id=$2",
        &[&principal.tenant.account_id(), &endpoint_id],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.commit().await.map_err(|_| EndpointError::Unavailable)?;
    Ok(())
}

async fn disable_endpoint(
    State(state): State<Arc<WebhookHttpState>>,
    Path(endpoint_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match retire(&mut client, &principal, endpoint_id, None).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rotate_endpoint(
    State(state): State<Arc<WebhookHttpState>>,
    Path(endpoint_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut client) = connect(&state).await else {
        return EndpointError::Unavailable.into_response();
    };
    let principal = match owner(&client, &state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    let ciphertext =
        match state
            .vault
            .seal(principal.tenant.account_id(), endpoint_id, secret.as_ref())
        {
            Ok(ciphertext) => ciphertext,
            Err(_) => return EndpointError::Unavailable.into_response(),
        };
    match retire(
        &mut client,
        &principal,
        endpoint_id,
        Some((&ciphertext, state.vault.version())),
    )
    .await
    {
        Ok(callback_url) => Json(SecretResponse {
            endpoint_id,
            callback_url,
            enabled: false,
            signing_secret_b64url: URL_SAFE_NO_PAD.encode(secret.as_ref()),
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

/// Disable and permanently retire queued work in one transaction. Completed
/// deliveries remain as audit history. An in-flight HTTPS request that already
/// loaded its payload can finish, but it cannot be retried on re-enable.
async fn retire(
    client: &mut Client,
    principal: &SessionPrincipal,
    endpoint_id: Uuid,
    replacement: Option<(&[u8], i32)>,
) -> Result<String, EndpointError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    let row = tx
        .query_opt(
            "SELECT callback_url FROM webhook_endpoints WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&principal.tenant.account_id(), &endpoint_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?
        .ok_or(EndpointError::NotFound)?;
    let callback_url: String = row.get(0);
    if let Some((ciphertext, version)) = replacement {
        tx.execute(
            "UPDATE webhook_endpoints SET enabled=false,signing_secret_ciphertext=$3, \
             signing_secret_key_version=$4 WHERE account_id=$1 AND id=$2",
            &[
                &principal.tenant.account_id(),
                &endpoint_id,
                &ciphertext,
                &version,
            ],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    } else {
        tx.execute(
            "UPDATE webhook_endpoints SET enabled=false WHERE account_id=$1 AND id=$2",
            &[&principal.tenant.account_id(), &endpoint_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    }
    // Wait for any concurrent claim/finish holding a delivery row, then close
    // its attempt in the same transaction. This prevents a retired lease from
    // retaining an uncompleted audit row.
    tx.query(
        "SELECT id FROM webhook_deliveries WHERE account_id=$1 AND endpoint_id=$2 \
         AND status IN ('pending','leased') FOR UPDATE",
        &[&principal.tenant.account_id(), &endpoint_id],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.execute(
        "UPDATE webhook_attempts a SET completed_at=now(),outcome='policy_rejected' \
         FROM webhook_deliveries d WHERE a.delivery_id=d.id AND d.account_id=$1 \
         AND d.endpoint_id=$2 AND d.status='leased' AND a.completed_at IS NULL",
        &[&principal.tenant.account_id(), &endpoint_id],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.execute(
        "UPDATE webhook_deliveries SET status='dead',terminal_reason='retired', \
         lease_owner=NULL,lease_until=NULL, \
         updated_at=now() WHERE account_id=$1 AND endpoint_id=$2 \
         AND status IN ('pending','leased')",
        &[&principal.tenant.account_id(), &endpoint_id],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    // A prior failed delivery may be replayed only while the endpoint remains
    // enabled with its original signing secret. Disable/rotate retires it too.
    tx.execute(
        "UPDATE webhook_deliveries SET terminal_reason='retired',updated_at=now() \
         WHERE account_id=$1 AND endpoint_id=$2 AND status='dead' \
         AND terminal_reason='failed'",
        &[&principal.tenant.account_id(), &endpoint_id],
    )
    .await
    .map_err(|_| EndpointError::Unavailable)?;
    tx.commit().await.map_err(|_| EndpointError::Unavailable)?;
    Ok(callback_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{login, register, verify_email};
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn fixture_key() -> Vec<u8> {
        rand::random::<[u8; 32]>().to_vec()
    }

    fn request(
        method: Method,
        uri: &str,
        body: Value,
        session: Option<(&str, &str)>,
        csrf: bool,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((token, csrf_token)) = session {
            builder = builder.header(
                header::COOKIE,
                format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf_token}"),
            );
            if csrf {
                builder = builder
                    .header(header::ORIGIN, "https://test.example")
                    .header("x-zrotext-csrf", csrf_token);
            }
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
    }

    fn replay_request(
        endpoint_id: Uuid,
        delivery_id: Uuid,
        key: Option<Uuid>,
        session: Option<(&str, &str)>,
        csrf: bool,
    ) -> Request<Body> {
        let uri = format!("/v1/webhooks/{endpoint_id}/deliveries/{delivery_id}/replay");
        let mut request = request(Method::POST, &uri, json!({}), session, csrf);
        if let Some(key) = key {
            request
                .headers_mut()
                .insert("idempotency-key", key.to_string().parse().unwrap());
        }
        request
    }

    async fn history_fixture(
        admin: &Client,
        account_id: Uuid,
        endpoint_id: Uuid,
        count: usize,
    ) -> Vec<Uuid> {
        admin.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) VALUES($1,$2,'https://user:private@hooks.example.org/receive',$3,1)", &[&endpoint_id, &account_id, &vec![8_u8; 32]]).await.unwrap();
        let device = Uuid::new_v4();
        let message = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        admin
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
                &[&device, &account_id],
            )
            .await
            .unwrap();
        admin.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')", &[&message, &account_id, &device, &vec![2_u8; 32], &b"private-message-body".as_slice(), &vec![3_u8; 32]]).await.unwrap();
        admin.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')", &[&attempt, &account_id, &message, &device]).await.unwrap();
        let mut ids = Vec::new();
        for index in 0..count {
            let event = Uuid::new_v4();
            let delivery = Uuid::new_v4();
            let sequence = (index + 1) as i64;
            admin.execute("INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,content_ciphertext,event_digest,signature_der) VALUES($1,$2,$3,$4,$5,$6,'captured_local',now(),1,'opaque_pilot',$7,$8,$9)", &[&event, &account_id, &device, &message, &attempt, &sequence, &vec![17_u8; 32], &vec![4_u8; 32], &vec![5_u8; 8]]).await.unwrap();
            let delivered = index == 0 && count > 1;
            let status = if delivered { "succeeded" } else { "pending" };
            let attempt_count: i16 = if delivered { 2 } else { 0 };
            let age = index as i32;
            admin.execute("INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status,attempt_count,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,now()-($7::int * interval '1 second'),now()-($7::int * interval '1 second'))", &[&delivery, &account_id, &endpoint_id, &event, &status, &attempt_count, &age]).await.unwrap();
            if delivered {
                admin.execute("INSERT INTO webhook_attempts(id,delivery_id,attempt_number,completed_at,outcome,http_status) VALUES($1,$2,1,now(),'http_error',500),($3,$2,2,now(),'ack',200)", &[&Uuid::new_v4(), &delivery, &Uuid::new_v4()]).await.unwrap();
            }
            ids.push(delivery);
        }
        ids
    }

    async fn mark_exhausted_failure(admin: &Client, delivery_id: Uuid, generation: i16) {
        admin
            .execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='failed', \
                 generation=$2,attempt_count=7 WHERE id=$1",
                &[&delivery_id, &generation],
            )
            .await
            .unwrap();
        for number in 1_i16..=7 {
            admin
                .execute(
                    "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number, \
                     completed_at,outcome,http_status) VALUES($1,$2,$3,$4,now(),'http_error',500)",
                    &[&Uuid::new_v4(), &delivery_id, &generation, &number],
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn manual_replay_is_owner_scoped_csrf_protected_bounded_and_idempotent() {
        let Ok(root_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            eprintln!("set ZT_AUTH_TEST_DATABASE_URL to run webhook replay database test");
            return;
        };
        let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("webhook_replay_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            admin.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(fixture_key()).unwrap());
        let password_a = Uuid::new_v4().to_string();
        let password_b = Uuid::new_v4().to_string();
        let a = register(&mut admin, &hasher, "replay-a@example.test", &password_a)
            .await
            .unwrap();
        let b = register(&mut admin, &hasher, "replay-b@example.test", &password_b)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(&admin, &hasher, "replay-a@example.test", &password_a)
            .await
            .unwrap();
        let sb = login(&admin, &hasher, "replay-b@example.test", &password_b)
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let app = router(WebhookHttpState {
            database_url: scoped_url.clone(),
            auth_hasher: hasher,
            canonical_origin: "https://test.example".into(),
            vault: Arc::new(WebhookSecretVault::new(1, Zeroizing::new(fixture_key())).unwrap()),
        });
        let endpoint = Uuid::new_v4();
        let foreign_endpoint = Uuid::new_v4();
        let ids = history_fixture(&admin, a.account_id, endpoint, 6).await;
        let foreign_ids = history_fixture(&admin, b.account_id, foreign_endpoint, 1).await;
        admin
            .execute(
                "UPDATE webhook_endpoints SET enabled=true, \
                 callback_url='https://hooks.example.org/receive' WHERE id=$1",
                &[&endpoint],
            )
            .await
            .unwrap();
        mark_exhausted_failure(&admin, ids[1], 1).await;
        admin
            .execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='policy_rejected', \
                 attempt_count=1 WHERE id=$1",
                &[&ids[2]],
            )
            .await
            .unwrap();
        admin.execute("INSERT INTO webhook_attempts(id,delivery_id,attempt_number,completed_at,outcome) VALUES($1,$2,1,now(),'policy_rejected')", &[&Uuid::new_v4(), &ids[2]]).await.unwrap();
        admin
            .execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='retired' WHERE id=$1",
                &[&ids[3]],
            )
            .await
            .unwrap();
        admin
            .execute(
                "UPDATE webhook_deliveries SET status='leased',attempt_count=1, \
                 lease_owner='fixture',lease_until=now()+interval '5 minutes' WHERE id=$1",
                &[&ids[5]],
            )
            .await
            .unwrap();
        admin
            .execute(
                "INSERT INTO webhook_attempts(id,delivery_id,attempt_number) VALUES($1,$2,1)",
                &[&Uuid::new_v4(), &ids[5]],
            )
            .await
            .unwrap();
        let key = Uuid::new_v4();
        let anonymous = app
            .clone()
            .oneshot(replay_request(endpoint, ids[1], Some(key), None, true))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let no_csrf = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(key),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        let missing_key = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                None,
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
        let foreign = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(key),
                Some((&sb.token, &sb.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        let foreign_delivery = app
            .clone()
            .oneshot(replay_request(
                foreign_endpoint,
                foreign_ids[0],
                Some(key),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(foreign_delivery.status(), StatusCode::NOT_FOUND);
        for id in [ids[0], ids[2], ids[3], ids[4], ids[5]] {
            let denied = app
                .clone()
                .oneshot(replay_request(
                    endpoint,
                    id,
                    Some(Uuid::new_v4()),
                    Some((&sa.token, &sa.csrf_token)),
                    true,
                ))
                .await
                .unwrap();
            assert_eq!(
                denied.status(),
                StatusCode::CONFLICT,
                "unexpected replay for {id}"
            );
        }

        // Multiple independent database clients race the same owner request.
        // Exactly one generation is created; every retry observes its result.
        let mut tasks = tokio::task::JoinSet::new();
        let target_delivery = ids[1];
        for _ in 0..12 {
            let url = scoped_url.clone();
            tasks.spawn(async move {
                let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
                tokio::spawn(async move { connection.await.unwrap() });
                replay(&mut db, a.account_id, endpoint, target_delivery, key)
                    .await
                    .unwrap()
            });
        }
        let mut created = 0;
        while let Some(result) = tasks.join_next().await {
            let result = result.unwrap();
            assert_eq!(result.delivery_id, ids[1]);
            assert_eq!(result.generation, 2);
            created += usize::from(result.created);
        }
        assert_eq!(created, 1);
        let count: i64 = admin
            .query_one(
                "SELECT count(*) FROM webhook_replay_requests WHERE delivery_id=$1",
                &[&ids[1]],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        let history: i64 = admin
            .query_one(
                "SELECT count(*) FROM webhook_attempts WHERE delivery_id=$1 AND generation=1",
                &[&ids[1]],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(history, 7);
        let repeated = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(key),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(repeated.status(), StatusCode::ACCEPTED);
        assert_eq!(json_body(repeated).await["created"], false);
        let other_delivery_same_key = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[2],
                Some(key),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(other_delivery_same_key.status(), StatusCode::CONFLICT);
        admin
            .execute(
                "UPDATE webhook_deliveries SET next_attempt_at=now()+interval '1 day' WHERE id=$1",
                &[&ids[4]],
            )
            .await
            .unwrap();
        for number in 1_i16..=7 {
            if number > 1 {
                admin.execute("UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1", &[&ids[1]]).await.unwrap();
            }
            let lease = crate::inbound::claim_webhook(&mut admin, "worker-replay")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (lease.delivery_id, lease.generation, lease.attempt_number),
                (ids[1], 2, number)
            );
            if number == 1 {
                let mut stale = lease.clone();
                stale.generation = 1;
                assert!(matches!(
                    crate::inbound::load_webhook_payload(&admin, &stale).await,
                    Err(crate::inbound::InboundError::StaleLease)
                ));
                assert!(matches!(
                    crate::inbound::finish_webhook(
                        &mut admin,
                        &stale,
                        crate::inbound::WebhookOutcome::Ack,
                        Some(200)
                    )
                    .await,
                    Err(crate::inbound::InboundError::StaleLease)
                ));
            }
            crate::inbound::finish_webhook(
                &mut admin,
                &lease,
                crate::inbound::WebhookOutcome::Timeout,
                None,
            )
            .await
            .unwrap();
        }
        let exhausted_generation: (String, Option<String>) = admin
            .query_one(
                "SELECT status,terminal_reason FROM webhook_deliveries WHERE id=$1",
                &[&ids[1]],
            )
            .await
            .map(|row| (row.get(0), row.get(1)))
            .unwrap();
        assert_eq!(exhausted_generation, ("dead".into(), Some("failed".into())));
        let late_retry = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(key),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(late_retry.status(), StatusCode::ACCEPTED);
        let late_retry = json_body(late_retry).await;
        assert_eq!(late_retry["generation"], 2);
        assert_eq!(late_retry["created"], false);
        let second_key = Uuid::new_v4();
        let second = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(second_key),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_eq!(json_body(second).await["generation"], 3);
        for number in 1_i16..=7 {
            if number > 1 {
                admin.execute("UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1", &[&ids[1]]).await.unwrap();
            }
            let lease = crate::inbound::claim_webhook(&mut admin, "worker-replay")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (lease.delivery_id, lease.generation, lease.attempt_number),
                (ids[1], 3, number)
            );
            crate::inbound::finish_webhook(
                &mut admin,
                &lease,
                crate::inbound::WebhookOutcome::Timeout,
                None,
            )
            .await
            .unwrap();
        }
        let exhausted = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(Uuid::new_v4()),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(exhausted.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(exhausted).await["code"], "replay_limit");
        let page = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/v1/webhooks/{endpoint}/deliveries"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        let page = json_body(page).await;
        let delivered = page["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["delivery_id"] == ids[1].to_string())
            .unwrap();
        assert_eq!(delivered["generation"], 3);
        assert_eq!(delivered["attempts"].as_array().unwrap().len(), 21);
        assert_eq!(delivered["attempts"][0]["generation"], 1);
        assert_eq!(delivered["attempts"][20]["generation"], 3);

        // Distinct request keys racing for one failed generation cannot both
        // create a replay, even though neither is an idempotent retry.
        mark_exhausted_failure(&admin, ids[4], 1).await;
        let mut competing = tokio::task::JoinSet::new();
        for competing_key in [Uuid::new_v4(), Uuid::new_v4()] {
            let url = scoped_url.clone();
            let competing_delivery = ids[4];
            competing.spawn(async move {
                let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
                tokio::spawn(async move { connection.await.unwrap() });
                replay(
                    &mut db,
                    a.account_id,
                    endpoint,
                    competing_delivery,
                    competing_key,
                )
                .await
            });
        }
        let mut accepted = 0;
        let mut rejected = 0;
        while let Some(result) = competing.join_next().await {
            match result.unwrap() {
                Ok(result) if result.created && result.generation == 2 => accepted += 1,
                Err(EndpointError::ReplayConflict) => rejected += 1,
                _ => panic!("unexpected competing replay result"),
            }
        }
        assert_eq!((accepted, rejected), (1, 1));
        let competing_count: i64 = admin
            .query_one(
                "SELECT count(*) FROM webhook_replay_requests WHERE delivery_id=$1",
                &[&ids[4]],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(competing_count, 1);

        let disable = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/disable"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(disable.status(), StatusCode::NO_CONTENT);
        let retired_reason: String = admin
            .query_one(
                "SELECT terminal_reason FROM webhook_deliveries WHERE id=$1",
                &[&ids[1]],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(retired_reason, "retired");
        let after_disable = app
            .clone()
            .oneshot(replay_request(
                endpoint,
                ids[1],
                Some(Uuid::new_v4()),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(after_disable.status(), StatusCode::CONFLICT);

        admin
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delivery_history_is_bounded_tenant_scoped_and_content_free() {
        let Ok(root_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            eprintln!("set ZT_AUTH_TEST_DATABASE_URL to run webhook history database test");
            return;
        };
        let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("webhook_history_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            admin.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(fixture_key()).unwrap());
        let password_a = Uuid::new_v4().to_string();
        let password_b = Uuid::new_v4().to_string();
        let a = register(&mut admin, &hasher, "history-a@example.test", &password_a)
            .await
            .unwrap();
        let b = register(&mut admin, &hasher, "history-b@example.test", &password_b)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(&admin, &hasher, "history-a@example.test", &password_a)
            .await
            .unwrap();
        let sb = login(&admin, &hasher, "history-b@example.test", &password_b)
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let app = router(WebhookHttpState {
            database_url: scoped_url,
            auth_hasher: hasher,
            canonical_origin: "https://test.example".into(),
            vault: Arc::new(WebhookSecretVault::new(1, Zeroizing::new(fixture_key())).unwrap()),
        });
        let endpoint = Uuid::new_v4();
        let other_endpoint = Uuid::new_v4();
        let foreign_endpoint = Uuid::new_v4();
        let ids = history_fixture(&admin, a.account_id, endpoint, 4).await;
        let other_ids = history_fixture(&admin, a.account_id, other_endpoint, 1).await;
        let foreign_ids = history_fixture(&admin, b.account_id, foreign_endpoint, 1).await;
        let path = format!("/v1/webhooks/{endpoint}/deliveries");

        let anonymous = app
            .clone()
            .oneshot(request(Method::GET, &path, json!({}), None, false))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let foreign = app
            .clone()
            .oneshot(request(
                Method::GET,
                &path,
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        let unknown = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/v1/webhooks/{}/deliveries", Uuid::new_v4()),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        let invalid_endpoint = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/v1/webhooks/not-a-uuid/deliveries",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(invalid_endpoint.status(), StatusCode::BAD_REQUEST);
        for suffix in [
            "?limit=0".to_string(),
            "?limit=21".to_string(),
            "?before=not-a-uuid".to_string(),
        ] {
            let invalid = app
                .clone()
                .oneshot(request(
                    Method::GET,
                    &format!("{path}{suffix}"),
                    json!({}),
                    Some((&sa.token, &sa.csrf_token)),
                    false,
                ))
                .await
                .unwrap();
            assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        }
        for cursor in [other_ids[0], foreign_ids[0], Uuid::new_v4()] {
            let invalid = app
                .clone()
                .oneshot(request(
                    Method::GET,
                    &format!("{path}?before={cursor}"),
                    json!({}),
                    Some((&sa.token, &sa.csrf_token)),
                    false,
                ))
                .await
                .unwrap();
            assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
        }

        let first = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("{path}?limit=2"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
        let first_text =
            String::from_utf8(to_bytes(first.into_body(), 16384).await.unwrap().to_vec()).unwrap();
        for private in [
            "private-message-body",
            "+15551234567",
            "callback_url",
            "signing_secret",
            "user:private",
            "content_ciphertext",
            "lease_owner",
            "signature_der",
            "event_digest",
        ] {
            assert!(!first_text.contains(private), "history disclosed {private}");
        }
        let first: Value = serde_json::from_str(&first_text).unwrap();
        let entries = first["deliveries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["delivery_id"], ids[0].to_string());
        assert_eq!(entries[0]["status"], "succeeded");
        assert_eq!(entries[0]["attempt_count"], 2);
        assert_eq!(entries[0]["next_attempt_at_ms"], Value::Null);
        assert_eq!(entries[0]["attempts"][0]["outcome"], "http_error");
        assert_eq!(entries[0]["attempts"][0]["http_status"], 500);
        assert_eq!(entries[0]["attempts"][1]["outcome"], "ack");
        assert_eq!(entries[1]["delivery_id"], ids[1].to_string());
        assert!(entries[1]["next_attempt_at_ms"].is_number());
        assert_eq!(first["next_before"], ids[1].to_string());
        let second = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("{path}?limit=2&before={}", ids[1]),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second = json_body(second).await;
        assert_eq!(second["deliveries"].as_array().unwrap().len(), 2);
        assert_eq!(second["deliveries"][0]["delivery_id"], ids[2].to_string());
        assert_eq!(second["deliveries"][1]["delivery_id"], ids[3].to_string());
        assert_eq!(second["next_before"], Value::Null);
        let default_page = app
            .oneshot(request(
                Method::GET,
                &path,
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(
            json_body(default_page).await["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            4
        );

        admin
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn endpoint_lifecycle_is_tenant_bound_and_retires_queued_deliveries() {
        let Ok(root_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            eprintln!("set ZT_AUTH_TEST_DATABASE_URL to run webhook endpoint database test");
            return;
        };
        let (mut admin, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("webhook_endpoint_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            admin.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(fixture_key()).unwrap());
        let password_a = Uuid::new_v4().to_string();
        let password_b = Uuid::new_v4().to_string();
        let a = register(&mut admin, &hasher, "hook-a@example.test", &password_a)
            .await
            .unwrap();
        let b = register(&mut admin, &hasher, "hook-b@example.test", &password_b)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(&admin, &hasher, "hook-a@example.test", &password_a)
            .await
            .unwrap();
        let sb = login(&admin, &hasher, "hook-b@example.test", &password_b)
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let vault = Arc::new(WebhookSecretVault::new(1, Zeroizing::new(fixture_key())).unwrap());
        let app = router(WebhookHttpState {
            database_url: scoped_url,
            auth_hasher: hasher,
            canonical_origin: "https://test.example".into(),
            vault: vault.clone(),
        });

        let body = json!({"callback_url":"https://hooks.example.org/receive"});
        let anonymous = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/webhooks",
                body.clone(),
                None,
                false,
            ))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let no_csrf = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/webhooks",
                body.clone(),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        let invalid = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/webhooks",
                json!({"callback_url":"https://127.0.0.1/hook"}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let created = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/webhooks",
                body.clone(),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
        let created = json_body(created).await;
        assert_eq!(created["enabled"], false);
        let endpoint: Uuid = created["endpoint_id"].as_str().unwrap().parse().unwrap();
        let first_secret = URL_SAFE_NO_PAD
            .decode(created["signing_secret_b64url"].as_str().unwrap())
            .unwrap();
        assert_eq!(first_secret.len(), 32);
        let stored = admin.query_one("SELECT signing_secret_ciphertext,signing_secret_key_version,enabled FROM webhook_endpoints WHERE id=$1 AND account_id=$2", &[&endpoint, &a.account_id]).await.unwrap();
        let ciphertext: Vec<u8> = stored.get(0);
        assert_ne!(ciphertext, first_secret);
        assert!(!stored.get::<_, bool>(2));
        assert_eq!(
            &*vault
                .open(a.account_id, endpoint, stored.get(1), &ciphertext)
                .unwrap(),
            &first_secret
        );

        let list_b = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/v1/webhooks",
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(
            json_body(list_b).await["endpoints"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let foreign_enable = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/enable"),
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(foreign_enable.status(), StatusCode::NOT_FOUND);
        let enable = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/enable"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(enable.status(), StatusCode::NO_CONTENT);

        let device = Uuid::new_v4();
        let message = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        admin
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
                &[&device, &a.account_id],
            )
            .await
            .unwrap();
        admin.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')", &[&message, &a.account_id, &device, &vec![2_u8; 32], &b"fixture".as_slice(), &vec![3_u8; 32]]).await.unwrap();
        admin.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')", &[&attempt, &a.account_id, &message, &device]).await.unwrap();
        let mut deliveries = Vec::new();
        for (index, status) in ["pending", "leased"].into_iter().enumerate() {
            let event = Uuid::new_v4();
            let delivery = Uuid::new_v4();
            admin.execute("INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) VALUES($1,$2,$3,$4,$5,$6,'captured_local',now(),1,'metadata_only',$7,$8)", &[&event, &a.account_id, &device, &message, &attempt, &((index+1) as i64), &vec![4_u8; 32], &vec![5_u8; 8]]).await.unwrap();
            admin.execute("INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status,attempt_count,lease_owner,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", &[&delivery, &a.account_id, &endpoint, &event, &status, &(if status == "leased" {1_i16} else {0_i16}), &if status == "leased" {Some("worker")} else {None}, &if status == "leased" {Some(std::time::SystemTime::now() + std::time::Duration::from_secs(300))} else {None}]).await.unwrap();
            if status == "leased" {
                admin.execute("INSERT INTO webhook_attempts(id,delivery_id,attempt_number) VALUES($1,$2,1)", &[&Uuid::new_v4(), &delivery]).await.unwrap();
            }
            deliveries.push(delivery);
        }
        let disabled = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/disable"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::NO_CONTENT);
        let outcomes = admin.query("SELECT d.status,a.outcome FROM webhook_deliveries d LEFT JOIN webhook_attempts a ON a.delivery_id=d.id WHERE d.endpoint_id=$1 ORDER BY d.id", &[&endpoint]).await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|row| row.get::<_, String>(0) == "dead"));
        assert!(
            outcomes
                .iter()
                .any(|row| row.get::<_, Option<String>>(1).as_deref() == Some("policy_rejected"))
        );
        let reenable = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/enable"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(reenable.status(), StatusCode::NO_CONTENT);
        let stale = admin
            .query_one(
                "SELECT count(*) FROM webhook_deliveries WHERE endpoint_id=$1 AND status<>'dead'",
                &[&endpoint],
            )
            .await
            .unwrap();
        assert_eq!(stale.get::<_, i64>(0), 0);
        let rotated = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/rotate"),
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let rotated = json_body(rotated).await;
        assert_eq!(rotated["enabled"], false);
        assert_ne!(
            rotated["signing_secret_b64url"],
            created["signing_secret_b64url"]
        );
        let list_a = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/v1/webhooks",
                json!({}),
                Some((&sa.token, &sa.csrf_token)),
                false,
            ))
            .await
            .unwrap();
        let list_text =
            String::from_utf8(to_bytes(list_a.into_body(), 4096).await.unwrap().to_vec()).unwrap();
        assert!(!list_text.contains("signing_secret"));
        assert_eq!(
            serde_json::from_str::<Value>(&list_text).unwrap()["endpoints"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let foreign_rotate = app
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{endpoint}/rotate"),
                json!({}),
                Some((&sb.token, &sb.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(foreign_rotate.status(), StatusCode::NOT_FOUND);
        for _ in 1..MAX_ENDPOINTS_PER_ACCOUNT {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    "/v1/webhooks",
                    body.clone(),
                    Some((&sa.token, &sa.csrf_token)),
                    true,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let excess = app
            .oneshot(request(
                Method::POST,
                "/v1/webhooks",
                body,
                Some((&sa.token, &sa.csrf_token)),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(excess.status(), StatusCode::CONFLICT);

        admin
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
