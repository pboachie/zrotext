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
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio_postgres::{Client, error::SqlState};
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
            "/v1/inbound/messages/{message_id}/events",
            get(list_inbound_events),
        )
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
    let (client, connection) = crate::runtime_db::connect(&state.database_url)
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
    paused_at_ms: Option<i64>,
    failure_started_at_ms: Option<i64>,
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
            "SELECT id,callback_url,enabled, \
             (extract(epoch FROM paused_at)*1000)::bigint, \
             (extract(epoch FROM failure_started_at)*1000)::bigint, \
             (extract(epoch FROM created_at)*1000)::bigint \
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
                    paused_at_ms: row.get(3),
                    failure_started_at_ms: row.get(4),
                    created_at_ms: row.get(5),
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

#[derive(Serialize)]
struct InboundEventView {
    event_id: Uuid,
    device_id: Uuid,
    attempt_id: Uuid,
    classification: String,
    observed_at_ms: i64,
    received_at_ms: i64,
    part_count: i16,
    content_kind: String,
}

#[derive(Serialize)]
struct InboundHistoryResponse {
    events: Vec<InboundEventView>,
    next_before: Option<Uuid>,
}

async fn list_inbound_events(
    State(state): State<Arc<WebhookHttpState>>,
    Path(message_id): Path<Uuid>,
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
    match inbound_history(&client, principal.tenant.account_id(), message_id, query).await {
        Ok(page) => Json(page).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn inbound_history(
    client: &Client,
    account_id: Uuid,
    message_id: Uuid,
    query: HistoryQuery,
) -> Result<InboundHistoryResponse, EndpointError> {
    let limit = query.limit.unwrap_or(MAX_HISTORY_PAGE);
    if !(1..=MAX_HISTORY_PAGE).contains(&limit) {
        return Err(EndpointError::BadRequest);
    }
    let message = client
        .query_opt(
            "SELECT id FROM messages WHERE account_id=$1 AND id=$2",
            &[&account_id, &message_id],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    if message.is_none() {
        return Err(EndpointError::NotFound);
    }
    let anchor: Option<(std::time::SystemTime, Uuid)> = match query.before {
        Some(before) => {
            let row = client.query_opt(
                "SELECT received_at,id FROM inbound_events WHERE account_id=$1 AND message_id=$2 AND id=$3",
                &[&account_id, &message_id, &before],
            ).await.map_err(|_| EndpointError::Unavailable)?.ok_or(EndpointError::NotFound)?;
            Some((row.get(0), row.get(1)))
        }
        None => None,
    };
    let anchor_time = anchor.as_ref().map(|(time, _)| *time);
    let anchor_id = anchor.map(|(_, id)| id);
    let rows = client
        .query(
            "SELECT id,device_id,attempt_id,classification, \
         (extract(epoch FROM observed_at)*1000)::bigint, \
         (extract(epoch FROM received_at)*1000)::bigint,part_count,content_kind \
         FROM inbound_events WHERE account_id=$1 AND message_id=$2 \
         AND ($3::timestamptz IS NULL OR (received_at,id)<($3,$4)) \
         ORDER BY received_at DESC,id DESC LIMIT $5",
            &[
                &account_id,
                &message_id,
                &anchor_time,
                &anchor_id,
                &(i64::from(limit) + 1),
            ],
        )
        .await
        .map_err(|_| EndpointError::Unavailable)?;
    let has_more = rows.len() > usize::from(limit);
    let events: Vec<InboundEventView> = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| InboundEventView {
            event_id: row.get(0),
            device_id: row.get(1),
            attempt_id: row.get(2),
            classification: row.get(3),
            observed_at_ms: row.get(4),
            received_at_ms: row.get(5),
            part_count: row.get(6),
            content_kind: row.get(7),
        })
        .collect();
    let next_before = if has_more {
        events.last().map(|event| event.event_id)
    } else {
        None
    };
    Ok(InboundHistoryResponse {
        events,
        next_before,
    })
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
    rng().fill_bytes(secret.as_mut());
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
        "UPDATE webhook_endpoints SET enabled=true,paused_at=NULL,failure_started_at=NULL \
         WHERE account_id=$1 AND id=$2",
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
    rng().fill_bytes(secret.as_mut());
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
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests;
