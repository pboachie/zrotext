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
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 4096;
const MAX_ENDPOINTS_PER_ACCOUNT: i64 = 8;

pub struct WebhookHttpState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    pub vault: Arc<WebhookSecretVault>,
}

pub fn router(state: WebhookHttpState) -> Router {
    Router::new()
        .route("/v1/webhooks", get(list_endpoints).post(create_endpoint))
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
    Unavailable,
}

impl IntoResponse for EndpointError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_webhook_endpoint"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Limit => (StatusCode::CONFLICT, "endpoint_limit"),
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
        "UPDATE webhook_deliveries SET status='dead',lease_owner=NULL,lease_until=NULL, \
         updated_at=now() WHERE account_id=$1 AND endpoint_id=$2 \
         AND status IN ('pending','leased')",
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
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
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
        ] {
            admin.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(vec![31; 32]).unwrap());
        let a = register(
            &mut admin,
            &hasher,
            "hook-a@example.test",
            "correct horse 123",
        )
        .await
        .unwrap();
        let b = register(
            &mut admin,
            &hasher,
            "hook-b@example.test",
            "correct horse 456",
        )
        .await
        .unwrap();
        verify_email(&mut admin, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut admin, &hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(&admin, &hasher, "hook-a@example.test", "correct horse 123")
            .await
            .unwrap();
        let sb = login(&admin, &hasher, "hook-b@example.test", "correct horse 456")
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let vault = Arc::new(WebhookSecretVault::new(1, Zeroizing::new(vec![7_u8; 32])).unwrap());
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
