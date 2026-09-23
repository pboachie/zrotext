// SPDX-License-Identifier: AGPL-3.0-only
//! Private synthetic-alpha message routes. The caller can select only a short
//! test-case identifier; this module constructs the fixed plaintext body.
//! Never mount as a general customer message-content endpoint.

use crate::{
    alpha_policy::AlphaPolicy,
    auth::{self, AuthError, Scope, TokenHasher},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};
use zrotext_domain::MessageState;

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_BODY_BYTES: usize = 1024;
const MAX_EXPIRY_MS: i64 = 15 * 60 * 1000;

#[derive(Clone)]
pub struct MessagesHttpState {
    database_url: String,
    hasher: Arc<TokenHasher>,
    policy: Arc<AlphaPolicy>,
}

impl MessagesHttpState {
    /// The runtime supplies a fail-closed policy with consented account and
    /// recipient allowlists from private configuration.
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        policy: Arc<AlphaPolicy>,
    ) -> Result<Self, &'static str> {
        if database_url.is_empty() {
            return Err("message database URL is required");
        }
        Ok(Self {
            database_url,
            hasher,
            policy,
        })
    }
}

pub fn router(state: MessagesHttpState) -> Router {
    Router::new()
        .route("/messages", post(accept))
        .route("/messages/{message_id}", get(status))
        .route("/messages/{message_id}/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(state))
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

#[derive(Debug)]
enum MessageHttpError {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
}

impl IntoResponse for MessageHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        (status, Json(ErrorBody { code })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn map_auth(error: AuthError) -> MessageHttpError {
    match error {
        AuthError::Unauthorized | AuthError::InvalidCredentials => MessageHttpError::Unauthorized,
        AuthError::Forbidden | AuthError::EmailNotVerified => MessageHttpError::Forbidden,
        AuthError::InvalidInput => MessageHttpError::BadRequest,
        AuthError::Database(_) | AuthError::Password => MessageHttpError::Unavailable,
    }
}

fn map_store(error: StoreError) -> MessageHttpError {
    match error {
        StoreError::InvalidInput => MessageHttpError::BadRequest,
        StoreError::IdempotencyConflict
        | StoreError::MessageIdConflict
        | StoreError::InvalidTransition => MessageHttpError::Conflict,
        StoreError::NotFound | StoreError::Revoked => MessageHttpError::NotFound,
        StoreError::Database(_) | StoreError::DispatchDisabled | StoreError::StaleFence => {
            MessageHttpError::Unavailable
        }
        StoreError::DeviceBusy | StoreError::EventIdConflict => MessageHttpError::Conflict,
    }
}

async fn connect(database_url: &str) -> Result<Client, MessageHttpError> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .map_err(|_| MessageHttpError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn bearer(headers: &HeaderMap) -> Result<&str, MessageHttpError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(MessageHttpError::Unauthorized)?;
    if values.next().is_some() {
        return Err(MessageHttpError::Unauthorized);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(' '))
        .ok_or(MessageHttpError::Unauthorized)
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, MessageHttpError> {
    let mut values = headers.get_all(IDEMPOTENCY_HEADER).iter();
    let value = values.next().ok_or(MessageHttpError::BadRequest)?;
    if values.next().is_some() {
        return Err(MessageHttpError::BadRequest);
    }
    value
        .to_str()
        .ok()
        .filter(|value| {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        })
        .ok_or(MessageHttpError::BadRequest)
}

fn valid_e164(number: &str) -> bool {
    number.starts_with('+')
        && (3..=16).contains(&number.len())
        && number.as_bytes()[1] != b'0'
        && number.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

fn now_ms() -> Result<i64, MessageHttpError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MessageHttpError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| MessageHttpError::Unavailable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptBody {
    client_message_id: Uuid,
    device_id: Uuid,
    recipient_e164: String,
    test_case_id: String,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct AcceptedBody {
    message_id: Uuid,
    created: bool,
}

async fn accept(
    State(state): State<Arc<MessagesHttpState>>,
    headers: HeaderMap,
    Json(body): Json<AcceptBody>,
) -> Result<Response, MessageHttpError> {
    if !state.policy.enabled() {
        return Err(MessageHttpError::NotFound);
    }
    let token = bearer(&headers)?;
    let key = idempotency_key(&headers)?;
    if !valid_e164(&body.recipient_e164)
        || body.test_case_id.is_empty()
        || body.test_case_id.len() > 32
        || !body
            .test_case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(MessageHttpError::BadRequest);
    }
    let now = now_ms()?;
    if body.expires_at_ms <= now || body.expires_at_ms > now + MAX_EXPIRY_MS {
        return Err(MessageHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, token)
        .await
        .map_err(map_auth)?;
    principal
        .require(Scope::MessagesSend, Some(body.device_id))
        .map_err(map_auth)?;
    let account_id = principal.tenant.account_id();
    if !state.policy.allows(account_id, &body.recipient_e164) {
        return Err(MessageHttpError::NotFound);
    }
    let active = client
        .query_opt(
            "SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL",
            &[&account_id, &body.device_id],
        )
        .await
        .map_err(|_| MessageHttpError::Unavailable)?
        .is_some();
    if !active {
        return Err(MessageHttpError::NotFound);
    }
    let synthetic_body = format!("ZROtext synthetic test: {}", body.test_case_id);
    let outcome = DeliveryStore::new(&mut client)
        .accept(NewMessage {
            account_id,
            client_message_id: body.client_message_id,
            device_id: body.device_id,
            idempotency_key: key,
            recipient_e164: &body.recipient_e164,
            synthetic_payload: synthetic_body.as_bytes(),
            expires_at_ms: body.expires_at_ms,
        })
        .await
        .map_err(map_store)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedBody {
            message_id: outcome.message_id,
            created: outcome.created,
        }),
    )
        .into_response())
}

#[derive(Serialize)]
struct StatusBody {
    message_id: Uuid,
    device_id: Uuid,
    state: MessageState,
    state_version: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

async fn status(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<StatusBody>, MessageHttpError> {
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, bearer(&headers)?)
        .await
        .map_err(map_auth)?;
    let snapshot = DeliveryStore::new(&mut client)
        .status(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
        .ok_or(MessageHttpError::NotFound)?;
    principal
        .require(Scope::MessagesRead, Some(snapshot.device_id))
        .map_err(map_auth)?;
    Ok(Json(StatusBody {
        message_id,
        device_id: snapshot.device_id,
        state: snapshot.state,
        state_version: snapshot.state_version,
        created_at_ms: snapshot.created_at_ms,
        updated_at_ms: snapshot.updated_at_ms,
    }))
}

async fn cancel(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, MessageHttpError> {
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, bearer(&headers)?)
        .await
        .map_err(map_auth)?;
    let snapshot = DeliveryStore::new(&mut client)
        .status(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
        .ok_or(MessageHttpError::NotFound)?;
    principal
        .require(Scope::MessagesSend, Some(snapshot.device_id))
        .map_err(map_auth)?;
    if DeliveryStore::new(&mut client)
        .cancel(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(MessageHttpError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    fn post(path: &str, token: &str, key: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(IDEMPOTENCY_HEADER, key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn owner(
        client: &mut Client,
        hasher: &TokenHasher,
        email: &str,
    ) -> (Uuid, Uuid, String, String, String) {
        let signup = auth::register(client, hasher, email, "correct horse 123")
            .await
            .unwrap();
        assert!(
            auth::verify_email(client, hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let session = auth::login(client, hasher, email, "correct horse 123")
            .await
            .unwrap();
        let principal = auth::authenticate_session(client, hasher, &session.token)
            .await
            .unwrap();
        let device_id = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
                &[&device_id, &signup.account_id],
            )
            .await
            .unwrap();
        let send = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesSend],
            Some(device_id),
            None,
        )
        .await
        .unwrap();
        let read = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesRead],
            Some(device_id),
            None,
        )
        .await
        .unwrap();
        let unbound_send = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesSend],
            None,
            None,
        )
        .await
        .unwrap();
        (
            signup.account_id,
            device_id,
            send.token,
            read.token,
            unbound_send.token,
        )
    }

    #[test]
    fn bearer_and_case_id_inputs_are_strict() {
        let mut headers = HeaderMap::new();
        assert!(bearer(&headers).is_err());
        headers.append(header::AUTHORIZATION, "Bearer ztk_one".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer ztk_two".parse().unwrap());
        assert!(bearer(&headers).is_err());
        assert!(valid_e164("+15555550101"));
        assert!(!valid_e164("+0123"));
        assert!(!valid_e164("+1 555"));
    }

    #[tokio::test]
    async fn postgres_alpha_http_accept_status_cancel_are_tenant_and_device_scoped() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_messages_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(vec![51; 32]).unwrap());
        let (account_a, device_a, send_a, read_a, unbound_send_a) =
            owner(&mut client, &hasher, "owner-a@example.test").await;
        let (_, device_b, _send_b, read_b, _) =
            owner(&mut client, &hasher, "owner-b@example.test").await;
        let policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                Some(&account_a.to_string()),
                Some("+15555550101"),
            )
            .unwrap(),
        );
        let app = router(MessagesHttpState::new(url.clone(), hasher.clone(), policy).unwrap());
        let message_id = Uuid::new_v4();
        let input = serde_json::json!({
            "client_message_id":message_id,
            "device_id":device_a,
            "recipient_e164":"+15555550101",
            "test_case_id":"case_1",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let missing_auth = Request::builder()
            .method("POST")
            .uri("/messages")
            .header(IDEMPOTENCY_HEADER, "case-0")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(input.to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(missing_auth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "case-1", input.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let accepted: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(accepted["message_id"], message_id.to_string());
        assert_eq!(accepted["created"], true);
        assert!(!String::from_utf8_lossy(&data).contains("+15555550101"));
        assert!(!String::from_utf8_lossy(&data).contains("synthetic test"));
        let saved: String = client
            .query_one(
                "SELECT convert_from(transport_payload,'UTF8') FROM messages WHERE id=$1",
                &[&message_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(saved, "ZROtext synthetic test: case_1");
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "case-1", input.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let replay: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(replay["created"], false);
        let mut changed = input.clone();
        changed["test_case_id"] = "changed".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-1", changed))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let mut bad_device = input.clone();
        bad_device["client_message_id"] = Uuid::new_v4().to_string().into();
        bad_device["device_id"] = device_b.to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-2", bad_device.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &unbound_send_a, "case-2", bad_device))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut wrong_number = input.clone();
        wrong_number["client_message_id"] = Uuid::new_v4().to_string().into();
        wrong_number["recipient_e164"] = "+15555550102".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-3", wrong_number))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &read_a, "case-4", input.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut arbitrary_plaintext = input.clone();
        arbitrary_plaintext["test_case_id"] = "hello world".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-5", arbitrary_plaintext))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let path = format!("/messages/{message_id}");
        let response = app.clone().oneshot(get(&path, &read_a)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(snapshot["state"], "queued");
        assert!(!String::from_utf8_lossy(&data).contains("+15555550101"));
        assert!(!String::from_utf8_lossy(&data).contains("synthetic test"));
        assert_eq!(
            app.clone()
                .oneshot(get(&path, &read_b))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let response = app
            .clone()
            .oneshot(post(
                &format!("{path}/cancel"),
                &send_a,
                "unused",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            app.clone()
                .oneshot(post(
                    &format!("{path}/cancel"),
                    &send_a,
                    "unused",
                    serde_json::json!({})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        client
            .execute(
                "UPDATE devices SET revoked_at=now() WHERE account_id=$1 AND id=$2",
                &[&account_a, &device_a],
            )
            .await
            .unwrap();
        let mut revoked_device_input = input.clone();
        revoked_device_input["client_message_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-7", revoked_device_input))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let disabled = router(
            MessagesHttpState::new(
                url,
                hasher,
                Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            )
            .unwrap(),
        );
        assert_eq!(
            disabled
                .oneshot(post("/messages", &send_a, "case-6", input))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
