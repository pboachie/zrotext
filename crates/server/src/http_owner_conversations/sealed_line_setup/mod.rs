// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit setup adapter. The default startup never mounts it. The separate
//! opt-in composition validates the installed schema and returns an unspawned
//! retention lane. Numbered draft migrations require final coordinator assignment.
pub mod lifecycle;
pub mod registration;
mod retention;
use super::OwnerConversationsState;
use crate::sealed_inbound::line_activation::sealed_exchange as exchange;
use crate::{
    api_json::ApiJson,
    auth::{TokenHasher, mfa::MfaCipher},
    http_auth::preauth::{OwnerAuthState, OwnerMutation},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD as B};
pub use retention::Retention;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone)]
pub struct SetupState {
    pub owner: OwnerConversationsState,
    pub mfa_cipher: Arc<MfaCipher>,
}
impl OwnerAuthState for SetupState {
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
pub fn router(state: SetupState) -> Router {
    Router::new()
        .route(
            "/v1/owner/conversation/sealed-line/bootstrap",
            post(bootstrap),
        )
        .route(
            "/v1/owner/conversation/sealed-line/owner-key/challenge",
            post(challenge),
        )
        .route(
            "/v1/owner/conversation/sealed-line/owner-key/{challenge_id}/complete",
            post(complete),
        )
        .route(
            "/v1/owner/conversation/sealed-line/owner-key/{challenge_id}/status",
            post(status),
        )
        .route(
            "/v1/owner/conversation/sealed-line/{line_id}/challenges",
            post(open),
        )
        .route(
            "/v1/owner/conversation/sealed-line/{line_id}/challenges/{challenge_id}/view",
            post(view),
        )
        .route(
            "/v1/owner/conversation/sealed-line/{line_id}/challenges/{challenge_id}/approve",
            post(approve),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(super::no_store))
        .with_state(Arc::new(state))
}
fn fail() -> Response {
    StatusCode::FORBIDDEN.into_response()
}
fn error(e: crate::sealed_root_ceremony::CeremonyError) -> Response {
    match e {
        crate::sealed_root_ceremony::CeremonyError::Database(_) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        crate::sealed_root_ceremony::CeremonyError::Authentication(_) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => fail(),
    }
}
fn xerror(e: exchange::ExchangeError) -> Response {
    match e {
        exchange::ExchangeError::Database(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        exchange::ExchangeError::NotFound => StatusCode::NOT_FOUND.into_response(),
        exchange::ExchangeError::InvalidInput => StatusCode::BAD_REQUEST.into_response(),
        _ => fail(),
    }
}
fn decode<const N: usize>(s: &str) -> Result<[u8; N], StatusCode> {
    let b = decode_bytes(s, N)?;
    b.try_into().map_err(|_| StatusCode::BAD_REQUEST)
}
fn decode_bytes(s: &str, max: usize) -> Result<Vec<u8>, StatusCode> {
    if s.len() > max.div_ceil(3) * 4 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let b = B.decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    if b.len() > max || B.encode(&b) != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(b)
}
fn number(s: &str) -> Result<i64, StatusCode> {
    let n = s.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST)?;
    if n <= 0 || n.to_string() != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(n)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    expected_session_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    expected_session_id: Uuid,
    device_id: Uuid,
    line_id: Uuid,
}
async fn bootstrap(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(b): ApiJson<Bootstrap>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match registration::bootstrap(&mut db, &p, b.device_id, b.line_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    expected_session_id: Uuid,
    device_id: Uuid,
    line_id: Uuid,
    expected_next_binding_generation: String,
    expected_root_fingerprint: String,
    current_device_signing_fingerprint: String,
    approval_point: String,
    connection_epoch: String,
    deployment_epoch: String,
    site_id: String,
    instance_id: String,
}
async fn challenge(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(b): ApiJson<Challenge>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let selection = (|| {
        Ok::<_, StatusCode>(registration::Selection {
            device: b.device_id,
            line: b.line_id,
            generation: number(&b.expected_next_binding_generation)?,
            root_fingerprint: decode(&b.expected_root_fingerprint)?,
            paired_fingerprint: decode(&b.current_device_signing_fingerprint)?,
            approval_point: decode(&b.approval_point)?,
            connection_epoch: number(&b.connection_epoch)?,
            deployment_epoch: number(&b.deployment_epoch)?,
            site_id: b.site_id,
            instance_id: b.instance_id,
        })
    })();
    let selection = match selection {
        Ok(x) => x,
        Err(e) => return e.into_response(),
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match registration::issue(&mut db, &p, &s.owner.canonical_origin, selection).await {
        Ok(statement) => {
            let scope = statement.scope();
            Json(serde_json::json!({"challenge_id":Uuid::from_bytes(scope.challenge),"unsigned_statement":B.encode(zrotext_root_material::line_key_registration::encode(&statement).expect("validated statement")),"issued_ms":scope.issued_ms.to_string(),"expires_ms":scope.expires_ms.to_string(),"root_pin":B.encode(statement.root_pin()),"root_fingerprint":B.encode(statement.root_fingerprint()),"current_device_signing_fingerprint":B.encode(scope.paired_signing_fingerprint),"approval_fingerprint":B.encode(scope.approval_fingerprint)})).into_response()
        }
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    expected_session_id: Uuid,
    unsigned_statement: String,
    root_signature: String,
    approval_signature: String,
    factor: String,
}
async fn complete(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path(id): Path<Uuid>,
    ApiJson(b): ApiJson<Complete>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let bytes = match decode_bytes(&b.unsigned_statement, 1024) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let signatures = (
        decode::<64>(&b.root_signature),
        decode::<64>(&b.approval_signature),
    );
    let (root, approval) = match signatures {
        (Ok(r), Ok(a)) => (r, a),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(e) = registration::complete(
        &mut db,
        &p,
        &s.owner.canonical_origin,
        &s.owner.auth_hasher,
        &s.mfa_cipher,
        id,
        registration::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor: &b.factor,
        },
    )
    .await
    {
        return error(e);
    }
    match registration::receipt(&mut db, &p, id).await {
        Ok(receipt) => Json(serde_json::json!({"receipt":receipt})).into_response(),
        Err(e) => error(e),
    }
}
async fn status(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path(id): Path<Uuid>,
    ApiJson(b): ApiJson<Session>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match registration::receipt(&mut db, &p, id).await {
        Ok(Some(receipt)) => {
            Json(serde_json::json!({"receipt":receipt,"pending":null})).into_response()
        }
        Ok(None) => {
            match registration::pending_context(&mut db, &p, id, &s.owner.canonical_origin).await {
                Ok(pending) => {
                    Json(serde_json::json!({"receipt":null,"pending":pending})).into_response()
                }
                Err(e) => error(e),
            }
        }
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    expected_session_id: Uuid,
    device_id: Uuid,
    registration_id: Uuid,
}
async fn open(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path(line): Path<Uuid>,
    ApiJson(b): ApiJson<Open>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match exchange::open(&mut db,&p,line,b.device_id,b.registration_id).await {Ok((c,expiry))=>Json(serde_json::json!({"challenge_id":c.id,"account_id":c.account_id,"line_id":c.line_id,"device_id":c.device_id,"binding_generation":c.generation.to_string(),"nonce":B.encode(c.nonce),"expires_ms":expiry.to_string(),"status":"awaiting_device","phone_acknowledged":false})).into_response(),Err(e)=>xerror(e)}
}
async fn view(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path((line, id)): Path<(Uuid, Uuid)>,
    ApiJson(b): ApiJson<Session>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match exchange::view(&mut db,&p,line,id).await {Ok(v)=>Json(serde_json::json!({"challenge_id":id,"line_id":line,"device_id":v.device_id,"binding_generation":v.generation.to_string(),"expires_ms":v.expires_at_ms.to_string(),"status":v.status.label(),"phone_acknowledged":v.phone_acknowledged,"observation":v.observation.map(|o|serde_json::json!({"android_api_level":o.android_api_level,"active_subscription_count":o.active_subscription_count,"selected_subscription_id":o.selected_subscription_id})),"device_statement":v.device_statement.map(|x|B.encode(x)),"device_signature_der":v.device_signature_der.map(|x|B.encode(x)),"owner_statement":v.owner_statement.map(|x|B.encode(x))})).into_response(),Err(e)=>xerror(e)}
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approve {
    expected_session_id: Uuid,
    owner_signature_der: String,
}
async fn approve(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path((line, id)): Path<(Uuid, Uuid)>,
    ApiJson(b): ApiJson<Approve>,
) -> Response {
    if b.expected_session_id != p.session_id {
        return fail();
    }
    let signature = match decode_bytes(&b.owner_signature_der, 80) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match exchange::approve(&mut db, &p, line, id, &signature).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => xerror(e),
    }
}
#[cfg(test)]
pub(crate) mod tests;

#[cfg(all(test, feature = "conversation-simulator-tests"))]
mod server_browser_fixture;
