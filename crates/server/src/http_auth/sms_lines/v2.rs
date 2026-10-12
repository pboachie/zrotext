// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit v2 routes. The existing URL and body shapes continue to issue v1.
use super::*;
use crate::sealed_inbound::line_activation::{
    LineActivationError,
    v2_runtime::{self as runtime, Purpose},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;

runtime::object_body! { pub(crate) struct OpenBody {device_id:String,opening_id:String} }
runtime::object_body! { pub(crate) struct ApproveBody {owner_signature_der_b64url:String} }
fn id(s: &str) -> Result<Uuid, AuthHttpError> {
    let id = Uuid::parse_str(s).map_err(|_| AuthHttpError::BadRequest)?;
    if id.is_nil() || id.to_string() != s {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(id)
}
fn signature(s: &str) -> Result<Vec<u8>, AuthHttpError> {
    if s.is_empty()
        || s.len() > 107
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(AuthHttpError::BadRequest);
    }
    let bytes = B.decode(s).map_err(|_| AuthHttpError::BadRequest)?;
    let der = p256::ecdsa::Signature::from_der(&bytes).map_err(|_| AuthHttpError::BadRequest)?;
    if !(8..=80).contains(&bytes.len()) || B.encode(&bytes) != s || der.to_der().as_bytes() != bytes
    {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(bytes)
}
fn error(e: LineActivationError) -> AuthHttpError {
    match e {
        LineActivationError::InvalidInput => AuthHttpError::BadRequest,
        LineActivationError::Unavailable => AuthHttpError::Forbidden,
        LineActivationError::Database(_) => AuthHttpError::Unavailable,
    }
}
pub(crate) async fn open(
    State(s): State<Arc<AuthHttpState>>,
    _gate: SmsLinesGate,
    Path(line): Path<String>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(b): ApiJson<OpenBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthHttpError> {
    require_enabled(&s)?;
    let line = id(&line)?;
    let device = id(&b.device_id)?;
    let opening = id(&b.opening_id)?;
    let mut db = connect(&s.database_url).await?;
    charge(&db, &s, &p).await?;
    let c = runtime::open(&mut db, &p, line, device, Purpose::Sms, opening, None)
        .await
        .map_err(error)?;
    Ok((
        StatusCode::CREATED,
        Json(
            serde_json::json!({"challenge_id":c.tuple.id,"account_id":c.tuple.account_id,"line_id":line,"device_id":device,"generation":c.tuple.generation.to_string(),"expires_at_ms":c.expires_at_ms}),
        ),
    ))
}
pub(crate) async fn view(
    State(s): State<Arc<AuthHttpState>>,
    _gate: SmsLinesGate,
    Path((line, challenge)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthHttpError> {
    require_enabled(&s)?;
    let line = id(&line)?;
    let challenge = id(&challenge)?;
    crate::http_auth::require_session_cookie(&headers)?;
    let mut db = connect(&s.database_url).await?;
    let p = require_owner(&db, &s.hasher, &s.canonical_origin, &headers, false).await?;
    let csrf_cookie = cookie(&headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    p.require_csrf_token(&s.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let v = runtime::view(&mut db, &p, line, challenge, Purpose::Sms)
        .await
        .map_err(error)?;
    Ok(Json(view_json(v)))
}
fn view_json(v: runtime::View) -> serde_json::Value {
    serde_json::json!({"challenge_id":v.challenge_id,"device_id":v.device_id,"generation":v.generation.to_string(),"expires_at_ms":v.expires_at_ms,"status":v.status,"observation_b64url":v.observation.map(|x|B.encode(x)),"device_statement_b64url":v.device_statement.map(|x|B.encode(x)),"device_signature_der_b64url":v.device_signature_der.map(|x|B.encode(x)),"owner_statement_b64url":v.owner_statement.map(|x|B.encode(x))})
}
pub(crate) async fn approve(
    State(s): State<Arc<AuthHttpState>>,
    _gate: SmsLinesGate,
    Path((line, challenge)): Path<(String, String)>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(b): ApiJson<ApproveBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_enabled(&s)?;
    let line = id(&line)?;
    let challenge = id(&challenge)?;
    let signature = signature(&b.owner_signature_der_b64url)?;
    let mut db = connect(&s.database_url).await?;
    charge(&db, &s, &p).await?;
    runtime::approve(&mut db, &p, line, challenge, Purpose::Sms, &signature)
        .await
        .map_err(error)?;
    crate::device_socket::wake_sms_line_activation();
    Ok(StatusCode::NO_CONTENT)
}
#[cfg(test)]
mod tests;
