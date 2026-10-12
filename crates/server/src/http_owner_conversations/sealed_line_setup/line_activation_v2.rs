// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit registered SEALED v2 owner routes; no default composition mount.
use super::*;
use crate::sealed_inbound::line_activation::{
    LineActivationError,
    v2_runtime::{self as runtime, Purpose},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as V2;
runtime::object_body! { pub(super) struct Open {expected_session_id:String,device_id:String,registration_id:String} }
runtime::object_body! { pub(super) struct Session {expected_session_id:String} }
runtime::object_body! { pub(super) struct Approve {expected_session_id:String,owner_signature_der_b64url:String} }
fn id(s: &str) -> Result<Uuid, StatusCode> {
    let id = Uuid::parse_str(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    if id.is_nil() || id.to_string() != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(id)
}
fn signature(s: &str) -> Result<Vec<u8>, StatusCode> {
    if s.is_empty()
        || s.len() > 107
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = V2.decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = p256::ecdsa::Signature::from_der(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !(8..=80).contains(&bytes.len())
        || V2.encode(&bytes) != s
        || sig.to_der().as_bytes() != bytes
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
fn error(e: LineActivationError) -> Response {
    match e {
        LineActivationError::Database(_) => StatusCode::SERVICE_UNAVAILABLE,
        LineActivationError::InvalidInput => StatusCode::BAD_REQUEST,
        LineActivationError::Unavailable => StatusCode::FORBIDDEN,
    }
    .into_response()
}
pub(super) async fn open(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path(line): Path<String>,
    ApiJson(b): ApiJson<Open>,
) -> Response {
    let ids = (|| {
        Ok::<_, StatusCode>((
            id(&line)?,
            id(&b.device_id)?,
            id(&b.registration_id)?,
            id(&b.expected_session_id)?,
        ))
    })();
    let (line, device, registration, session) = match ids {
        Ok(ids) => ids,
        Err(e) => return e.into_response(),
    };
    if session != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match runtime::open(&mut db,&p,line,device,Purpose::Sealed,registration,Some(registration)).await {
        Ok(c)=>Json(serde_json::json!({"challenge_id":c.tuple.id,"account_id":c.tuple.account_id,"line_id":line,"device_id":device,"generation":c.tuple.generation.to_string(),"expires_at_ms":c.expires_at_ms,"status":"awaiting_device","phone_acknowledged":false})).into_response(),
        Err(e)=>error(e),
    }
}
pub(super) async fn view(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path((line, challenge)): Path<(String, String)>,
    ApiJson(b): ApiJson<Session>,
) -> Response {
    let ids =
        (|| Ok::<_, StatusCode>((id(&line)?, id(&challenge)?, id(&b.expected_session_id)?)))();
    let (line, challenge, session) = match ids {
        Ok(ids) => ids,
        Err(e) => return e.into_response(),
    };
    if session != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match runtime::view(&mut db,&p,line,challenge,Purpose::Sealed).await {
        Ok(v)=>Json(serde_json::json!({"challenge_id":v.challenge_id,"device_id":v.device_id,"generation":v.generation.to_string(),"expires_at_ms":v.expires_at_ms,"status":v.status,"phone_acknowledged":v.phone_acknowledged,"observation_b64url":v.observation.map(|x|V2.encode(x)),"device_statement_b64url":v.device_statement.map(|x|V2.encode(x)),"device_signature_der_b64url":v.device_signature_der.map(|x|V2.encode(x)),"owner_statement_b64url":v.owner_statement.map(|x|V2.encode(x))})).into_response(),
        Err(e)=>error(e),
    }
}
pub(super) async fn approve(
    State(s): State<Arc<SetupState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    Path((line, challenge)): Path<(String, String)>,
    ApiJson(b): ApiJson<Approve>,
) -> Response {
    let ids = (|| {
        Ok::<_, StatusCode>((
            id(&line)?,
            id(&challenge)?,
            id(&b.expected_session_id)?,
            signature(&b.owner_signature_der_b64url)?,
        ))
    })();
    let (line, challenge, session, signature) = match ids {
        Ok(ids) => ids,
        Err(e) => return e.into_response(),
    };
    if session != p.session_id {
        return fail();
    }
    let Ok(mut db) = crate::runtime_db::connect(&s.owner.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match runtime::approve(&mut db, &p, line, challenge, Purpose::Sealed, &signature).await {
        Ok(()) => {
            crate::device_socket::wake_sms_line_activation();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests;
