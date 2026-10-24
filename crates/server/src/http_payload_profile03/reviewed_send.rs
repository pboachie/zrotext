// SPDX-License-Identifier: AGPL-3.0-only
//! Optional real reviewed03 owner admission. A queue receipt supplies no grant
//! or radio permission; existing main routes do not mount this library router.
use super::*;
use crate::reviewed_intent03::live as reviewed;
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
object_body! {struct Send{v:u8,envelope:String,reviewed_intent:String,reviewed_signature:String}}
object_body! {struct Status{v:u8,message_id:String,interval_id:String,envelope_sha256:String,reviewed_intent_sha256:String,reviewed_signature_sha256:String}}
enum Input {
    Send {
        envelope: Vec<u8>,
        intent: Vec<u8>,
        signature: Vec<u8>,
    },
    Status(reviewed::Status03),
}
fn hash(raw: &str) -> Result<[u8; 32], StatusCode> {
    let bytes: [u8; 32] = request::binary(raw, 32, 32)?.try_into().unwrap();
    if bytes == [0; 32] {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
fn parse(status: bool, raw: &[u8]) -> Result<Input, StatusCode> {
    if raw.is_empty() || raw.len() > 96 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if status {
        let b: Status = serde_json::from_slice(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
        request::version(b.v)?;
        Ok(Input::Status(reviewed::Status03 {
            message: request::id(&b.message_id)?,
            interval: request::id(&b.interval_id)?,
            envelope: hash(&b.envelope_sha256)?,
            intent: hash(&b.reviewed_intent_sha256)?,
            signature: hash(&b.reviewed_signature_sha256)?,
        }))
    } else {
        let b: Send = serde_json::from_slice(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
        request::version(b.v)?;
        let intent = request::binary(&b.reviewed_intent, 592, 803)?;
        crate::reviewed_intent03::v2::Intent03V2::decode(&intent)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        Ok(Input::Send {
            envelope: request::binary(&b.envelope, 557, 34213)?,
            intent,
            signature: request::binary(&b.reviewed_signature, 64, 64)?,
        })
    }
}
pub async fn router(state: ProfileHttpState) -> Result<Router, &'static str> {
    let db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| "reviewed database unavailable")?;
    crate::conversation_reviewed_send03_storage::require_v2(&*db)
        .await
        .map_err(|_| "reviewed schema unavailable")?;
    Ok(Router::new()
        .route("/v1/owner/conversation/send03", post(send))
        .route("/v1/owner/conversation/send03/status", post(status))
        .with_state(Arc::new(state)))
}
async fn send(State(s): State<Arc<ProfileHttpState>>, r: Request) -> Response {
    wire_response(handle(&s, false, r).await)
}
async fn status(State(s): State<Arc<ProfileHttpState>>, r: Request) -> Response {
    wire_response(handle(&s, true, r).await)
}
async fn handle(
    s: &ProfileHttpState,
    status: bool,
    request: Request,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    let (parts, body) = request.into_parts();
    preflight(s, &parts.headers, !status).await?;
    if parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let raw = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, 96 * 1024))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let input = parse(status, &raw)?;
    let mut db = crate::runtime_db::connect(&s.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::conversation_reviewed_send03_storage::require_v2(&tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner =
        ordinary_owner03::authenticate(&tx, &s.hasher, &s.origin, source(&parts.headers)?)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let (code, reply) = match input {
        Input::Send {
            envelope,
            intent,
            signature,
        } => {
            let (new, reply) =
                reviewed::admit(&tx, &mut owner, &intent, &signature, &envelope, &s.origin)
                    .await
                    .map_err(mapped)?;
            (
                if new {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                reply,
            )
        }
        Input::Status(expected) => (
            StatusCode::OK,
            reviewed::status(&tx, &mut owner, expected)
                .await
                .map_err(mapped)?,
        ),
    };
    owner
        .revalidate()
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    drop(owner);
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((code, reply))
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    use uuid::Uuid;
    #[test]
    fn reviewed_bodies_cannot_import_owner_ceiling_or_alternative_profile_authority() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/reviewed-intent03-v2.json"
        ))
        .unwrap();
        let bytes = crate::sealed_manifest03::tests::hex(&fixture["cases"][0]["intent_hex"]);
        let raw=serde_json::json!({"v":1,"envelope":B.encode([1;557]),"reviewed_intent":B.encode(&bytes),"reviewed_signature":B.encode([3;64])}).to_string();
        assert!(parse(false, raw.as_bytes()).is_ok());
        for changed in [
            format!("{{\"sms_ceiling\":6,{}", &raw[1..]),
            format!("{{\"v\":1,{}", &raw[1..]),
            "[]".into(),
        ] {
            assert!(parse(false, changed.as_bytes()).is_err());
        }
        let historical: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/reviewed-intent03.json"
        ))
        .unwrap();
        let legacy = crate::sealed_manifest03::tests::hex(&historical["cases"][0]["intent_hex"]);
        let raw = serde_json::json!({"v":1,"envelope":B.encode([1;557]),"reviewed_intent":B.encode(legacy),"reviewed_signature":B.encode([3;64])}).to_string();
        assert!(parse(false, raw.as_bytes()).is_err());
        let raw=serde_json::json!({"v":1,"message_id":Uuid::from_u128(1),"interval_id":Uuid::from_u128(2),"envelope_sha256":B.encode([1;32]),"reviewed_intent_sha256":B.encode([2;32]),"reviewed_signature_sha256":B.encode([3;32])}).to_string();
        assert!(parse(true, raw.as_bytes()).is_ok());
        assert!(
            parse(
                true,
                format!("{{\"owner_session_id\":\"x\",{}", &raw[1..]).as_bytes()
            )
            .is_err()
        );
    }
}
