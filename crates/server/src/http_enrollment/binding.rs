// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use enrollment::binding::{self, BindingChallenge};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::sealed_inbound::line_activation::v2_runtime::object_body;
object_body! {pub(super) struct ChallengeBody {key_fingerprint:String}}
object_body! {pub(super) struct ReadBody {account_id:String,challenge_id:String,challenge_nonce:String,signature_der:String}}

fn canonical_id(text: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(text).ok()?;
    (!id.is_nil() && id.to_string() == text).then_some(id)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

async fn admitted(s: &EnrollmentHttpState, db: &Client) -> Result<(), Response> {
    match abuse_limits::consume(db, &s.auth_hasher, Limit::PairBinding, None).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(StatusCode::TOO_MANY_REQUESTS.into_response()),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
    }
}

pub(super) async fn challenge(
    State(s): State<Arc<EnrollmentHttpState>>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ChallengeBody>,
) -> Response {
    let fp = match binding::parse_fingerprint(&body.key_fingerprint) {
        Ok(v) => v,
        Err(e) => return public_error(e),
    };
    let Some(id) = canonical_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let db = match connect(&s).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = admitted(&s, &db).await {
        return e;
    }
    match binding::issue(&db,&s.enrollment_hasher,id,fp,now()).await {
        Ok(c)=>Json(serde_json::json!({"schema_version":1,"account_id":c.account_id,"pairing_id":c.pairing_id,"challenge_id":c.challenge_id,"challenge_nonce":URL_SAFE_NO_PAD.encode(c.nonce),"key_fingerprint":body.key_fingerprint})).into_response(),
        Err(EnrollmentError::Unavailable)=>match binding::unclaimed_terminal(&db,id).await {
            Ok(Some(code))=>(StatusCode::CONFLICT,Json(serde_json::json!({"code":code}))).into_response(),
            Ok(None)=>StatusCode::NOT_FOUND.into_response(),Err(e)=>public_error(e)
        },
        Err(e)=>public_error(e)
    }
}

pub(super) async fn read(
    State(s): State<Arc<EnrollmentHttpState>>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ReadBody>,
) -> Response {
    let (Some(id), Some(account_id), Some(challenge_id)) = (
        canonical_id(&id),
        canonical_id(&body.account_id),
        canonical_id(&body.challenge_id),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let nonce = match decode_nonce(&body.challenge_nonce) {
        Ok(v) if URL_SAFE_NO_PAD.encode(v) == body.challenge_nonce => v,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let signature = match decode_bounded(&body.signature_der, 107, 8, 80) {
        Ok(v) if URL_SAFE_NO_PAD.encode(&v) == body.signature_der => v,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let db = match connect(&s).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = admitted(&s, &db).await {
        return e;
    }
    // Derive the original key fingerprint from a server-issued challenge's
    // candidate. Neither browser nor phone supplies replacement key material.
    let fp = match db.query_opt("SELECT fingerprint FROM device_keys WHERE source_pairing_id=$1 UNION ALL SELECT key_fingerprint FROM pairing_requests WHERE id=$1 AND approved_at IS NULL AND claimed_at IS NOT NULL LIMIT 1",&[&id]).await {
        Ok(Some(r))=>match r.get::<_,Vec<u8>>(0).try_into() {Ok(v)=>v,Err(_)=>return StatusCode::NOT_FOUND.into_response()},
        Ok(None)=>return StatusCode::NOT_FOUND.into_response(),Err(_)=>return StatusCode::SERVICE_UNAVAILABLE.into_response()
    };
    let c = BindingChallenge {
        account_id,
        pairing_id: id,
        challenge_id,
        nonce,
        fingerprint: fp,
    };
    match binding::read(&db, &s.enrollment_hasher, c, &signature, now()).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => public_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locator_ids_are_canonical_and_nonzero() {
        assert!(canonical_id("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").is_some());
        for bad in [
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(canonical_id(bad).is_none());
        }
    }
}
