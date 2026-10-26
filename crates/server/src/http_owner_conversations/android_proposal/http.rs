// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit authenticated bounded public issue/context endpoints. No default mount.
use super::*;
use crate::{api_json::ApiJson, http_auth::preauth::OwnerMutation};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware,
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::Arc;
#[cfg(test)]
mod tests;

pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/conversation/android-proposal", post(register))
        .route(
            "/v1/owner/conversation/android-proposal/context",
            post(context),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn(super::super::no_store))
        .with_state(Arc::new(state))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    kind: i16,
    proposal_b64: String,
    expected_session_id: Uuid,
    #[serde(default, deserialize_with = "present_string")]
    encrypted_archive_b64: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    phone_export_b64: Option<String>,
}
// Missing fields remain absent; a present null is not absence. String parsing
// also keeps duplicate fields under the enclosing closed struct's serde guard.
fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    kind: i16,
    proposal_sha256_hex: String,
    expected_session_id: Uuid,
}
// Restrict these two HTTP DTOs to streamed JSON maps. Forwarding MapAccess
// keeps the derived unknown/duplicate-field and present-null checks intact;
// materializing a Value first would erase duplicate keys.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(Object(std::marker::PhantomData))
    }
}
fn decode(value: &str, max: usize) -> Result<Vec<u8>, ConversationError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(ConversationError::Invalid);
    }
    let b = STANDARD
        .decode(value)
        .map_err(|_| ConversationError::Invalid)?;
    if b.is_empty() || b.len() > max || STANDARD.encode(&b) != value {
        return Err(ConversationError::Invalid);
    }
    Ok(b)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(value: &str) -> Result<[u8; 32], ConversationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ConversationError::Invalid);
    }
    let mut out = [0; 32];
    for (i, s) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(
            std::str::from_utf8(s).map_err(|_| ConversationError::Invalid)?,
            16,
        )
        .map_err(|_| ConversationError::Invalid)?;
    }
    Ok(out)
}
async fn register(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(MapOnly(b)): ApiJson<MapOnly<Register>>,
) -> Result<Json<serde_json::Value>, ConversationError> {
    if b.expected_session_id != p.session_id || ![3, 4, 5].contains(&b.kind) {
        return Err(ConversationError::Forbidden);
    }
    let bytes = decode(&b.proposal_b64, 20480)?;
    let selected = packet::selection(b.kind, &bytes)?;
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    let tx = db.transaction().await?;
    lifecycle::require_installed(&tx).await?;
    let current = authority::lock(&tx, &p, &selected).await?;
    let inputs = match (b.kind, b.encrypted_archive_b64, b.phone_export_b64) {
        (3, Some(archive), Some(phone)) => Some(inspect_genesis_inputs(
            GenesisBinding {
                account: p.tenant.account_id(),
                device: selected.device,
                line: selected.line,
                generation: selected.generation,
                origin: &state.canonical_origin,
                root_pin: &current.pin,
                root_fingerprint: &current.fingerprint,
                paired_signing_point: &current.paired_point,
                paired_signing_fingerprint: &current.paired_fingerprint,
            },
            &decode(&phone, 223)?,
            &decode(&archive, 845)?,
        )?),
        (4 | 5, None, None) => None,
        _ => return Err(ConversationError::Invalid),
    };
    let now = authority::fresh(&tx, &p, &selected, &current).await?;
    let record = packet::validate(
        b.kind,
        packet::Context {
            p: &p,
            s: &selected,
            c: &current,
            origin: &state.canonical_origin,
            now,
        },
        &bytes,
        inputs.as_ref(),
    )?;
    operation_live(&tx, &p, &selected, &current, &record).await?;
    let hash = store::save(&tx, &p, &selected, &current, &record).await?;
    final_record(
        &tx,
        &p,
        &selected,
        &current,
        &state.canonical_origin,
        &record,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({"v":1,"kind":b.kind,"proposal_sha256_hex":hex(&hash),"owner_session_id":p.session_id,"expires_ms":record.expires.to_string()}),
    ))
}
async fn context(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(p, _slot): OwnerMutation,
    ApiJson(MapOnly(b)): ApiJson<MapOnly<Context>>,
) -> Result<Json<serde_json::Value>, ConversationError> {
    if b.expected_session_id != p.session_id || ![3, 4, 5].contains(&b.kind) {
        return Err(ConversationError::Forbidden);
    }
    let hash = digest(&b.proposal_sha256_hex)?;
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    let tx = db.transaction().await?;
    lifecycle::require_installed(&tx).await?;
    // Unlocked metadata is only a lookup selector. Re-read immutable scope under
    // root-before-account locks before returning anything authoritative.
    let row=tx.query_opt("SELECT device_id,line_id,binding_generation,peer FROM owner_android_proposals WHERE account_id=$1 AND kind=$2 AND user_id=$3 AND session_id=$4 AND proposal_sha256=$5",&[&p.tenant.account_id(),&b.kind,&p.user_id,&p.session_id,&hash.as_slice()]).await?.ok_or(ConversationError::Forbidden)?;
    let selected = Selection {
        device: row.get(0),
        line: row.get(1),
        generation: row.get(2),
        peer: row.get(3),
    };
    let current = authority::lock(&tx, &p, &selected).await?;
    let record = store::load(
        &tx,
        &p,
        &selected,
        &current,
        b.kind,
        &hash,
        &state.canonical_origin,
    )
    .await?;
    let now = final_record(
        &tx,
        &p,
        &selected,
        &current,
        &state.canonical_origin,
        &record,
    )
    .await?;
    let value = serde_json::json!({"v":1,"kind":b.kind,"account_id":p.tenant.account_id(),"user_id":p.user_id,"session_id":p.session_id,"origin":state.canonical_origin,"root_fingerprint_hex":hex(&current.fingerprint),"proposal_sha256_hex":hex(&hash),"proposal_b64":STANDARD.encode(&record.packet),"expected_context":record.expected,"server_now_ms":now.to_string(),"expires_ms":record.expires.to_string()});
    tx.commit().await?;
    Ok(Json(value))
}
