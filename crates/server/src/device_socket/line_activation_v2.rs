// SPDX-License-Identifier: AGPL-3.0-only
//! Closed protocol negotiation and the actual v2 exchange socket adapter.
use super::*;
use crate::sealed_inbound::line_activation::v2_runtime::{self as runtime, Ack, Purpose};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};
pub(super) const PROTOCOL: &str = "zrotext-device-status-v2-line-activation-v2";
pub(super) const SEALED_PROTOCOL: &str =
    "zrotext-sealed-dispatch-v2-device-status-v2-line-activation-v2";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LineProtocol {
    Legacy,
    Complete,
}
impl LineProtocol {
    pub(super) fn version(self) -> i16 {
        match self {
            Self::Legacy => 1,
            Self::Complete => 2,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Negotiated {
    pub status: Option<&'static str>,
    pub sealed_version: Option<u8>,
    pub line: LineProtocol,
}
impl Negotiated {
    pub(super) fn selected(token: Option<&str>) -> Self {
        let (status, sealed_version, line) = match token {
            Some(PROTOCOL) => (
                Some(preconditions::PROTOCOL_V2),
                None,
                LineProtocol::Complete,
            ),
            Some(SEALED_PROTOCOL) => (
                Some(preconditions::PROTOCOL_V2),
                Some(2),
                LineProtocol::Complete,
            ),
            Some(preconditions::PROTOCOL_V2) => {
                (Some(preconditions::PROTOCOL_V2), None, LineProtocol::Legacy)
            }
            Some(preconditions::PROTOCOL) => {
                (Some(preconditions::PROTOCOL), None, LineProtocol::Legacy)
            }
            Some(crate::sealed_dispatch::wire::PROTOCOL_V2) => (
                Some(preconditions::PROTOCOL_V2),
                Some(2),
                LineProtocol::Legacy,
            ),
            Some(crate::sealed_dispatch::wire::PROTOCOL) => (
                Some(preconditions::PROTOCOL_V2),
                Some(1),
                LineProtocol::Legacy,
            ),
            _ => (None, None, LineProtocol::Legacy),
        };
        Self {
            status,
            sealed_version,
            line,
        }
    }
}
pub(super) enum Incoming {
    Proof {
        purpose: Purpose,
        epoch: i64,
        id: Uuid,
        observation: Vec<u8>,
        der: Vec<u8>,
    },
    Installed {
        epoch: i64,
        ack: Ack,
    },
}
struct Closed(BTreeMap<String, Value>);
impl<'de> Deserialize<'de> for Closed {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Closed;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a closed line frame")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Closed, A::Error> {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    values.insert(key, map.next_value::<Value>()?);
                }
                Ok(Closed(values))
            }
        }
        decoder.deserialize_map(Object)
    }
}
fn string<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key)?.as_str()
}
pub(super) fn positive(s: &str) -> Option<i64> {
    if s.is_empty()
        || s.len() > 19
        || s.as_bytes()[0] == b'0'
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok().filter(|n| *n > 0)
}
fn id(m: &BTreeMap<String, Value>, key: &str) -> Option<Uuid> {
    let text = string(m, key)?;
    let parsed = Uuid::parse_str(text).ok()?;
    (!parsed.is_nil() && parsed.to_string() == text).then_some(parsed)
}
pub(super) fn bytes(s: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    if s.is_empty()
        || s.len() > max.div_ceil(3) * 4
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(s).ok()?;
    (raw.len() >= min && raw.len() <= max && URL_SAFE_NO_PAD.encode(&raw) == s).then_some(raw)
}
/// None delegates unchanged legacy/status frames to the existing decoder.
pub(super) fn parse(raw: &str) -> Result<Option<Incoming>, ()> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    let Closed(m) = serde_json::from_str(raw).map_err(|_| ())?;
    let kind = string(&m, "type").ok_or(())?;
    let purpose = match kind {
        "sms_line_proof_v2" => Purpose::Sms,
        "sealed_line_proof_v2" | "sealed_line_installed_v2" => Purpose::Sealed,
        _ if (kind.starts_with("sms_line_") || kind.starts_with("sealed_line_"))
            && kind.ends_with("_v2") =>
        {
            return Err(());
        }
        _ => return Ok(None),
    };
    if m.get("v").and_then(Value::as_i64) != Some(2) {
        return Err(());
    }
    let epoch = positive(string(&m, "connection_epoch").ok_or(())?).ok_or(())?;
    let challenge = id(&m, "challenge_id").ok_or(())?;
    if kind == "sealed_line_installed_v2" {
        let keys = [
            "type",
            "v",
            "connection_epoch",
            "challenge_id",
            "account_id",
            "line_id",
            "device_id",
            "generation",
            "device_statement_sha256",
            "device_signature_sha256",
        ];
        if m.len() != keys.len() || keys.iter().any(|k| !m.contains_key(*k)) {
            return Err(());
        }
        let statement = bytes(string(&m, "device_statement_sha256").ok_or(())?, 32, 32).ok_or(())?;
        let signature = bytes(string(&m, "device_signature_sha256").ok_or(())?, 32, 32).ok_or(())?;
        return Ok(Some(Incoming::Installed {
            epoch,
            ack: Ack {
                challenge_id: challenge,
                account_id: id(&m, "account_id").ok_or(())?,
                line_id: id(&m, "line_id").ok_or(())?,
                device_id: id(&m, "device_id").ok_or(())?,
                generation: positive(string(&m, "generation").ok_or(())?).ok_or(())?,
                device_statement_sha256: statement.try_into().map_err(|_| ())?,
                device_signature_sha256: signature.try_into().map_err(|_| ())?,
            },
        }));
    }
    let keys = [
        "type",
        "v",
        "connection_epoch",
        "challenge_id",
        "observation_b64url",
        "signature_der",
    ];
    if m.len() != keys.len() || keys.iter().any(|k| !m.contains_key(*k)) {
        return Err(());
    }
    let observation = bytes(string(&m, "observation_b64url").ok_or(())?, 121, 121).ok_or(())?;
    let der = bytes(string(&m, "signature_der").ok_or(())?, 8, 80).ok_or(())?;
    let signature = p256::ecdsa::Signature::from_der(&der).map_err(|_| ())?;
    if signature.to_der().as_bytes() != der {
        return Err(());
    }
    Ok(Some(Incoming::Proof {
        purpose,
        epoch,
        id: challenge,
        observation,
        der,
    }))
}
fn scoped(mut v: Value, p: Purpose, epoch: i64) -> Value {
    if p == Purpose::Sealed {
        v["connection_epoch"] = Value::String(epoch.to_string());
    }
    v
}
fn challenge_frame(c: runtime::Challenge, p: Purpose, epoch: i64) -> Value {
    let c_id = c.tuple;
    scoped(
        serde_json::json!({"type":format!("{}_line_challenge_v2",p.label()),"v":2,
        "challenge_id":c_id.id,"account_id":c_id.account_id,"line_id":c_id.line_id,"device_id":c_id.device_id,
        "generation":c_id.generation.to_string(),"nonce":URL_SAFE_NO_PAD.encode(c_id.nonce),"expires_at_ms":c.expires_at_ms}),
        p,
        epoch,
    )
}
fn ack_frame(a: Ack, p: Purpose, epoch: i64) -> Value {
    scoped(
        serde_json::json!({"type":format!("{}_line_activated_v2",p.label()),"v":2,
        "challenge_id":a.challenge_id,"account_id":a.account_id,"line_id":a.line_id,"device_id":a.device_id,
        "generation":a.generation.to_string(),"device_statement_sha256":URL_SAFE_NO_PAD.encode(a.device_statement_sha256),
        "device_signature_sha256":URL_SAFE_NO_PAD.encode(a.device_signature_sha256)}),
        p,
        epoch,
    )
}
async fn send(socket: &mut WebSocket, value: Value) -> bool {
    let Ok(raw) = serde_json::to_string(&value) else {
        return false;
    };
    raw.len() <= MAX_FRAME_BYTES && socket.send(Message::Text(raw.into())).await.is_ok()
}
pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    s: InboundSession<'_>,
    sealed_setup: bool,
    frame: Incoming,
) -> Option<()> {
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let (purpose, id, accepted, kind, installed_ack) = match frame {
        Incoming::Proof {
            purpose,
            epoch,
            id,
            observation,
            der,
        } => {
            if epoch != s.connection_epoch
                || (purpose == Purpose::Sms && !state.sms_line_activation_enabled)
                || (purpose == Purpose::Sealed && !sealed_setup)
            {
                return None;
            }
            let accepted =
                runtime::record_device_proof(&mut db, s, purpose, id, &observation, &der)
                    .await
                    .ok()?;
            (
                purpose,
                id,
                accepted,
                format!("{}_line_proof_ack_v2", purpose.label()),
                None,
            )
        }
        Incoming::Installed { epoch, ack } => {
            if !sealed_setup || epoch != s.connection_epoch {
                return None;
            }
            let accepted = runtime::confirm_sealed_install(&mut db, s, ack)
                .await
                .ok()?;
            (
                Purpose::Sealed,
                ack.challenge_id,
                accepted,
                "sealed_line_install_ack_v2".to_owned(),
                Some(ack),
            )
        }
    };
    runtime::current(&mut db, s).await.ok()?;
    if accepted && let Some(ack) = installed_ack {
        runtime::current_ack(&mut db, s, ack).await.ok()?;
    }
    let value = scoped(
        serde_json::json!({"type":kind,"v":2,"challenge_id":id,"accepted":accepted}),
        purpose,
        s.connection_epoch,
    );
    // A failed send leaves commit disposition as it was; never infer rollback.
    send(socket, value).await.then_some(())
}
pub(super) async fn push(
    socket: &mut WebSocket,
    url: &str,
    s: InboundSession<'_>,
    purpose: Purpose,
    sent: &mut Vec<Uuid>,
    retire: bool,
) -> Option<bool> {
    let mut db = runtime_db::connect_device(url).await.ok()?;
    if purpose == Purpose::Sms && retire {
        runtime::retire_sms(&mut db, s).await.ok()?;
    }
    let mut pushed = false;
    if let Some(c) = runtime::next_challenge(&mut db, s, purpose).await.ok()? {
        runtime::current_challenge(&mut db, s, purpose, &c)
            .await
            .ok()?;
        if !send(socket, challenge_frame(c, purpose, s.connection_epoch)).await {
            return None;
        }
        pushed = true;
    }
    if sent.len() < MAX_SMS_LINE_ACKS_PER_CONNECTION
        && let Some(a) = runtime::next_ack(&mut db, s, purpose, sent).await.ok()?
    {
        runtime::current_ack(&mut db, s, a).await.ok()?;
        if !send(socket, ack_frame(a, purpose, s.connection_epoch)).await {
            return None;
        }
        sent.push(a.challenge_id);
        pushed = true;
    }
    Some(pushed)
}
#[cfg(test)]
mod db_tests;
#[cfg(test)]
mod tests;
