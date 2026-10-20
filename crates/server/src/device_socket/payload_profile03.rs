// SPDX-License-Identifier: AGPL-3.0-only
//! Additive03 ceremony frames on the actual authenticated enrolled stream.
//! No legacy grant fallback, hardware assertion or dispatch permission.
use super::*;
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use crate::sealed_payload_election03::{device_context, live};
pub(super) const PROTOCOL: &str = "zrotext-device-status-v2+sealed-dispatch-v3";
mod interval;
object_body! {struct Session {v:u8,r#type:String,connection_epoch:i64,challenge:String}}
object_body! {struct Proof {v:u8,r#type:String,challenge_id:String,device_signature:String}}
object_body! {struct Current {v:u8,r#type:String,connection_epoch:i64,challenge:String,line_id:String}}
pub(super) enum Incoming {
    Interval(interval::Frame),
    Session {
        epoch: i64,
        challenge: Uuid,
    },
    Proof {
        challenge: Uuid,
        signature: Vec<u8>,
    },
    Current {
        epoch: i64,
        challenge: Uuid,
        line: Uuid,
    },
}
pub(super) struct CurrentReads {
    nonces: Vec<Uuid>,
    last: Option<Instant>,
}
impl CurrentReads {
    pub(super) fn new() -> Self {
        Self {
            nonces: Vec::new(),
            last: None,
        }
    }
    fn admit(&mut self, challenge: Uuid, now: Instant) -> bool {
        if challenge.is_nil()
            || self.nonces.len() >= 64
            || self.nonces.contains(&challenge)
            || self.last.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_none_or(|age| age < Duration::from_secs(25))
            })
        {
            return false;
        }
        self.nonces.push(challenge);
        self.last = Some(now);
        true
    }
}
fn id(s: &str) -> Result<Uuid, ()> {
    let v = Uuid::parse_str(s).map_err(|_| ())?;
    if v.is_nil() || v.to_string() != s {
        return Err(());
    }
    Ok(v)
}
pub(super) fn parse(raw: &str) -> Result<Option<Incoming>, ()> {
    // The discriminator is deliberately open only for initial routing. The
    // selected typed object is decoded again with closed fields and duplicate
    // detection; no serde_json::Value collapse can hide escaped duplicates.
    #[derive(serde::Deserialize)]
    struct Type {
        r#type: String,
    }
    let tag: Type = {
        let mut decoder = serde_json::Deserializer::from_str(raw);
        let tag = crate::sealed_inbound::line_activation::v2_runtime::decode_object(&mut decoder)
            .map_err(|_| ())?;
        decoder.end().map_err(|_| ())?;
        tag
    };
    if tag.r#type.starts_with("conversation_interval_") {
        if raw.len() > MAX_FRAME_BYTES {
            return Err(());
        }
        return interval::parse(&tag.r#type, raw).map(|frame| Some(Incoming::Interval(frame)));
    }
    if !tag.r#type.starts_with("payload_profile_") {
        return Ok(None);
    }
    if raw.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    Ok(Some(match tag.r#type.as_str() {
        "payload_profile_current03_request" => {
            let b: Current = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag.r#type || b.connection_epoch <= 0 {
                return Err(());
            }
            Incoming::Current {
                epoch: b.connection_epoch,
                challenge: id(&b.challenge)?,
                line: id(&b.line_id)?,
            }
        }
        "payload_profile_session03_request" => {
            let b: Session = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag.r#type || b.connection_epoch <= 0 {
                return Err(());
            }
            Incoming::Session {
                epoch: b.connection_epoch,
                challenge: id(&b.challenge)?,
            }
        }
        "payload_profile_proof03" => {
            let b: Proof = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag.r#type {
                return Err(());
            }
            Incoming::Proof {
                challenge: id(&b.challenge_id)?,
                signature: line_activation_v2::bytes(&b.device_signature, 64, 64).ok_or(())?,
            }
        }
        _ => return Err(()),
    }))
}
async fn send(socket: &mut WebSocket, value: serde_json::Value) -> Option<()> {
    let raw = serde_json::to_string(&value).ok()?;
    if raw.len() > 192 * 1024 {
        return None;
    }
    socket.send(Message::Text(raw.into())).await.ok()
}
pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
    samples: &mut sealed_session::Samples,
    reads: &mut CurrentReads,
    frame: Incoming,
) -> Option<()> {
    if let Incoming::Interval(frame) = frame {
        if !samples.is_sampled() {
            return None;
        }
        return interval::dispatch(socket, state, session, origin, reads, frame).await;
    }
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    let deployment = u64::try_from(state.deployment_epoch)
        .ok()
        .filter(|v| *v > 0)?;
    match frame {
        Incoming::Interval(_) => return None,
        Incoming::Current {
            epoch,
            challenge,
            line,
        } => {
            if epoch != session.connection_epoch
                || !samples.is_sampled()
                || !reads.admit(challenge, Instant::now())
            {
                return None;
            }
            let result = live::device_current(
                &tx,
                session,
                &state.site_id,
                &state.instance_id,
                deployment,
                line,
                origin,
            )
            .await;
            let reply = match result {
                Ok(current) => {
                    serde_json::json!({"v":1,"type":"payload_profile_current03","connection_epoch":session.connection_epoch,"challenge":challenge,"current":current})
                }
                Err(error) => {
                    let reason = match error {
                        live::Error::NotFound => "not_accepted",
                        live::Error::Expired => "expired",
                        live::Error::Authentication
                        | live::Error::Conflict
                        | live::Error::Unsupported => "unsupported",
                        _ => return None,
                    };
                    serde_json::json!({"v":1,"type":"payload_profile_current03_unavailable","connection_epoch":session.connection_epoch,"challenge":challenge,"reason":reason})
                }
            };
            // Read-only snapshots do not extend a lease, authenticate an
            // owner or install readiness. Later grant/fetch re-locks actual
            // permission, never retaining this detached JSON as authority.
            tx.rollback().await.ok()?;
            drop(db);
            send(socket, reply).await?;
        }
        Incoming::Session { epoch, challenge } => {
            if epoch != session.connection_epoch || !samples.admit(challenge, Instant::now()) {
                return None;
            }
            let selector = device_context::Selector {
                account: session.account_id,
                device: session.device_id,
                site: state.site_id.clone(),
                instance: state.instance_id.clone(),
                connection_epoch: u64::try_from(session.connection_epoch).ok()?,
                deployment_epoch: deployment,
            };
            let mut current = device_context::lock(&tx, &selector).await.ok()?;
            current.revalidate().await.ok()?;
            let now = current.checked_primary_ms();
            let reply = serde_json::json!({"v":1,"type":"payload_profile_session03","challenge":challenge,"account_id":session.account_id,"device_id":session.device_id,"connection_epoch":session.connection_epoch,"deployment_epoch":state.deployment_epoch,"session_id":samples.session_id(),"server_time_ms":now,"site_id":state.site_id,"instance_id":state.instance_id,"line_activation_version":2});
            drop(current);
            tx.commit().await.ok()?;
            drop(db);
            send(socket, reply).await?;
            samples.sampled();
        }
        Incoming::Proof {
            challenge,
            signature,
        } => {
            if !samples.is_sampled() {
                return None;
            }
            live::device_proof(
                &tx,
                live::SocketSelection03 {
                    session,
                    site: &state.site_id,
                    instance: &state.instance_id,
                    deployment,
                    origin,
                },
                challenge,
                &signature,
            )
            .await
            .ok()?;
            tx.commit().await.ok()?;
            // This immutable retention has no new permission/acceptance ACK.
            // Owner's exact proof read drives its distinct fresh-factor commit.
        }
    }
    Some(())
}
pub(super) async fn push(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
) -> Option<()> {
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    let result = live::device_challenge(
        &tx,
        session,
        &state.site_id,
        &state.instance_id,
        u64::try_from(state.deployment_epoch).ok()?,
        origin,
    )
    .await;
    let reply = match result {
        Ok(reply) => reply,
        Err(
            live::Error::Authentication
            | live::Error::Conflict
            | live::Error::Expired
            | live::Error::Unsupported
            | live::Error::NotFound,
        ) => return Some(()),
        Err(live::Error::Database(e))
            if e.code()
                .is_some_and(|c| matches!(c.code(), "55P03" | "57014")) =>
        {
            return Some(());
        }
        Err(_) => return None,
    };
    tx.commit().await.ok()?;
    drop(db);
    if let Some(reply) = reply {
        send(socket, reply).await?
    }
    interval::push(socket, state, session, origin).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile03_negotiation_never_selects_a_legacy_grant_version() {
        let selected = line_activation_v2::Negotiated::selected(Some(PROTOCOL));
        assert_eq!(selected.sealed_version, Some(3));
        assert_eq!(selected.line, line_activation_v2::LineProtocol::Complete);
        assert_eq!(
            line_activation_v2::Negotiated::selected(Some(line_activation_v2::SEALED_PROTOCOL))
                .sealed_version,
            Some(2)
        );
    }
    #[test]
    fn profile03_frames_are_closed_and_do_not_reinterpret_existing_types() {
        let challenge = Uuid::from_u128(4);
        let valid=serde_json::json!({"v":1,"type":"payload_profile_session03_request","connection_epoch":1,"challenge":challenge}).to_string();
        assert!(matches!(
            parse(&valid),
            Ok(Some(Incoming::Session { epoch: 1, .. }))
        ));
        assert!(matches!(
            parse("{\"type\":\"heartbeat\",\"v\":1}"),
            Ok(None)
        ));
        for raw in [
            format!(
                "{{\"v\":1,\"type\":\"payload_profile_session03_request\",\"connection_epoch\":1,\"challenge\":\"{challenge}\",\"extra\":1}}"
            ),
            format!(
                r#"{{"v":1,"type":"payload_profile_session03_request","connection_epoch":1,"challenge":"{challenge}","\u0076":1}}"#
            ),
            format!("[1,\"payload_profile_session03_request\",1,\"{challenge}\"]"),
            "{\"type\":\"payload_profile_future03\",\"v\":1}".to_owned(),
        ] {
            assert!(parse(&raw).is_err());
        }
    }
    #[test]
    fn device_selection_reads_preserve_nonce_rate_and_per_connection_boundaries() {
        let start = Instant::now();
        let mut reads = CurrentReads::new();
        assert!(!reads.admit(Uuid::nil(), start));
        assert!(reads.admit(Uuid::from_u128(1), start));
        assert!(!reads.admit(Uuid::from_u128(1), start + Duration::from_secs(25)));
        assert!(!reads.admit(Uuid::from_u128(2), start + Duration::from_millis(24_999)));
        for n in 2..=64 {
            assert!(reads.admit(
                Uuid::from_u128(n),
                start + Duration::from_secs((n as u64 - 1) * 25)
            ));
        }
        assert!(!reads.admit(Uuid::from_u128(65), start + Duration::from_secs(64 * 25)));
        let raw=serde_json::json!({"v":1,"type":"payload_profile_current03_request","connection_epoch":1,"challenge":Uuid::from_u128(1),"line_id":Uuid::from_u128(2)}).to_string();
        assert!(matches!(
            parse(&raw),
            Ok(Some(Incoming::Current { epoch: 1, .. }))
        ));
    }
}
