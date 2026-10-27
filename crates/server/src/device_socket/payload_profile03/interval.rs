// SPDX-License-Identifier: AGPL-3.0-only
//! Distinct closed03 content-consent frames on the actual enrolled socket.
//! Replies are sent only after the narrow mutation transaction commits.
use super::*;
use crate::conversation_interval03::live as interval;
object_body! {struct Signature{v:u8,r#type:String,interval_id:String,statement_sha256:String,signature:String}}
object_body! {struct Status{v:u8,r#type:String,interval_id:String,challenge:String}}
object_body! {struct Stop{v:u8,r#type:String,interval_id:String,statement_sha256:String}}
pub(in crate::device_socket) enum Frame {
    Approve {
        interval: Uuid,
        digest: [u8; 32],
        signature: Vec<u8>,
    },
    Install {
        interval: Uuid,
        digest: [u8; 32],
        signature: Vec<u8>,
    },
    Status {
        interval: Uuid,
        challenge: Uuid,
    },
    Stop {
        interval: Uuid,
        digest: [u8; 32],
    },
}
fn digest(raw: &str) -> Result<[u8; 32], ()> {
    let bytes: [u8; 32] = line_activation_v2::bytes(raw, 32, 32)
        .ok_or(())?
        .try_into()
        .map_err(|_| ())?;
    if bytes == [0; 32] {
        return Err(());
    }
    Ok(bytes)
}
pub(super) fn parse(tag: &str, raw: &str) -> Result<Frame, ()> {
    Ok(match tag {
        "conversation_interval_approve03" | "conversation_interval_install03" => {
            let b: Signature = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag {
                return Err(());
            }
            let interval = id(&b.interval_id)?;
            let digest = digest(&b.statement_sha256)?;
            let signature = line_activation_v2::bytes(&b.signature, 64, 64).ok_or(())?;
            if tag == "conversation_interval_approve03" {
                Frame::Approve {
                    interval,
                    digest,
                    signature,
                }
            } else {
                Frame::Install {
                    interval,
                    digest,
                    signature,
                }
            }
        }
        "conversation_interval_status03_request" => {
            let b: Status = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag {
                return Err(());
            }
            Frame::Status {
                interval: id(&b.interval_id)?,
                challenge: id(&b.challenge)?,
            }
        }
        "conversation_interval_stop03" => {
            let b: Stop = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag {
                return Err(());
            }
            Frame::Stop {
                interval: id(&b.interval_id)?,
                digest: digest(&b.statement_sha256)?,
            }
        }
        _ => return Err(()),
    })
}
fn device<'a>(
    state: &'a DeviceSocketState,
    session: DeviceSession,
    origin: &'a str,
) -> Option<interval::DeviceInterval03<'a>> {
    Some(interval::DeviceInterval03 {
        session,
        site: &state.site_id,
        instance: &state.instance_id,
        deployment: u64::try_from(state.deployment_epoch)
            .ok()
            .filter(|v| *v > 0)?,
        origin,
    })
}
pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
    reads: &mut CurrentReads,
    frame: Frame,
) -> Option<()> {
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .native_build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    let device = device(state, session, origin)?;
    let reply = match frame {
        Frame::Approve {
            interval,
            digest,
            signature,
        } => interval::device_approve(&tx, device, interval, &digest, &signature)
            .await
            .ok()?,
        Frame::Install {
            interval,
            digest,
            signature,
        } => interval::device_install(&tx, device, interval, &digest, &signature)
            .await
            .ok()?,
        Frame::Stop { interval, digest } => interval::device_stop(&tx, device, interval, &digest)
            .await
            .ok()?,
        Frame::Status {
            interval,
            challenge,
        } => {
            if !reads.admit(challenge, Instant::now()) {
                return None;
            }
            interval::device_status(&tx, device, interval, challenge)
                .await
                .ok()?
        }
    };
    tx.commit().await.ok()?;
    drop(db);
    send(socket, reply).await
}
pub(super) async fn push(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
) -> Option<()> {
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .native_build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    if !crate::conversation_profile03_storage::optional(&tx)
        .await
        .ok()?
    {
        return Some(());
    }
    let reply = match interval::device_challenge(&tx, device(state, session, origin)?).await {
        Ok(reply) => reply,
        Err(
            live::Error::NotFound
            | live::Error::Authentication
            | live::Error::Conflict
            | live::Error::Expired
            | live::Error::Unsupported,
        ) => return Some(()),
        Err(live::Error::Database(e))
            if e.code()
                .is_some_and(|c| matches!(c.code(), "55P03" | "57014")) =>
        {
            return Some(());
        }
        Err(_) => return None,
    };
    tx.rollback().await.ok()?;
    drop(db);
    if let Some(reply) = reply {
        send(socket, reply).await?;
    }
    Some(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    #[test]
    fn content_ceremony_frames_never_accept_owner_selectors_or_unknown_fields() {
        let interval = Uuid::from_u128(2);
        let raw=serde_json::json!({"v":1,"type":"conversation_interval_approve03","interval_id":interval,"statement_sha256":B.encode([1;32]),"signature":B.encode([2;64])}).to_string();
        assert!(matches!(
            super::super::parse(&raw),
            Ok(Some(Incoming::Interval(Frame::Approve { .. })))
        ));
        for addition in [
            r#", "owner_session_id":"00000000-0000-0000-0000-000000000003"}"#,
            r#", "\u0076":1}"#,
        ] {
            let bad = format!("{}{}", &raw[..raw.len() - 1], addition);
            assert!(super::super::parse(&bad).is_err());
        }
        assert!(super::super::parse(r#"{"v":1,"type":"conversation_interval_future03"}"#).is_err());
        assert!(super::super::parse("[1,\"conversation_interval_approve03\"]").is_err());
    }
}
