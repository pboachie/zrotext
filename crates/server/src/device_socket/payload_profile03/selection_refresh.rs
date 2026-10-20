// SPDX-License-Identifier: AGPL-3.0-only
//! Exact refresh frames on the already authenticated enrolled03 socket.
//! A reply follows durable commit; no received actor or epoch selects authority.
use super::*;
use crate::selection_refresh03::live as refresh;
object_body! {struct Proof{v:u8,r#type:String,connection_epoch:i64,refresh_id:String,observation:String,device_signature:String}}
object_body! {struct Installed{v:u8,r#type:String,connection_epoch:i64,refresh_id:String,bundle_sha256:String,device_signature:String}}
pub(in crate::device_socket) struct Frame {
    epoch: i64,
    refresh: Uuid,
    action: Action,
}
enum Action {
    Proof {
        observation: Vec<u8>,
        signature: Vec<u8>,
    },
    Installed {
        digest: [u8; 32],
        signature: Vec<u8>,
    },
}
pub(super) fn parse(tag: &str, raw: &str) -> Result<Option<Frame>, ()> {
    Ok(Some(match tag {
        "payload_profile_selection_proof03" => {
            let b: Proof = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag || b.connection_epoch <= 0 {
                return Err(());
            }
            Frame {
                epoch: b.connection_epoch,
                refresh: id(&b.refresh_id)?,
                action: Action::Proof {
                    observation: line_activation_v2::bytes(&b.observation, 121, 121).ok_or(())?,
                    signature: line_activation_v2::bytes(&b.device_signature, 64, 64).ok_or(())?,
                },
            }
        }
        "payload_profile_selection_installed03" => {
            let b: Installed = serde_json::from_str(raw).map_err(|_| ())?;
            if b.v != 1 || b.r#type != tag || b.connection_epoch <= 0 {
                return Err(());
            }
            let digest: [u8; 32] = line_activation_v2::bytes(&b.bundle_sha256, 32, 32)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?;
            if digest == [0; 32] {
                return Err(());
            }
            Frame {
                epoch: b.connection_epoch,
                refresh: id(&b.refresh_id)?,
                action: Action::Installed {
                    digest,
                    signature: line_activation_v2::bytes(&b.device_signature, 64, 64).ok_or(())?,
                },
            }
        }
        _ => return Ok(None),
    }))
}
fn scope<'a>(
    state: &'a DeviceSocketState,
    session: DeviceSession,
    origin: &'a str,
) -> Option<live::SocketSelection03<'a>> {
    Some(live::SocketSelection03 {
        session,
        site: &state.site_id,
        instance: &state.instance_id,
        deployment: u64::try_from(state.deployment_epoch)
            .ok()
            .filter(|n| *n > 0)?,
        origin,
    })
}
pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
    samples: &sealed_session::Samples,
    frame: Frame,
) -> Option<()> {
    if frame.epoch != session.connection_epoch || !samples.is_sampled() {
        return None;
    }
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    let actual = scope(state, session, origin)?;
    let reply = match frame.action {
        Action::Proof {
            observation,
            signature,
        } => {
            refresh::device_proof(&tx, &actual, frame.refresh, &observation, &signature)
                .await
                .ok()?;
            None
        }
        Action::Installed { digest, signature } => Some(
            refresh::device_installed(&tx, &actual, frame.refresh, &digest, &signature)
                .await
                .ok()?,
        ),
    };
    tx.commit().await.ok()?;
    drop(db);
    if let Some(reply) = reply {
        send(socket, reply).await?;
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
    let actual = scope(state, session, origin)?;
    let result = refresh::device_challenge(&tx, &actual).await;
    let reply = match result {
        Ok(value) => value,
        Err(
            live::Error::Authentication
            | live::Error::Conflict
            | live::Error::Expired
            | live::Error::Unsupported
            | live::Error::NotFound,
        ) => return Some(()),
        Err(live::Error::Database(ref e))
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
        if serde_json::to_vec(&reply).ok()?.len() > 192 * 1024 {
            return None;
        }
        send(socket, reply).await?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    #[test]
    fn refresh_proof_is_closed_and_cannot_import_an_owner_or_change_profile() {
        let valid=serde_json::json!({"v":1,"type":"payload_profile_selection_proof03","connection_epoch":1,"refresh_id":Uuid::from_u128(2),"observation":URL_SAFE_NO_PAD.encode([1;121]),"device_signature":URL_SAFE_NO_PAD.encode([2;64])}).to_string();
        assert!(
            parse("payload_profile_selection_proof03", &valid)
                .unwrap()
                .is_some()
        );
        for raw in [
            format!("{{\"owner_session_id\":\"x\",{}", &valid[1..]),
            format!("{{\"v\":1,{}", &valid[1..]),
            valid.replace("\"connection_epoch\":1", "\"connection_epoch\":0"),
        ] {
            assert!(parse("payload_profile_selection_proof03", &raw).is_err());
        }
    }
}
