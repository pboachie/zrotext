// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated bounded historical candidates, distinct current projection and
//! exact-tip readback. No content permission, enrollment or implicit renewal.
use super::*;
use crate::manifest_install03::live::{self as manifests, HistoryCursor03, Position03};
object_body! {struct Current{v:u8,r#type:String,connection_epoch:i64,challenge:String,line_id:String}}
object_body! {struct History{v:u8,r#type:String,connection_epoch:i64,challenge:String,line_id:String,after_version:String,after_digest:String,after_ancestry_sha256:String,tip_version:serde_json::Value,tip_digest:serde_json::Value,tip_ancestry_sha256:serde_json::Value}}
object_body! {struct Installed{v:u8,r#type:String,connection_epoch:i64,challenge:String,line_id:String,tip_version:String,tip_digest:String,tip_ancestry_sha256:String,election_digest:String}}
pub(in crate::device_socket) struct Frame {
    epoch: i64,
    challenge: Uuid,
    request: Operation,
}
enum Operation {
    Current(Uuid),
    History(HistoryCursor03),
    Installed {
        line: Uuid,
        tip: Position03,
        election: [u8; 32],
    },
}
fn number(s: &str) -> Result<u64, ()> {
    let n = s.parse::<u64>().map_err(|_| ())?;
    if n == 0 || n > i64::MAX as u64 || n.to_string() != s {
        return Err(());
    }
    Ok(n)
}
fn digest(s: &str) -> Result<[u8; 32], ()> {
    line_activation_v2::bytes(s, 32, 32)
        .ok_or(())?
        .try_into()
        .map_err(|_| ())
}
fn header(v: u8, kind: &str, tag: &str, epoch: i64, challenge: &str) -> Result<(i64, Uuid), ()> {
    if v != 1 || kind != tag || epoch <= 0 {
        return Err(());
    }
    Ok((epoch, id(challenge)?))
}
pub(super) fn parse(tag: &str, raw: &str) -> Result<Option<Frame>, ()> {
    Ok(Some(match tag {
        "payload_profile_manifest_current03_request" => {
            let b: Current = serde_json::from_str(raw).map_err(|_| ())?;
            let (epoch, challenge) = header(b.v, &b.r#type, tag, b.connection_epoch, &b.challenge)?;
            Frame {
                epoch,
                challenge,
                request: Operation::Current(id(&b.line_id)?),
            }
        }
        "payload_profile_manifest03_request" => {
            let b: History = serde_json::from_str(raw).map_err(|_| ())?;
            let (epoch, challenge) = header(b.v, &b.r#type, tag, b.connection_epoch, &b.challenge)?;
            let values = [&b.tip_version, &b.tip_digest, &b.tip_ancestry_sha256];
            let tip = if values.iter().all(|v| v.is_null()) {
                None
            } else {
                Some(Position03 {
                    version: number(values[0].as_str().ok_or(())?)?,
                    digest: digest(values[1].as_str().ok_or(())?)?,
                    prefix: digest(values[2].as_str().ok_or(())?)?,
                })
            };
            Frame {
                epoch,
                challenge,
                request: Operation::History(HistoryCursor03 {
                    line: id(&b.line_id)?,
                    after: Position03 {
                        version: number(&b.after_version)?,
                        digest: digest(&b.after_digest)?,
                        prefix: digest(&b.after_ancestry_sha256)?,
                    },
                    tip,
                }),
            }
        }
        "payload_profile_manifest03_installed" => {
            let b: Installed = serde_json::from_str(raw).map_err(|_| ())?;
            let (epoch, challenge) = header(b.v, &b.r#type, tag, b.connection_epoch, &b.challenge)?;
            Frame {
                epoch,
                challenge,
                request: Operation::Installed {
                    line: id(&b.line_id)?,
                    tip: Position03 {
                        version: number(&b.tip_version)?,
                        digest: digest(&b.tip_digest)?,
                        prefix: digest(&b.tip_ancestry_sha256)?,
                    },
                    election: digest(&b.election_digest)?,
                },
            }
        }
        _ => return Ok(None),
    }))
}
pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    session: DeviceSession,
    origin: &str,
    samples: &mut sealed_session::Samples,
    reads: &mut CurrentReads,
    frame: Frame,
) -> Option<()> {
    if frame.epoch != session.connection_epoch
        || !samples.is_sampled()
        || !reads.admit(frame.challenge, Instant::now())
    {
        return None;
    }
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .ok()?;
    let scope = live::SocketSelection03 {
        session,
        site: &state.site_id,
        instance: &state.instance_id,
        deployment: u64::try_from(state.deployment_epoch)
            .ok()
            .filter(|n| *n > 0)?,
        origin,
    };
    let reply = match frame.request {
        Operation::Current(line) => {
            serde_json::json!({"v":1,"type":"payload_profile_manifest_current03","connection_epoch":session.connection_epoch,"challenge":frame.challenge,"current":manifests::current_device(&tx,&scope,line).await.ok()?})
        }
        Operation::History(cursor) => {
            serde_json::json!({"v":1,"type":"payload_profile_manifest03","connection_epoch":session.connection_epoch,"challenge":frame.challenge,"history":manifests::device_history(&tx,&scope,&cursor).await.ok()?})
        }
        Operation::Installed {
            line,
            tip,
            election,
        } => {
            let compared = manifests::device_readback(&tx, &scope, line, tip, election)
                .await
                .ok()?;
            use base64::Engine;
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            serde_json::json!({"v":1,"type":"payload_profile_manifest03_installed_ack","connection_epoch":session.connection_epoch,"challenge":frame.challenge,"line_id":line,"tip_version":tip.version.to_string(),"tip_digest":b.encode(tip.digest),"tip_ancestry_sha256":b.encode(tip.prefix),"election_digest":b.encode(election),"compared_ms":compared.to_string()})
        }
    };
    // These operations write no server highwater/permission and extend no lease.
    // Readback is exact selected-tip confirmation, not device attestation.
    tx.rollback().await.ok()?;
    drop(db);
    send(socket, reply).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_current_and_readback_are_distinct_closed_nonce_bound_requests() {
        let tag = "payload_profile_manifest_current03_request";
        let raw=serde_json::json!({"v":1,"type":tag,"connection_epoch":1,"challenge":Uuid::from_u128(2),"line_id":Uuid::from_u128(3)}).to_string();
        assert!(parse(tag, &raw).unwrap().is_some());
        let extra = raw.replacen('}', ",\"tip_version\":\"2\"}", 1);
        assert!(parse(tag, &extra).is_err());
        assert!(parse(tag, &format!("[{raw}]")).is_err());
        assert!(parse(tag, &format!("{{\"v\":1,{}", &raw[1..])).is_err());
        assert!(
            parse("payload_profile_current03_request", &raw)
                .unwrap()
                .is_none()
        );
    }
}
