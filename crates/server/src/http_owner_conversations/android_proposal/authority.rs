// SPDX-License-Identifier: AGPL-3.0-only
//! Shared root-before-owner locks and current paired phone scope, never a new lease.
use super::super::{ConversationError, SessionPrincipal, fresh_owner, lock_line, lock_owner};
use crate::sealed_manifest::{self, ChainPosition, ManifestTrust};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) struct Selection {
    pub device: Uuid,
    pub line: Uuid,
    pub generation: i64,
    pub peer: String,
}
pub(super) struct Current {
    pub pin: [u8; 94],
    pub fingerprint: [u8; 32],
    pub version: i64,
    pub digest: Option<[u8; 32]>,
    pub manifest: Option<Vec<u8>>,
    pub high_water: i64,
    pub paired_point: [u8; 65],
    pub paired_fingerprint: [u8; 32],
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
    pub site: String,
    pub instance: String,
}
fn reject() -> ConversationError {
    ConversationError::Forbidden
}
impl Current {
    pub(super) fn verify(&self, account: Uuid, now: i64) -> Result<(), ConversationError> {
        if now <= 0 || now < self.high_water {
            return Err(reject());
        }
        if self.version == 0 {
            if self.digest.is_some() || self.manifest.is_some() || self.high_water != 0 {
                return Err(reject());
            }
        } else {
            let trust = ManifestTrust {
                account_id: *account.as_bytes(),
                root_fingerprint: self.fingerprint,
                generation: 1,
                position: ChainPosition::Current {
                    version: self.version.try_into().map_err(|_| reject())?,
                    digest: self.digest.ok_or_else(reject)?,
                },
            };
            sealed_manifest::verify(
                &self.pin,
                self.manifest.as_deref().ok_or_else(reject)?,
                &trust,
                now as u64,
            )
            .map_err(|_| reject())?;
        }
        Ok(())
    }
}
pub(super) async fn lock(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
) -> Result<Current, ConversationError> {
    if s.device.is_nil()
        || s.line.is_nil()
        || s.generation <= 0
        || !(3..=16).contains(&s.peer.len())
        || !s.peer.starts_with('+')
        || !matches!(s.peer.as_bytes()[1], b'1'..=b'9')
        || !s.peer.as_bytes()[2..].iter().all(u8::is_ascii_digit)
    {
        return Err(ConversationError::Invalid);
    }
    let a = p.tenant.account_id();
    let r=tx.query_opt("SELECT root_pin,root_fingerprint,version,semantic_digest,manifest,last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL AND generation=1 AND anchor_digest=$2 FOR UPDATE",&[&a,&vec![0u8;32]]).await?.ok_or_else(reject)?;
    let pin: [u8; 94] = r.get::<_, Vec<u8>>(0).try_into().map_err(|_| reject())?;
    let fingerprint: [u8; 32] = r.get::<_, Vec<u8>>(1).try_into().map_err(|_| reject())?;
    if zrotext_root_material::sealed_root_enrollment::root_fingerprint(&pin, a.as_bytes())
        .map_err(|_| reject())?
        != fingerprint
    {
        return Err(reject());
    }
    lock_owner(tx, p).await?;
    lock_line(tx, a, s.device, s.line, s.generation).await?;
    let k=tx.query_opt("SELECT k.signing_key_sec1,k.fingerprint,s.connection_epoch,s.deployment_epoch,s.site_id,s.instance_id FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN device_sessions s ON (s.account_id,s.device_id)=(d.account_id,d.id) JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority e ON e.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND s.lease_until>clock_timestamp() AND t.enabled AND NOT t.draining AND e.epoch=s.deployment_epoch AND NOT pg_is_in_recovery() FOR SHARE OF d,k,s,t,e",&[&a,&s.device]).await?.ok_or_else(reject)?;
    let paired_point: [u8; 65] = k.get::<_, Vec<u8>>(0).try_into().map_err(|_| reject())?;
    let paired_fingerprint: [u8; 32] = k.get::<_, Vec<u8>>(1).try_into().map_err(|_| reject())?;
    if VerifyingKey::from_sec1_bytes(&paired_point).is_err()
        || Sha256::digest(paired_point).as_slice() != paired_fingerprint
    {
        return Err(reject());
    }
    let c = Current {
        pin,
        fingerprint,
        version: r.get(2),
        digest: r
            .get::<_, Option<Vec<u8>>>(3)
            .map(TryInto::try_into)
            .transpose()
            .map_err(|_| reject())?,
        manifest: r.get(4),
        high_water: r.get(5),
        paired_point,
        paired_fingerprint,
        connection_epoch: k.get(2),
        deployment_epoch: k.get(3),
        site: k.get(4),
        instance: k.get(5),
    };
    fresh(tx, p, s, &c).await?;
    Ok(c)
}
pub(super) async fn fresh(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
) -> Result<i64, ConversationError> {
    fresh_owner(tx, p).await?;
    // One database clock samples owner and phone deadlines together, after waits.
    let r=tx.query_opt("WITH tick AS MATERIALIZED(SELECT clock_timestamp() AS utc) SELECT floor(extract(epoch FROM tick.utc)*1000)::bigint FROM tick,devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN device_sessions s ON (s.account_id,s.device_id)=(d.account_id,d.id) JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority e ON e.singleton=TRUE, sessions o JOIN memberships m ON (m.account_id,m.user_id)=(o.account_id,o.user_id) JOIN users u ON u.id=o.user_id JOIN accounts a ON a.id=o.account_id WHERE a.id=$1 AND o.id=$2 AND u.id=$3 AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL AND o.revoked_at IS NULL AND o.expires_at>tick.utc AND COALESCE(o.last_used_at,o.created_at)>tick.utc-interval '72 hours' AND d.account_id=a.id AND d.id=$4 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND k.fingerprint=$5 AND k.signing_key_sec1=$6 AND s.connection_epoch=$7 AND s.deployment_epoch=$8 AND s.site_id=$9 AND s.instance_id=$10 AND s.lease_until>tick.utc AND t.enabled AND NOT t.draining AND e.epoch=s.deployment_epoch AND NOT pg_is_in_recovery()",&[&p.tenant.account_id(),&p.session_id,&p.user_id,&s.device,&c.paired_fingerprint.as_slice(),&c.paired_point.as_slice(),&c.connection_epoch,&c.deployment_epoch,&c.site,&c.instance]).await?.ok_or_else(reject)?;
    let utc: i64 = r.get(0);
    c.verify(p.tenant.account_id(), utc)?;
    Ok(utc)
}
pub(super) async fn reject_known_alias(
    tx: &Transaction<'_>,
    a: Uuid,
    points: &[[u8; 65]],
) -> Result<(), ConversationError> {
    for point in points {
        if tx.query_opt("SELECT 1 FROM known_signing_point_reservations WHERE account_id=$1 AND signing_key_sec1=$2",&[&a,&point.as_slice()]).await?.is_some(){return Err(reject());}
    }
    Ok(())
}
