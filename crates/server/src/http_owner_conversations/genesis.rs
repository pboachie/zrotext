// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-cookie first manifest installation under an already provisioned root.
//! Public directory projections never prove independently exported phone reader origin.
//! The owner must independently compare the root and exported phone points before
//! signing. This transaction creates no consent, interval, device action or send authority.
use super::{ConversationError, OwnerConversationsState, SessionPrincipal};
use crate::sealed_manifest::{self, ChainPosition, ManifestTrust};
use crate::{api_json::ApiJson, http_auth::preauth::OwnerMutation};
use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::Arc;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub peer: String,
}
impl Selection {
    fn valid(&self) -> bool {
        let peer = self.peer.as_bytes();
        !self.device_id.is_nil()
            && !self.line_id.is_nil()
            && self.binding_generation > 0
            && (3..=16).contains(&peer.len())
            && peer[0] == b'+'
            && (b'1'..=b'9').contains(&peer[1])
            && peer[2..].iter().all(u8::is_ascii_digit)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub expected_session_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub peer: String,
    pub current_device_signing_fingerprint: String,
    pub expected_root_fingerprint: String,
    pub phone_reader_point: String,
    pub archive_reader_point: String,
    pub phone_signer_point: String,
    pub owner_signer_point: String,
    pub signed_manifest: String,
}

struct Root {
    pin: Vec<u8>,
    fingerprint: [u8; 32],
    version: i64,
    digest: Option<Vec<u8>>,
    bytes: Option<Vec<u8>>,
    high_water: i64,
}

async fn lock_root(tx: &Transaction<'_>, account: Uuid) -> Result<Root, ConversationError> {
    // Shared sealed authority order: authority first, then account and identity fences.
    let row = tx.query_opt("SELECT root_pin,root_fingerprint,generation,anchor_digest,version,semantic_digest,manifest,last_verified_ms \
        FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR UPDATE", &[&account])
        .await?.ok_or(ConversationError::Forbidden)?;
    if row.get::<_, i64>(2) != 1 || row.get::<_, Vec<u8>>(3) != [0; 32] {
        return Err(ConversationError::Forbidden);
    }
    let root = Root {
        pin: row.get(0),
        fingerprint: row
            .get::<_, Vec<u8>>(1)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        version: row.get(4),
        digest: row.get(5),
        bytes: row.get(6),
        high_water: row.get(7),
    };
    if !(0..=1).contains(&root.version) {
        return Err(ConversationError::Conflict);
    }
    Ok(root)
}

fn decode(value: &str, size: usize) -> Result<Vec<u8>, ConversationError> {
    if value.len() > size.div_ceil(3) * 4 {
        return Err(ConversationError::Invalid);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| ConversationError::Invalid)?;
    if bytes.len() != size || STANDARD.encode(&bytes) != value {
        return Err(ConversationError::Invalid);
    }
    Ok(bytes)
}

async fn clock(tx: &Transaction<'_>, high_water: i64) -> Result<i64, ConversationError> {
    let now = super::activation::now(tx).await?;
    if now <= 0 || now < high_water {
        return Err(ConversationError::Forbidden);
    }
    Ok(now)
}

async fn key(
    tx: &Transaction<'_>,
    account: Uuid,
    selected: &Selection,
) -> Result<(Vec<u8>, Vec<u8>), ConversationError> {
    super::lock_line(
        tx,
        account,
        selected.device_id,
        selected.line_id,
        selected.binding_generation,
    )
    .await?;
    let row = tx
        .query_opt(
            "SELECT k.signing_key_sec1,k.fingerprint FROM devices d \
        JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
        JOIN device_sessions s ON (s.account_id,s.device_id)=(d.account_id,d.id) \
        JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE \
        WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
        AND s.lease_until>clock_timestamp() AND t.enabled AND NOT t.draining \
        AND p.epoch=s.deployment_epoch AND NOT pg_is_in_recovery() FOR SHARE OF d,k,s,t,p",
            &[&account, &selected.device_id],
        )
        .await?
        .ok_or(ConversationError::Forbidden)?;
    let point: Vec<u8> = row.get(0);
    let fingerprint: Vec<u8> = row.get(1);
    use sha2::{Digest, Sha256};
    if point.len() != 65
        || fingerprint.len() != 32
        || Sha256::digest(&point).as_slice() != fingerprint
        || p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_err()
    {
        return Err(ConversationError::Forbidden);
    }
    Ok((point, fingerprint))
}

fn trust(account: Uuid, root: &Root) -> ManifestTrust {
    ManifestTrust {
        account_id: *account.as_bytes(),
        root_fingerprint: root.fingerprint,
        generation: 1,
        position: ChainPosition::Genesis {
            anchor_digest: [0; 32],
        },
    }
}

fn exact_roles(
    bytes: &[u8],
    selected: &Selection,
    points: &[Vec<u8>; 4],
    now: i64,
) -> Result<(), ConversationError> {
    if bytes.len() != 811 || bytes[150] != 4 {
        return Err(ConversationError::Invalid);
    }
    for (i, role) in [1u8, 2, 4, 6].iter().enumerate() {
        let r = &bytes[151 + i * 149..151 + (i + 1) * 149];
        let scoped = *role == 1 || *role == 4;
        if r[0] != *role
            || r[33..98] != points[i]
            || r[98..114]
                != if scoped {
                    *selected.device_id.as_bytes()
                } else {
                    [0; 16]
                }
            || r[114..130]
                != if scoped {
                    *selected.line_id.as_bytes()
                } else {
                    [0; 16]
                }
            || u16::from_be_bytes(r[130..132].try_into().unwrap()) != [4, 12, 2, 0][i]
            || r[148] != 1
            || r[132..148] != bytes[37..53]
            || u64::from_be_bytes(r[132..140].try_into().unwrap()) > now as u64
            || u64::from_be_bytes(r[140..148].try_into().unwrap()) <= now as u64
        {
            return Err(ConversationError::Forbidden);
        }
    }
    Ok(())
}

pub async fn bootstrap_manifest(
    client: &mut Client,
    owner: &SessionPrincipal,
    selected: &Selection,
) -> Result<serde_json::Value, ConversationError> {
    if !selected.valid() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let root = lock_root(&tx, owner.tenant.account_id()).await?;
    super::lock_owner(&tx, owner).await?;
    let (device_point, device_fingerprint) = key(&tx, owner.tenant.account_id(), selected).await?;
    if key(&tx, owner.tenant.account_id(), selected).await?
        != (device_point.clone(), device_fingerprint.clone())
    {
        return Err(ConversationError::Forbidden);
    }
    super::fresh_owner(&tx, owner).await?;
    let now = clock(&tx, root.high_water).await?;
    if root.version == 0 {
        // Verify the provisioned pin independently of untrusted manifest bytes.
        use sha2::{Digest, Sha256};
        if root.pin.len() != 94
            || &root.pin[..5] != b"ZTRP\x02"
            || root.pin[5..21] != *owner.tenant.account_id().as_bytes()
            || root.pin[21..29] != 1u64.to_be_bytes()
            || Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &root.pin].concat()).as_slice()
                != root.fingerprint
            || p256::ecdsa::VerifyingKey::from_sec1_bytes(&root.pin[29..94]).is_err()
            || root.digest.is_some()
            || root.bytes.is_some()
            || root.high_water != 0
        {
            return Err(ConversationError::Forbidden);
        }
    } else {
        let verified = sealed_manifest::verify(
            &root.pin,
            root.bytes.as_deref().ok_or(ConversationError::Forbidden)?,
            &trust(owner.tenant.account_id(), &root),
            now as u64,
        )
        .map_err(|_| ConversationError::Forbidden)?;
        if root.digest.as_deref() != Some(verified.digest().as_slice()) {
            return Err(ConversationError::Forbidden);
        }
    }
    let result = serde_json::json!({"v":1,"trust_candidate":true,"owner_session_live":true,"authority_live":true,
        "device_key_live":true,"line_binding_live":true,"consent_live":false,"phase":"unprepared",
        "account_id":owner.tenant.account_id(),"session_id":owner.session_id,"device_id":selected.device_id,
        "line_id":selected.line_id,"binding_generation":selected.binding_generation.to_string(),"peer":selected.peer,
        "current_device_signing_point":STANDARD.encode(device_point),"current_device_signing_fingerprint":STANDARD.encode(device_fingerprint),"server_now_ms":now.to_string(),"root_pin":STANDARD.encode(&root.pin),
        "root_fingerprint":STANDARD.encode(root.fingerprint),"trust_generation":"1","manifest_version":root.version.to_string(),
        "manifest_digest":root.digest.as_ref().map(|b| STANDARD.encode(b)),"current_manifest":root.bytes.as_ref().map(|b| STANDARD.encode(b))});
    tx.commit().await?;
    Ok(result)
}

pub async fn install_manifest(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: &InstallRequest,
) -> Result<(), ConversationError> {
    if request.expected_session_id != owner.session_id {
        return Err(ConversationError::Forbidden);
    }
    let selected = Selection {
        device_id: request.device_id,
        line_id: request.line_id,
        binding_generation: request.binding_generation,
        peer: request.peer.clone(),
    };
    if !selected.valid() {
        return Err(ConversationError::Invalid);
    }
    let bytes = decode(&request.signed_manifest, 811)?;
    let fingerprint = decode(&request.expected_root_fingerprint, 32)?;
    let device_fingerprint = decode(&request.current_device_signing_fingerprint, 32)?;
    let points = [
        decode(&request.phone_reader_point, 65)?,
        decode(&request.archive_reader_point, 65)?,
        decode(&request.phone_signer_point, 65)?,
        decode(&request.owner_signer_point, 65)?,
    ];
    let tx = client.transaction().await?;
    let root = lock_root(&tx, owner.tenant.account_id()).await?;
    if fingerprint != root.fingerprint || root.pin.get(29..94) != Some(points[3].as_slice()) {
        return Err(ConversationError::Forbidden);
    }
    super::lock_owner(&tx, owner).await?;
    if key(&tx, owner.tenant.account_id(), &selected).await?
        != (points[2].clone(), device_fingerprint.clone())
    {
        return Err(ConversationError::Forbidden);
    }
    super::fresh_owner(&tx, owner).await?;
    let now = clock(&tx, root.high_water).await?;
    let verified = sealed_manifest::verify(
        &root.pin,
        &bytes,
        &trust(owner.tenant.account_id(), &root),
        now as u64,
    )
    .map_err(|_| ConversationError::Forbidden)?;
    exact_roles(&bytes, &selected, &points, now)?;
    // Genesis accepts exactly version one. Exact-byte retries retain acceptance
    // time; a semantic or signature fork cannot replace the durable manifest.
    if root.version == 1 {
        if root.bytes.as_deref() != Some(bytes.as_slice())
            || root.digest.as_deref() != Some(verified.digest().as_slice())
        {
            return Err(ConversationError::Conflict);
        }
        tx.execute(
            "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
            &[&owner.tenant.account_id(), &now],
        )
        .await?;
    } else {
        let changed = tx.execute("UPDATE sealed_manifest_authorities SET version=1,semantic_digest=$2,manifest=$3,accepted_at_ms=$4,last_verified_ms=$4 \
            WHERE account_id=$1 AND version=0 AND revoked_at IS NULL", &[&owner.tenant.account_id(), &verified.digest().as_slice(), &bytes, &now]).await?;
        if changed != 1 {
            return Err(ConversationError::Conflict);
        }
    }
    super::fresh_owner(&tx, owner).await?;
    // A database write can wait. Freshness, owner and
    // paired device-session expiry must still hold at the final database wall time.
    if key(&tx, owner.tenant.account_id(), &selected).await?
        != (points[2].clone(), device_fingerprint.clone())
    {
        return Err(ConversationError::Forbidden);
    }
    super::fresh_owner(&tx, owner).await?;
    let final_now = clock(&tx, now).await?;
    sealed_manifest::verify(
        &root.pin,
        &bytes,
        &trust(owner.tenant.account_id(), &root),
        final_now as u64,
    )
    .map_err(|_| ConversationError::Forbidden)?;
    exact_roles(&bytes, &selected, &points, final_now)?;
    tx.execute(
        "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
        &[&owner.tenant.account_id(), &final_now],
    )
    .await?;
    // The final write can itself wait. Revalidate after it, without another
    // mutation that could move acceptance beyond these authority checks.
    super::fresh_owner(&tx, owner).await?;
    if key(&tx, owner.tenant.account_id(), &selected).await?
        != (points[2].clone(), device_fingerprint.clone())
    {
        return Err(ConversationError::Forbidden);
    }
    super::fresh_owner(&tx, owner).await?;
    let commit_now = clock(&tx, final_now).await?;
    sealed_manifest::verify(
        &root.pin,
        &bytes,
        &trust(owner.tenant.account_id(), &root),
        commit_now as u64,
    )
    .map_err(|_| ConversationError::Forbidden)?;
    exact_roles(&bytes, &selected, &points, commit_now)?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn bootstrap(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(selected): ApiJson<Selection>,
) -> Result<Json<serde_json::Value>, ConversationError> {
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    Ok(Json(
        bootstrap_manifest(&mut client, &owner, &selected).await?,
    ))
}
pub(super) async fn install(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(request): ApiJson<InstallRequest>,
) -> Result<StatusCode, ConversationError> {
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    install_manifest(&mut client, &owner, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
