// SPDX-License-Identifier: AGPL-3.0-only
//! Private cryptographic progress cache. Only independently verified original
//! prefix progress is cached. Schema/current records are re-read on every use;
//! no owner, factor, device lease, physical handle or send permission is cached.
use super::{
    records::{self, Receipt},
    *,
};
use crate::sealed_payload_election03::live::{Error, manifest_history::History03};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio_postgres::Transaction;
type Result<T> = std::result::Result<T, Error>;
const CAPACITY: usize = 64;
const RETAIN: Duration = Duration::from_secs(300);
const MAX_PAGES: usize = 8;
const WORK: Duration = Duration::from_secs(2);
pub(super) struct Progress {
    pub signed: Vec<u8>,
    pub verified: crypto::VerifiedManifest03,
    pub accepted: u64,
    pub version: u64,
    pub digest: [u8; 32],
    pub prefix: [u8; 32],
    opening: Option<Uuid>,
    retention: Option<[u8; 32]>,
}
type Cache = HashMap<[u8; 32], (Instant, Arc<Progress>)>;
fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn get(key: &[u8; 32]) -> Result<Option<Arc<Progress>>> {
    let mut all = cache().lock().map_err(|_| Error::Unavailable)?;
    all.retain(|_, (when, _)| when.elapsed() < RETAIN);
    Ok(all.get(key).map(|(_, value)| Arc::clone(value)))
}
fn save(key: [u8; 32], value: Arc<Progress>) -> Result<()> {
    let mut all = cache().lock().map_err(|_| Error::Unavailable)?;
    if let Some((_, prior)) = all.get(&key)
        && (prior.version > value.version
            || prior.version == value.version && prior.prefix != value.prefix)
    {
        return Err(Error::Conflict);
    }
    if all.len() >= CAPACITY && !all.contains_key(&key) {
        let oldest = all
            .iter()
            .min_by_key(|(_, (when, _))| *when)
            .map(|(key, _)| *key)
            .ok_or(Error::Unavailable)?;
        all.remove(&oldest);
    }
    all.insert(key, (Instant::now(), value));
    Ok(())
}
pub(super) fn base(h: &History03) -> Result<Progress> {
    let a = &h.accepted;
    let id = h
        .first
        .identity_at(a.accepted_at_ms)
        .map_err(|_| Error::Unsupported)?;
    let verified = crypto::verify_current(&h.first_signed, &h.first, a.accepted_at_ms)
        .map_err(|_| Error::Unsupported)?;
    Ok(Progress {
        signed: h.first_signed.clone(),
        verified,
        accepted: a.accepted_at_ms,
        version: id.version,
        digest: id.digest,
        prefix: base_commitment(
            h.account,
            h.challenge,
            h.binding,
            &h.first_signed,
            a.accepted_at_ms,
            &a.election_bundle_sha256,
        )
        .map_err(|_| Error::Unsupported)?,
        opening: None,
        retention: None,
    })
}
pub(super) fn advance(
    prior: &Progress,
    row: &Receipt,
    h: &History03,
    origin: &str,
) -> Result<Progress> {
    row.scope(h, origin)?;
    if row.predecessor_opening != prior.opening
        || row.prior_prefix != prior.prefix
        || row.prior_signed != prior.signed
        || row.prior_accepted != prior.accepted
        || row.statement.numbers[3] != prior.version
        || row.statement.digests[5] != prior.digest
        || row.accepted > h.checked_ms
    {
        return Err(Error::Conflict);
    }
    let statement = Statement03::decode(row.statement.bytes()).map_err(|_| Error::Unsupported)?;
    let checked = verify(
        statement,
        &row.signature,
        &row.signed,
        Predecessor03 {
            signed: &prior.signed,
            verified: &prior.verified,
            accepted_ms: prior.accepted,
        },
        &ExpectedInstall03 {
            account: h.account,
            user: Uuid::from_bytes(row.statement.ids[1]),
            owner_session: Uuid::from_bytes(row.statement.ids[2]),
            device: h.device,
            line: h.line,
            binding: h.binding,
            election_challenge: h.challenge,
            binding_generation: h.generation,
            vault_generation: 1,
            selection_epoch: h.epoch,
            root_fingerprint: h.accepted.root_fingerprint,
            election_commitment: h.accepted.election_commitment,
            election_bundle_sha256: h.accepted.election_bundle_sha256,
            canonical_origin: origin,
        },
        row.accepted,
    )
    .map_err(|_| Error::Unsupported)?;
    if checked.operation() != row.operation {
        return Err(Error::Unsupported);
    }
    let id = checked
        .successor
        .identity_at(row.accepted)
        .map_err(|_| Error::Unsupported)?;
    // The policy keeps every physical/root/registered identity unchanged; a
    // browser replacement cannot borrow enrollment or original SEALED custody.
    if row.statement.point == h.device_point
        || row.statement.point == h.approval_point
        || row.statement.point.as_slice() == &h.pin[29..]
    {
        return Err(Error::Unsupported);
    }
    Ok(Progress {
        signed: row.signed.clone(),
        verified: checked.successor,
        accepted: row.accepted,
        version: id.version,
        digest: id.digest,
        prefix: row.prefix,
        opening: Some(row.statement.opening()),
        retention: Some(row.retention_identity()),
    })
}
async fn retained(
    tx: &Transaction<'_>,
    cached: &Progress,
    h: &History03,
    origin: &str,
) -> Result<()> {
    if let Some(retention) = cached.retention {
        let row = records::by_version(tx, h.account, cached.version)
            .await?
            .ok_or(Error::Conflict)?;
        row.scope(h, origin)?;
        if row.retention_identity() != retention
            || row.prefix != cached.prefix
            || row.signed != cached.signed
            || Some(row.statement.opening()) != cached.opening
        {
            return Err(Error::Conflict);
        }
    } else {
        let original = base(h)?;
        if original.prefix != cached.prefix
            || original.signed != cached.signed
            || original.accepted != cached.accepted
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
/// Bounded cold work retains private verified progress, then refuses effects
/// until the exact held tip is reached. A later call may resume; no lifetime
/// successor cap, unsigned SQL shortcut, caller boolean or version-only cache.
pub(super) async fn warm(
    tx: &Transaction<'_>,
    h: &History03,
    origin: &str,
) -> Result<Arc<Progress>> {
    crate::payload_profile_manifests::require(tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    let start = Instant::now();
    let initial = base(h)?;
    let key = crypto::sha(&[h.original_identity.as_slice(), &initial.prefix].concat());
    let mut progress = match get(&key)? {
        Some(value) => {
            retained(tx, &value, h, origin).await?;
            value
        }
        None => Arc::new(initial),
    };
    if progress.version > h.tip_version {
        return Err(Error::Conflict);
    }
    for _ in 0..MAX_PAGES {
        if progress.version == h.tip_version {
            break;
        }
        if start.elapsed() >= WORK {
            break;
        }
        let page = records::page(tx, h.account, progress.version, h.tip_version).await?;
        if page.is_empty() {
            return Err(Error::Conflict);
        }
        for row in page {
            if start.elapsed() >= WORK {
                break;
            }
            progress = Arc::new(advance(&progress, &row, h, origin)?);
            save(key, Arc::clone(&progress))?;
        }
    }
    if progress.version != h.tip_version {
        return Err(Error::Unavailable);
    }
    if progress.signed != h.tip_signed
        || progress.digest != h.tip_digest
        || progress.accepted != h.tip_accepted_ms
    {
        return Err(Error::Conflict);
    }
    // One fresh root-signature verification ties a reused checkpoint to the
    // actual held tip; expiry is deliberately checked by the current consumer.
    crypto::verify_current(&h.tip_signed, &progress.verified, h.tip_accepted_ms)
        .map_err(|_| Error::Unsupported)?;
    save(key, Arc::clone(&progress))?;
    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{bytes, corpus, first, number};
    use super::*;
    fn original(prefix: [u8; 32]) -> Arc<Progress> {
        let v = corpus();
        let verified = first(&v);
        let signed = bytes(&v["first03"]["signed_hex"]);
        let accepted = number(&v["first03"]["accepted_ms"]);
        let identity = verified.identity_at(accepted).unwrap();
        Arc::new(Progress {
            signed,
            verified,
            accepted,
            version: identity.version,
            digest: identity.digest,
            prefix,
            opening: None,
            retention: None,
        })
    }
    #[test]
    fn cached_crypto_progress_is_private_scope_bound_and_rejects_same_version_fork() {
        let key: [u8; 32] = rand::random();
        let genuine = original([1; 32]);
        save(key, Arc::clone(&genuine)).unwrap();
        let retained = get(&key).unwrap().unwrap();
        assert!(Arc::ptr_eq(&genuine, &retained));
        assert!(get(&rand::random()).unwrap().is_none());
        assert!(save(key, original([2; 32])).is_err());
        let again = get(&key).unwrap().unwrap();
        assert_eq!(again.prefix, [1; 32]);
        cache().lock().unwrap().remove(&key);
    }
}
