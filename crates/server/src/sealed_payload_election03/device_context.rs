// SPDX-License-Identifier: AGPL-3.0-only
//! Held current database device rows, not socket authentication or effect
//! permission. Callers supply their trusted application transaction and must
//! independently authenticate the ingress, owner/MFA and accepted election.
use super::adapter_contract::{self, DeviceSessionIdentity03};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;
use zrotext_root_material::sealed_root_enrollment;

#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("current device context unavailable")]
    Refused,
    #[error("current device context fence busy")]
    Busy,
    #[error("current device context storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ContextError>;

/// Exact lookup expectations only. Possessing or copying these fields never
/// authenticates a device socket, a session credential or a tenant principal.
#[derive(Clone, PartialEq, Eq)]
pub struct Selector {
    pub account: Uuid,
    pub device: Uuid,
    pub site: String,
    pub instance: String,
    pub connection_epoch: u64,
    pub deployment_epoch: u64,
}

#[derive(PartialEq, Eq)]
struct Rows {
    selector: Selector,
    selection_epoch: u64,
    root_fingerprint: [u8; 32],
    signing_key_id: [u8; 32],
    lease_until_ms: u64,
    // Preserve the database timestamp's full precision for exact row equality.
    // The conservative millisecond cutoff is only an expiry predicate.
    lease_until_wire: [u8; 8],
    canonical: Vec<u8>,
    digest: [u8; 32],
}

/// Opaque row witness borrowing the actual transaction that acquired its locks.
/// Canonical bytes/digests are identities, never detached current permission.
/// Revalidate immediately before later composition: held rows do not stop time
/// or prevent the transaction owner from changing its own rows or search path.
/// This is neither owner/MFA/CSRF proof nor an accepted-selection/effect token.
pub struct HeldDeviceContext03<'held, 'db> {
    tx: &'held Transaction<'db>,
    rows: Rows,
    checked_ms: u64,
}
impl HeldDeviceContext03<'_, '_> {
    pub fn canonical_identity(&self) -> &[u8] {
        &self.rows.canonical
    }
    pub fn identity_digest(&self) -> &[u8; 32] {
        &self.rows.digest
    }
    pub fn selection_epoch(&self) -> u64 {
        self.rows.selection_epoch
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.rows.root_fingerprint
    }
    pub fn enrollment_signing_key_id(&self) -> &[u8; 32] {
        &self.rows.signing_key_id
    }

    /// Freshly repeat every row/identity/epoch/predicate and the primary clock
    /// in this same transaction; a cached lease deadline is insufficient.
    pub async fn revalidate(&mut self) -> Result<()> {
        pin(self.tx).await?;
        let (rows, checked) = read_rows(self.tx, &self.rows.selector, self.checked_ms).await?;
        if rows != self.rows {
            return Err(ContextError::Refused);
        }
        self.checked_ms = checked;
        Ok(())
    }
}

async fn pin(tx: &Transaction<'_>) -> Result<()> {
    // Pin operators as well as functions before all policy or clock queries.
    // These bounds remain local to the caller-owned transaction.
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .try_get::<_, String>(0)?
        != "read committed"
    {
        return Err(ContextError::Refused);
    }
    Ok(())
}
fn positive(n: i64) -> Result<u64> {
    u64::try_from(n)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(ContextError::Refused)
}
fn fixed<const N: usize>(row: &Row, column: usize) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(column)?
        .try_into()
        .map_err(|_| ContextError::Refused)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let r = tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await?;
    let now = positive(r.try_get(1)?)?;
    if r.try_get::<_, bool>(0)? || now < floor {
        return Err(ContextError::Refused);
    }
    Ok(now)
}

/// Lock actual current device records with bounded refusal and return a witness
/// tied to this caller-owned READ COMMITTED transaction. No commit or rollback
/// occurs here; the caller must roll back the whole transaction on any refusal.
/// This does not certify the complete schema/state graph or authorize profile03.
pub async fn lock<'held, 'db>(
    tx: &'held Transaction<'db>,
    expected: &Selector,
) -> Result<HeldDeviceContext03<'held, 'db>> {
    if expected.account.is_nil()
        || expected.device.is_nil()
        || expected.connection_epoch == 0
        || expected.deployment_epoch == 0
        || expected.connection_epoch > i64::MAX as u64
        || expected.deployment_epoch > i64::MAX as u64
    {
        return Err(ContextError::Refused);
    }
    pin(tx).await?;
    let (rows, checked_ms) = read_rows(tx, expected, 0).await?;
    Ok(HeldDeviceContext03 {
        tx,
        rows,
        checked_ms,
    })
}

async fn read_rows(tx: &Transaction<'_>, expected: &Selector, floor: u64) -> Result<(Rows, u64)> {
    let entered = clock(tx, floor).await?;
    // Match existing authority-before-account ordering; unsupported rotated or
    // missing roots cannot be reconstructed as a new generation-one origin.
    let root = tx.query_opt("SELECT root_pin,root_fingerprint,generation,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT", &[&expected.account]).await?.ok_or(ContextError::Refused)?;
    let pin: [u8; 94] = fixed(&root, 0)?;
    let fingerprint: [u8; 32] = fixed(&root, 1)?;
    let verified: i64 = root.try_get(3)?;
    if root.try_get::<_, i64>(2)? != 1
        || verified < 0
        || sealed_root_enrollment::root_fingerprint(&pin, expected.account.as_bytes())
            .map_err(|_| ContextError::Refused)?
            != fingerprint
    {
        return Err(ContextError::Refused);
    }
    let fence = adapter_contract::account_fence_key(expected.account.as_bytes())
        .map_err(|_| ContextError::Refused)?;
    if !tx
        .query_one(
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)",
            &[&fence],
        )
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(ContextError::Busy);
    }
    let anchor=tx.query_opt("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR SHARE NOWAIT",&[&expected.account]).await?.ok_or(ContextError::Refused)?;
    let epoch: i64 = anchor.try_get(1)?;
    if anchor.try_get::<_, String>(0)? != "live" || epoch < 0 {
        return Err(ContextError::Refused);
    }
    tx.query_opt(
        "SELECT id FROM public.accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
        &[&expected.account],
    )
    .await?
    .ok_or(ContextError::Refused)?;
    // Every digest field comes from the locked rows, including version95's
    // epoch-bound admission; expectations only choose and compare the record.
    let r=tx.query_opt("SELECT s.account_id,s.device_id,s.site_id,s.instance_id,s.connection_epoch,s.deployment_epoch,s.line_activation_version,k.signing_key_sec1,k.fingerprint,pg_catalog.floor(extract(epoch FROM s.lease_until)*1000)::bigint,pg_catalog.timestamptz_send(s.lease_until) FROM public.device_sessions s JOIN public.devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN public.device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND t.enabled AND NOT t.draining AND p.epoch=s.deployment_epoch FOR SHARE OF s,d,k,t,p NOWAIT",&[&expected.account,&expected.device]).await?.ok_or(ContextError::Refused)?;
    let actual = Selector {
        account: r.try_get(0)?,
        device: r.try_get(1)?,
        site: r.try_get(2)?,
        instance: r.try_get(3)?,
        connection_epoch: positive(r.try_get(4)?)?,
        deployment_epoch: positive(r.try_get(5)?)?,
    };
    let version = u16::try_from(r.try_get::<_, i16>(6)?).map_err(|_| ContextError::Refused)?;
    let point: Vec<u8> = r.try_get(7)?;
    let stored_fingerprint: [u8; 32] = fixed(&r, 8)?;
    let lease_until_ms = positive(r.try_get(9)?)?;
    let lease_until_wire = fixed(&r, 10)?;
    if &actual != expected || point.as_slice() == &pin[29..] {
        return Err(ContextError::Refused);
    }
    let signing_key_id = adapter_contract::enrollment_signing_key_id(&point, &stored_fingerprint)
        .map_err(|_| ContextError::Refused)?;
    let identity = DeviceSessionIdentity03 {
        account_id: *actual.account.as_bytes(),
        device_id: *actual.device.as_bytes(),
        site_id: &actual.site,
        instance_id: &actual.instance,
        connection_epoch: actual.connection_epoch,
        deployment_epoch: actual.deployment_epoch,
        line_activation_version: version,
        enrollment_signing_key_id: signing_key_id,
    };
    let canonical = identity.canonical().map_err(|_| ContextError::Refused)?;
    let digest = identity.digest().map_err(|_| ContextError::Refused)?;
    let checked = clock(tx, entered.max(verified as u64)).await?;
    if checked >= lease_until_ms {
        return Err(ContextError::Refused);
    }
    Ok((
        Rows {
            selector: actual,
            selection_epoch: epoch as u64,
            root_fingerprint: fingerprint,
            signing_key_id,
            lease_until_ms,
            lease_until_wire,
            canonical,
            digest,
        },
        checked,
    ))
}

#[cfg(test)]
mod tests;
