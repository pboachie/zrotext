// SPDX-License-Identifier: AGPL-3.0-only
//! Held ordinary owner records, not bearer, CSRF, TOTP or reviewer credential
//! authentication. A trusted application caller must independently authenticate
//! its request and establish every accepted-election/state/effect predicate.
use super::adapter_contract::{self, OwnerSessionIdentity03};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;
use zrotext_root_material::sealed_root_enrollment;

const IDLE_MS: u64 = 72 * 60 * 60 * 1000;
#[derive(Debug, thiserror::Error)]
pub enum OwnerRecordsError {
    #[error("current ordinary owner records unavailable")]
    Refused,
    #[error("current ordinary owner fence busy")]
    Busy,
    #[error("current ordinary owner storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, OwnerRecordsError>;

/// Lookup selectors only; UUIDs and copied roles authenticate no credential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub account: Uuid,
    pub user: Uuid,
    pub session: Uuid,
}
#[derive(PartialEq, Eq)]
struct Records {
    selector: Selector,
    selection_epoch: u64,
    root_fingerprint: [u8; 32],
    // Internal consistency only. Never exported as credential verification.
    credential_state: [u8; 32],
    expiry_ms: u64,
    activity_ms: u64,
    times: Vec<Option<[u8; 8]>>,
    canonical: Vec<u8>,
    digest: [u8; 32],
}

/// Opaque witness borrowing the actual transaction that holds these rows.
/// Exported identity bytes are never detached current permission. This reads
/// ordinary sessions only; isolated reviewer authentication is a separate
/// adapter. It neither spends nor manufactures a bearer/CSRF/MFA/root proof.
pub struct HeldOwnerRecords03<'held, 'db> {
    tx: &'held Transaction<'db>,
    records: Records,
    checked_ms: u64,
}
impl HeldOwnerRecords03<'_, '_> {
    pub fn canonical_identity(&self) -> &[u8] {
        &self.records.canonical
    }
    pub fn identity_digest(&self) -> &[u8; 32] {
        &self.records.digest
    }
    pub fn selection_epoch(&self) -> u64 {
        self.records.selection_epoch
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.records.root_fingerprint
    }
    /// Conservative millisecond deadline for this exact session and its idle
    /// policy. This timestamp alone is never a detached authorization proof.
    pub fn session_deadline_ms(&self) -> u64 {
        self.records
            .expiry_ms
            .min(self.records.activity_ms.saturating_add(IDLE_MS))
    }
    /// The last actual primary clock observation retained by this witness.
    /// Composing adapters must not reset their clock floor after a recheck.
    pub fn checked_at_ms(&self) -> u64 {
        self.checked_ms
    }
    /// Repeat actual row, credential-state, epoch and temporal checks directly
    /// before later composition. Locks cannot stop time or own-transaction writes.
    pub async fn revalidate(&mut self) -> Result<()> {
        pin(self.tx).await?;
        let (records, checked) =
            read_records(self.tx, self.records.selector, self.checked_ms).await?;
        if records != self.records {
            return Err(OwnerRecordsError::Refused);
        }
        self.checked_ms = checked;
        Ok(())
    }
}

async fn pin(tx: &Transaction<'_>) -> Result<()> {
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .try_get::<_, String>(0)?
        != "read committed"
    {
        return Err(OwnerRecordsError::Refused);
    }
    Ok(())
}
fn fixed<const N: usize>(r: &Row, i: usize) -> Result<[u8; N]> {
    r.try_get::<_, Vec<u8>>(i)?
        .try_into()
        .map_err(|_| OwnerRecordsError::Refused)
}
fn time_wire(r: &Row, i: usize) -> Result<Option<[u8; 8]>> {
    r.try_get::<_, Option<Vec<u8>>>(i)?
        .map(|v| v.try_into().map_err(|_| OwnerRecordsError::Refused))
        .transpose()
}
fn positive(n: i64) -> Result<u64> {
    u64::try_from(n)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(OwnerRecordsError::Refused)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let r=tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await?;
    let now = positive(r.try_get(1)?)?;
    if r.try_get::<_, bool>(0)? || now < floor {
        return Err(OwnerRecordsError::Refused);
    }
    Ok(now)
}

/// Lock actual ordinary owner records in a caller-owned primary READ COMMITTED
/// transaction. No commit/rollback or authentication occurs here. The caller
/// must roll back the whole transaction on refusal and separately verify actual
/// bearer/origin/CSRF/step-up/election permissions. This is not a schema certificate.
pub async fn lock<'held, 'db>(
    tx: &'held Transaction<'db>,
    selector: Selector,
) -> Result<HeldOwnerRecords03<'held, 'db>> {
    if selector.account.is_nil() || selector.user.is_nil() || selector.session.is_nil() {
        return Err(OwnerRecordsError::Refused);
    }
    pin(tx).await?;
    let (records, checked_ms) = read_records(tx, selector, 0).await?;
    Ok(HeldOwnerRecords03 {
        tx,
        records,
        checked_ms,
    })
}

async fn read_records(
    tx: &Transaction<'_>,
    selector: Selector,
    floor: u64,
) -> Result<(Records, u64)> {
    let entered = clock(tx, floor).await?;
    let root=tx.query_opt("SELECT root_pin,root_fingerprint,generation,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT",&[&selector.account]).await?.ok_or(OwnerRecordsError::Refused)?;
    let root_pin: [u8; 94] = fixed(&root, 0)?;
    let root_fingerprint: [u8; 32] = fixed(&root, 1)?;
    let verified: i64 = root.try_get(3)?;
    if root.try_get::<_, i64>(2)? != 1
        || verified < 0
        || sealed_root_enrollment::root_fingerprint(&root_pin, selector.account.as_bytes())
            .map_err(|_| OwnerRecordsError::Refused)?
            != root_fingerprint
    {
        return Err(OwnerRecordsError::Refused);
    }
    let fence = adapter_contract::account_fence_key(selector.account.as_bytes())
        .map_err(|_| OwnerRecordsError::Refused)?;
    if !tx
        .query_one(
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)",
            &[&fence],
        )
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(OwnerRecordsError::Busy);
    }
    let anchor=tx.query_opt("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR SHARE NOWAIT",&[&selector.account]).await?.ok_or(OwnerRecordsError::Refused)?;
    let epoch: i64 = anchor.try_get(1)?;
    if anchor.try_get::<_, String>(0)? != "live" || epoch < 0 {
        return Err(OwnerRecordsError::Refused);
    }
    tx.query_opt(
        "SELECT id FROM public.accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
        &[&selector.account],
    )
    .await?
    .ok_or(OwnerRecordsError::Refused)?;
    // A supplied selector cannot stand in for any role, enrollment or session
    // predicate. All retained values originate in these actual locked records.
    let r=tx.query_opt("SELECT s.account_id,s.user_id,s.id,u.email,u.password_hash,s.token_hash,s.csrf_hash,f.secret_nonce,f.secret_ciphertext,pg_catalog.timestamptz_send(s.expires_at),pg_catalog.timestamptz_send(s.created_at),pg_catalog.timestamptz_send(s.last_used_at),pg_catalog.timestamptz_send(u.email_verified_at),pg_catalog.timestamptz_send(f.enabled_at),pg_catalog.floor(extract(epoch FROM s.expires_at)*1000)::bigint,pg_catalog.floor(extract(epoch FROM COALESCE(s.last_used_at,s.created_at))*1000)::bigint,pg_catalog.floor(extract(epoch FROM s.created_at)*1000)::bigint,pg_catalog.floor(extract(epoch FROM u.email_verified_at)*1000)::bigint,pg_catalog.floor(extract(epoch FROM f.enabled_at)*1000)::bigint FROM public.sessions s JOIN public.memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN public.users u ON u.id=m.user_id JOIN public.owner_mfa f ON (f.account_id,f.user_id)=(m.account_id,m.user_id) WHERE s.account_id=$1 AND s.user_id=$2 AND s.id=$3 AND s.revoked_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL FOR SHARE OF s,m,u,f NOWAIT",&[&selector.account,&selector.user,&selector.session]).await?.ok_or(OwnerRecordsError::Refused)?;
    let actual = Selector {
        account: r.try_get(0)?,
        user: r.try_get(1)?,
        session: r.try_get(2)?,
    };
    if actual != selector {
        return Err(OwnerRecordsError::Refused);
    }
    let email: String = r.try_get(3)?;
    let verifier: String = r.try_get(4)?;
    if !(3..=254).contains(&email.len()) || verifier.is_empty() || verifier.len() > 1024 {
        return Err(OwnerRecordsError::Refused);
    }
    let token: [u8; 32] = fixed(&r, 5)?;
    let csrf: [u8; 32] = fixed(&r, 6)?;
    let nonce: [u8; 12] = fixed(&r, 7)?;
    let ciphertext: [u8; 36] = fixed(&r, 8)?;
    // This private digest prevents same-transaction credential substitutions.
    // It does not parse/verify a password or decrypt/verify an MFA factor, and
    // neither the material nor this consistency digest has a public accessor.
    let mut state = Sha256::new();
    state.update(b"internal/profile03/ordinary-owner-record-state/v1\0");
    for bytes in [
        email.as_bytes(),
        verifier.as_bytes(),
        &token,
        &csrf,
        &nonce,
        &ciphertext,
    ] {
        state.update((bytes.len() as u64).to_be_bytes());
        state.update(bytes);
    }
    let credential_state = state.finalize().into();
    let mut times = Vec::new();
    for i in 9..14 {
        times.push(time_wire(&r, i)?);
    }
    let expiry_ms = positive(r.try_get(14)?)?;
    let activity_ms = positive(r.try_get(15)?)?;
    let created_ms = positive(r.try_get(16)?)?;
    let email_verified_ms = positive(r.try_get(17)?)?;
    let mfa_enabled_ms = positive(r.try_get(18)?)?;
    let checked = clock(
        tx,
        [
            entered,
            verified as u64,
            activity_ms,
            created_ms,
            email_verified_ms,
            mfa_enabled_ms,
        ]
        .into_iter()
        .max()
        .unwrap(),
    )
    .await?;
    if checked >= expiry_ms || checked.saturating_sub(activity_ms) >= IDLE_MS {
        return Err(OwnerRecordsError::Refused);
    }
    let identity = OwnerSessionIdentity03 {
        account_id: *actual.account.as_bytes(),
        user_id: *actual.user.as_bytes(),
        session_id: *actual.session.as_bytes(),
    };
    let canonical = identity
        .canonical()
        .map_err(|_| OwnerRecordsError::Refused)?;
    let digest = identity.digest().map_err(|_| OwnerRecordsError::Refused)?;
    Ok((
        Records {
            selector: actual,
            selection_epoch: epoch as u64,
            root_fingerprint,
            credential_state,
            expiry_ms,
            activity_ms,
            times,
            canonical,
            digest,
        },
        checked,
    ))
}

#[cfg(test)]
mod tests;
