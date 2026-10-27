// SPDX-License-Identifier: AGPL-3.0-only
//! Ordinary cookie/CSRF authentication over held owner records. This is not a
//! fresh MFA/root proof, accepted profile selection or authorization to send.
use super::{FreshVerification, Role, SessionPrincipal, Tenant, TokenHasher, valid_token};
use crate::sealed_payload_election03::{
    adapter_contract,
    owner_records::{self, HeldOwnerRecords03, OwnerRecordsError, Selector},
};
use subtle::ConstantTimeEq;
use tokio_postgres::Transaction;

pub mod step_up;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ordinary owner authentication refused")]
    Refused,
    #[error("ordinary owner records unavailable")]
    Records(#[from] OwnerRecordsError),
    #[error("ordinary owner authentication storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, Error>;

/// Transient raw request inputs. Configuration must supply the hasher and
/// canonical origin independently; request fields cannot choose either.
#[derive(Clone, Copy)]
pub struct RequestSource<'a> {
    pub session_cookie: &'a str,
    pub origin: &'a str,
    pub csrf_cookie: &'a str,
    pub csrf_header: &'a str,
}

/// Authentication remains tied to the transaction retaining its owner locks.
/// No secret or reusable unlocked principal is retained or exported. Separate
/// step-up, schema/state, device, election and effect checks remain mandatory.
pub struct HeldOrdinaryOwner03<'held, 'db> {
    tx: &'held Transaction<'db>,
    selector: Selector,
    records: HeldOwnerRecords03<'held, 'db>,
    origin_digest: [u8; 32],
}
impl HeldOrdinaryOwner03<'_, '_> {
    pub(crate) fn selected_identity(&self) -> Selector {
        self.selector
    }
    pub(crate) fn uses_transaction(&self, tx: &Transaction<'_>) -> bool {
        std::ptr::eq(self.tx, tx)
    }
    pub fn canonical_identity(&self) -> &[u8] {
        self.records.canonical_identity()
    }
    pub fn identity_digest(&self) -> &[u8; 32] {
        self.records.identity_digest()
    }
    pub fn origin_digest(&self) -> &[u8; 32] {
        &self.origin_digest
    }
    pub fn selection_epoch(&self) -> u64 {
        self.records.selection_epoch()
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        self.records.root_fingerprint()
    }
    pub fn session_deadline_ms(&self) -> u64 {
        self.records.session_deadline_ms()
    }
    pub fn checked_at_ms(&self) -> u64 {
        self.records.checked_at_ms()
    }
    /// Recheck exact held credentials, records and primary time immediately
    /// before later composition. Trusted code can mutate its own transaction.
    pub async fn revalidate(&mut self) -> Result<()> {
        self.records.revalidate().await?;
        Ok(())
    }
}

fn check_source(canonical_origin: &str, source: RequestSource<'_>) -> Result<[u8; 32]> {
    // Bound before the existing base64 decoder can allocate. Do not normalize
    // secrets, compare a request origin to itself or accept another token realm.
    if source.session_cookie.len() != 47
        || source.csrf_cookie.len() != 47
        || source.csrf_header.len() != 47
        || !valid_token(source.session_cookie, "zts_")
        || !valid_token(source.csrf_cookie, "ztc_")
        || !valid_token(source.csrf_header, "ztc_")
        || !bool::from(
            source
                .csrf_cookie
                .as_bytes()
                .ct_eq(source.csrf_header.as_bytes()),
        )
        || canonical_origin.len() > 2048
        || source.origin != canonical_origin
    {
        return Err(Error::Refused);
    }
    adapter_contract::origin_digest(canonical_origin).map_err(|_| Error::Refused)
}

async fn pin(tx: &Transaction<'_>) -> Result<()> {
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .try_get::<_, String>(0)?
        != "read committed"
    {
        return Err(Error::Refused);
    }
    Ok(())
}

// An unlocked lookup is only a hint. It is private and cannot construct a proof.
async fn credential_hint(tx: &Transaction<'_>, hash: &[u8; 32]) -> Result<Selector> {
    let row = tx
        .query_opt(
            "SELECT account_id,user_id,id FROM public.sessions WHERE token_hash=$1",
            &[&&hash[..]],
        )
        .await?
        .ok_or(Error::Refused)?;
    Ok(Selector {
        account: row.try_get(0)?,
        user: row.try_get(1)?,
        session: row.try_get(2)?,
    })
}

/// Authenticate an actual ordinary cookie and CSRF proof in the caller's
/// primary READ COMMITTED transaction. No activity, MFA, token or budget writes
/// occur. The caller owns HTTP admission and must roll back on any refusal.
pub async fn authenticate<'held, 'db>(
    tx: &'held Transaction<'db>,
    hasher: &TokenHasher,
    canonical_origin: &str,
    source: RequestSource<'_>,
) -> Result<HeldOrdinaryOwner03<'held, 'db>> {
    let origin_digest = check_source(canonical_origin, source)?;
    pin(tx).await?;
    let hash = hasher.digest(b"session-v1", source.session_cookie);
    let selector = credential_hint(tx, &hash).await?;
    lock_and_verify(
        tx,
        hasher,
        canonical_origin,
        source,
        selector,
        &hash,
        origin_digest,
    )
    .await
}

// Kept private so tests can interleave a committed token rotation between the
// lookup and locks. No external caller can supply an authenticated selector.
async fn lock_and_verify<'held, 'db>(
    tx: &'held Transaction<'db>,
    hasher: &TokenHasher,
    canonical_origin: &str,
    source: RequestSource<'_>,
    selector: Selector,
    hash: &[u8; 32],
    origin_digest: [u8; 32],
) -> Result<HeldOrdinaryOwner03<'held, 'db>> {
    let mut records = owner_records::lock(tx, selector).await?;
    let row = tx.query_opt(
        "SELECT csrf_hash FROM public.sessions WHERE account_id=$1 AND user_id=$2 AND id=$3 AND token_hash=$4 AND revoked_at IS NULL",
        &[&selector.account, &selector.user, &selector.session, &&hash[..]],
    ).await?.ok_or(Error::Refused)?;
    let csrf_hash = row
        .try_get::<_, Vec<u8>>(0)?
        .try_into()
        .map_err(|_| Error::Refused)?;
    // Role originates in the just-locked ordinary-owner predicate. This
    // temporary value exists only to reuse the established pure CSRF verifier;
    // its unlocked freshness shortcut is spent and it never escapes.
    let principal = SessionPrincipal {
        tenant: Tenant {
            account_id: selector.account,
        },
        user_id: selector.user,
        session_id: selector.session,
        role: Role::Owner,
        csrf_hash,
        verification: FreshVerification {
            at: None,
            unspent: std::sync::atomic::AtomicBool::new(false),
        },
    };
    principal
        .require_csrf(
            hasher,
            source.origin,
            canonical_origin,
            source.csrf_cookie,
            source.csrf_header,
        )
        .map_err(|_| Error::Refused)?;
    records.revalidate().await?;
    Ok(HeldOrdinaryOwner03 {
        tx,
        selector,
        records,
        origin_digest,
    })
}

#[cfg(test)]
mod tests;
