// SPDX-License-Identifier: AGPL-3.0-only
//! Actual owner/device/record composition for the explicit profile03 service.
//! HTTP and socket mounting remain gated until the complete effect path passes.
use crate::auth::ordinary_owner03::{HeldOrdinaryOwner03, step_up::HeldStepUp03};
use crate::sealed_payload_election03::owner_records::Selector;
use tokio_postgres::{Row, Transaction};

mod challenge;
mod current03;
mod state02;
#[cfg(test)]
mod tests;
mod transition;

pub use challenge::Reservation;
pub use current03::current;
pub(crate) use current03::device_current;
pub(crate) use current03::{
    HeldMessageSelection03, hold_interval_selection, hold_owner_selection, hold_step_up_selection,
};
pub(crate) use transition::device_challenge;
pub(crate) use transition::device_proof;
pub use transition::{accept, bootstrap, historical_accept, reserve, status};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("payload profile authentication refused")]
    Authentication,
    #[error("payload profile state unsupported")]
    Unsupported,
    #[error("payload profile request conflicted")]
    Conflict,
    #[error("payload profile interval expired")]
    Expired,
    #[error("payload profile record not found")]
    NotFound,
    #[error("payload profile unavailable")]
    Unavailable,
    #[error("payload profile storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, Error>;

// Authenticated browser variants borrow genuine proofs; Reserved is explicitly
// read-only selected records for a prior authorized challenge. No selector or
// digest constructor upgrades received identities to current owner/factor proof.
enum Owner<'a, 'held, 'db> {
    Ordinary(&'a HeldOrdinaryOwner03<'held, 'db>),
    StepUp(&'a HeldStepUp03<'held, 'db>),
    Reserved(&'a ReservedOwner<'held, 'db>),
}
// Read-only currentness of the ORIGINAL reservation's selected owner records.
// This is not current cookie authentication or fresh MFA. Only an enrolled
// socket reading that prior authorized reservation uses this variant; reserve
// and accept still require an actual HeldStepUp03, never this record witness.
struct ReservedOwner<'held, 'db> {
    tx: &'held Transaction<'db>,
    selector: Selector,
    records: super::owner_records::HeldOwnerRecords03<'held, 'db>,
    origin: [u8; 32],
}
impl Owner<'_, '_, '_> {
    fn selector(&self) -> Selector {
        match self {
            Self::Ordinary(p) => p.selected_identity(),
            Self::StepUp(p) => p.selected_identity(),
            Self::Reserved(p) => p.selector,
        }
    }
    fn uses(&self, tx: &Transaction<'_>) -> bool {
        match self {
            Self::Ordinary(p) => p.uses_transaction(tx),
            Self::StepUp(p) => p.uses_transaction(tx),
            Self::Reserved(p) => std::ptr::eq(p.tx, tx),
        }
    }
    fn root(&self) -> &[u8; 32] {
        match self {
            Self::Ordinary(p) => p.root_fingerprint(),
            Self::StepUp(p) => p.root_fingerprint(),
            Self::Reserved(p) => p.records.root_fingerprint(),
        }
    }
    fn origin(&self) -> &[u8; 32] {
        match self {
            Self::Ordinary(p) => p.origin_digest(),
            Self::StepUp(p) => p.origin_digest(),
            Self::Reserved(p) => &p.origin,
        }
    }
    fn session(&self) -> &[u8; 32] {
        match self {
            Self::Ordinary(p) => p.identity_digest(),
            Self::StepUp(p) => p.owner_identity_digest(),
            Self::Reserved(p) => p.records.identity_digest(),
        }
    }
    fn epoch(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.selection_epoch(),
            Self::StepUp(p) => p.selection_epoch(),
            Self::Reserved(p) => p.records.selection_epoch(),
        }
    }
    fn deadline(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.session_deadline_ms(),
            Self::StepUp(p) => p.expires_at_ms(),
            Self::Reserved(p) => p.records.session_deadline_ms(),
        }
    }
    fn checked(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.checked_at_ms(),
            Self::StepUp(p) => p.checked_primary_ms(),
            Self::Reserved(p) => p.records.checked_at_ms(),
        }
    }
}
fn fixed<const N: usize>(row: &Row, column: usize) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(column)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
fn positive(n: i64) -> Result<u64> {
    u64::try_from(n)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let r=tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await?;
    let now = positive(r.try_get(1)?)?;
    if r.try_get::<_, bool>(0)? || now < floor {
        return Err(Error::Unavailable);
    }
    Ok(now)
}
