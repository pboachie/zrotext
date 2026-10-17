// SPDX-License-Identifier: AGPL-3.0-only
//! Review-only broker/session/root access. No production composition mounts it.
//! The configured cryptographic scope is not proof of deployment containment.

pub(crate) mod current;
pub mod frames;
pub mod passwords;
pub(crate) mod roots;
pub mod storage;

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("review request rejected")]
    Rejected,
    #[error("review operation unavailable or unknown")]
    Unavailable,
    #[error("review operation already in progress or outcome unknown")]
    BusyUnknown,
    #[error("review request budget exhausted")]
    RateLimited,
    #[error("review database operation unavailable")]
    Database(#[from] tokio_postgres::Error),
}

pub type Result<T> = std::result::Result<T, AccessError>;
