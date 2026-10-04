// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant managed-reader grant metadata. No content reader, model or effect API.
mod grants;
pub(crate) mod lifecycle;
mod model;
pub use model::{GrantRequest, PolicyIdentity, Selection, SourceKind};
pub struct OwnerCeremony<'a> {
    pub owner: &'a crate::auth::SessionPrincipal,
    pub hasher: &'a crate::auth::TokenHasher,
    pub cipher: &'a crate::auth::mfa::MfaCipher,
    pub password: &'a str,
    pub factor: &'a str,
}

/// No production constructor enables issuance before a trusted reader/policy
/// issuer exists. Installing the SQL proposal alone does not enable this API.
#[derive(Default)]
pub struct ManagedGrants {
    candidate: bool,
}
impl ManagedGrants {
    #[cfg(test)]
    pub(crate) fn synthetic_candidate() -> Self {
        Self { candidate: true }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("managed reader authority unavailable")]
    Unavailable,
    #[error("invalid managed reader scope")]
    Invalid,
    #[error("managed reader scope conflicts")]
    Conflict,
    #[error("managed reader scope forbidden")]
    Forbidden,
    #[error("managed reader grant missing")]
    NotFound,
    #[error("owner ceremony failed")]
    Authentication(#[from] crate::auth::AuthError),
    #[error("archive authority failed")]
    Archive(#[from] crate::http_owner_conversations::ConversationError),
    #[error("managed reader storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
