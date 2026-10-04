// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant owner issuance library. No production aggregate initializer, schema
//! installation, router mount, private custody or restore admission is supplied.

pub(crate) mod export;
pub(crate) mod lifecycle;
pub(crate) mod model;
mod store;

pub(crate) enum Error {
    Invalid,
    NotFound,
    Conflict,
    Unavailable,
    Authentication(crate::auth::AuthError),
    Database(tokio_postgres::Error),
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid issuer input",
            Self::NotFound => "issuer cursor unavailable",
            Self::Conflict => "issuer conflict",
            Self::Unavailable => "issuer unavailable",
            Self::Authentication(_) => "issuer authentication refusal",
            Self::Database(error) => {
                if error.is_closed() {
                    "issuer database connection closed"
                } else {
                    "issuer database refusal"
                }
            }
        })
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::Database(value)
    }
}
impl From<crate::auth::AuthError> for Error {
    fn from(value: crate::auth::AuthError) -> Self {
        Self::Authentication(value)
    }
}
impl From<crate::sealed_root_ceremony::CeremonyError> for Error {
    fn from(value: crate::sealed_root_ceremony::CeremonyError) -> Self {
        match value {
            crate::sealed_root_ceremony::CeremonyError::Authentication(e) => {
                Self::Authentication(e)
            }
            crate::sealed_root_ceremony::CeremonyError::Database(e) => Self::Database(e),
            crate::sealed_root_ceremony::CeremonyError::Rejected(_) => Self::Conflict,
        }
    }
}
impl From<crate::sealed_manifest_store::AdmissionError> for Error {
    fn from(value: crate::sealed_manifest_store::AdmissionError) -> Self {
        match value {
            crate::sealed_manifest_store::AdmissionError::Database(e) => Self::Database(e),
            crate::sealed_manifest_store::AdmissionError::Rejected(_) => Self::Conflict,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
