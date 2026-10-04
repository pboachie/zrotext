// SPDX-License-Identifier: AGPL-3.0-only
//! Provider-neutral hosted billing checks. Disabled until explicitly mounted
//! by the runtime owner; no credentials, provider calls or default commercial plan.

pub mod admission;
pub mod namespace;
pub mod policy;
pub mod store;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Disabled,
    InvalidConfiguration,
    NamespaceMismatch,
    TenantMismatch,
    StalePolicy,
    StaleObservation,
    Pending,
    Restricted,
    QuotaExceeded,
    DeviceCapExceeded,
    ReplayConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Deployment {
    SelfHosted,
    HostedPaid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillingCheck {
    NotRequired,
    Checked,
}

/// Deployment is immutable SERVER configuration, never a request field. Keep
/// self hosting independent even of opening a billing database connection.
pub fn for_deployment(
    deployment: Deployment,
    check: impl FnOnce() -> Result<(), Refusal>,
) -> Result<BillingCheck, Refusal> {
    match deployment {
        Deployment::SelfHosted => Ok(BillingCheck::NotRequired),
        Deployment::HostedPaid => check().map(|()| BillingCheck::Checked),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod store_tests;
