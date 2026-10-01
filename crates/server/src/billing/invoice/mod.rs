// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant invoice-bound TEST policy. No live payment API or price activation.

pub(crate) mod lifecycle;
mod model;
mod provider;
mod store;

#[cfg(test)]
mod tests;

use super::{BillingError, SubscriptionSnapshot, TestQuotaPlan};
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

/// Created only by the pinned TEST reader, with the observation kept private.
pub(super) struct CurrentInvoice {
    observation: model::Observation,
}

impl CurrentInvoice {
    pub(super) fn subscription(&self) -> &SubscriptionSnapshot {
        &self.observation.subscription
    }
}

pub(super) async fn fetch(
    http: &reqwest::Client,
    key: &str,
    base: &str,
    subscription_id: &str,
) -> Result<CurrentInvoice, BillingError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        provider::fetch(http, key, base, subscription_id),
    )
    .await
    .map_err(|_| super::worker::ProviderFailure::Transport)?
}

pub(super) async fn enabled<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
) -> Result<bool, BillingError> {
    store::enabled(db, account).await
}

pub(super) async fn apply(
    tx: &Transaction<'_>,
    account: Uuid,
    snapshot: &SubscriptionSnapshot,
    current: Option<&CurrentInvoice>,
    plans: &[TestQuotaPlan],
    generation: i64,
) -> Result<(), BillingError> {
    store::apply(
        tx,
        account,
        snapshot,
        current.map(|proof| &proof.observation),
        plans,
        generation,
    )
    .await
}
