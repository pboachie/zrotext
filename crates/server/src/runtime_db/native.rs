// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit native entry before business locks, including raw-client helpers.
use super::{ConnectError, PooledClient};
use tokio_postgres::{Client, IsolationLevel, Transaction, TransactionBuilder};
use zrotext_delivery_store::{DeliveryStore, HostedBackendCandidate, enter_hosted_transaction};

/// A raw Client has no initialized hosted candidate. It therefore works only
/// for a genuinely unscoped/manual database. Erasing a pooled client to Client
/// cannot silently turn a hosted connection into a manual connection.
pub trait NativeConnection {
    fn native_candidate(&self) -> Option<HostedBackendCandidate>;
    fn native_client(&mut self) -> &mut Client;
}
impl NativeConnection for Client {
    fn native_candidate(&self) -> Option<HostedBackendCandidate> {
        None
    }
    fn native_client(&mut self) -> &mut Client {
        self
    }
}
impl NativeConnection for PooledClient {
    fn native_candidate(&self) -> Option<HostedBackendCandidate> {
        self.hosted_backend
    }
    fn native_client(&mut self) -> &mut Client {
        self.client.as_mut().expect("client present until drop")
    }
}

async fn enter(
    tx: &Transaction<'_>,
    candidate: Option<&HostedBackendCandidate>,
) -> Result<(), ConnectError> {
    enter_hosted_transaction(tx, candidate)
        .await
        .map(|_| ())
        .map_err(|error| match error {
            zrotext_delivery_store::StoreError::Database(error) => ConnectError::Database(error),
            _ => ConnectError::Identity,
        })
}

pub(crate) async fn begin<C: NativeConnection>(
    db: &mut C,
) -> Result<Transaction<'_>, ConnectError> {
    let candidate = db.native_candidate();
    let tx = db.native_client().transaction().await?;
    // Failure drops this uncommitted transaction; callers never continue on
    // an aborted transaction or manufacture a substitute backend proof.
    enter(&tx, candidate.as_ref()).await?;
    Ok(tx)
}

pub struct NativeTransactionBuilder<'a> {
    builder: TransactionBuilder<'a>,
    candidate: Option<HostedBackendCandidate>,
}
impl<'a> NativeTransactionBuilder<'a> {
    pub fn isolation_level(mut self, level: IsolationLevel) -> Self {
        self.builder = self.builder.isolation_level(level);
        self
    }
    pub fn read_only(mut self, value: bool) -> Self {
        self.builder = self.builder.read_only(value);
        self
    }
    pub fn deferrable(mut self, value: bool) -> Self {
        self.builder = self.builder.deferrable(value);
        self
    }
    pub async fn start(self) -> Result<Transaction<'a>, ConnectError> {
        let tx = self.builder.start().await?;
        enter(&tx, self.candidate.as_ref()).await?;
        Ok(tx)
    }
}

impl PooledClient {
    /// Each call enters THIS actual transaction. Pool checkout is not entry.
    pub async fn native_transaction(&mut self) -> Result<Transaction<'_>, ConnectError> {
        begin(self).await
    }
    pub fn native_build_transaction(&mut self) -> NativeTransactionBuilder<'_> {
        let candidate = self.hosted_backend;
        NativeTransactionBuilder {
            builder: self.native_client().build_transaction(),
            candidate,
        }
    }
    /// Transfer only configuration from the same genuinely initialized
    /// client. The Store enters every one of its own transactions again.
    pub fn delivery_store(&mut self) -> DeliveryStore<'_> {
        delivery_store(self, None)
    }
    pub fn delivery_store_with_idempotency_days(&mut self, days: i32) -> DeliveryStore<'_> {
        delivery_store(self, Some(days))
    }
}

pub(crate) fn delivery_store<C: NativeConnection>(
    db: &mut C,
    days: Option<i32>,
) -> DeliveryStore<'_> {
    let candidate = db.native_candidate();
    let store = match days {
        None => DeliveryStore::new(db.native_client()),
        Some(days) => DeliveryStore::with_idempotency_days(db.native_client(), days),
    };
    match candidate {
        Some(candidate) => store.with_hosted_backend(candidate),
        None => store,
    }
}
