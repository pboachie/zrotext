// SPDX-License-Identifier: AGPL-3.0-only
//! Exact-transaction complete ancestry for content adapters. Public history
//! candidates and SQL structural retention cannot construct this held proof.
use super::*;
use crate::conversation_interval03::{self, PhysicalSource03};
use crate::sealed_payload_election03::{
    device_context::HeldDeviceContext03,
    live::{
        Error,
        manifest_history::{self, History03},
    },
};
use std::sync::Arc;
use tokio_postgres::Transaction;
type Result<T> = std::result::Result<T, Error>;

pub(crate) struct SelectedManifest03<'held, 'db> {
    tx: &'held Transaction<'db>,
    history: History03,
    progress: Arc<verified_history::Progress>,
    origin: String,
}
impl<'held, 'db> SelectedManifest03<'held, 'db> {
    pub(crate) async fn lock(
        tx: &'held Transaction<'db>,
        account: Uuid,
        line: Uuid,
        origin: &str,
    ) -> Result<Self> {
        let history = manifest_history::lock(tx, account, line, origin).await?;
        let progress = verified_history::warm(tx, &history, origin).await?;
        Ok(Self {
            tx,
            history,
            progress,
            origin: origin.to_owned(),
        })
    }
    pub(crate) fn history(&self) -> &History03 {
        &self.history
    }
    pub(crate) fn prefix(&self) -> &[u8; 32] {
        &self.progress.prefix
    }
    pub(crate) fn manifest_at(&self, now: u64) -> Result<crypto::VerifiedManifest03> {
        if now < self.history.checked_ms {
            return Err(Error::Unavailable);
        }
        crypto::verify_current(&self.history.tip_signed, &self.progress.verified, now)
            .map_err(|_| Error::Expired)
    }
    pub(crate) async fn revalidate(&self, tx: &Transaction<'_>) -> Result<()> {
        if !std::ptr::eq(self.tx, tx) {
            return Err(Error::Authentication);
        }
        let actual =
            manifest_history::lock(tx, self.history.account, self.history.line, &self.origin)
                .await?;
        let progress = verified_history::warm(tx, &actual, &self.origin).await?;
        if actual.original_identity != self.history.original_identity
            || actual.binding != self.history.binding
            || actual.epoch != self.history.epoch
            || actual.tip_signed != self.history.tip_signed
            || actual.tip_version != self.history.tip_version
            || actual.tip_digest != self.history.tip_digest
            || actual.tip_accepted_ms != self.history.tip_accepted_ms
            || progress.prefix != self.progress.prefix
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Current authenticated-ingress selectors are checked separately by the
    /// caller. This reads actual device rows without demanding a physical
    /// handle that a reconnect ceremony is meant to restore.
    pub(crate) async fn device_context(
        &self,
        tx: &'held Transaction<'db>,
    ) -> Result<HeldDeviceContext03<'held, 'db>> {
        self.revalidate(tx).await?;
        current::context(tx, &self.history).await
    }
    /// Historical material from this exact fully verified immutable prefix.
    /// It grants no current signer, owner, physical or content permission.
    pub(crate) async fn retained_material(
        &self,
        tx: &Transaction<'_>,
        version: u64,
    ) -> Result<(Vec<u8>, u64)> {
        self.revalidate(tx).await?;
        let h = &self.history;
        if version == h.accepted.accepted_manifest_version {
            return Ok((h.first_signed.clone(), h.accepted.accepted_at_ms));
        }
        if version > h.tip_version {
            return Err(Error::Conflict);
        }
        let row = records::by_version(tx, h.account, version)
            .await?
            .ok_or(Error::Conflict)?;
        row.scope(h, &self.origin)?;
        Ok((row.signed, row.accepted))
    }
    pub(crate) async fn physical(
        &self,
        tx: &Transaction<'_>,
        context: &HeldDeviceContext03<'_, '_>,
    ) -> Result<Physical03> {
        self.revalidate(tx).await?;
        let lease = context.selected_identity();
        if lease.account != self.history.account
            || lease.device != self.history.device
            || context.selection_epoch() != self.history.epoch
            || context.root_fingerprint() != &self.history.accepted.root_fingerprint
        {
            return Err(Error::Conflict);
        }
        let source = current::physical(tx, &self.history, context, &self.origin).await?;
        let original_binding = Uuid::from_bytes(self.history.accepted.old_binding_id);
        let source_bytes = match &source {
            current::Physical03::Original => PhysicalSource03::OriginalV2 {
                original_binding,
                activation_evidence: self.history.activation.canonical_evidence(),
            },
            current::Physical03::Refreshed {
                refresh,
                bundle,
                accepted,
                installed,
            } => PhysicalSource03::OwnerRefresh03 {
                refresh_id: *refresh,
                bundle,
                accepted_ms: *accepted,
                installed_ms: *installed,
            },
        };
        let digest = conversation_interval03::physical_digest(
            self.history.account,
            self.history.device,
            self.history.line,
            self.history.binding,
            &self.history.accepted.election_commitment,
            context.identity_digest(),
            source_bytes,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Physical03 { source, digest })
    }
}

pub(crate) struct Physical03 {
    source: current::Physical03,
    digest: [u8; 32],
}
impl Physical03 {
    pub(crate) fn identity(&self) -> (&'static str, Option<Uuid>) {
        match &self.source {
            current::Physical03::Original => ("original_v2", None),
            current::Physical03::Refreshed { refresh, .. } => ("owner_refresh03", Some(*refresh)),
        }
    }
    pub(crate) fn projection(&self) -> serde_json::Value {
        self.source.projection()
    }
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
