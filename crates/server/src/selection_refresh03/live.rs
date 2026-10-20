// SPDX-License-Identifier: AGPL-3.0-only
//! Actual fresh owner/device refresh integration. Every mutation borrows the
//! caller's transaction; refusal requires rollback of factor and SQL together.
use super::{core::Core03, *};
use crate::{
    auth::ordinary_owner03::{HeldOrdinaryOwner03, step_up::HeldStepUp03},
    manifest_install03::SelectedManifest03,
    sealed_payload_election03::{
        activation_evidence::ActivationEvidence03,
        adapter_contract::{self, OwnerSessionIdentity03},
        device_context::HeldDeviceContext03,
        live::{Error, SocketSelection03, manifest_history},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
mod records;
mod service;
pub(crate) use service::{
    approve, device_challenge, device_installed, device_proof, historical_approval, installed,
    proof, reserve, status,
};
type Result<T> = std::result::Result<T, Error>;

fn scalar(n: i64) -> Result<u64> {
    u64::try_from(n)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(Error::Unsupported)
}
fn dbtime(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| Error::Unsupported)
}
fn fixed<const N: usize>(row: &Row, name: &str) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::payload_profile_selections::require(tx)
        .await
        .map_err(|_| Error::Unavailable)
}
/// Select the mutation lock mode before reading any history or device witness.
/// The account is selected by the authenticated ingress, but these locks alone
/// authenticate neither the socket nor its original proof or current lease.
async fn device_mutation_mode(tx: &Transaction<'_>, account: Uuid) -> Result<()> {
    ready(tx).await?;
    tx.query_opt("SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR UPDATE NOWAIT", &[&account]).await?.ok_or(Error::Unsupported)?;
    let key =
        adapter_contract::account_fence_key(account.as_bytes()).map_err(|_| Error::Unsupported)?;
    if !tx
        .query_one("SELECT pg_catalog.pg_try_advisory_xact_lock($1)", &[&key])
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(Error::Conflict);
    }
    let anchor = tx.query_opt("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE NOWAIT", &[&account]).await?.ok_or(Error::Unsupported)?;
    if anchor.try_get::<_, String>(0)? != "live" || anchor.try_get::<_, i64>(1)? != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let r = tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await?;
    let now = scalar(r.try_get(1)?)?;
    if r.try_get::<_, bool>(0)? || now < floor {
        return Err(Error::Unavailable);
    }
    Ok(now)
}
struct Scope<'held, 'db> {
    tx: &'held Transaction<'db>,
    selected: SelectedManifest03<'held, 'db>,
    context: HeldDeviceContext03<'held, 'db>,
    origin: [u8; 32],
    subscription: i32,
    checked: u64,
    deadline: u64,
}
impl<'held, 'db> Scope<'held, 'db> {
    async fn lock(
        tx: &'held Transaction<'db>,
        account: Uuid,
        line: Uuid,
        origin: &str,
    ) -> Result<Self> {
        ready(tx).await?;
        let selected = SelectedManifest03::lock(tx, account, line, origin).await?;
        let context = selected.device_context(tx).await?;
        let original =
            ActivationEvidence03::decode(selected.history().activation.canonical_evidence())
                .map_err(|_| Error::Unsupported)?;
        let subscription =
            i32::from_be_bytes(original.device_statement[138..142].try_into().unwrap());
        if subscription < 0 {
            return Err(Error::Unsupported);
        }
        let mut scope = Self {
            tx,
            selected,
            context,
            origin: adapter_contract::origin_digest(origin).map_err(|_| Error::Unsupported)?,
            subscription,
            checked: 0,
            deadline: 0,
        };
        scope.revalidate().await?;
        Ok(scope)
    }
    async fn revalidate(&mut self) -> Result<()> {
        self.selected.revalidate(self.tx).await?;
        self.context
            .revalidate()
            .await
            .map_err(|_| Error::Unavailable)?;
        let h = self.selected.history();
        let now = clock(
            self.tx,
            self.checked
                .max(h.checked_ms)
                .max(self.context.checked_primary_ms()),
        )
        .await?;
        let manifest = self.selected.manifest_at(now)?;
        let keys = manifest
            .profile_election_keys(
                h.device.as_bytes(),
                h.line.as_bytes(),
                &h.device_point,
                &h.approval_point,
                now,
            )
            .map_err(|_| Error::Unsupported)?;
        if keys.reader_id != h.accepted.selected_reader_key_id {
            return Err(Error::Conflict);
        }
        self.deadline = keys.expires_ms.min(self.context.lease_deadline_ms());
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        self.checked = now;
        Ok(())
    }
    fn socket(&self, socket: &SocketSelection03<'_>) -> Result<()> {
        let actual = self.context.selected_identity();
        if socket.session.account_id != actual.account
            || socket.session.device_id != actual.device
            || socket.site != actual.site
            || socket.instance != actual.instance
            || socket.session.connection_epoch <= 0
            || socket.session.connection_epoch as u64 != actual.connection_epoch
            || socket.deployment != actual.deployment_epoch
            || adapter_contract::origin_digest(socket.origin).map_err(|_| Error::Unsupported)?
                != self.origin
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    async fn expected<'a>(&'a self, row: &'a records::Challenge) -> Result<ExpectedRefresh03<'a>> {
        if row.core.numbers[2] != self.selected.history().tip_version {
            return Err(Error::Conflict);
        }
        self.historical_expected(row).await
    }
    async fn historical_expected<'a>(
        &'a self,
        row: &'a records::Challenge,
    ) -> Result<ExpectedRefresh03<'a>> {
        let h = self.selected.history();
        let material = self
            .selected
            .retained_material(self.tx, row.core.numbers[2])
            .await?;
        if row.manifest != material.0
            || row.manifest_accepted != material.1
            || row.manifest.len() < 64
            || crypto::sha(&row.manifest[..row.manifest.len() - 64]) != row.core.digests[6]
            || row.device_point != h.device_point
            || row.owner_point != h.approval_point
            || row.device_session != *self.context.selected_identity()
            || row.owner_digest
                != (OwnerSessionIdentity03 {
                    account_id: *h.account.as_bytes(),
                    user_id: *row.user.as_bytes(),
                    session_id: *row.session.as_bytes(),
                })
                .digest()
                .map_err(|_| Error::Unsupported)?
        {
            return Err(Error::Conflict);
        }
        Ok(ExpectedRefresh03 {
            account: h.account,
            device: h.device,
            line: h.line,
            binding: h.binding,
            refresh: row.core.ids[3],
            binding_generation: h.generation,
            manifest_version: row.core.numbers[2],
            selection_epoch: h.epoch,
            election: &h.accepted.election_commitment,
            election_bundle: &h.accepted.election_bundle_sha256,
            reader: &h.accepted.selected_reader_key_id,
            device_point: &h.device_point,
            owner_point: &h.approval_point,
            root: &h.accepted.root_fingerprint,
            manifest: &row.core.digests[6],
            device_session: self.context.identity_digest(),
            owner_session: &row.owner_digest,
            origin: &self.origin,
            original_subscription: self.subscription,
        })
    }
    fn original_manifest(
        &self,
        row: &records::Challenge,
        receipt: &records::Receipt,
    ) -> Result<()> {
        use zrotext_root_material::profile03_manifest as shared;
        let h = self.selected.history();
        let checkpoint = shared::verify_checkpoint(
            &h.pin,
            &row.manifest,
            &shared::Checkpoint03 {
                account_id: *h.account.as_bytes(),
                root_fingerprint: h.accepted.root_fingerprint,
                version: row.core.numbers[2],
                digest: row.core.digests[6],
                accepted_ms: row.manifest_accepted,
            },
            receipt.accepted,
        )
        .map_err(|_| Error::Unsupported)?;
        let at = receipt.installed.map_or(receipt.accepted, |v| v.0);
        let manifest = crypto::verify_current(&row.manifest, &checkpoint, at)
            .map_err(|_| Error::Unsupported)?;
        let keys = manifest
            .profile_election_keys(
                h.device.as_bytes(),
                h.line.as_bytes(),
                &h.device_point,
                &h.approval_point,
                at,
            )
            .map_err(|_| Error::Unsupported)?;
        if keys.reader_id != h.accepted.selected_reader_key_id
            || at >= keys.expires_ms
            || row.core.issued < row.manifest_accepted
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
