// SPDX-License-Identifier: AGPL-3.0-only
//! Actual closed interval storage composed with genuine held owner/device
//! selection. No received phase, selector or manifest replaces those witnesses.
use super::*;
use crate::auth::ordinary_owner03::{HeldOrdinaryOwner03, step_up::HeldStepUp03};
use crate::sealed_payload_election03::live::{self as selected, Error, HeldMessageSelection03};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
mod mappings;
mod pending;
mod service;
pub(crate) use service::{
    DeviceInterval03, Reserve03, device_approve, device_challenge, device_install, device_status,
    device_stop, historical_request, owner_status, request, reserve, stop,
};
type Result<T> = std::result::Result<T, Error>;

/// Constructed only by the exact closed storage reader. It is retained evidence,
/// not cookie authentication or an installed content permission by itself.
pub(crate) struct StoredInterval03 {
    statement: Statement03,
    phase: String,
    owner: Option<[u8; 64]>,
    phone: Option<[u8; 64]>,
    installed: Option<[u8; 64]>,
    requested_ms: Option<u64>,
    approved_ms: Option<u64>,
    installed_ms: Option<u64>,
    stopped_ms: Option<u64>,
}
fn scalar(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(Error::Unsupported)
}
fn fixed<const N: usize>(row: &Row, name: &str) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
fn signature(row: &Row, name: &str) -> Result<Option<[u8; 64]>> {
    row.try_get::<_, Option<Vec<u8>>>(name)?
        .map(|v| v.try_into().map_err(|_| Error::Unsupported))
        .transpose()
}
fn time(row: &Row, name: &str) -> Result<Option<u64>> {
    row.try_get::<_, Option<i64>>(name)?.map(scalar).transpose()
}
fn dbtime(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Unsupported)
}
async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::conversation_profile03_storage::require(tx)
        .await
        .map_err(|_| Error::Unavailable)
}
impl StoredInterval03 {
    pub(crate) fn statement(&self) -> &Statement03 {
        &self.statement
    }
    pub(crate) fn selected_owner(
        &self,
    ) -> crate::sealed_payload_election03::owner_records::Selector {
        let (user, session) = self.statement.owner();
        crate::sealed_payload_election03::owner_records::Selector {
            account: self.statement.account_id(),
            user,
            session,
        }
    }
    fn from_row(row: &Row) -> Result<Self> {
        let statement = Statement03::decode(&row.try_get::<_, Vec<u8>>("statement")?)
            .map_err(|_| Error::Unsupported)?;
        for (name, id) in [
            "account_id",
            "device_id",
            "line_id",
            "binding_id",
            "interval_id",
            "receipt_id",
            "initiating_user_id",
            "initiating_session_id",
            "opening_id",
        ]
        .into_iter()
        .zip(statement.ids)
        {
            if row.try_get::<_, Uuid>(name)? != Uuid::from_bytes(id) {
                return Err(Error::Conflict);
            }
        }
        for (name, value) in [
            "binding_generation",
            "vault_generation",
            "manifest_version",
            "selection_epoch",
            "issued_ms",
            "setup_expires_ms",
            "interval_starts_ms",
            "interval_expires_ms",
        ]
        .into_iter()
        .zip(statement.numbers)
        {
            if scalar(row.try_get(name)?)? != value {
                return Err(Error::Conflict);
            }
        }
        for (name, digest) in [
            "selected_reader_key_id",
            "archive_reader_key_id",
            "phone_signer_key_id",
            "browser_signer_key_id",
            "root_fingerprint",
            "manifest_digest",
            "election_commitment",
            "election_bundle_sha256",
            "owner_session_digest",
            "configured_origin_digest",
            "device_session_digest",
            "physical_selection_digest",
            "nonce",
        ]
        .into_iter()
        .zip(statement.digests)
        {
            if fixed::<32>(row, name)? != digest {
                return Err(Error::Conflict);
            }
        }
        let mut integration = Vec::new();
        for r in statement.integrations() {
            integration.extend(r.connector_id.as_bytes());
            integration.extend(r.read_grant_id.as_bytes());
            integration.extend(r.key_id);
        }
        if row.try_get::<_, Vec<u8>>("integration_readers")? != integration
            || row.try_get::<_, String>("peer")?.as_bytes() != statement.peer()
            || fixed::<32>(row, "statement_sha256")? != statement.digest()
        {
            return Err(Error::Conflict);
        }
        let phase: String = row.try_get("phase")?;
        let value = Self {
            statement,
            phase,
            owner: signature(row, "owner_signature")?,
            phone: signature(row, "phone_signature")?,
            installed: signature(row, "installed_signature")?,
            requested_ms: time(row, "requested_ms")?,
            approved_ms: time(row, "approved_ms")?,
            installed_ms: time(row, "installed_ms")?,
            stopped_ms: time(row, "stopped_ms")?,
        };
        let owner = value.owner.is_some() && value.requested_ms.is_some();
        let phone = value.phone.is_some() && value.approved_ms.is_some();
        let installed = value.installed.is_some() && value.installed_ms.is_some();
        if value.owner.is_some() != value.requested_ms.is_some()
            || value.phone.is_some() != value.approved_ms.is_some()
            || value.installed.is_some() != value.installed_ms.is_some()
            || phone && !owner
            || installed && !phone
        {
            return Err(Error::Unsupported);
        }
        let shape = match value.phase.as_str() {
            "reserved" => !owner && !phone && !installed,
            "requested" => owner && !phone && !installed,
            "install_pending" => owner && phone && !installed,
            "active" => owner && phone && installed,
            "stopped" | "expired" => true,
            _ => false,
        };
        if !shape {
            return Err(Error::Unsupported);
        }
        Ok(value)
    }
    pub(crate) async fn read(tx: &Transaction<'_>, account: Uuid, interval: Uuid) -> Result<Self> {
        ready(tx).await?;
        let row=tx.query_opt("SELECT * FROM public.conversation_profile03_intervals WHERE account_id=$1 AND interval_id=$2 FOR SHARE NOWAIT",&[&account,&interval]).await?.ok_or(Error::NotFound)?;
        Self::from_row(&row)
    }
    fn require_owner(&self, held: &HeldMessageSelection03<'_, '_, '_>) -> Result<()> {
        if self.selected_owner() != held.selected() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn context<'a>(
        &'a self,
        held: &'a HeldMessageSelection03<'_, '_, '_>,
    ) -> ExpectedConsent03<'a> {
        let (archive, phone, browser) = self.statement.keys();
        held.consent_context(
            archive,
            phone,
            browser,
            self.statement.peer(),
            self.statement.integrations(),
        )
    }
    async fn validate(
        &self,
        held: &mut HeldMessageSelection03<'_, '_, '_>,
        pending: bool,
    ) -> Result<mappings::Mappings03> {
        self.require_owner(held)?;
        held.revalidate().await?;
        let mappings = mappings::read(held, &self.statement).await?;
        let expected = self.context(held);
        verify_retained(
            &self.statement,
            self.owner.as_ref().zip(self.requested_ms),
            self.phone.as_ref().zip(self.approved_ms),
            self.installed.as_ref().zip(self.installed_ms),
            &expected,
            held.now_ms(),
        )
        .map_err(|_| Error::Unsupported)?;
        if pending && held.now_ms() >= self.statement.times().1 {
            return Err(Error::Expired);
        }
        if matches!(self.phase.as_str(), "stopped" | "expired") {
            return Err(Error::Expired);
        }
        // Registry rows are held, but primary time can still advance during the
        // read; repeat both actual authority and the exact registry deadlines.
        held.revalidate().await?;
        mappings.require_current(held.now_ms())?;
        Ok(mappings)
    }
    fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"v":1,"opening_id":self.statement.opening_id(),"interval_id":self.statement.interval_id(),"receipt_id":self.statement.receipt_id(),"statement":B.encode(self.statement.bytes()),"phase":self.phase,"owner_signature":self.owner.map(|s|B.encode(s)),"phone_signature":self.phone.map(|s|B.encode(s)),"installed_signature":self.installed.map(|s|B.encode(s)),"requested_ms":self.requested_ms.map(|v|v.to_string()),"approved_ms":self.approved_ms.map(|v|v.to_string()),"installed_ms":self.installed_ms.map(|v|v.to_string())})
    }
    pub(crate) async fn permission(
        &self,
        held: &mut HeldMessageSelection03<'_, '_, '_>,
        kind: &str,
        id: Uuid,
    ) -> Result<serde_json::Value> {
        if !["interval_challenge", "interval_status", "fetch"].contains(&kind)
            || id.is_nil()
            || kind == "fetch" && self.phase != "active"
        {
            return Err(Error::Conflict);
        }
        if kind == "interval_challenge" && id != self.statement.receipt_id() {
            return Err(Error::Conflict);
        }
        let mapping = self
            .validate(held, kind != "fetch" && self.phase != "active")
            .await?;
        let deadline = held
            .authority()
            .permission_expires_at_ms
            .min(self.statement.times().3)
            .min(mapping.deadline());
        if held.now_ms() >= deadline {
            return Err(Error::Expired);
        }
        Ok(
            serde_json::json!({"v":1,"kind":"interval_permission03","request_kind":kind,"request_id":id,"interval_id":self.statement.interval_id(),"statement_sha256":B.encode(self.statement.digest()),"statement":B.encode(self.statement.bytes()),"owner_signature":self.owner.map(|s|B.encode(s)),"phone_signature":self.phone.map(|s|B.encode(s)),"installed_signature":self.installed.map(|s|B.encode(s)),"requested_ms":self.requested_ms.map(|v|v.to_string()),"approved_ms":self.approved_ms.map(|v|v.to_string()),"installed_ms":self.installed_ms.map(|v|v.to_string()),"phase":self.phase,"device_session_digest":B.encode(held.device_session_digest()),"physical_selection_digest":B.encode(held.physical_digest()),"owner_session_digest":B.encode(self.statement.owner_digest()),"compared_ms":held.now_ms().to_string(),"permission_expires_ms":deadline.to_string(),"readers":mapping.projection()}),
        )
    }
}

fn only_row(rows: Vec<Row>) -> Result<StoredInterval03> {
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    StoredInterval03::from_row(&rows[0])
}
