// SPDX-License-Identifier: AGPL-3.0-only
//! Exact retained originals only. Reading these rows authenticates neither a
//! browser nor a phone; mutation callers separately hold genuine witnesses.
use super::*;

pub(super) struct Challenge {
    pub(super) core: Core03,
    pub(super) opening: Uuid,
    pub(super) user: Uuid,
    pub(super) session: Uuid,
    pub(super) owner_digest: [u8; 32],
    pub(super) device_point: [u8; 65],
    pub(super) owner_point: [u8; 65],
    pub(super) device_session: crate::sealed_payload_election03::device_context::Selector,
    pub(super) manifest: Vec<u8>,
    pub(super) manifest_accepted: u64,
    pub(super) observation: Option<[u8; 121]>,
    pub(super) device_signature: Option<[u8; 64]>,
    pub(super) proof_ms: Option<u64>,
    pub(super) closed: Option<(u64, Uuid)>,
}
fn optional_fixed<const N: usize>(row: &Row, key: &str) -> Result<Option<[u8; N]>> {
    row.try_get::<_, Option<Vec<u8>>>(key)?
        .map(|b| b.try_into().map_err(|_| Error::Unsupported))
        .transpose()
}
fn optional_time(row: &Row, key: &str) -> Result<Option<u64>> {
    row.try_get::<_, Option<i64>>(key)?.map(scalar).transpose()
}
impl Challenge {
    pub(super) fn read(row: &Row) -> Result<Self> {
        let core =
            Core03::decode(&row.try_get::<_, Vec<u8>>("core")?).map_err(|_| Error::Unsupported)?;
        for (key, value) in [
            "account_id",
            "device_id",
            "line_id",
            "refresh_id",
            "binding_id",
        ]
        .into_iter()
        .zip(core.ids)
        {
            if row.try_get::<_, Uuid>(key)? != value {
                return Err(Error::Conflict);
            }
        }
        for (key, value) in [
            "binding_generation",
            "vault_generation",
            "manifest_version",
            "selection_epoch",
        ]
        .into_iter()
        .zip(core.numbers)
        {
            if scalar(row.try_get(key)?)? != value {
                return Err(Error::Conflict);
            }
        }
        for (key, value) in [
            "election_commitment",
            "election_bundle_sha256",
            "selected_reader_key_id",
            "device_signing_key_id",
            "owner_approval_key_id",
            "root_fingerprint",
            "manifest_digest",
            "device_session_digest",
            "owner_session_digest",
            "configured_origin_digest",
            "nonce",
        ]
        .into_iter()
        .zip(core.digests)
        {
            if fixed::<32>(row, key)? != value {
                return Err(Error::Conflict);
            }
        }
        if scalar(row.try_get("issued_ms")?)? != core.issued
            || scalar(row.try_get("expires_ms")?)? != core.expires
        {
            return Err(Error::Conflict);
        }
        let manifest: Vec<u8> = row.try_get("signed_manifest")?;
        if fixed::<32>(row, "signed_manifest_sha256")? != crypto::sha(&manifest) {
            return Err(Error::Conflict);
        }
        let user: Uuid = row.try_get("initiating_user_id")?;
        let session: Uuid = row.try_get("initiating_session_id")?;
        let opening: Uuid = row.try_get("opening_id")?;
        if user.is_nil() || session.is_nil() || opening.is_nil() {
            return Err(Error::Unsupported);
        }
        let observation = optional_fixed(row, "device_observation")?;
        let device_signature = optional_fixed(row, "device_signature")?;
        let proof_ms = optional_time(row, "device_proof_ms")?;
        if observation.is_some() != device_signature.is_some()
            || device_signature.is_some() != proof_ms.is_some()
            || proof_ms.is_some_and(|n| n < core.issued || n >= core.expires)
        {
            return Err(Error::Unsupported);
        }
        let closed_time = optional_time(row, "closed_unaccepted_ms")?;
        let target: Option<Uuid> = row.try_get("superseded_by_refresh_id")?;
        let closed = match (closed_time, target) {
            (None, None) => None,
            (Some(t), Some(id)) if !id.is_nil() && t >= core.expires => Some((t, id)),
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            opening,
            user,
            session,
            owner_digest: core.digests[8],
            device_point: fixed(row, "device_point")?,
            owner_point: fixed(row, "owner_point")?,
            device_session: crate::sealed_payload_election03::device_context::Selector {
                account: core.ids[0],
                device: core.ids[1],
                site: row.try_get("proof_site_id")?,
                instance: row.try_get("proof_instance_id")?,
                connection_epoch: scalar(row.try_get("proof_connection_epoch")?)?,
                deployment_epoch: scalar(row.try_get("proof_deployment_epoch")?)?,
            },
            core,
            manifest,
            manifest_accepted: scalar(row.try_get("manifest_accepted_ms")?)?,
            observation,
            device_signature,
            proof_ms,
            closed,
        })
    }
    pub(super) fn actor(
        &self,
        who: crate::sealed_payload_election03::owner_records::Selector,
        same_session: bool,
        origin: &[u8; 32],
    ) -> Result<()> {
        if self.core.ids[0] != who.account
            || self.user != who.user
            || same_session && self.session != who.session
            || self.core.digests[9] != *origin
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) async fn projection(&self, tx: &Transaction<'_>) -> Result<serde_json::Value> {
        let receipt = Receipt::lookup(tx, self.core.ids[0], self.core.ids[3]).await?;
        let status = match receipt {
            Some(ref r) if r.installed.is_some() => "installed",
            Some(_) => "approved",
            None => "reserved",
        };
        Ok(
            serde_json::json!({"v":1,"opening_id":self.opening,"refresh_id":self.core.ids[3],"core":B.encode(self.core.bytes),"issued_ms":self.core.issued.to_string(),"expires_ms":self.core.expires.to_string(),"status":status,"closed_unaccepted":ancestors(tx,self).await?}),
        )
    }
}
pub(super) async fn by_opening(
    tx: &Transaction<'_>,
    account: Uuid,
    opening: Uuid,
) -> Result<Option<Challenge>> {
    let row = tx.query_opt("SELECT * FROM public.payload_profile_selection_challenges WHERE account_id=$1 AND opening_id=$2 FOR SHARE NOWAIT", &[&account,&opening]).await?;
    row.as_ref().map(Challenge::read).transpose()
}
pub(super) async fn by_id(tx: &Transaction<'_>, account: Uuid, refresh: Uuid) -> Result<Challenge> {
    let row=tx.query_opt("SELECT * FROM public.payload_profile_selection_challenges WHERE account_id=$1 AND refresh_id=$2 FOR SHARE NOWAIT", &[&account,&refresh]).await?.ok_or(Error::NotFound)?;
    Challenge::read(&row)
}
async fn ancestors(tx: &Transaction<'_>, target: &Challenge) -> Result<Vec<serde_json::Value>> {
    let mut next = target.core.ids[3];
    let mut issued = target.core.issued;
    let mut result = Vec::new();
    loop {
        let rows = tx.query("SELECT * FROM public.payload_profile_selection_challenges WHERE account_id=$1 AND superseded_by_refresh_id=$2 ORDER BY issued_ms,refresh_id LIMIT 2", &[&target.core.ids[0], &next]).await?;
        if rows.is_empty() {
            break;
        }
        if rows.len() != 1 || result.len() == 16 {
            return Err(Error::Unsupported);
        }
        let old = Challenge::read(&rows[0])?;
        let (closed, link) = old.closed.ok_or(Error::Conflict)?;
        if closed != issued
            || link != next
            || old.core.issued >= issued
            || old.core.ids[0..3] != target.core.ids[0..3]
            || old.core.ids[4] != target.core.ids[4]
            || old.device_session != target.device_session
        {
            return Err(Error::Conflict);
        }
        result.push(serde_json::json!({"opening_id":old.opening,"refresh_id":old.core.ids[3],"core":B.encode(old.core.bytes),"closed_unaccepted_ms":closed.to_string(),"superseded_by_refresh_id":link}));
        next = old.core.ids[3];
        issued = old.core.issued;
    }
    result.reverse();
    Ok(result)
}
pub(super) struct Receipt {
    pub(super) bundle: [u8; 745],
    pub(super) accepted: u64,
    pub(super) installed: Option<(u64, [u8; 64])>,
}
impl Receipt {
    pub(super) async fn lookup(
        tx: &Transaction<'_>,
        account: Uuid,
        refresh: Uuid,
    ) -> Result<Option<Self>> {
        let Some(row) = tx.query_opt("SELECT * FROM public.payload_profile_selection_receipts WHERE account_id=$1 AND refresh_id=$2 FOR SHARE NOWAIT", &[&account,&refresh]).await? else { return Ok(None); };
        let bundle: [u8; 745] = fixed(&row, "bundle")?;
        if fixed::<32>(&row, "bundle_sha256")? != crypto::sha(&bundle) {
            return Err(Error::Conflict);
        }
        let accepted = scalar(row.try_get("accepted_ms")?)?;
        let installed = match (
            optional_time(&row, "installed_ms")?,
            optional_fixed(&row, "installed_signature")?,
        ) {
            (None, None) => None,
            (Some(t), Some(s)) if t >= accepted => Some((t, s)),
            _ => return Err(Error::Unsupported),
        };
        Ok(Some(Self {
            bundle,
            accepted,
            installed,
        }))
    }
    pub(super) fn projection(&self, row: &Challenge) -> serde_json::Value {
        serde_json::json!({"v":1,"opening_id":row.opening,"refresh_id":row.core.ids[3],"bundle_sha256":B.encode(crypto::sha(&self.bundle)),"accepted_ms":self.accepted.to_string()})
    }
}
