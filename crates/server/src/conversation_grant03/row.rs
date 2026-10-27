// SPDX-License-Identifier: AGPL-3.0-only
//! Exact nonpersonal retained grant. Syntax does not authenticate this record;
//! only the closed storage reader constructs it from the held actual ledger.
use super::*;
use tokio_postgres::Row;

pub(super) struct GrantRow03 {
    pub(super) ids: [Uuid; 12],
    pub(super) numbers: [u64; 11],
    pub(super) digests: [[u8; 32]; 14],
    pub(super) site: String,
    pub(super) instance: String,
    ceiling: u8,
    physical_source: String,
    physical_refresh: Option<Uuid>,
}
fn scalar(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)
}
impl GrantRow03 {
    pub(super) fn actor(&self, actor: DeviceInterval03<'_>, attempt: Uuid) -> Result<()> {
        if self.ids[0] != actor.session.account_id
            || self.ids[7] != actor.session.device_id
            || self.ids[2] != attempt
            || self.site != actor.site
            || self.instance != actor.instance
            || self.numbers[2]
                != u64::try_from(actor.session.connection_epoch)
                    .map_err(|_| Error::Authentication)?
            || self.numbers[3] != actor.deployment
            || self.digests[8]
                != crate::sealed_payload_election03::adapter_contract::origin_digest(actor.origin)
                    .map_err(|_| Error::Authentication)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn from_row(row: &Row) -> Result<Self> {
        let mut ids = [Uuid::nil(); 12];
        for (id, name) in ids.iter_mut().zip([
            "account_id",
            "message_id",
            "attempt_id",
            "interval_id",
            "interval_receipt_id",
            "initiating_user_id",
            "initiating_session_id",
            "device_id",
            "line_id",
            "binding_id",
            "election_challenge_id",
            "original_binding_id",
        ]) {
            *id = row.try_get(name)?;
            if id.is_nil() {
                return Err(Error::Unsupported);
            }
        }
        let mut numbers = [0; 11];
        for (number, name) in numbers.iter_mut().zip([
            "binding_generation",
            "attempt_generation",
            "connection_epoch",
            "deployment_epoch",
            "trust_generation",
            "manifest_version",
            "selection_epoch",
            "admitted_ms",
            "issued_ms",
            "expires_at_ms",
            "authority_deadline_ms",
        ]) {
            *number = scalar(row.try_get(name)?)?;
        }
        if numbers[1] != 1
            || numbers[4] != 1
            || numbers[6] != 1
            || numbers[7] > numbers[8]
            || numbers[8] >= numbers[9]
            || numbers[9] - numbers[8] > 30_000
            || numbers[9] > numbers[10]
        {
            return Err(Error::Unsupported);
        }
        let mut digests = [[0; 32]; 14];
        for (digest, name) in digests.iter_mut().zip([
            "reader_key_id",
            "envelope_sha256",
            "unsigned_sha256",
            "manifest_digest",
            "root_fingerprint",
            "election_digest",
            "election_bundle_sha256",
            "owner_session_digest",
            "configured_origin_digest",
            "device_session_digest",
            "physical_selection_digest",
            "interval_statement_sha256",
            "intent_sha256",
            "signature_sha256",
        ]) {
            *digest = row
                .try_get::<_, Vec<u8>>(name)?
                .try_into()
                .map_err(|_| Error::Unsupported)?;
            if *digest == [0; 32] {
                return Err(Error::Unsupported);
            }
        }
        let ceiling = u8::try_from(row.try_get::<_, i16>("authenticated_segment_ceiling")?)
            .map_err(|_| Error::Unsupported)?;
        let source: String = row.try_get("physical_source_kind")?;
        let refresh: Option<Uuid> = row.try_get("physical_refresh_id")?;
        if !(1..=6).contains(&ceiling)
            || row.try_get::<_, String>("lease_owner")? != format!("profile03:{}", ids[2])
            || !matches!(
                (source.as_str(), refresh),
                ("original_v2", None) | ("owner_refresh03", Some(_))
            )
            || refresh.is_some_and(|id| id.is_nil())
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            ids,
            numbers,
            digests,
            site: row.try_get("site_id")?,
            instance: row.try_get("instance_id")?,
            ceiling,
            physical_source: source,
            physical_refresh: refresh,
        })
    }
    pub(super) fn frame(&self) -> Result<GrantFrame03> {
        let ids = &self.ids;
        let n = &self.numbers;
        let d = &self.digests;
        let value = serde_json::json!({"v":1,"type":"sealed_execution_grant","grant_version":3,"envelope_profile":3,"manifest_profile":3,"reader_role":1,"segment_count":self.ceiling,"account_id":ids[0],"device_id":ids[7],"line_id":ids[8],"message_id":ids[1],"attempt_id":ids[2],"connection_epoch":sqltime(n[2])?,"deployment_epoch":sqltime(n[3])?,"binding_generation":sqltime(n[0])?,"attempt_generation":sqltime(n[1])?,"expires_at_ms":sqltime(n[9])?,"trust_generation":sqltime(n[4])?,"manifest_version":sqltime(n[5])?,"reader_key_id":B.encode(d[0]),"envelope_sha256":B.encode(d[1]),"unsigned_sha256":B.encode(d[2]),"manifest_digest":B.encode(d[3]),"root_fingerprint":B.encode(d[4]),"election_digest":B.encode(d[5])});
        GrantFrame03::parse(&serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unsupported)
    }
    pub(super) fn matches(&self, review: &HeldReviewed03<'_, '_>) -> Result<()> {
        let held = review.selected();
        let a = held.authority();
        let who = held.selected();
        if held.now_ms() < self.numbers[8]
            || held.now_ms() >= self.numbers[9]
            || self.numbers[9] > a.permission_expires_at_ms
        {
            return Err(Error::Expired);
        }
        if self.ids[..10]
            != [
                who.account,
                review.stored_message(),
                self.ids[2],
                review.interval_id(),
                review.interval_receipt_id(),
                who.user,
                who.session,
                Uuid::from_bytes(a.device_id),
                Uuid::from_bytes(a.line_id),
                Uuid::from_bytes(a.binding_id),
            ]
            || self.numbers[0] != a.binding_generation
            || self.numbers[4] != a.vault_generation
            || self.numbers[5] != a.manifest_version
            || self.numbers[7] != review.admitted_ms()
            || self.digests[0] != a.selected_reader_key_id
            || self.digests[1] != *review.envelope_sha256()
            || self.digests[2] != *review.unsigned_sha256()
            || self.digests[3] != a.manifest_digest
            || self.digests[4] != a.root_fingerprint
            || self.digests[5] != a.election_commitment
            || self.digests[6] != a.election_bundle_sha256
            || self.digests[9] != *held.device_session_digest()
            || self.digests[10] != *held.physical_digest()
            || self.digests[11] != *review.interval_sha256()
            || self.digests[12] != *review.intent_sha256()
            || self.digests[13] != *review.signature_sha256()
            || self.ceiling != review.sms_ceiling()
            || (self.physical_source.as_str(), self.physical_refresh) != held.physical_identity()
        {
            return Err(Error::Conflict);
        }
        let identity = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
            account_id: *who.account.as_bytes(),
            user_id: *who.user.as_bytes(),
            session_id: *who.session.as_bytes(),
        }
        .digest()
        .map_err(|_| Error::Unsupported)?;
        if identity != self.digests[7]
            || self.digests[8] != *review.origin_sha256()
            || (self.ids[10], self.ids[11]) != held.original_binding_ids()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
