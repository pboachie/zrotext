// SPDX-License-Identifier: AGPL-3.0-only
//! Exact current mutable connector registrations and read grants. Signed IDs
//! and manifest role3 alone do not establish these actual live row predicates.
use super::*;
struct Mapping03 {
    selected: IntegrationReader03,
    point: [u8; 65],
    generation: u64,
    registration_expires: u64,
    grant_expires: u64,
    key_from: u64,
    key_until: u64,
}
pub(super) struct Mappings03 {
    rows: Vec<Mapping03>,
    deadline: u64,
}
impl Mappings03 {
    pub(super) fn deadline(&self) -> u64 {
        self.deadline
    }
    pub(super) fn require_current(&self, now: u64) -> Result<()> {
        if now >= self.deadline || self.rows.iter().any(|r| now < r.key_from) {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub(super) fn projection(&self) -> Vec<serde_json::Value> {
        self.rows.iter().map(|r|serde_json::json!({"connector_id":r.selected.connector_id,"read_grant_id":r.selected.read_grant_id,"key_id":B.encode(r.selected.key_id),"key_point":B.encode(r.point),"manifest_generation":r.generation.to_string(),"read_directions":12,"registration_expires_ms":r.registration_expires.to_string(),"grant_expires_ms":r.grant_expires.to_string(),"key_valid_from_ms":r.key_from.to_string(),"key_valid_until_ms":r.key_until.to_string()})).collect()
    }
}
pub(super) async fn read(
    held: &HeldMessageSelection03<'_, '_, '_>,
    statement: &Statement03,
) -> Result<Mappings03> {
    let mut rows = Vec::new();
    let mut deadline = i64::MAX as u64;
    for selected in statement.integrations() {
        let row=held.tx().query_opt(
            "SELECT r.key_point,r.manifest_generation,r.expires_ms,g.expires_ms,k.valid_from_ms,k.valid_until_ms FROM public.connector_registrations r JOIN public.connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) JOIN public.connector_grants g ON (g.account_id,g.connector_id)=(r.account_id,r.connector_id) WHERE r.account_id=$1 AND r.connector_id=$2 AND r.key_id=$3 AND g.grant_id=$4 AND r.state='active' AND r.revoked_ms IS NULL AND k.retired_ms IS NULL AND g.kind='read' AND g.read_directions=12 AND g.line_id=$5 AND g.revoked_ms IS NULL AND (pg_catalog.cardinality(g.conversation_restriction)=0 OR $6=ANY(g.conversation_restriction)) FOR SHARE OF r,k,g NOWAIT",
            &[&statement.account_id(),&selected.connector_id,&selected.key_id.as_slice(),&selected.read_grant_id,&statement.line_id(),&statement.interval_id()]
        ).await?.ok_or(Error::Authentication)?;
        let point: [u8; 65] = row
            .try_get::<_, Vec<u8>>(0)?
            .try_into()
            .map_err(|_| Error::Unsupported)?;
        let generation = scalar(row.try_get(1)?)?;
        let registration_expires = scalar(row.try_get(2)?)?;
        let grant_expires = scalar(row.try_get(3)?)?;
        let key_from = scalar(row.try_get(4)?)?;
        let key_until = scalar(row.try_get(5)?)?;
        let (manifest_point, manifest_from, manifest_until) = held
            .manifest()
            .integration_reader03(&selected.key_id, held.now_ms())
            .map_err(|_| Error::Authentication)?;
        if point != manifest_point
            || generation != held.authority().vault_generation
            || crate::sealed_manifest::key_id(3, &point) != selected.key_id
            || key_from > held.now_ms()
            || manifest_from > held.now_ms()
        {
            return Err(Error::Conflict);
        }
        deadline = deadline
            .min(registration_expires)
            .min(grant_expires)
            .min(key_until)
            .min(manifest_until);
        rows.push(Mapping03 {
            selected: selected.clone(),
            point,
            generation,
            registration_expires,
            grant_expires,
            key_from,
            key_until,
        });
    }
    let selected = Mappings03 { rows, deadline };
    selected.require_current(held.now_ms())?;
    Ok(selected)
}
