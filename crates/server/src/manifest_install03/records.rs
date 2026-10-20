// SPDX-License-Identifier: AGPL-3.0-only
//! Closed immutable receipt decoding. Structure and hashes alone never replace
//! original root/possession verification or a held current authorization.
use super::*;
use crate::sealed_payload_election03::live::{Error, manifest_history::History03};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
type Result<T> = std::result::Result<T, Error>;
pub(super) struct Receipt {
    pub statement: Statement03,
    pub signature: [u8; 64],
    pub signed: Vec<u8>,
    pub prior_signed: Vec<u8>,
    pub predecessor_opening: Option<Uuid>,
    pub prior_accepted: u64,
    pub accepted: u64,
    pub operation: Operation03,
    pub prefix: [u8; 32],
    pub prior_prefix: [u8; 32],
    pub pin: [u8; 94],
}
fn fixed<const N: usize>(row: &Row, name: &str) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
fn positive(row: &Row, name: &str) -> Result<u64> {
    u64::try_from(row.try_get::<_, i64>(name)?)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)
}
impl Receipt {
    pub(super) fn decode(row: &Row) -> Result<Self> {
        let statement = Statement03::decode(&row.try_get::<_, Vec<u8>>("statement")?)
            .map_err(|_| Error::Unsupported)?;
        let signature = fixed(row, "signature")?;
        let signed: Vec<u8> = row.try_get("successor_signed_manifest")?;
        let prior_signed: Vec<u8> = row.try_get("predecessor_signed_manifest")?;
        if !(366..=9753).contains(&signed.len()) || !(366..=9753).contains(&prior_signed.len()) {
            return Err(Error::Unsupported);
        }
        for (name, id) in [
            "account_id",
            "initiating_user_id",
            "initiating_session_id",
            "device_id",
            "line_id",
            "binding_id",
            "election_challenge_id",
            "opening_id",
        ]
        .into_iter()
        .zip(statement.ids)
        {
            if row.try_get::<_, Uuid>(name)?.as_bytes() != &id {
                return Err(Error::Unsupported);
            }
        }
        for (name, n) in [
            "binding_generation",
            "vault_generation",
            "selection_epoch",
            "predecessor_version",
            "successor_version",
            "issued_ms",
            "expires_ms",
        ]
        .into_iter()
        .zip(statement.numbers)
        {
            if positive(row, name)? != n {
                return Err(Error::Unsupported);
            }
        }
        for (name, digest) in [
            "root_fingerprint",
            "election_commitment",
            "election_bundle_sha256",
            "configured_origin_digest",
            "owner_session_digest",
            "predecessor_digest",
            "successor_signed_manifest_sha256",
            "browser_signer_key_id",
        ]
        .into_iter()
        .zip(statement.digests)
        {
            if fixed::<32>(row, name)? != digest {
                return Err(Error::Unsupported);
            }
        }
        let accepted = positive(row, "accepted_ms")?;
        let prior_accepted = positive(row, "predecessor_accepted_ms")?;
        let deadline = positive(row, "acceptance_deadline_ms")?;
        if fixed::<65>(row, "browser_signer_point")? != statement.point
            || fixed::<32>(row, "statement_sha256")? != crypto::sha(statement.bytes())
            || fixed::<32>(row, "predecessor_signed_manifest_sha256")? != crypto::sha(&prior_signed)
            || crypto::sha(&signed) != statement.digests[6]
            || crypto::sha(&signed[..signed.len() - 64]) != fixed::<32>(row, "successor_digest")?
            || crypto::sha(&prior_signed[..prior_signed.len() - 64]) != statement.digests[5]
            || prior_accepted > accepted
            || accepted < statement.numbers[5]
            || accepted >= statement.expires()
            || accepted >= deadline
        {
            return Err(Error::Unsupported);
        }
        let operation = match row.try_get::<_, String>("operation")?.as_str() {
            "enroll" => Operation03::Enroll,
            "renew" => Operation03::Renew,
            "replace" => Operation03::Replace,
            _ => return Err(Error::Unsupported),
        };
        let prior_prefix = fixed(row, "predecessor_ancestry_sha256")?;
        let prefix = fixed(row, "ancestry_sha256")?;
        if prefix
            != step_commitment(&prior_prefix, &statement, &signature, &signed, accepted)
                .map_err(|_| Error::Unsupported)?
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            statement,
            signature,
            signed,
            prior_signed,
            predecessor_opening: row.try_get("predecessor_opening_id")?,
            prior_accepted,
            accepted,
            operation,
            prefix,
            prior_prefix,
            pin: fixed(row, "root_pin")?,
        })
    }
    pub(super) fn scope(&self, h: &History03, origin: &str) -> Result<()> {
        let s = &self.statement;
        if self.pin != h.pin
            || s.account() != h.account
            || s.ids[3] != *h.device.as_bytes()
            || s.line() != h.line
            || s.ids[5] != *h.binding.as_bytes()
            || s.ids[6] != *h.challenge.as_bytes()
            || s.numbers[..3] != [h.generation, 1, h.epoch]
            || s.digests[..4]
                != [
                    h.accepted.root_fingerprint,
                    h.accepted.election_commitment,
                    h.accepted.election_bundle_sha256,
                    crate::sealed_payload_election03::adapter_contract::origin_digest(origin)
                        .map_err(|_| Error::Unsupported)?,
                ]
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(super) fn retention_identity(&self) -> [u8; 32] {
        crypto::sha(
            &[
                self.statement.bytes().as_slice(),
                &self.signature,
                &self.signed,
                &self.prior_signed,
                &self.accepted.to_be_bytes(),
                &self.prior_accepted.to_be_bytes(),
                &self.prefix,
                &self.prior_prefix,
                &self.pin,
                self.operation.as_str().as_bytes(),
                self.predecessor_opening.unwrap_or(Uuid::nil()).as_bytes(),
            ]
            .concat(),
        )
    }
    pub(super) fn entry(&self) -> serde_json::Value {
        serde_json::json!({"opening_id":self.statement.opening(),"statement":B.encode(self.statement.bytes()),"signature":B.encode(self.signature),"successor_manifest03":B.encode(&self.signed),"accepted_ms":self.accepted.to_string()})
    }
    pub(super) fn projection(&self) -> serde_json::Value {
        serde_json::json!({"v":1,"opening_id":self.statement.opening(),"line_id":self.statement.line(),"binding_id":Uuid::from_bytes(self.statement.ids[5]),"election_digest":B.encode(self.statement.digests[1]),"statement":B.encode(self.statement.bytes()),"signature":B.encode(self.signature),"successor_manifest03":B.encode(&self.signed),"accepted_ms":self.accepted.to_string(),"predecessor_version":self.statement.numbers[3].to_string(),"predecessor_digest":B.encode(self.statement.digests[5]),"successor_version":self.statement.numbers[4].to_string(),"successor_digest":B.encode(crypto::sha(&self.signed[..self.signed.len()-64])),"operation":self.operation.as_str(),"predecessor_ancestry_sha256":B.encode(self.prior_prefix),"ancestry_sha256":B.encode(self.prefix)})
    }
}
pub(super) async fn by_opening(
    tx: &Transaction<'_>,
    account: Uuid,
    opening: Uuid,
) -> Result<Option<Receipt>> {
    tx.query_opt("SELECT * FROM public.payload_profile_manifest_successors WHERE account_id=$1 AND opening_id=$2",&[&account,&opening]).await?.as_ref().map(Receipt::decode).transpose()
}
pub(super) async fn by_version(
    tx: &Transaction<'_>,
    account: Uuid,
    version: u64,
) -> Result<Option<Receipt>> {
    let version = i64::try_from(version).map_err(|_| Error::Unsupported)?;
    tx.query_opt("SELECT * FROM public.payload_profile_manifest_successors WHERE account_id=$1 AND successor_version=$2",&[&account,&version]).await?.as_ref().map(Receipt::decode).transpose()
}
pub(super) async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    after: u64,
    tip: u64,
) -> Result<Vec<Receipt>> {
    let after = i64::try_from(after).map_err(|_| Error::Unsupported)?;
    let tip = i64::try_from(tip).map_err(|_| Error::Unsupported)?;
    let rows=tx.query("SELECT * FROM public.payload_profile_manifest_successors WHERE account_id=$1 AND successor_version>$2 AND successor_version<=$3 ORDER BY successor_version LIMIT 8",&[&account,&after,&tip]).await?;
    let mut out = Vec::with_capacity(rows.len());
    let mut raw = 0usize;
    for row in rows {
        let receipt = Receipt::decode(&row)?;
        let size = 513 + 64 + receipt.signed.len();
        if raw + size > 65536 {
            break;
        }
        raw += size;
        out.push(receipt);
    }
    Ok(out)
}
