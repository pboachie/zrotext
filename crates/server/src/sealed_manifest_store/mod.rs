// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant candidate-02 durable authority. No route calls this module.
//!
//! A separate, independently authenticated ceremony must provision the immutable
//! pin; this module intentionally has no provisioning, reset or rotation API.
//! Admission locks authority before the existing account/device/key/line/session
//! and writer fences. Keep admission, envelope verification and future effects in
//! the same transaction. Call `Admission::context` immediately before effects and
//! commit, then release the borrow before committing. Its wall-time check cannot
//! promise that a lease will remain valid after arbitrary caller delays. Roll back
//! the transaction on any error; a rejected admission is not permission to commit
//! other work. No content is stored and no runtime gate is enabled here.

use crate::{
    inbound::InboundSession,
    sealed_envelope::{ExpectedContext, Kind},
    sealed_inbound::line_binding_ready,
    sealed_manifest::{self, ChainPosition, EnvelopeAuthority, ManifestTrust, VerifiedManifest},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("sealed authority rejected: {0}")]
    Rejected(&'static str),
    #[error("sealed authority database operation failed")]
    Database(#[from] tokio_postgres::Error),
}
impl From<&'static str> for AdmissionError {
    fn from(value: &'static str) -> Self {
        Self::Rejected(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionChange {
    Advanced,
    Replayed,
}

/// Transaction-bound, non-cloneable proof of admission, not an ingest permit.
/// No manifest getter bypasses the final identity/session/freshness recheck.
pub struct Admission<'tx, 'connection, 'session> {
    tx: &'tx Transaction<'connection>,
    session: InboundSession<'session>,
    line: Uuid,
    binding_generation: i64,
    pin: Vec<u8>,
    bytes: Vec<u8>,
    trust: ManifestTrust,
    manifest: VerifiedManifest,
    change: AdmissionChange,
}

impl Admission<'_, '_, '_> {
    pub fn change(&self) -> AdmissionChange {
        self.change
    }

    /// Recheck after all waits and before future effects/commit. The returned
    /// context borrows this admission and the caller's recipient list. A caller
    /// must still verify the exact envelope with `sealed_envelope::verify` and
    /// enforce durable event identity/sequence fences in this same transaction.
    pub async fn context<'a>(
        &'a self,
        wanted: &EnvelopeAuthority<'a>,
    ) -> Result<ExpectedContext<'a>, AdmissionError> {
        if wanted.kind != Kind::Inbound
            || wanted.account_id != *self.session.account_id.as_bytes()
            || wanted.device_id != *self.session.device_id.as_bytes()
            || wanted.line_id != *self.line.as_bytes()
        {
            return Err("inbound admission identity".into());
        }
        if !line_binding_ready(self.tx, self.session, self.line, self.binding_generation).await? {
            return Err("sealed line/session fence".into());
        }
        // Detect same-transaction authority changes too: row locks only protect
        // against other transactions, not changes made by this caller itself.
        let row = self
            .tx
            .query_opt(
                "SELECT version,semantic_digest,last_verified_ms FROM sealed_manifest_authorities \
             WHERE account_id=$1 AND revoked_at IS NULL",
                &[&self.session.account_id],
            )
            .await?
            .ok_or(AdmissionError::Rejected("missing/revoked authority"))?;
        let version: i64 = row.get(0);
        let digest: Option<Vec<u8>> = row.get(1);
        if version != self.manifest.version() as i64
            || digest.as_deref() != Some(self.manifest.digest().as_slice())
        {
            return Err("changed admission authority".into());
        }
        let now = wall_time(self.tx, row.get(2)).await?;
        sealed_manifest::verify(&self.pin, &self.bytes, &self.trust, now)?;
        let context = self.manifest.envelope_context(wanted, now)?;
        self.tx
            .execute(
                "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
                &[&self.session.account_id, &(now as i64)],
            )
            .await?;
        Ok(context)
    }
}

async fn wall_time(tx: &Transaction<'_>, high_water: i64) -> Result<u64, AdmissionError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if now <= 0 || now < high_water {
        return Err("database time regressed".into());
    }
    Ok(now as u64)
}

/// Accept the next signed manifest or replay the exact current semantic value.
/// `bytes` never supplies trust. An absent provisioned pin fails closed. The row
/// lock serializes simultaneous advances/forks through transaction completion.
pub async fn admit<'tx, 'connection, 'session>(
    tx: &'tx Transaction<'connection>,
    session: InboundSession<'session>,
    line: Uuid,
    binding_generation: i64,
    bytes: &[u8],
) -> Result<Admission<'tx, 'connection, 'session>, AdmissionError> {
    // Bound attacker-controlled input before touching storage. This header only
    // selects a chain expectation; verify() authenticates every byte below.
    if !(364..=9751).contains(&bytes.len()) || &bytes[..5] != b"ZTMA\x02" {
        return Err("manifest shape".into());
    }
    let incoming_version = u64::from_be_bytes(bytes[29..37].try_into().unwrap());
    let row = tx
        .query_opt(
            "SELECT root_pin,root_fingerprint,generation,anchor_digest,version,semantic_digest, \
         manifest,accepted_at_ms,last_verified_ms FROM sealed_manifest_authorities \
         WHERE account_id=$1 AND revoked_at IS NULL FOR UPDATE",
            &[&session.account_id],
        )
        .await?
        .ok_or(AdmissionError::Rejected("missing/revoked authority"))?;
    let pin: Vec<u8> = row.get(0);
    let fingerprint: Vec<u8> = row.get(1);
    let generation: i64 = row.get(2);
    let anchor: Vec<u8> = row.get(3);
    let version: i64 = row.get(4);
    let digest: Option<Vec<u8>> = row.get(5);
    let previous: Option<Vec<u8>> = row.get(6);
    let accepted_at: Option<i64> = row.get(7);
    let high_water: i64 = row.get(8);
    let mut trust = ManifestTrust {
        account_id: *session.account_id.as_bytes(),
        root_fingerprint: fingerprint.try_into().map_err(|_| "stored fingerprint")?,
        generation: generation.try_into().map_err(|_| "stored generation")?,
        position: ChainPosition::Genesis {
            anchor_digest: anchor.try_into().map_err(|_| "stored anchor")?,
        },
    };
    if version > 0 {
        let digest = digest
            .ok_or("stored digest")?
            .try_into()
            .map_err(|_| "stored digest")?;
        trust.position = ChainPosition::Current {
            version: version as u64,
            digest,
        };
        // Authenticate the stored high-water at its original acceptance time,
        // not at current time: an expired predecessor may receive a fresh next
        // version, but it cannot itself be replayed after expiry.
        sealed_manifest::verify(
            &pin,
            previous.as_deref().ok_or("stored manifest")?,
            &trust,
            accepted_at
                .ok_or("stored acceptance")?
                .try_into()
                .map_err(|_| "stored acceptance")?,
        )?;
        if incoming_version != version as u64 {
            trust.position = ChainPosition::After {
                version: version as u64,
                digest,
            };
        }
    }
    if !line_binding_ready(tx, session, line, binding_generation).await? {
        return Err("sealed line/session fence".into());
    }
    let now = wall_time(tx, high_water).await?;
    let manifest = sealed_manifest::verify(&pin, bytes, &trust, now)?;
    let change = if incoming_version == version as u64 {
        AdmissionChange::Replayed
    } else {
        AdmissionChange::Advanced
    };
    if change == AdmissionChange::Advanced {
        tx.execute(
            "UPDATE sealed_manifest_authorities SET version=$2,semantic_digest=$3,manifest=$4, \
             accepted_at_ms=$5,last_verified_ms=$5 WHERE account_id=$1",
            &[
                &session.account_id,
                &(manifest.version() as i64),
                &manifest.digest().as_slice(),
                &bytes,
                &(now as i64),
            ],
        )
        .await?;
    } else {
        tx.execute(
            "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
            &[&session.account_id, &(now as i64)],
        )
        .await?;
    }
    trust.position = ChainPosition::Current {
        version: manifest.version(),
        digest: *manifest.digest(),
    };
    Ok(Admission {
        tx,
        session,
        line,
        binding_generation,
        pin,
        bytes: bytes.to_vec(),
        trust,
        manifest,
        change,
    })
}

#[cfg(test)]
pub(crate) mod tests;
