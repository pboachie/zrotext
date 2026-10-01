// SPDX-License-Identifier: AGPL-3.0-only
//! Current-only authority for dormant queue admission and owner reads. No
//! device session, root provisioning or manifest advancement is synthesized.

use super::{AdmissionError, ChainPosition, ManifestTrust, VerifiedManifest, wall_time};
use crate::{
    sealed_envelope::{ExpectedContext, Kind},
    sealed_manifest::{self, EnvelopeAuthority},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct ManifestSnapshot {
    pub generation: i64,
    pub version: i64,
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
    pub accepted_ms: i64,
}

pub(crate) struct CurrentAuthority<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    account: Uuid,
    pin: Vec<u8>,
    bytes: Vec<u8>,
    trust: ManifestTrust,
    manifest: VerifiedManifest,
    /// Set once `context` has written this admission's `last_verified_ms`;
    /// a second recheck re-reads the row but must not rewrite the hot row.
    verified_write: bool,
}

pub(crate) async fn lock_current<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    account: Uuid,
) -> Result<CurrentAuthority<'tx, 'connection>, AdmissionError> {
    let row = tx.query_opt(
        "SELECT root_pin,root_fingerprint,generation,anchor_digest,version,semantic_digest,manifest,last_verified_ms \
         FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL AND version>0 FOR UPDATE",
        &[&account],
    ).await?.ok_or(AdmissionError::Rejected("missing current authority"))?;
    let pin: Vec<u8> = row.get(0);
    let bytes: Vec<u8> = row.get(6);
    let trust = ManifestTrust {
        account_id: *account.as_bytes(),
        root_fingerprint: row
            .get::<_, Vec<u8>>(1)
            .try_into()
            .map_err(|_| "stored fingerprint")?,
        generation: row
            .get::<_, i64>(2)
            .try_into()
            .map_err(|_| "stored generation")?,
        position: ChainPosition::Current {
            version: row
                .get::<_, i64>(4)
                .try_into()
                .map_err(|_| "stored version")?,
            digest: row
                .get::<_, Vec<u8>>(5)
                .try_into()
                .map_err(|_| "stored digest")?,
        },
    };
    let now = wall_time(tx, row.get(7)).await?;
    let manifest = sealed_manifest::verify(&pin, &bytes, &trust, now)?;
    Ok(CurrentAuthority {
        tx,
        account,
        pin,
        bytes,
        trust,
        manifest,
        verified_write: false,
    })
}

impl CurrentAuthority<'_, '_> {
    pub(crate) async fn next_snapshot(
        &mut self,
        bytes: &[u8],
    ) -> Result<ManifestSnapshot, AdmissionError> {
        let now = self.checked_time().await?;
        let mut trust = self.trust.clone();
        trust.position = super::ChainPosition::After {
            version: self.manifest.version(),
            digest: *self.manifest.digest(),
        };
        let next = sealed_manifest::verify(&self.pin, bytes, &trust, now)?;
        Ok(ManifestSnapshot {
            generation: next.generation() as i64,
            version: next.version() as i64,
            digest: *next.digest(),
            bytes: bytes.to_vec(),
            accepted_ms: now as i64,
        })
    }
    pub(crate) fn generation(&self) -> i64 {
        self.manifest.generation() as i64
    }

    pub(crate) async fn authorize_agent_signer(
        &mut self,
        line: Uuid,
        signer: &[u8; 32],
    ) -> Result<(), AdmissionError> {
        let now = self.checked_time().await?;
        if !self
            .manifest
            .active_agent_signer(line.as_bytes(), signer, now)
        {
            return Err("current agent signer authority".into());
        }
        Ok(())
    }

    pub(crate) async fn authorize_agent_reader(
        &mut self,
        key_id: &[u8; 32],
        directions: u16,
    ) -> Result<(), AdmissionError> {
        let now = self.checked_time().await?;
        if !self.manifest.active_agent_reader(key_id, directions, now) {
            return Err("current agent connector authority".into());
        }
        Ok(())
    }

    /// Selected integration readers must be active in the same pinned current
    /// manifest as the device/line. A stored registration alone is insufficient.
    pub(crate) async fn integration_snapshot(
        &mut self,
        device: Uuid,
        line: Uuid,
        point: &[u8],
    ) -> Result<(ManifestSnapshot, [u8; 32], u16), AdmissionError> {
        let now = self.checked_time().await?;
        self.manifest
            .conversation_keys(device.as_bytes(), line.as_bytes(), now)?;
        let (reader, scope, _) =
            self.manifest
                .active_integration_reader(point, now)
                .ok_or(AdmissionError::Rejected(
                    "selected integration reader authority",
                ))?;
        Ok((
            ManifestSnapshot {
                generation: self.generation(),
                version: self.manifest.version() as i64,
                digest: *self.manifest.digest(),
                bytes: self.bytes.clone(),
                accepted_ms: now as i64,
            },
            reader,
            scope,
        ))
    }

    /// A workflow signer is a distinct active role-5 key for this exact line.
    pub(crate) async fn workflow_signer(
        &mut self,
        device: Uuid,
        line: Uuid,
        id: &[u8; 32],
    ) -> Result<(), AdmissionError> {
        self.workflow_signer_deadline(device, line, id)
            .await
            .map(|_| ())
    }

    pub(crate) async fn workflow_signer_deadline(
        &mut self,
        device: Uuid,
        line: Uuid,
        id: &[u8; 32],
    ) -> Result<i64, AdmissionError> {
        let now = self.checked_time().await?;
        self.manifest
            .conversation_keys(device.as_bytes(), line.as_bytes(), now)?;
        let until = self
            .manifest
            .active_agent_signer_until(line.as_bytes(), id, now)
            .ok_or(AdmissionError::Rejected("workflow signer authority"))?;
        i64::try_from(until).map_err(|_| AdmissionError::Rejected("workflow signer deadline"))
    }

    /// Invoke after every potentially blocking storage operation, immediately
    /// before commit. Also detects authority changes made within this transaction.
    pub(crate) async fn context<'a>(
        &'a mut self,
        wanted: &EnvelopeAuthority<'a>,
    ) -> Result<ExpectedContext<'a>, AdmissionError> {
        if wanted.kind != Kind::Outbound || wanted.account_id != *self.account.as_bytes() {
            return Err("outbound authority identity".into());
        }
        self.current_context(wanted).await
    }

    /// Owner reads authorize existing inbound signatures against exact current
    /// trust. This is not device-ingest authority or capture-time consent proof.
    pub(crate) async fn inbound_context<'a>(
        &'a mut self,
        wanted: &EnvelopeAuthority<'a>,
    ) -> Result<ExpectedContext<'a>, AdmissionError> {
        if wanted.kind != Kind::Inbound || wanted.account_id != *self.account.as_bytes() {
            return Err("inbound reader authority identity".into());
        }
        self.current_context(wanted).await
    }

    async fn current_context<'a>(
        &'a mut self,
        wanted: &EnvelopeAuthority<'a>,
    ) -> Result<ExpectedContext<'a>, AdmissionError> {
        let now = self.checked_time().await?;
        Ok(self.manifest.envelope_context(wanted, now)?)
    }

    pub(crate) async fn conversation_keys(
        &mut self,
        device: Uuid,
        line: Uuid,
    ) -> Result<([u8; 32], [u8; 32]), AdmissionError> {
        let now = self.checked_time().await?;
        Ok(self
            .manifest
            .conversation_keys(device.as_bytes(), line.as_bytes(), now)?)
    }

    pub(crate) async fn snapshot(
        &mut self,
        wanted: &EnvelopeAuthority<'_>,
    ) -> Result<ManifestSnapshot, AdmissionError> {
        let now = self.checked_time().await?;
        if wanted.kind != Kind::Inbound || wanted.account_id != *self.account.as_bytes() {
            return Err("snapshot identity".into());
        }
        self.manifest.envelope_context(wanted, now)?;
        Ok(ManifestSnapshot {
            generation: self.generation(),
            version: self.manifest.version() as i64,
            digest: *self.manifest.digest(),
            bytes: self.bytes.clone(),
            accepted_ms: now as i64,
        })
    }

    pub(crate) async fn admission_deadline(
        &mut self,
        wanted: &EnvelopeAuthority<'_>,
    ) -> Result<i64, AdmissionError> {
        let now = self.checked_time().await?;
        if wanted.kind != Kind::Inbound || wanted.account_id != *self.account.as_bytes() {
            return Err("deadline identity".into());
        }
        Ok(self.manifest.admission_deadline(wanted, now)? as i64)
    }

    pub(crate) async fn outbound_deadline(
        &mut self,
        wanted: &EnvelopeAuthority<'_>,
    ) -> Result<i64, AdmissionError> {
        let now = self.checked_time().await?;
        if wanted.kind != Kind::Outbound || wanted.account_id != *self.account.as_bytes() {
            return Err("outbound deadline identity".into());
        }
        Ok(self.manifest.admission_deadline(wanted, now)? as i64)
    }

    /// Re-prove the original signature without rewriting its authenticated epoch.
    /// Snapshot came from the immutable verified-ingest provenance table, not
    /// from untrusted envelope claims. Current reader AND signer remain required.
    pub(crate) async fn verify_history(
        &mut self,
        wanted: &EnvelopeAuthority<'_>,
        snapshot: &ManifestSnapshot,
        envelope: &[u8],
    ) -> Result<(), AdmissionError> {
        self.inbound_context(wanted).await?;
        if snapshot.generation != self.generation()
            || snapshot.version <= 0
            || snapshot.accepted_ms <= 0
        {
            return Err("historical trust generation".into());
        }
        let trust = ManifestTrust {
            account_id: *self.account.as_bytes(),
            root_fingerprint: self.trust.root_fingerprint,
            generation: snapshot.generation as u64,
            position: ChainPosition::Current {
                version: snapshot.version as u64,
                digest: snapshot.digest,
            },
        };
        let historical = sealed_manifest::verify(
            &self.pin,
            &snapshot.bytes,
            &trust,
            snapshot.accepted_ms as u64,
        )?;
        let context = historical.envelope_context(wanted, snapshot.accepted_ms as u64)?;
        crate::sealed_envelope::verify(envelope, &context)
            .map_err(|_| AdmissionError::Rejected("historical envelope proof"))?;
        Ok(())
    }

    async fn checked_time(&mut self) -> Result<u64, AdmissionError> {
        let row = self.tx.query_opt(
            "SELECT root_pin,root_fingerprint,generation,version,semantic_digest,manifest,last_verified_ms \
             FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL",
            &[&self.account],
        ).await?.ok_or(AdmissionError::Rejected("revoked authority"))?;
        if row.get::<_, Vec<u8>>(0) != self.pin
            || row.get::<_, Vec<u8>>(1) != self.trust.root_fingerprint
            || row.get::<_, i64>(2) != self.generation()
            || row.get::<_, i64>(3) != self.manifest.version() as i64
            || row.get::<_, Option<Vec<u8>>>(4).as_deref()
                != Some(self.manifest.digest().as_slice())
            || row.get::<_, Option<Vec<u8>>>(5).as_deref() != Some(self.bytes.as_slice())
        {
            return Err("changed current authority".into());
        }
        let now = wall_time(self.tx, row.get(6)).await?;
        // The row recheck above pins the locked authority's exact bytes and
        // chain position under this transaction's FOR UPDATE lock, so the
        // signature and role proofs from lock_current cannot have changed;
        // only freshness can, and envelope_context rechecks that here.
        if !self.verified_write {
            self.tx
                .execute(
                    "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
                    &[&self.account, &(now as i64)],
                )
                .await?;
            self.verified_write = true;
        }
        Ok(now)
    }
}
