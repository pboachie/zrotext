// SPDX-License-Identifier: AGPL-3.0-only
//! Current-only authority for dormant outbound queue admission. No inbound
//! session, root provisioning or manifest advancement is synthesized here.

use super::{AdmissionError, ChainPosition, ManifestTrust, VerifiedManifest, wall_time};
use crate::{
    sealed_envelope::{ExpectedContext, Kind},
    sealed_manifest::{self, EnvelopeAuthority},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct CurrentAuthority<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    account: Uuid,
    pin: Vec<u8>,
    bytes: Vec<u8>,
    trust: ManifestTrust,
    manifest: VerifiedManifest,
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
    })
}

impl CurrentAuthority<'_, '_> {
    pub(crate) fn generation(&self) -> i64 {
        self.manifest.generation() as i64
    }

    /// Invoke after every potentially blocking storage operation, immediately
    /// before commit. Also detects authority changes made within this transaction.
    pub(crate) async fn context<'a>(
        &'a self,
        wanted: &EnvelopeAuthority<'a>,
    ) -> Result<ExpectedContext<'a>, AdmissionError> {
        if wanted.kind != Kind::Outbound || wanted.account_id != *self.account.as_bytes() {
            return Err("outbound authority identity".into());
        }
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
        sealed_manifest::verify(&self.pin, &self.bytes, &self.trust, now)?;
        let context = self.manifest.envelope_context(wanted, now)?;
        self.tx
            .execute(
                "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
                &[&self.account, &(now as i64)],
            )
            .await?;
        Ok(context)
    }
}
