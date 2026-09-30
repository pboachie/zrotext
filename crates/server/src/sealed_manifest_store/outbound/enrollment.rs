// SPDX-License-Identifier: AGPL-3.0-only
//! Narrow successor validation; never rewrites an existing role or root pin.
use super::*;
use crate::http_owner_conversations::enrollment::Enrollment;

impl CurrentAuthority<'_, '_> {
    pub(crate) async fn install_browser_successor(
        &mut self,
        bytes: &[u8],
        r: &Enrollment,
    ) -> Result<(), AdmissionError> {
        let now = self.checked_time().await?;
        if self.manifest.digest() != &r.predecessor {
            return Err("enrollment predecessor".into());
        }
        let next = self.next_snapshot(bytes).await?;
        let old_count = self.bytes[150] as usize;
        if bytes[150] as usize != old_count + 1 || bytes[45..53] != self.bytes[45..53] {
            return Err("enrollment record count/expiry".into());
        }
        let added = bytes[151..bytes.len() - 64]
            .chunks_exact(149)
            .find(|k| k[0] == 5 && k[1..33] == r.signer)
            .ok_or("enrollment signer")?;
        if added[33..98] != r.public_point
            || added[98..114] != [0; 16]
            || added[114..130] != *r.line.as_bytes()
            || added[130..132] != [0, 1]
            || added[148] != 1
        {
            return Err("enrollment signer scope".into());
        }
        let until = u64::from_be_bytes(
            added[140..148]
                .try_into()
                .map_err(|_| "enrollment lifetime")?,
        );
        if until <= now
            || until
                > now
                    .checked_add(1_800_000)
                    .ok_or("enrollment time overflow")?
        {
            return Err("enrollment lifetime".into());
        }
        let remaining: Vec<&[u8]> = bytes[151..bytes.len() - 64]
            .chunks_exact(149)
            .filter(|k| *k != added)
            .collect();
        let original: Vec<&[u8]> = self.bytes[151..self.bytes.len() - 64]
            .chunks_exact(149)
            .collect();
        if remaining != original {
            return Err("enrollment changed existing authority".into());
        }
        for (role, id) in [(1, r.phone_reader), (2, r.archive_reader)] {
            let key = original
                .iter()
                .find(|k| k[0] == role && k[1..33] == id)
                .ok_or("enrollment reader")?;
            let from = u64::from_be_bytes(
                key[132..140]
                    .try_into()
                    .map_err(|_| "enrollment reader lifetime")?,
            );
            let until = u64::from_be_bytes(
                key[140..148]
                    .try_into()
                    .map_err(|_| "enrollment reader lifetime")?,
            );
            if key[148] != 1
                || key[131] & 4 == 0
                || from > now
                || until <= now
                || role == 1
                    && (key[98..114] != *r.device.as_bytes() || key[114..130] != *r.line.as_bytes())
            {
                return Err("enrollment reader scope".into());
            }
        }
        // Recheck after signature verification and every earlier lock wait, before durable CAS.
        self.checked_time().await?;
        let changed=self.tx.execute("UPDATE sealed_manifest_authorities SET version=$2,semantic_digest=$3,manifest=$4,accepted_at_ms=$5,last_verified_ms=$5 WHERE account_id=$1 AND version=$6 AND semantic_digest=$7 AND revoked_at IS NULL",
            &[&self.account,&next.version,&next.digest.as_slice(),&next.bytes,&next.accepted_ms,&(self.manifest.version() as i64),&r.predecessor.as_slice()]).await?;
        if changed != 1 {
            return Err("enrollment CAS".into());
        }
        Ok(())
    }
    pub(crate) async fn recheck_installed_successor(
        &mut self,
        bytes: &[u8],
        r: &Enrollment,
    ) -> Result<(), AdmissionError> {
        let row=self.tx.query_opt("SELECT manifest,version,semantic_digest,last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL",&[&self.account]).await?.ok_or("enrollment revoked")?;
        if row.get::<_, Vec<u8>>(0) != bytes {
            return Err("enrollment replaced".into());
        }
        let now = wall_time(self.tx, row.get(3)).await?;
        let mut trust = self.trust.clone();
        trust.position = ChainPosition::Current {
            version: row
                .get::<_, i64>(1)
                .try_into()
                .map_err(|_| "enrollment version")?,
            digest: row
                .get::<_, Vec<u8>>(2)
                .try_into()
                .map_err(|_| "enrollment digest")?,
        };
        let manifest = sealed_manifest::verify(&self.pin, bytes, &trust, now)?;
        let readers = [
            crate::sealed_envelope::ExpectedRecipient {
                role: 1,
                key_id: r.phone_reader,
            },
            crate::sealed_envelope::ExpectedRecipient {
                role: 2,
                key_id: r.archive_reader,
            },
        ];
        manifest.envelope_context(
            &EnvelopeAuthority {
                kind: Kind::Outbound,
                account_id: *self.account.as_bytes(),
                device_id: *r.device.as_bytes(),
                line_id: *r.line.as_bytes(),
                message_id: *r.line.as_bytes(),
                signer_key_id: r.signer,
                peer: r.peer.as_bytes(),
                recipients: &readers,
            },
            now,
        )?;
        Ok(())
    }
}
