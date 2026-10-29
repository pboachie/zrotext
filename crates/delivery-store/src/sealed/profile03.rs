// SPDX-License-Identifier: AGPL-3.0-only
//! Typed additive queue writes after real reviewed03 capture. This is storage,
//! not a cryptographic admission or a dispatcher. The closed database writer
//! requires the exact immutable sidecar in the same transaction.
use super::*;

pub struct Profile03QueueInput<'a> {
    pub message_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub manifest_generation: i64,
    pub manifest_version: i64,
    pub manifest_digest: &'a [u8; 32],
    pub signer_key_id: &'a [u8; 32],
    pub unsigned_digest: &'a [u8; 32],
    pub recipient: &'a str,
    pub envelope: &'a [u8],
    pub expires_at_ms: i64,
    /// Required authenticated intent ceiling. There is no missing-ceiling mode.
    pub segment_limit: u8,
}

impl AccountAdmission<'_, '_> {
    /// Requires a finite configured quota even for an unbound self-hosted
    /// account. A hosted protected trigger retains its own genuine reservation
    /// path. Neither this method nor its caller duplicates that reservation.
    pub async fn enqueue_profile03(
        &self,
        input: &Profile03QueueInput<'_>,
    ) -> Result<AcceptOutcome, StoreError> {
        if input.message_id.is_nil()
            || input.device_id.is_nil()
            || input.line_id.is_nil()
            || input.binding_generation <= 0
            || input.manifest_generation != 1
            || input.manifest_version <= 0
            || !(557..=34213).contains(&input.envelope.len())
            || !input.envelope.starts_with(b"ZTSE\x03\x01\0\0")
            || input.expires_at_ms <= 0
            || !(1..=6).contains(&input.segment_limit)
        {
            return Err(StoreError::InvalidInput);
        }
        if !self.reserve && self.bound.is_some() {
            // lock_account(..., false) cannot accidentally opt the additive
            // profile out of genuine quota enforcement.
            return Err(StoreError::QuotaNotConfigured);
        }
        let tx = self.tx;
        if tx.query_opt(
            "SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active=TRUE \
             UNION ALL SELECT 1 FROM owner_recipient_holds \
             WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL LIMIT 1",
            &[&self.account, &input.recipient],
        ).await?.is_some() {
            return Err(StoreError::RecipientSuppressed);
        }
        if let Some(row) = tx.query_opt(
            "SELECT transport_mode,request_digest,device_id,sealed_line_id,sealed_binding_generation, \
             sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id,sealed_segment_limit,transport_payload \
             FROM messages WHERE account_id=$1 AND id=$2",
            &[&self.account, &input.message_id],
        ).await? {
            if row.try_get::<_, String>(0)? != "sealed_profile03"
                || row.try_get::<_, Vec<u8>>(1)? != input.unsigned_digest.as_slice()
                || row.try_get::<_, Uuid>(2)? != input.device_id
                || row.try_get::<_, Option<Uuid>>(3)? != Some(input.line_id)
                || row.try_get::<_, Option<i64>>(4)? != Some(input.binding_generation)
                || row.try_get::<_, Option<i64>>(5)? != Some(input.manifest_generation)
                || row.try_get::<_, Option<i64>>(6)? != Some(input.manifest_version)
                || row.try_get::<_, Option<Vec<u8>>>(7)?.as_deref() != Some(input.manifest_digest.as_slice())
                || row.try_get::<_, Option<Vec<u8>>>(8)?.as_deref() != Some(input.signer_key_id.as_slice())
                || row.try_get::<_, Option<i16>>(9)? != Some(i16::from(input.segment_limit))
                || row.try_get::<_, Option<Vec<u8>>>(10)?.is_some_and(|bytes| bytes != input.envelope)
            {
                return Err(StoreError::MessageIdConflict);
            }
            return Ok(AcceptOutcome { message_id: input.message_id, created: false, line_label: None });
        }
        let counts = tx.query_one(
            "SELECT COUNT(*) FILTER (WHERE device_id=$2),COUNT(*) FROM messages \
             WHERE account_id=$1 AND state IN ('queued','claimed') AND expires_at>clock_timestamp()",
            &[&self.account, &input.device_id],
        ).await?;
        if counts.try_get::<_, i64>(0)? >= MAX_PENDING_PER_DEVICE
            || counts.try_get::<_, i64>(1)? >= MAX_PENDING_PER_ACCOUNT
        {
            return Err(StoreError::QueueFull);
        }
        let recipient_digest = Sha256::digest(input.recipient.as_bytes());
        let inserted = tx.query_opt(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode, \
             transport_payload,request_digest,state,expires_at,sealed_line_id,sealed_binding_generation, \
             sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id,sealed_segment_limit) \
             VALUES($1,$2,$3,$4,$5,'sealed_profile03',$6,$7,'queued',to_timestamp($8::bigint::double precision/1000), \
             $9,$10,$11,$12,$13,$14,$15) ON CONFLICT(id) DO NOTHING RETURNING id",
            &[&input.message_id,&self.account,&input.device_id,&input.recipient,&recipient_digest.as_slice(),
              &input.envelope,&input.unsigned_digest.as_slice(),&input.expires_at_ms,&input.line_id,
              &input.binding_generation,&input.manifest_generation,&input.manifest_version,
              &input.manifest_digest.as_slice(),&input.signer_key_id.as_slice(),&i16::from(input.segment_limit)],
        ).await?;
        if inserted.is_none() {
            return Err(StoreError::MessageIdConflict);
        }
        if self.reserve {
            reserve_outbound(tx, self.account, input.message_id, None, self.bound).await?;
        }
        tx.execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id) VALUES($1,$2,$3)",
            &[&input.message_id, &self.account, &input.device_id],
        )
        .await?;
        Ok(AcceptOutcome {
            message_id: input.message_id,
            created: true,
            line_label: None,
        })
    }
}
