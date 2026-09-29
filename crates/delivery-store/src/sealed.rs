// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant queue storage, not cryptographic authorization or a grant API.
//! The server owns a READ COMMITTED transaction, locks/verifies current authority
//! first, and rechecks it after these writes before committing. Any error rolls
//! back the entire transaction. No existing dispatcher accepts this transport.

use super::{
    AcceptOutcome, MAX_PENDING_PER_ACCOUNT, MAX_PENDING_PER_DEVICE, StoreError,
    lock_billing_account, reserve_outbound,
};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub struct CandidateQueueInput<'a> {
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
}

/// Account lock and billing policy cannot be fabricated by storage callers.
pub struct AccountAdmission<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    account: Uuid,
    reserve: bool,
    billed: bool,
}

pub async fn lock_account<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    account: Uuid,
    billing_enabled: bool,
) -> Result<AccountAdmission<'tx, 'connection>, StoreError> {
    let (reserve, billed) = lock_billing_account(tx, account, billing_enabled).await?;
    if tx
        .query_opt(
            "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL",
            &[&account],
        )
        .await?
        .is_none()
    {
        return Err(StoreError::Revoked);
    }
    Ok(AccountAdmission {
        tx,
        account,
        reserve,
        billed,
    })
}

impl AccountAdmission<'_, '_> {
    /// Input must come from the exact verified envelope in the same transaction.
    /// Retained unsigned identity survives ciphertext redaction; signatures may
    /// differ but an exact replay never replaces bytes, adds jobs or spends again.
    pub async fn enqueue(
        &self,
        input: &CandidateQueueInput<'_>,
    ) -> Result<AcceptOutcome, StoreError> {
        let tx = self.tx;
        if input.message_id.is_nil()
            || input.device_id.is_nil()
            || input.line_id.is_nil()
            || input.binding_generation <= 0
            || input.manifest_generation <= 0
            || input.manifest_version <= 0
            || !(426..=34213).contains(&input.envelope.len())
            || !input.envelope.starts_with(b"ZTSE\x02\x01")
            || input.expires_at_ms <= 0
        {
            return Err(StoreError::InvalidInput);
        }
        // Account lock serializes signed STOP and owner hold writers, including replays.
        if tx.query_opt(
            "SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active=TRUE \
             UNION ALL SELECT 1 FROM owner_recipient_holds \
             WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL LIMIT 1",
            &[&self.account, &input.recipient],
        ).await?.is_some() {
            return Err(StoreError::RecipientSuppressed);
        }
        let existing = tx.query_opt(
            "SELECT transport_mode,request_digest,device_id,sealed_line_id,sealed_binding_generation, \
             sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id \
             FROM messages WHERE account_id=$1 AND id=$2",
            &[&self.account, &input.message_id],
        ).await?;
        if let Some(row) = existing {
            if row.get::<_, String>(0) != "sealed_candidate02"
                || row.get::<_, Vec<u8>>(1) != input.unsigned_digest.as_slice()
                || row.get::<_, Uuid>(2) != input.device_id
                || row.get::<_, Option<Uuid>>(3) != Some(input.line_id)
                || row.get::<_, Option<i64>>(4) != Some(input.binding_generation)
                || row.get::<_, Option<i64>>(5) != Some(input.manifest_generation)
                || row.get::<_, Option<i64>>(6) != Some(input.manifest_version)
                || row.get::<_, Option<Vec<u8>>>(7).as_deref()
                    != Some(input.manifest_digest.as_slice())
                || row.get::<_, Option<Vec<u8>>>(8).as_deref()
                    != Some(input.signer_key_id.as_slice())
            {
                return Err(StoreError::MessageIdConflict);
            }
            return Ok(AcceptOutcome {
                message_id: input.message_id,
                created: false,
            });
        }
        let counts = tx.query_one(
            "SELECT COUNT(*) FILTER (WHERE device_id=$2),COUNT(*) FROM messages \
             WHERE account_id=$1 AND state IN ('queued','claimed') AND expires_at>clock_timestamp()",
            &[&self.account, &input.device_id],
        ).await?;
        if counts.get::<_, i64>(0) >= MAX_PENDING_PER_DEVICE
            || counts.get::<_, i64>(1) >= MAX_PENDING_PER_ACCOUNT
        {
            return Err(StoreError::QueueFull);
        }
        let recipient_digest = Sha256::digest(input.recipient.as_bytes());
        let inserted = tx.query_opt(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode, \
             transport_payload,request_digest,state,expires_at,sealed_line_id,sealed_binding_generation, \
             sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id) \
             VALUES($1,$2,$3,$4,$5,'sealed_candidate02',$6,$7,'queued',to_timestamp($8::bigint::double precision/1000), \
             $9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING RETURNING id",
            &[&input.message_id,&self.account,&input.device_id,&input.recipient,&recipient_digest.as_slice(),
              &input.envelope,&input.unsigned_digest.as_slice(),&input.expires_at_ms,&input.line_id,
              &input.binding_generation,&input.manifest_generation,&input.manifest_version,
              &input.manifest_digest.as_slice(),&input.signer_key_id.as_slice()],
        ).await?;
        if inserted.is_none() {
            return Err(StoreError::MessageIdConflict);
        }
        if self.reserve {
            reserve_outbound(tx, self.account, input.message_id, None, Some(self.billed)).await?;
        }
        tx.execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id) VALUES($1,$2,$3)",
            &[&input.message_id, &self.account, &input.device_id],
        )
        .await?;
        Ok(AcceptOutcome {
            message_id: input.message_id,
            created: true,
        })
    }
}
