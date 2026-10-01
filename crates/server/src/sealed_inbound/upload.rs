// SPDX-License-Identifier: AGPL-3.0-only
//! Sealed inbound HTTP upload admission (#538). The device-socket pilot
//! carries its manifest in-stream; this path serves `POST /v1/sealed/
//! inbound-events`, where an account API key authorized for the uploading
//! device submits one kind-02 envelope and the authority is the stored
//! current chain. Opaque bytes only: no plaintext, no webhook, no grant and
//! no radio effect. Reuse of the device-socket ingest SQL is deliberate:
//! both paths must keep identical replay-fence semantics.

use crate::{
    auth::{ApiPrincipal, Scope, TokenHasher},
    inbound::consume_storage_budget,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::inbound_upload,
};
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;

const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("invalid sealed inbound claims")]
    InvalidClaims,
    #[error("current authorization or line binding rejected")]
    Forbidden,
    #[error("sealed authority rejected")]
    Authority(#[from] crate::sealed_manifest_store::AdmissionError),
    #[error("sealed envelope verification failed")]
    Verification(#[from] sealed_envelope::VerifyError),
    #[error("sealed observed time outside acceptance window")]
    StaleEvent,
    #[error("sealed event identity conflict")]
    EventConflict,
    #[error("sealed device sequence conflict")]
    SequenceConflict,
    #[error("inbound storage budget exhausted")]
    BudgetExhausted,
    #[error("sealed upload database operation failed")]
    Database(#[from] tokio_postgres::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub struct UploadOutcome {
    pub event_id: Uuid,
    pub created: bool,
}

/// Site and deployment fence for the uploading caller. `instance_id` and
/// `connection_epoch` of the device-socket session have no HTTP analogue and
/// stay empty/zero; the API key, active line binding and site epoch gates in
/// `bindings` replace them.
pub struct UploadContext<'a> {
    pub site_id: &'a str,
    pub deployment_epoch: i64,
}

async fn bindings(
    tx: &Transaction<'_>,
    principal: &ApiPrincipal,
    uploader: &UploadContext<'_>,
    device: Uuid,
    line: Uuid,
) -> Result<i64, UploadError> {
    let row = tx.query_opt(
        "SELECT l.current_binding_generation FROM accounts a \
         JOIN api_keys k ON k.account_id=a.id \
         JOIN memberships m ON (m.account_id,m.user_id)=(k.account_id,k.created_by_user_id) \
         JOIN users u ON u.id=k.created_by_user_id \
         JOIN devices d ON d.account_id=a.id AND d.id=$3 \
         JOIN device_keys dk ON (dk.account_id,dk.device_id)=(d.account_id,d.id) \
         JOIN phone_lines l ON l.account_id=a.id AND l.id=$4 \
         JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)= \
             (a.id,l.id,d.id,l.current_binding_generation) \
         JOIN sites s ON s.site_id=$5 CROSS JOIN deployment_authority p \
         WHERE a.id=$1 AND a.disabled_at IS NULL AND k.id=$2 AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) \
           AND 'messages:send'=ANY(k.scopes) AND (k.bound_device_id IS NULL OR k.bound_device_id=d.id) \
           AND u.email_verified_at IS NOT NULL AND d.revoked_at IS NULL AND dk.revoked_at IS NULL \
           AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' \
           AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL AND b.activated_at IS NOT NULL \
           AND s.enabled AND NOT s.draining AND p.singleton AND p.epoch=$6 AND NOT pg_is_in_recovery() \
         FOR SHARE OF k,m,u,d,dk,l,b,s,p",
        &[&principal.tenant.account_id(),&principal.key_id,&device,&line,&uploader.site_id,&uploader.deployment_epoch],
    ).await?.ok_or(UploadError::Forbidden)?;
    Ok(row.get(0))
}

async fn check_age(tx: &Transaction<'_>, observed_ms: i64) -> Result<(), UploadError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if observed_ms <= 0
        || observed_ms < now.saturating_sub(MAX_AGE_MS)
        || observed_ms > now.saturating_add(MAX_FUTURE_MS)
    {
        return Err(UploadError::StaleEvent);
    }
    Ok(())
}

/// Own admission, verification, durable replay fences and commit as one unit,
/// mirroring the device-socket `ingest_candidate02`. All errors roll back. A
/// replay still requires current authority and a valid event age; it never
/// replaces saved bytes or rehydrates purged ciphertext.
pub async fn upload_inbound02(
    client: &mut Client,
    principal: &ApiPrincipal,
    _hasher: &TokenHasher,
    uploader: UploadContext<'_>,
    bytes: &[u8],
) -> Result<UploadOutcome, UploadError> {
    // Parse before obtaining database locks. These are untrusted selectors
    // until manifest authorization and exact signature verification pass.
    let claims = sealed_envelope::parse(bytes, Profile::Draft02Candidate)
        .map_err(|_| UploadError::InvalidClaims)?;
    if claims.kind != Kind::Inbound {
        return Err(UploadError::InvalidClaims);
    }
    let account = principal.tenant.account_id();
    let device = Uuid::from_slice(claims.device_id).map_err(|_| UploadError::InvalidClaims)?;
    let line = Uuid::from_slice(claims.line_id).map_err(|_| UploadError::InvalidClaims)?;
    let event_id = Uuid::from_slice(claims.event_id.ok_or(UploadError::InvalidClaims)?)
        .map_err(|_| UploadError::InvalidClaims)?;
    if event_id.is_nil() {
        return Err(UploadError::InvalidClaims);
    }
    let sequence = claims.local_sequence.ok_or(UploadError::InvalidClaims)? as i64;
    let observed_ms = claims.observed_ms as i64;
    principal
        .require(Scope::MessagesSend, Some(device))
        .map_err(|_| UploadError::Forbidden)?;
    if claims.account_id != account.as_bytes() {
        return Err(UploadError::Forbidden);
    }
    let recipients: Vec<ExpectedRecipient> = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap
                    .key_id
                    .try_into()
                    .map_err(|_| UploadError::InvalidClaims)?,
            })
        })
        .collect::<Result<_, UploadError>>()?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Inbound,
        account_id: *account.as_bytes(),
        device_id: *device.as_bytes(),
        line_id: *line.as_bytes(),
        message_id: *event_id.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| UploadError::InvalidClaims)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    let binding_generation = bindings(&tx, principal, &uploader, device, line).await?;
    let mut authority = inbound_upload::lock_current(&tx, account).await?;
    // Verify exactly once per envelope (#509): the authority context pins the
    // manifest, and the pre-commit recheck below re-validates freshness
    // without re-deriving signatures.
    let context = authority.context(&wanted).await?;
    let verified = sealed_envelope::verify(bytes, &context)?;
    check_age(&tx, observed_ms).await?;
    // Charge the shared account/device storage budget before the INSERT, in
    // this transaction, so a saturated budget never writes envelope bytes. An
    // already stored event is a free replay. The savepoint releases the
    // charge if a concurrent writer stores the same event first.
    let stored = tx
        .query_opt(
            "SELECT 1 FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&account, &event_id],
        )
        .await?
        .is_some();
    if !stored {
        tx.batch_execute("SAVEPOINT sealed_inbound_budget").await?;
        if !consume_storage_budget(&tx, account, device).await? {
            return Err(UploadError::BudgetExhausted);
        }
    }
    // All unique constraints remain race authorities, including a collision
    // with a different tenant's globally allocated event UUID. Never read its
    // content.
    let inserted = tx
        .query_opt(
            "INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation, \
             device_sequence,observed_at,received_at,part_count,envelope,unsigned_digest,envelope_profile) \
             VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7::bigint::double precision/1000), \
             to_timestamp($8::bigint::double precision/1000),NULL,$9,$10,2) \
             ON CONFLICT DO NOTHING RETURNING id",
            &[&event_id,&account,&device,&line,&binding_generation,&sequence,
              &observed_ms,&observed_ms,&bytes,&verified.unsigned_digest().as_slice()],
        ).await?;
    if inserted.is_none() {
        if !stored {
            tx.batch_execute("ROLLBACK TO SAVEPOINT sealed_inbound_budget")
                .await?;
        }
        let same_event = tx
            .query_opt(
                "SELECT device_id,line_id,device_sequence,unsigned_digest,envelope_profile \
             FROM sealed_inbound_events WHERE account_id=$1 AND id=$2 FOR SHARE",
                &[&account, &event_id],
            )
            .await?;
        if let Some(row) = same_event {
            if row.get::<_,Uuid>(0) != device || row.get::<_,Uuid>(1) != line
                || row.get::<_,i64>(2) != sequence || row.get::<_,Vec<u8>>(3).as_slice() != verified.unsigned_digest().as_slice()
                || row.get::<_,i16>(4) != 2
            {
                return Err(UploadError::EventConflict);
            }
        } else if tx.query_opt(
            "SELECT 1 FROM sealed_inbound_events WHERE account_id=$1 AND device_id=$2 AND device_sequence=$3",
            &[&account,&device,&sequence],
        ).await?.is_some() {
            return Err(UploadError::SequenceConflict);
        } else {
            return Err(UploadError::EventConflict);
        }
    }
    // INSERT/uniqueness checks and replay-row locks can wait after earlier
    // time checks. Recheck temporal authority and the line binding
    // immediately before committing either outcome.
    check_age(&tx, observed_ms).await?;
    authority.context(&wanted).await?;
    drop(authority);
    if bindings(&tx, principal, &uploader, device, line).await? != binding_generation {
        return Err(UploadError::Forbidden);
    }
    tx.commit().await?;
    Ok(UploadOutcome {
        event_id,
        created: inserted.is_some(),
    })
}

#[cfg(test)]
mod tests;
