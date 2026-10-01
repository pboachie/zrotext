// SPDX-License-Identifier: AGPL-3.0-only
//! Optional sealed grants. Admission, execution authority and radio evidence
//! remain distinct; no unknown attempt is automatically granted again.
pub mod http;
#[cfg(test)]
mod tests;
pub mod wire;

use crate::{
    alpha_policy::AlphaPolicy,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::outbound,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;
use wire::{Fetch, GrantFrame, Ready};
use zrotext_delivery_store::{
    Claim, GrantTransport, SessionRecord, StoreError, grant_in_transaction,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sealed execution unavailable")]
    Refused,
    #[error("sealed execution storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("sealed execution fence rejected")]
    Store(#[from] StoreError),
}

struct Queued {
    message: Uuid,
    line: Uuid,
    binding: i64,
    manifest_generation: i64,
    manifest_version: i64,
    manifest_digest: Vec<u8>,
    unsigned_digest: Vec<u8>,
    bytes: Vec<u8>,
    segment_limit: u8,
    expires_ms: i64,
}

/// All identity comes from the authenticated socket and exact active binding.
/// Locks remain held across both final clock checks and the caller's commit.
async fn live(
    tx: &Transaction<'_>,
    session: &SessionRecord,
    line: Uuid,
    binding: i64,
) -> Result<Vec<u8>, Error> {
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&session.account_id],
    )
    .await?
    .ok_or(Error::Refused)?;
    let row = tx.query_opt(
        "SELECT k.signing_key_sec1 FROM device_sessions ds \
         JOIN devices d ON (d.account_id,d.id)=(ds.account_id,ds.device_id) \
         JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
         JOIN sites s ON s.site_id=ds.site_id JOIN deployment_authority p ON p.singleton \
         JOIN phone_lines l ON l.account_id=ds.account_id AND l.id=$7 \
         JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)= \
            (ds.account_id,l.id,ds.device_id,l.current_binding_generation) \
         WHERE ds.account_id=$1 AND ds.device_id=$2 AND ds.connection_epoch=$3 \
         AND ds.deployment_epoch=$4 AND ds.site_id=$5 AND ds.instance_id=$6 \
         AND ds.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
         AND s.enabled AND NOT s.draining AND p.epoch=$4 AND p.dispatch_enabled AND NOT pg_is_in_recovery() \
         AND l.state='active' AND l.approved_at IS NOT NULL AND l.current_binding_generation=$8 \
         AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL \
         AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL \
         FOR SHARE OF ds,d,k,s,p,l,b",
        &[&session.account_id,&session.device_id,&session.epoch,&session.deployment_epoch,
          &session.site_id,&session.instance_id,&line,&binding],
    ).await?.ok_or(Error::Refused)?;
    Ok(row.get(0))
}

async fn not_suppressed(tx: &Transaction<'_>, account: Uuid, peer: &str) -> Result<(), Error> {
    if tx.query_opt("SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active \
        UNION ALL SELECT 1 FROM owner_recipient_holds WHERE account_id=$1 AND recipient_e164=$2 \
        AND released_at IS NULL LIMIT 1", &[&account,&peer]).await?.is_some() {
        return Err(Error::Refused);
    }
    Ok(())
}

async fn now(tx: &Transaction<'_>) -> Result<i64, Error> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0))
}

fn envelope<'a>(
    queued: &'a Queued,
    session: &SessionRecord,
    reader: &[u8; 32],
) -> Result<(sealed_envelope::Envelope<'a>, Vec<ExpectedRecipient>), Error> {
    let claims = sealed_envelope::parse(&queued.bytes, Profile::Draft02Candidate)
        .map_err(|_| Error::Refused)?;
    if claims.kind != Kind::Outbound
        || claims.account_id != session.account_id.as_bytes()
        || claims.device_id != session.device_id.as_bytes()
        || claims.line_id != queued.line.as_bytes()
        || claims.message_id != queued.message.as_bytes()
        || claims.keyset_version != queued.manifest_version as u64
        || claims.manifest_digest != queued.manifest_digest
        || claims.expires_ms != Some(queued.expires_ms as u64)
        || !claims
            .wraps
            .iter()
            .any(|wrap| wrap.role == 1 && wrap.key_id == reader)
    {
        return Err(Error::Refused);
    }
    let recipients = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap.key_id.try_into().map_err(|_| Error::Refused)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((claims, recipients))
}

/// A negotiated, allowlisted socket claims exactly one still-ungranted job.
/// A failed send leaves the existing one-use fence unresolved, never reissued.
pub async fn grant(
    client: &mut Client,
    session: &SessionRecord,
    ready: &Ready,
    policy: &AlphaPolicy,
) -> Result<Option<GrantFrame>, Error> {
    let reader = ready.validate(session.epoch).map_err(|_| Error::Refused)?;
    if !policy.allows_account(session.account_id) {
        return Ok(None);
    }
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    // Matches sealed admission/lifecycle ordering: authority, account, job, message.
    let mut authority = outbound::lock_current(&tx, session.account_id)
        .await
        .map_err(|_| Error::Refused)?;
    live(&tx, session, ready.line_id, ready.binding_generation).await?;
    let picked = tx.query_opt("SELECT j.message_id FROM dispatch_jobs j JOIN messages m \
        ON (m.account_id,m.id)=(j.account_id,j.message_id) WHERE j.account_id=$1 AND j.device_id=$2 \
        AND j.finished_at IS NULL AND j.grant_issued_at IS NULL AND j.next_attempt_at<=clock_timestamp() \
        AND (j.lease_until IS NULL OR j.lease_until<clock_timestamp()) \
        AND m.transport_mode='sealed_candidate02' AND m.state IN ('queued','claimed') \
        AND m.expires_at>clock_timestamp() AND m.sealed_line_id=$3 AND m.sealed_binding_generation=$4 \
        AND m.sealed_segment_limit BETWEEN 1 AND 6 AND m.transport_payload IS NOT NULL \
        ORDER BY j.next_attempt_at,j.message_id FOR UPDATE OF j SKIP LOCKED LIMIT 1",
        &[&session.account_id,&session.device_id,&ready.line_id,&ready.binding_generation]).await?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let message: Uuid = picked.get(0);
    let row=tx.query_one("SELECT sealed_line_id,sealed_binding_generation,sealed_manifest_generation, \
        sealed_manifest_version,sealed_manifest_digest,request_digest,transport_payload,sealed_segment_limit, \
        floor(extract(epoch FROM expires_at)*1000)::bigint FROM messages \
        WHERE account_id=$1 AND id=$2 FOR UPDATE", &[&session.account_id,&message]).await?;
    let queued = Queued {
        message,
        line: row.get(0),
        binding: row.get(1),
        manifest_generation: row.get(2),
        manifest_version: row.get(3),
        manifest_digest: row.get(4),
        unsigned_digest: row.get(5),
        bytes: row.get(6),
        segment_limit: u8::try_from(row.get::<_, i16>(7)).map_err(|_| Error::Refused)?,
        expires_ms: row.get(8),
    };
    let (claims, recipients) = envelope(&queued, session, &reader)?;
    let peer = std::str::from_utf8(claims.peer).map_err(|_| Error::Refused)?;
    if !policy.allows(session.account_id, peer) {
        return Ok(None);
    }
    not_suppressed(&tx, session.account_id, peer).await?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *session.account_id.as_bytes(),
        device_id: *session.device_id.as_bytes(),
        line_id: *queued.line.as_bytes(),
        message_id: *message.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| Error::Refused)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    if authority.generation() != queued.manifest_generation {
        return Err(Error::Refused);
    }
    let context = authority
        .context(&wanted)
        .await
        .map_err(|_| Error::Refused)?;
    let verified = sealed_envelope::verify(&queued.bytes, &context).map_err(|_| Error::Refused)?;
    if verified.unsigned_digest().as_slice() != queued.unsigned_digest {
        return Err(Error::Refused);
    }
    let deadline = queued.expires_ms.min(
        authority
            .outbound_deadline(&wanted)
            .await
            .map_err(|_| Error::Refused)?,
    );
    if now(&tx).await? >= deadline {
        return Err(Error::Refused);
    }
    let worker = format!(
        "{}:{}:{}",
        session.instance_id, session.device_id, session.epoch
    );
    let generation:i64=tx.query_one("UPDATE dispatch_jobs SET lease_owner=$3,lease_until=clock_timestamp()+interval '30 seconds', \
        generation=generation+1 WHERE account_id=$1 AND message_id=$2 RETURNING generation",
        &[&session.account_id,&message,&worker]).await?.get(0);
    let attempt = Uuid::new_v4();
    let envelope_digest: [u8; 32] = Sha256::digest(&queued.bytes).into();
    tx.execute("INSERT INTO sealed_grant_authorizations(account_id,message_id,attempt_id,device_id,line_id, \
        binding_generation,attempt_generation,connection_epoch,deployment_epoch,site_id,instance_id, \
        manifest_generation,manifest_version,manifest_digest,reader_key_id,envelope_digest,unsigned_digest, \
        segment_limit,authority_expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        &[&session.account_id,&message,&attempt,&session.device_id,&queued.line,&queued.binding,&generation,
          &session.epoch,&session.deployment_epoch,&session.site_id,&session.instance_id,&queued.manifest_generation,
          &queued.manifest_version,&queued.manifest_digest,&reader.as_slice(),&envelope_digest.as_slice(),
          &queued.unsigned_digest,&i16::from(queued.segment_limit),&deadline]).await?;
    tx.execute("UPDATE messages SET state='claimed',state_version=state_version+1,updated_at=clock_timestamp() \
        WHERE account_id=$1 AND id=$2", &[&session.account_id,&message]).await?;
    let claim = Claim {
        account_id: session.account_id,
        message_id: message,
        device_id: session.device_id,
        generation,
        worker_id: worker,
    };
    let granted = grant_in_transaction(
        &tx,
        &claim,
        session,
        attempt,
        GrantTransport::SealedCandidate02,
        Some(deadline),
    )
    .await?;
    live(&tx, session, queued.line, queued.binding).await?;
    authority
        .context(&wanted)
        .await
        .map_err(|_| Error::Refused)?;
    if now(&tx).await? >= granted.expires_at_ms {
        return Err(Error::Refused);
    }
    let frame = GrantFrame {
        v: 1,
        kind: "sealed_execution_grant".into(),
        grant_version: 1,
        account_id: session.account_id,
        device_id: session.device_id,
        line_id: queued.line,
        message_id: message,
        attempt_id: attempt,
        connection_epoch: session.epoch,
        deployment_epoch: session.deployment_epoch,
        binding_generation: queued.binding,
        attempt_generation: generation,
        reader_role: 1,
        reader_key_id: URL_SAFE_NO_PAD.encode(reader),
        envelope_sha256: URL_SAFE_NO_PAD.encode(envelope_digest),
        unsigned_sha256: URL_SAFE_NO_PAD.encode(&queued.unsigned_digest),
        expires_at_ms: granted.expires_at_ms,
        segment_count: queued.segment_limit,
    };
    drop(authority);
    tx.commit().await?;
    Ok(Some(frame))
}

/// Repeatable encrypted retrieval is bound to the current one-use attempt.
/// Failure is intentionally indistinguishable from absence at the HTTP edge.
pub async fn fetch(
    client: &mut Client,
    request: &Fetch,
    site: &str,
    epoch: i64,
    policy: &AlphaPolicy,
) -> Result<Vec<u8>, Error> {
    let transcript = wire::fetch_transcript(&request.grant).map_err(|_| Error::Refused)?;
    let grant = &request.grant;
    if grant.deployment_epoch != epoch
        || !policy.allows_account(grant.account_id)
        || request.signature_der.len() > 107
    {
        return Err(Error::Refused);
    }
    let key = client
        .query_opt(
            "SELECT k.signing_key_sec1 FROM device_keys k JOIN devices d \
        ON (d.account_id,d.id)=(k.account_id,k.device_id) JOIN accounts a ON a.id=k.account_id \
        WHERE k.account_id=$1 AND k.device_id=$2 AND k.revoked_at IS NULL AND d.revoked_at IS NULL \
        AND a.disabled_at IS NULL",
            &[&grant.account_id, &grant.device_id],
        )
        .await?
        .ok_or(Error::Refused)?;
    let public =
        VerifyingKey::from_sec1_bytes(&key.get::<_, Vec<u8>>(0)).map_err(|_| Error::Refused)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&request.signature_der)
        .map_err(|_| Error::Refused)?;
    if URL_SAFE_NO_PAD.encode(&signature) != request.signature_der {
        return Err(Error::Refused);
    }
    let signature = Signature::from_der(&signature).map_err(|_| Error::Refused)?;
    public
        .verify(&transcript, &signature)
        .map_err(|_| Error::Refused)?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    let mut authority = outbound::lock_current(&tx, grant.account_id)
        .await
        .map_err(|_| Error::Refused)?;
    let owner = tx
        .query_opt(
            "SELECT site_id,instance_id FROM sealed_grant_authorizations \
        WHERE account_id=$1 AND device_id=$2 AND attempt_id=$3",
            &[&grant.account_id, &grant.device_id, &grant.attempt_id],
        )
        .await?
        .ok_or(Error::Refused)?;
    let session = SessionRecord {
        account_id: grant.account_id,
        device_id: grant.device_id,
        site_id: owner.get(0),
        instance_id: owner.get(1),
        epoch: grant.connection_epoch,
        deployment_epoch: grant.deployment_epoch,
    };
    live(&tx, &session, grant.line_id, grant.binding_generation).await?;
    let row=tx.query_opt("SELECT g.site_id,g.instance_id,g.manifest_generation,g.manifest_version,g.manifest_digest, \
        g.unsigned_digest,m.transport_payload,g.segment_limit,floor(extract(epoch FROM m.expires_at)*1000)::bigint \
        FROM sealed_grant_authorizations g JOIN dispatch_fences f ON (f.account_id,f.message_id,f.attempt_id)= \
        (g.account_id,g.message_id,g.attempt_id) JOIN messages m ON (m.account_id,m.id)=(g.account_id,g.message_id) \
        WHERE g.account_id=$1 AND g.device_id=$2 AND g.line_id=$3 AND g.message_id=$4 AND g.attempt_id=$5 \
        AND g.connection_epoch=$6 AND g.deployment_epoch=$7 AND g.binding_generation=$8 AND g.attempt_generation=$9 \
        AND g.reader_key_id=$10 AND g.envelope_digest=$11 AND g.unsigned_digest=$12 AND g.segment_limit=$13 \
        AND g.site_id=$14 AND g.authority_expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        AND f.generation=$9 AND f.session_epoch=$6 AND f.deployment_epoch=$7 AND f.outcome='granted' \
        AND f.grant_expires_at>clock_timestamp() AND (extract(epoch FROM f.grant_expires_at)*1000)::bigint=$15 \
        AND m.state='claimed' AND m.transport_mode='sealed_candidate02' AND m.expires_at>clock_timestamp() \
        AND m.transport_payload IS NOT NULL FOR SHARE OF m,f", &[&grant.account_id,&grant.device_id,&grant.line_id,&grant.message_id,
          &grant.attempt_id,&grant.connection_epoch,&grant.deployment_epoch,&grant.binding_generation,&grant.attempt_generation,
          &wire::digest(&grant.reader_key_id).map_err(|_|Error::Refused)?.as_slice(),
          &wire::digest(&grant.envelope_sha256).map_err(|_|Error::Refused)?.as_slice(),
          &wire::digest(&grant.unsigned_sha256).map_err(|_|Error::Refused)?.as_slice(),&i16::from(grant.segment_count),
          &site,&grant.expires_at_ms]).await?.ok_or(Error::Refused)?;
    let queued = Queued {
        message: grant.message_id,
        line: grant.line_id,
        binding: grant.binding_generation,
        manifest_generation: row.get(2),
        manifest_version: row.get(3),
        manifest_digest: row.get(4),
        unsigned_digest: row.get(5),
        bytes: row.get(6),
        segment_limit: grant.segment_count,
        expires_ms: row.get(8),
    };
    if queued.bytes.len() > 34213
        || Sha256::digest(&queued.bytes).as_slice()
            != wire::digest(&grant.envelope_sha256).map_err(|_| Error::Refused)?
        || authority.generation() != queued.manifest_generation
    {
        return Err(Error::Refused);
    }
    let reader = wire::digest(&grant.reader_key_id).map_err(|_| Error::Refused)?;
    let (claims, recipients) = envelope(&queued, &session, &reader)?;
    let peer = std::str::from_utf8(claims.peer).map_err(|_| Error::Refused)?;
    if !policy.allows(grant.account_id, peer) {
        return Err(Error::Refused);
    }
    not_suppressed(&tx, grant.account_id, peer).await?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *grant.account_id.as_bytes(),
        device_id: *grant.device_id.as_bytes(),
        line_id: *grant.line_id.as_bytes(),
        message_id: *grant.message_id.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| Error::Refused)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    let context = authority
        .context(&wanted)
        .await
        .map_err(|_| Error::Refused)?;
    let verified = sealed_envelope::verify(&queued.bytes, &context).map_err(|_| Error::Refused)?;
    if verified.unsigned_digest().as_slice() != queued.unsigned_digest {
        return Err(Error::Refused);
    }
    live(&tx, &session, grant.line_id, grant.binding_generation).await?;
    if now(&tx).await? >= grant.expires_at_ms {
        return Err(Error::Refused);
    }
    drop(authority);
    tx.commit().await?;
    Ok(queued.bytes)
}
