// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant one-use execution admission for an already confirmed conversation.
//! No generic sealed claim, alpha conversion, key creation or radio operation.
use super::*;
use crate::http_owner_conversations::send;
use crate::sealed_envelope::{self, ExpectedRecipient, Kind, Profile};
use crate::sealed_manifest::EnvelopeAuthority;
use crate::sealed_manifest_store::outbound::lock_current;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio_postgres::Row;

const MAX_JSON: usize = 2048;
const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;
pub(crate) mod lifecycle;
pub(crate) mod permission;

fn effect_error(error: tokio_postgres::Error) -> ConversationError {
    if error.as_db_error().is_some_and(|db| {
        matches!(
            db.code(),
            &tokio_postgres::error::SqlState::CHECK_VIOLATION
                | &tokio_postgres::error::SqlState::UNIQUE_VIOLATION
        )
    }) {
        ConversationError::Forbidden
    } else {
        ConversationError::Database(error)
    }
}

struct Record {
    device: Uuid,
    attempt: Uuid,
    generation: i64,
    phone_session: Uuid,
    origin: Vec<u8>,
    site: String,
    instance: String,
    connection_epoch: i64,
    deployment_epoch: i64,
    reader: Vec<u8>,
    envelope: Vec<u8>,
    unsigned: Vec<u8>,
    expires: i64,
    segments: i16,
}
impl Record {
    fn saved(row: Row) -> Self {
        Self {
            device: row.get(0),
            attempt: row.get(1),
            generation: row.get(2),
            phone_session: row.get(3),
            origin: row.get(4),
            site: row.get(5),
            instance: row.get(6),
            connection_epoch: row.get(7),
            deployment_epoch: row.get(8),
            reader: row.get(9),
            envelope: row.get(10),
            unsigned: row.get(11),
            expires: row.get(12),
            segments: row.get(13),
        }
    }
}

pub(super) async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    challenge: Uuid,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let interval = Uuid::from_slice(&bytes[166..182]).map_err(|_| ConversationError::Invalid)?;
    let tx = client.transaction().await?;
    if !lifecycle::validate(&tx).await? || !send::queue::lifecycle::validate(&tx).await? {
        return Err(ConversationError::Forbidden);
    }
    let mut authority = lock_current(&tx, authenticated.device.account_id).await?;
    // Inherit the original queue reservation, never reserve or spend again.
    // Existing billing-customer/account ordering also fences new bindings.
    let _account =
        zrotext_delivery_store::sealed::lock_account(&tx, authenticated.device.account_id, false)
            .await
            .map_err(|_| ConversationError::Forbidden)?;
    live(&tx, authenticated.device).await?;
    let selected = activation::load(&tx, authenticated.device.account_id, interval)
        .await
        .map_err(|e| match e {
            ConversationError::Database(_) => e,
            _ => ConversationError::Forbidden,
        })?;
    let expected = scope(&selected.statement)?;
    let end = 118 + expected.len();
    if selected.phase != "active"
        || selected.statement.device != authenticated.device.device_id
        || bytes.get(118..end) != Some(expected.as_slice())
        || bytes.len() != end + 64
    {
        return Err(ConversationError::Forbidden);
    }
    let message =
        Uuid::from_slice(&bytes[end..end + 16]).map_err(|_| ConversationError::Invalid)?;
    let attempt =
        Uuid::from_slice(&bytes[end + 16..end + 32]).map_err(|_| ConversationError::Invalid)?;
    if message.is_nil() || attempt.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let proof = tx.query_opt("SELECT confirmation,signature,initiating_session_id FROM conversation_confirmation_records \
        WHERE account_id=$1 AND message_id=$2 AND device_id=$3 AND interval_id=$4 FOR UPDATE",
        &[&authenticated.device.account_id,&message,&authenticated.device.device_id,&interval]).await?
        .ok_or(ConversationError::Forbidden)?;
    let confirmation: Option<Vec<u8>> = proof.get(0);
    let signature: Option<Vec<u8>> = proof.get(1);
    let origin: Uuid = proof.get(2);
    let confirmation = confirmation.ok_or(ConversationError::Forbidden)?;
    let signature = signature.ok_or(ConversationError::Forbidden)?;
    let job = tx.query_opt("SELECT j.generation,j.lease_owner,(j.lease_until IS NULL OR j.lease_until<clock_timestamp()),j.grant_issued_at,j.finished_at, \
        j.next_attempt_at<=clock_timestamp(),m.state,m.transport_payload,m.request_digest \
        FROM dispatch_jobs j JOIN messages m ON (m.account_id,m.id)=(j.account_id,j.message_id) \
        WHERE (j.account_id,j.message_id,j.device_id)=($1,$2,$3) AND m.transport_mode='sealed_candidate02' FOR UPDATE OF j,m",
        &[&authenticated.device.account_id,&message,&authenticated.device.device_id]).await?
        .ok_or(ConversationError::Forbidden)?;
    let envelope: Option<Vec<u8>> = job.get(7);
    let envelope = envelope.ok_or(ConversationError::Forbidden)?;
    let full: [u8; 32] = Sha256::digest(&envelope).into();
    if bytes[end + 32..] != full {
        return Err(ConversationError::Forbidden);
    }
    let c = send::authorize_delivery(
        &tx,
        authenticated.device,
        origin,
        &envelope,
        &confirmation,
        &signature,
    )
    .await?;
    if c.message != message || c.interval != interval {
        return Err(ConversationError::Forbidden);
    }
    let parsed = sealed_envelope::parse(&envelope, Profile::Draft02Candidate)
        .map_err(|_| ConversationError::Forbidden)?;
    let unsigned: [u8; 32] = Sha256::digest(parsed.unsigned).into();
    let reader: [u8; 32] = parsed
        .wraps
        .first()
        .filter(|w| w.role == 1)
        .ok_or(ConversationError::Forbidden)?
        .key_id
        .try_into()
        .map_err(|_| ConversationError::Forbidden)?;
    if job.get::<_, Vec<u8>>(8) != unsigned {
        return Err(ConversationError::Forbidden);
    }
    let readers = [
        ExpectedRecipient {
            role: 1,
            key_id: reader,
        },
        ExpectedRecipient {
            role: 2,
            key_id: c.reader,
        },
    ];
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *c.account.as_bytes(),
        device_id: *c.device.as_bytes(),
        line_id: *c.line.as_bytes(),
        message_id: *message.as_bytes(),
        signer_key_id: c.signer,
        peer: c.peer.as_bytes(),
        recipients: &readers,
    };
    let inbound_readers = activation::readers(&selected.statement);
    let inbound = activation::wanted(&selected.statement, message, &inbound_readers);
    let phone_deadline: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM lease_until)*1000)::bigint FROM device_sessions \
        WHERE account_id=$1 AND device_id=$2",
            &[&c.account, &c.device],
        )
        .await?
        .get(0);
    let now = activation::now(&tx).await?;
    let deadline = c
        .expires_ms
        .min(phone_deadline)
        .min(activation::origin(&tx, &selected.statement).await?)
        .min(authority.outbound_admission_deadline(&wanted).await?)
        .min(authority.admission_deadline(&inbound).await? as i64)
        .min(
            now.checked_add(30_000)
                .ok_or(ConversationError::Forbidden)?,
        );
    if deadline <= now {
        return Err(ConversationError::Forbidden);
    }
    let saved = tx.query_opt("SELECT device_id,attempt_id,generation,phone_session,origin_hash,site_id,instance_id, \
        session_epoch,deployment_epoch,reader_key_id,envelope_digest,unsigned_digest,expires_at_ms,segment_count \
        FROM conversation_execution_records WHERE account_id=$1 AND message_id=$2 FOR UPDATE", &[&c.account,&message]).await?;
    let record = if let Some(saved) = saved {
        let record = Record::saved(saved);
        if record.generation != 1
            || record.device != c.device
            || record.attempt != attempt
            || record.phone_session != authenticated.phone_session
            || record.origin != authenticated.origin_hash
            || record.site != authenticated.device.site_id
            || record.instance != authenticated.device.instance_id
            || record.connection_epoch != authenticated.device.connection_epoch
            || record.deployment_epoch != authenticated.device.deployment_epoch
            || record.reader != reader
            || record.envelope != full
            || record.unsigned != unsigned
            || record.expires > deadline
            || record.expires <= now
            || job.get::<_, String>(6) != "claimed"
            || job.get::<_, i64>(0) != record.generation
        {
            return Err(ConversationError::Forbidden);
        }
        if tx.query_opt("SELECT 1 FROM conversation_execution_records r JOIN message_attempts a ON a.id=r.attempt_id \
            JOIN dispatch_fences f ON f.attempt_id=a.id JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(r.account_id,r.message_id) \
            WHERE r.account_id=$1 AND r.message_id=$2 AND a.status='granted' AND f.outcome='granted' \
            AND j.grant_issued_at IS NOT NULL AND j.finished_at IS NULL AND j.lease_owner='conversation:'||r.phone_session::text \
            AND j.lease_until=to_timestamp(r.expires_at_ms::double precision/1000) \
            AND f.grant_expires_at=j.lease_until AND conversation_execution_initial_valid(r)", &[&c.account,&message]).await?.is_none() {
            return Err(ConversationError::Forbidden);
        }
        record
    } else {
        if job.get::<_,i64>(0)!=0 || job.get::<_,String>(6)!="queued" || !job.get::<_,bool>(5)
            || job.get::<_,Option<std::time::SystemTime>>(3).is_some()
            || job.get::<_,Option<std::time::SystemTime>>(4).is_some()
            || !job.get::<_,bool>(2)
            || tx.query_opt("SELECT 1 FROM message_attempts WHERE account_id=$1 AND message_id=$2",&[&c.account,&message]).await?.is_some()
            || tx.query_opt("SELECT 1 FROM dispatch_fences WHERE device_id=$1 AND outcome IN ('granted','submitting','unknown')",&[&c.device]).await?.is_some() {
            return Err(ConversationError::Forbidden);
        }
        let record = Record {
            device: c.device,
            attempt,
            generation: 1,
            phone_session: authenticated.phone_session,
            origin: authenticated.origin_hash.to_vec(),
            site: authenticated.device.site_id.into(),
            instance: authenticated.device.instance_id.into(),
            connection_epoch: authenticated.device.connection_epoch,
            deployment_epoch: authenticated.device.deployment_epoch,
            reader: reader.to_vec(),
            envelope: full.to_vec(),
            unsigned: unsigned.to_vec(),
            expires: deadline,
            segments: 6,
        };
        tx.execute("INSERT INTO conversation_execution_records(account_id,message_id,device_id,attempt_id,generation,phone_session, \
            origin_hash,site_id,instance_id,session_epoch,deployment_epoch,reader_key_id,envelope_digest,unsigned_digest,expires_at_ms,segment_count) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[&c.account,&message,&record.device,&attempt,&record.generation,&record.phone_session,&record.origin,&record.site,&record.instance,
            &record.connection_epoch,&record.deployment_epoch,&record.reader,&record.envelope,&record.unsigned,&record.expires,&record.segments]).await.map_err(effect_error)?;
        tx.execute("UPDATE dispatch_jobs SET generation=$3,lease_owner=$4,lease_until=to_timestamp($5::bigint::double precision/1000), \
            grant_issued_at=clock_timestamp() WHERE account_id=$1 AND message_id=$2",&[&c.account,&message,&record.generation,
            &format!("conversation:{}",record.phone_session),&record.expires]).await.map_err(effect_error)?;
        tx.execute("UPDATE messages SET state='claimed',state_version=state_version+1,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
            &[&c.account,&message]).await?;
        tx.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
            VALUES($1,$2,$3,$4,$5,$6,$7,'granted')",&[&attempt,&c.account,&message,&c.device,&record.generation,
            &record.connection_epoch,&record.deployment_epoch]).await.map_err(effect_error)?;
        tx.execute("INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,recipient_digest, \
            grant_expires_at,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::bigint::double precision/1000),'granted')",
            &[&message,&c.account,&c.device,&attempt,&record.generation,&record.connection_epoch,&record.deployment_epoch,
            &Sha256::digest(c.peer.as_bytes()).to_vec(),&record.expires]).await.map_err(effect_error)?;
        record
    };
    if [
        c.generation,
        record.generation,
        record.connection_epoch,
        record.deployment_epoch,
        record.expires,
    ]
    .iter()
    .any(|v| !(1..=MAX_EXACT_INTEGER).contains(v))
        || !(1..=6).contains(&record.segments)
    {
        return Err(ConversationError::Forbidden);
    }
    // Existing strict grant fields, authenticated by the same negotiated header.
    let json=serde_json::to_vec(&serde_json::json!({"v":1,"type":"sealed_execution_grant","grant_version":1,
        "account_id":c.account,"device_id":c.device,"line_id":c.line,"message_id":message,"attempt_id":attempt,
        "connection_epoch":record.connection_epoch,"deployment_epoch":record.deployment_epoch,"binding_generation":c.generation,
        "attempt_generation":record.generation,"reader_role":1,"reader_key_id":URL_SAFE_NO_PAD.encode(&record.reader),
        "envelope_sha256":URL_SAFE_NO_PAD.encode(&record.envelope),"unsigned_sha256":URL_SAFE_NO_PAD.encode(&record.unsigned),
        "expires_at_ms":record.expires,"segment_count":record.segments})).map_err(|_|ConversationError::Invalid)?;
    if json.len() > MAX_JSON {
        return Err(ConversationError::Invalid);
    }
    let checked = send::authorize_delivery(
        &tx,
        authenticated.device,
        origin,
        &envelope,
        &confirmation,
        &signature,
    )
    .await?;
    if checked != c || activation::now(&tx).await? >= record.expires {
        return Err(ConversationError::Forbidden);
    }
    live(&tx, authenticated.device).await?;
    if !tx
        .query_one(
            "SELECT conversation_execution_initial_valid(r) FROM conversation_execution_records r \
        WHERE account_id=$1 AND message_id=$2",
            &[&c.account, &message],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err(ConversationError::Forbidden);
    }
    drop(authority);

    tx.commit().await.map_err(effect_error)?;
    let mut reply = header(authenticated, 19, challenge)?;
    reply.extend_from_slice(&(json.len() as u16).to_be_bytes());
    reply.extend(json);
    Ok(reply)
}
