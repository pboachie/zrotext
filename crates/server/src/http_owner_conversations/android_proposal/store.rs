// SPDX-License-Identifier: AGPL-3.0-only
//! Original-session immutable issuance records. Callers validate typed packets
//! and server-derived expectations under the same root-before-account locks.
use super::{
    super::{ConversationError, SessionPrincipal},
    authority::{Current, Selection},
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;
#[cfg(test)]
mod tests;

pub(super) struct Record {
    pub kind: i16,
    pub packet: Vec<u8>,
    pub expected: serde_json::Value,
    pub issued: i64,
    pub expires: i64,
    pub interval: Option<Uuid>,
}
fn reject() -> ConversationError {
    ConversationError::Forbidden
}
fn encode_record(r: &Record) -> Result<String, ConversationError> {
    if !(3..=5).contains(&r.kind)
        || r.packet.is_empty()
        || r.packet.len() > 20480
        || !r.expected.is_object()
        || r.issued <= 0
        || r.expires <= r.issued
        || r.expires
            .checked_sub(r.issued)
            .is_none_or(|ttl| ttl > 300000)
        || (r.kind == 5) != r.interval.is_some()
        || r.interval.is_some_and(|id| id.is_nil())
        || r.expected["scope"]["origin"]
            .as_str()
            .is_none_or(|origin| origin.is_empty() || origin.len() > 512)
    {
        return Err(ConversationError::Invalid);
    }
    let encoded = serde_json::to_string(&r.expected).map_err(|_| ConversationError::Invalid)?;
    if encoded.len() > 4096 {
        return Err(ConversationError::Invalid);
    }
    Ok(encoded)
}
fn live(r: &Record, now: i64) -> Result<(), ConversationError> {
    if now < r.issued || now >= r.expires {
        return Err(reject());
    }
    Ok(())
}
async fn now(tx: &Transaction<'_>) -> Result<i64, ConversationError> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0))
}
const SELECT_RECORD: &str = "SELECT user_id,session_id,proposal_sha256,proposal,expected_context::text,origin,root_fingerprint,checkpoint_version,checkpoint_digest,device_id,line_id,binding_generation,peer,paired_fingerprint,connection_epoch,deployment_epoch,site_id,instance_id,interval_id,issued_ms,expires_ms FROM owner_android_proposals WHERE account_id=$1 AND kind=$2 FOR UPDATE";

fn checked_record(
    row: &Row,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
    kind: i16,
    sha: &[u8; 32],
    origin: &str,
) -> Result<Record, ConversationError> {
    let bytes: Vec<u8> = row.get(3);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if row.get::<_, Uuid>(0) != p.user_id
        || row.get::<_, Uuid>(1) != p.session_id
        || row.get::<_, Vec<u8>>(2) != *sha
        || digest != *sha
        || row.get::<_, String>(5) != origin
        || row.get::<_, Vec<u8>>(6) != c.fingerprint
        || row.get::<_, i64>(7) != c.version
        || row.get::<_, Option<Vec<u8>>>(8) != c.digest.map(|v| v.to_vec())
        || row.get::<_, Uuid>(9) != s.device
        || row.get::<_, Uuid>(10) != s.line
        || row.get::<_, i64>(11) != s.generation
        || row.get::<_, String>(12) != s.peer
        || row.get::<_, Vec<u8>>(13) != c.paired_fingerprint
        || row.get::<_, i64>(14) != c.connection_epoch
        || row.get::<_, i64>(15) != c.deployment_epoch
        || row.get::<_, String>(16) != c.site
        || row.get::<_, String>(17) != c.instance
    {
        return Err(reject());
    }
    let record = Record {
        kind,
        packet: bytes,
        expected: serde_json::from_str(&row.get::<_, String>(4)).map_err(|_| reject())?,
        interval: row.get(18),
        issued: row.get(19),
        expires: row.get(20),
    };
    encode_record(&record).map_err(|_| reject())?;
    if record.expected["scope"]["origin"].as_str() != Some(origin) {
        return Err(reject());
    }
    Ok(record)
}
pub(super) async fn save(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
    r: &Record,
) -> Result<[u8; 32], ConversationError> {
    let encoded = encode_record(r)?;
    if c.version < 0
        || (r.kind == 3 && (c.version != 0 || c.digest.is_some()))
        || (r.kind != 3 && (c.version == 0 || c.digest.is_none()))
    {
        return Err(ConversationError::Invalid);
    }
    live(r, now(tx).await?)?;
    let a = p.tenant.account_id();
    let sha: [u8; 32] = Sha256::digest(&r.packet).into();
    // The already-held account lock serializes all pending slots and retries.
    // A replacement is possible only after the old deadline, never by UPDATE.
    tx.execute("DELETE FROM owner_android_proposals WHERE account_id=$1 AND kind=$2 AND expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[&a,&r.kind]).await?;
    let prior = tx.query_opt(SELECT_RECORD, &[&a, &r.kind]).await?;
    if let Some(prior) = prior {
        let old = checked_record(
            &prior,
            p,
            s,
            c,
            r.kind,
            &sha,
            r.expected["scope"]["origin"]
                .as_str()
                .ok_or(ConversationError::Invalid)?,
        )
        .map_err(|_| ConversationError::Conflict)?;
        if old.packet != r.packet
            || old.expected != r.expected
            || old.issued != r.issued
            || old.expires != r.expires
            || old.interval != r.interval
        {
            return Err(ConversationError::Conflict);
        }
    } else {
        tx.execute("INSERT INTO owner_android_proposals(account_id,kind,user_id,session_id,proposal_sha256,proposal,expected_context,origin,root_fingerprint,checkpoint_version,checkpoint_digest,device_id,line_id,binding_generation,peer,paired_fingerprint,connection_epoch,deployment_epoch,site_id,instance_id,interval_id,issued_ms,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)",&[&a,&r.kind,&p.user_id,&p.session_id,&sha.as_slice(),&r.packet,&encoded,&r.expected["scope"]["origin"].as_str().ok_or(ConversationError::Invalid)?,&c.fingerprint.as_slice(),&c.version,&c.digest.map(|v|v.to_vec()),&s.device,&s.line,&s.generation,&s.peer,&c.paired_fingerprint.as_slice(),&c.connection_epoch,&c.deployment_epoch,&c.site,&c.instance,&r.interval,&r.issued,&r.expires]).await?;
    }
    // The row lock or INSERT may have waited. The caller must still revalidate
    // owner/session/root/phone authority before commit and roll back any error.
    live(r, now(tx).await?)?;
    Ok(sha)
}
pub(super) async fn load(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
    kind: i16,
    sha: &[u8; 32],
    origin: &str,
) -> Result<Record, ConversationError> {
    if !(3..=5).contains(&kind) {
        return Err(reject());
    }
    let row = tx
        .query_opt(SELECT_RECORD, &[&p.tenant.account_id(), &kind])
        .await?
        .ok_or_else(reject)?;
    let record = checked_record(&row, p, s, c, kind, sha, origin)?;
    live(&record, now(tx).await?)?;
    Ok(record)
}
pub(super) async fn prune<C: tokio_postgres::GenericClient + Sync>(
    db: &C,
    limit: i64,
) -> Result<u64, tokio_postgres::Error> {
    db.execute("WITH due AS MATERIALIZED(SELECT account_id,kind FROM owner_android_proposals WHERE expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY expires_ms LIMIT $1 FOR UPDATE SKIP LOCKED) DELETE FROM owner_android_proposals p USING due d WHERE (p.account_id,p.kind)=(d.account_id,d.kind) AND p.expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[&limit.clamp(1,100)]).await
}
