// SPDX-License-Identifier: AGPL-3.0-only
//! Proof content has a short lifetime; immutable replay metadata has none.
use crate::http_owner_conversations::{
    ConversationError, SessionPrincipal, fresh_owner, lock_owner,
};
use serde::Serialize;
use std::time::SystemTime;
use tokio_postgres::{Client, GenericClient, types::Type};
use uuid::Uuid;

pub(crate) async fn installed<C: GenericClient + Sync>(
    db: &C,
) -> Result<bool, tokio_postgres::Error> {
    Ok(db
        .query_one(
            "SELECT to_regclass('conversation_confirmation_records') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

/// Pins the complete column contract in the same transaction before erasure.
/// An installed but incomplete table is an error, never the absent-table path.
pub(crate) async fn validate<C: GenericClient + Sync>(
    db: &C,
) -> Result<bool, tokio_postgres::Error> {
    let statement = db.prepare("SELECT account_id,message_id,interval_id,initiating_session_id,device_id,line_id,binding_generation,trust_generation,manifest_version,manifest_digest,signer_key_id,reader_key_id,body_digest,expires_at_ms,envelope_digest,confirmation_digest,signature_digest,confirmation,signature,created_at FROM conversation_confirmation_records LIMIT 0").await?;
    let expected = [
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::TIMESTAMPTZ,
    ];
    Ok(statement
        .columns()
        .iter()
        .map(|column| column.type_())
        .eq(expected.iter()))
}
/// No schema is created here. This accommodates the pre-allocation schema;
/// queue admission itself always requires the complete allocated contract.
pub(crate) async fn redact(client: &Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    assert!((1..=1000).contains(&limit));
    if !installed(client).await? {
        return Ok(0);
    }
    client.execute("WITH due AS (SELECT c.account_id,c.message_id FROM conversation_confirmation_records c JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id) JOIN sessions s ON (s.account_id,s.id)=(c.account_id,c.initiating_session_id) JOIN users u ON u.id=s.user_id JOIN messages m ON (m.account_id,m.id)=(c.account_id,c.message_id) WHERE c.confirmation IS NOT NULL AND (c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000) OR i.closed_at IS NOT NULL OR i.phase<>'active' OR s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() OR u.email_verified_at IS NULL OR m.transport_payload IS NULL OR NOT EXISTS (SELECT 1 FROM memberships x WHERE x.account_id=c.account_id AND x.user_id=s.user_id AND x.role='owner' AND x.revoked_at IS NULL)) ORDER BY c.expires_at_ms,c.account_id,c.message_id FOR UPDATE OF c SKIP LOCKED LIMIT $1) UPDATE conversation_confirmation_records c SET confirmation=NULL,signature=NULL FROM due WHERE (c.account_id,c.message_id)=(due.account_id,due.message_id)", &[&limit]).await
}

#[derive(Debug, Serialize)]
pub(crate) struct ProofMetadata {
    pub message_id: Uuid,
    pub interval_id: Uuid,
    pub initiating_session_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    pub proof_retained: bool,
}
#[derive(Debug, Serialize)]
pub(crate) struct ProofInventory {
    pub records: Vec<ProofMetadata>,
    pub truncated: bool,
    pub next_cursor: Option<Uuid>,
}
/// Metadata only: no peer, original confirmation, signature or envelope bytes.
pub(crate) async fn inventory(
    client: &mut Client,
    owner: &SessionPrincipal,
    before: Option<Uuid>,
) -> Result<ProofInventory, ConversationError> {
    const LIMIT: usize = 100;
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx).await? {
        if before.is_some() {
            return Err(ConversationError::NotFound);
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(ProofInventory {
            records: vec![],
            truncated: false,
            next_cursor: None,
        });
    }
    let account = owner.tenant.account_id();
    let at: Option<SystemTime> = match before {
        Some(id) => Some(tx.query_opt("SELECT created_at FROM conversation_confirmation_records WHERE account_id=$1 AND message_id=$2", &[&account,&id]).await?.ok_or(ConversationError::NotFound)?.get(0)),
        None => None,
    };
    let rows = tx.query("SELECT message_id,interval_id,initiating_session_id,device_id,line_id,binding_generation,trust_generation,manifest_version,expires_at_ms,(extract(epoch FROM created_at)*1000)::bigint,confirmation IS NOT NULL FROM conversation_confirmation_records WHERE account_id=$1 AND ($2::timestamptz IS NULL OR (created_at,message_id)<($2,$3::uuid)) ORDER BY created_at DESC,message_id DESC LIMIT $4 FOR SHARE", &[&account,&at,&before,&(LIMIT as i64+1)]).await?;
    let truncated = rows.len() > LIMIT;
    let records: Vec<_> = rows
        .iter()
        .take(LIMIT)
        .map(|r| ProofMetadata {
            message_id: r.get(0),
            interval_id: r.get(1),
            initiating_session_id: r.get(2),
            device_id: r.get(3),
            line_id: r.get(4),
            binding_generation: r.get(5),
            trust_generation: r.get(6),
            manifest_version: r.get(7),
            expires_at_ms: r.get(8),
            created_at_ms: r.get(9),
            proof_retained: r.get(10),
        })
        .collect();
    let next_cursor = if truncated {
        records.last().map(|r| r.message_id)
    } else {
        None
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(ProofInventory {
        records,
        truncated,
        next_cursor,
    })
}
