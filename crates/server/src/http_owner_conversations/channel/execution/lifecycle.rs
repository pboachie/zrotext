// SPDX-License-Identifier: AGPL-3.0-only
//! Immutable execution identity survives content retention; erasure is atomic.
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
            "SELECT to_regclass('conversation_execution_records') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

/// An existing malformed table must never take the optional absence path.
pub(crate) async fn validate<C: GenericClient + Sync>(
    db: &C,
) -> Result<bool, tokio_postgres::Error> {
    let statement = db
        .prepare("SELECT * FROM conversation_execution_records LIMIT 0")
        .await?;
    let names = [
        "account_id",
        "message_id",
        "device_id",
        "attempt_id",
        "generation",
        "phone_session",
        "origin_hash",
        "site_id",
        "instance_id",
        "session_epoch",
        "deployment_epoch",
        "reader_key_id",
        "envelope_digest",
        "unsigned_digest",
        "expires_at_ms",
        "segment_count",
        "created_at",
    ];
    let expected = [
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::INT8,
        Type::UUID,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::INT8,
        Type::INT2,
        Type::TIMESTAMPTZ,
    ];
    Ok(statement
        .columns()
        .iter()
        .map(|column| column.name())
        .eq(names)
        && statement
            .columns()
            .iter()
            .map(|column| column.type_())
            .eq(expected.iter()))
}

#[derive(Debug, Serialize)]
pub(crate) struct ExecutionMetadata {
    pub message_id: Uuid,
    pub device_id: Uuid,
    pub attempt_id: Uuid,
    pub attempt_generation: i64,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
}
#[derive(Debug, Serialize)]
pub(crate) struct ExecutionInventory {
    pub records: Vec<ExecutionMetadata>,
    pub truncated: bool,
    pub next_cursor: Option<Uuid>,
}
/// No content, recipient, transient channel token, site or key material.
pub(crate) async fn inventory(
    client: &mut Client,
    owner: &SessionPrincipal,
    before: Option<Uuid>,
) -> Result<ExecutionInventory, ConversationError> {
    const LIMIT: usize = 100;
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx).await? {
        if before.is_some() {
            return Err(ConversationError::NotFound);
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(ExecutionInventory {
            records: vec![],
            truncated: false,
            next_cursor: None,
        });
    }
    if !validate(&tx).await? {
        return Err(ConversationError::Forbidden);
    }
    let account = owner.tenant.account_id();
    let at:Option<SystemTime>=match before {
        Some(id)=>Some(tx.query_opt("SELECT created_at FROM conversation_execution_records WHERE account_id=$1 AND message_id=$2",&[&account,&id]).await?.ok_or(ConversationError::NotFound)?.get(0)),
        None=>None,
    };
    let rows=tx.query("SELECT message_id,device_id,attempt_id,generation,expires_at_ms,floor(extract(epoch FROM created_at)*1000)::bigint FROM conversation_execution_records WHERE account_id=$1 AND ($2::timestamptz IS NULL OR (created_at,message_id)<($2,$3::uuid)) ORDER BY created_at DESC,message_id DESC LIMIT $4 FOR SHARE",&[&account,&at,&before,&(LIMIT as i64+1)]).await?;
    let truncated = rows.len() > LIMIT;
    let records: Vec<_> = rows
        .iter()
        .take(LIMIT)
        .map(|r| ExecutionMetadata {
            message_id: r.get(0),
            device_id: r.get(1),
            attempt_id: r.get(2),
            attempt_generation: r.get(3),
            expires_at_ms: r.get(4),
            created_at_ms: r.get(5),
        })
        .collect();
    let next_cursor = if truncated {
        records.last().map(|r| r.message_id)
    } else {
        None
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(ExecutionInventory {
        records,
        truncated,
        next_cursor,
    })
}
