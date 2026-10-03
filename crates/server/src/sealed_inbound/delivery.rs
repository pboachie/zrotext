// SPDX-License-Identifier: AGPL-3.0-only
//! Explicitly selected opaque conversation-event outbox. A general upload is
//! not interval consent; only already verified capture provenance can enqueue.
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) mod lifecycle;
mod sender;
mod worker;
pub use worker::dispatch_one;

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("sealed delivery authority unavailable")]
    Forbidden,
    #[error("sealed delivery queue capacity exhausted")]
    Capacity,
    #[error("sealed delivery storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("sealed delivery current authority unavailable")]
    Authority(#[from] crate::sealed_manifest_store::AdmissionError),
    #[error("sealed delivery conversation authority unavailable")]
    Conversation(#[from] crate::http_owner_conversations::ConversationError),
    #[error("sealed delivery signing secret unavailable")]
    Secret(#[from] crate::webhook_worker::WorkerError),
}

/// Called only inside the verified event's admission transaction. An exact
/// retry never adopts a newly configured endpoint or recreates a purged row.
pub(crate) async fn enqueue(
    tx: &Transaction<'_>,
    account: Uuid,
    event: Uuid,
    created: bool,
) -> Result<u64, DeliveryError> {
    if !created {
        return Ok(0);
    }
    let Some(provenance) = tx
        .query_opt(
            "SELECT interval_id,trust_generation FROM conversation_inbound_provenance \
         WHERE account_id=$1 AND event_id=$2",
            &[&account, &event],
        )
        .await?
    else {
        return Ok(0);
    };
    // Same root-before-account order as capture; account serializes queue caps
    // and endpoint lifecycle. No general API key becomes a content reader.
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&account],
    )
    .await?;
    let endpoints = tx
        .query(
            "SELECT id FROM webhook_endpoints WHERE account_id=$1 AND enabled \
         AND sealed_events_enabled ORDER BY id FOR SHARE",
            &[&account],
        )
        .await?;
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM sealed_event_deliveries WHERE account_id=$1 \
         AND status IN ('pending','leased')",
            &[&account],
        )
        .await?
        .get(0);
    if endpoints.len() > 5 || count + endpoints.len() as i64 > 10_000 {
        return Err(DeliveryError::Capacity);
    }
    let interval: Uuid = provenance.get(0);
    let generation: i64 = provenance.get(1);
    for endpoint in &endpoints {
        tx.execute("INSERT INTO sealed_event_deliveries(id,account_id,endpoint_id,event_id,interval_id,trust_generation) \
            VALUES($1,$2,$3,$4,$5,$6)",
            &[&Uuid::new_v4(),&account,&endpoint.get::<_,Uuid>(0),&event,&interval,&generation]).await?;
    }
    Ok(endpoints.len() as u64)
}

pub(crate) fn retry_seconds(attempt: i16) -> Option<i32> {
    [60, 300, 900, 3600, 21600, 86400]
        .get(attempt.checked_sub(1)? as usize)
        .copied()
}

#[cfg(test)]
mod tests;
