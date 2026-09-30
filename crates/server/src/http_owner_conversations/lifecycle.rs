// SPDX-License-Identifier: AGPL-3.0-only
//! Account-scoped inventory; never exports ciphertext or private key material.
use super::{ConversationError, SessionPrincipal, fresh_owner, lock_owner};
use serde::Serialize;
use std::time::SystemTime;
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) const INVENTORY_LIMIT: usize = 100;

#[derive(Debug, Serialize)]
pub(crate) struct ConsentInventory {
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub peer: Option<String>,
    pub disclosure_version: String,
    pub enabled_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SealedEventInventory {
    pub event_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub envelope_profile: i16,
    pub received_at_ms: i64,
    pub content_retained: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConversationInventory {
    pub consent: Option<ConsentInventory>,
    pub sealed_events: Vec<SealedEventInventory>,
    pub sealed_events_truncated: bool,
    pub sealed_events_next_cursor: Option<Uuid>,
}

/// This inventories all account-owned sealed inbound identities, including
/// purged replay tombstones. It confers no content-read or key authority.
/// Consent currently stores only the latest selection, not interval history.
pub(crate) async fn inventory(
    client: &mut Client,
    owner: &SessionPrincipal,
    before: Option<Uuid>,
) -> Result<ConversationInventory, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let point: Option<(SystemTime, Uuid)> = match before {
        Some(id) => Some((
            tx.query_opt(
                "SELECT received_at FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?
            .ok_or(ConversationError::NotFound)?
            .get(0),
            id,
        )),
        None => None,
    };
    let before_at = point.map(|p| p.0);
    let before_id = point.map(|p| p.1);
    let consent = tx.query_opt(
        "SELECT device_id,line_id,binding_generation,peer,disclosure_version, \
         (extract(epoch FROM enabled_at)*1000)::bigint,(extract(epoch FROM revoked_at)*1000)::bigint \
         FROM owner_conversation_consents WHERE account_id=$1 FOR SHARE",
        &[&account],
    ).await?.map(|row| ConsentInventory {
        device_id: row.get(0), line_id: row.get(1), binding_generation: row.get(2),
        peer: row.get(3), disclosure_version: row.get(4), enabled_at_ms: row.get(5), revoked_at_ms: row.get(6),
    });
    let rows = tx
        .query(
            "SELECT id,device_id,line_id,binding_generation,envelope_profile, \
         (extract(epoch FROM received_at)*1000)::bigint,(envelope IS NOT NULL) \
         FROM sealed_inbound_events WHERE account_id=$1 \
         AND ($2::timestamptz IS NULL OR (received_at,id)<($2,$3::uuid)) \
         ORDER BY received_at DESC,id DESC LIMIT $4 FOR SHARE",
            &[
                &account,
                &before_at,
                &before_id,
                &(INVENTORY_LIMIT as i64 + 1),
            ],
        )
        .await?;
    let sealed_events_truncated = rows.len() > INVENTORY_LIMIT;
    let sealed_events: Vec<_> = rows
        .iter()
        .take(INVENTORY_LIMIT)
        .map(|row| SealedEventInventory {
            event_id: row.get(0),
            device_id: row.get(1),
            line_id: row.get(2),
            binding_generation: row.get(3),
            envelope_profile: row.get(4),
            received_at_ms: row.get(5),
            content_retained: row.get(6),
        })
        .collect();
    let sealed_events_next_cursor = if sealed_events_truncated {
        sealed_events.last().map(|e| e.event_id)
    } else {
        None
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(ConversationInventory {
        consent,
        sealed_events,
        sealed_events_truncated,
        sealed_events_next_cursor,
    })
}

/// Withdrawn selection metadata is not a replay tombstone. Bound its lifetime
/// to the existing sealed-inbound content retention window; active selections
/// remain until explicit withdrawal. No ciphertext or event identity is erased.
pub(crate) async fn prune_withdrawn(
    client: &Client,
    days: i32,
    limit: i64,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "WITH due AS (SELECT account_id FROM owner_conversation_consents \
         WHERE revoked_at<=clock_timestamp()-$1::int * interval '1 day' \
         ORDER BY revoked_at,account_id FOR UPDATE SKIP LOCKED LIMIT $2) \
         DELETE FROM owner_conversation_consents c USING due WHERE c.account_id=due.account_id",
            &[&days, &limit],
        )
        .await
}
