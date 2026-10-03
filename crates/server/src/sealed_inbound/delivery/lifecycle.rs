// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded owner takeout of opaque delivery metadata and its seven attempts.
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{ConversationError, fresh_owner, lock_owner},
};
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Serialize)]
pub(crate) struct Export {
    pub items: Vec<serde_json::Value>,
    pub next_cursor: Option<Uuid>,
}

pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    after: Option<Uuid>,
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    if let Some(id) = after {
        tx.query_opt(
            "SELECT id FROM sealed_event_deliveries WHERE account_id=$1 AND id=$2",
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query("SELECT d.id,(to_jsonb(d)||jsonb_build_object('attempts',coalesce( \
        (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.attempt_number) FROM sealed_event_delivery_attempts a WHERE a.delivery_id=d.id),'[]'::jsonb)))::text \
        FROM sealed_event_deliveries d WHERE d.account_id=$1 AND ($2::uuid IS NULL OR d.id>$2) ORDER BY d.id LIMIT 21 FOR SHARE OF d",
        &[&account,&after]).await?;
    let result = Export {
        next_cursor: (rows.len() > 20).then(|| rows[19].get(0)),
        items: rows
            .iter()
            .take(20)
            .map(|r| {
                serde_json::from_str(&r.get::<_, String>(1))
                    .map_err(|_| ConversationError::Unavailable)
            })
            .collect::<Result<_, _>>()?,
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
