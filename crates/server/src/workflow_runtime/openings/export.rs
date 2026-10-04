// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded current-owner metadata takeout. Erased bindings are NULL; opaque
//! occupancy/response-use fences convey no decryption or increasing authority.
use super::store;
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{self as owner_context, ConversationError},
    workflow_runtime::lifecycle::Page,
};
use serde::Serialize;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Default, Serialize)]
pub struct Export {
    pub openings: Page,
    pub offers: Page,
    pub allocations: Page,
    pub requests: Page,
}
pub async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<Uuid>; 4],
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    owner_context::lock_owner(&tx, owner).await?;
    if !store::installed(&tx).await? {
        if cursors.iter().any(Option::is_some) {
            return Err(ConversationError::NotFound);
        }
        owner_context::fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Export::default());
    }
    let account = owner.tenant.account_id();
    let result = Export {
        openings: page(&tx, account, "workflow_openings", "id", cursors[0]).await?,
        offers: page(&tx, account, "workflow_opening_offers", "id", cursors[1]).await?,
        allocations: page(
            &tx,
            account,
            "workflow_opening_allocations",
            "id",
            cursors[2],
        )
        .await?,
        requests: page(
            &tx,
            account,
            "workflow_opening_requests",
            "request_id",
            cursors[3],
        )
        .await?,
    };
    owner_context::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: &str,
    id: &str,
    cursor: Option<Uuid>,
) -> Result<Page, ConversationError> {
    if let Some(cursor) = cursor {
        tx.query_opt(
            &format!("SELECT {id} FROM {table} WHERE account_id=$1 AND {id}=$2"),
            &[&account, &cursor],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    // Future database columns must not enter takeout without explicit review.
    let fields = match table {
        "workflow_openings" => {
            "account_id,id,definition_version,state_version,capacity,phase,description_context_id,description_revision,description_digest,decision_deadline_ms,created_by_user,created_session,created_ms"
        }
        "workflow_opening_offers" => {
            "account_id,id,opening_id,opening_definition_version,state_version,phase,binding_scrubbed,contact_identity,current_contact_id,purpose,consent_episode_id,context_id,context_revision,context_digest,issued_ms,expires_ms,created_by_user,created_session"
        }
        "workflow_opening_allocations" => {
            "account_id,id,opening_id,binding_scrubbed,offer_id,offer_state_version,contact_identity,event_id,event_digest,response_use_digest,observed_ms,accepted_ms,decision_deadline_ms,phase,state_version,reserved_by_user,reserved_session,confirmed_by_user,confirmed_session,confirmed_ms"
        }
        "workflow_opening_requests" => {
            "account_id,request_id,opening_id,redacted,admission_charged,subject_kind,subject_id,operation,request_digest,result,actor_user_id,actor_session_id,committed_ms"
        }
        _ => return Err(ConversationError::Unavailable),
    };
    let projection = fields
        .split(',')
        .map(|field| format!("'{field}',{field}"))
        .collect::<Vec<_>>()
        .join(",");
    let rows=tx.query(&format!("SELECT {id},jsonb_build_object({projection})::text FROM {table} WHERE account_id=$1 AND ($2::uuid IS NULL OR {id}>$2) ORDER BY {id} LIMIT 21 FOR SHARE"),&[&account,&cursor]).await?;
    let next_cursor = if rows.len() > 20 {
        Some(rows[19].get(0))
    } else {
        None
    };
    let items = rows
        .iter()
        .take(20)
        .map(|row| {
            serde_json::from_str(&row.get::<_, String>(1))
                .map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<_, _>>()?;
    Ok(Page { items, next_cursor })
}
