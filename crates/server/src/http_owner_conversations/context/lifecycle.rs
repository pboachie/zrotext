// SPDX-License-Identifier: AGPL-3.0-only
use super::super::lock_owner;
use super::{ConversationError, SessionPrincipal, authorize, load};
use crate::sealed_manifest_store::outbound::lock_current;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
const PAGE: usize = 20;

#[derive(Serialize)]
pub struct ExceptionsPage {
    pub items: Vec<Value>,
    pub next_cursor: Option<Uuid>,
}
pub async fn exceptions(
    client: &mut Client,
    owner: &SessionPrincipal,
    context: Uuid,
    before: Option<Uuid>,
) -> Result<ExceptionsPage, ConversationError> {
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    let bytes = load(&tx, account, context, None).await?;
    let h = super::wire::parse(&bytes)?;
    authorize(&tx, owner, &mut authority, &h, false).await?;
    if let Some(id) = before {
        tx.query_opt(
            "SELECT id FROM workflow_exceptions WHERE account_id=$1 AND context_id=$2 AND id=$3",
            &[&account, &context, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query("SELECT id,to_jsonb(e)::text FROM workflow_exceptions e WHERE account_id=$1 AND context_id=$2 AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT 21 FOR SHARE",&[&account,&context,&before]).await?;
    let next_cursor = if rows.len() > PAGE {
        Some(rows[PAGE - 1].get(0))
    } else {
        None
    };
    let items = rows
        .iter()
        .take(PAGE)
        .map(|r| {
            serde_json::from_str::<Value>(&r.get::<_, String>(1))
                .map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<_, _>>()?;
    authorize(&tx, owner, &mut authority, &h, false).await?;
    drop(authority);
    tx.commit().await?;
    Ok(ExceptionsPage { items, next_cursor })
}

#[derive(Serialize)]
pub(crate) struct ExportPage {
    pub items: Vec<Value>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Serialize)]
pub(crate) struct WorkflowExport {
    pub contexts: ExportPage,
    pub versions: ExportPage,
    pub exceptions: ExportPage,
    pub audit: ExportPage,
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: &str,
    before: Option<Uuid>,
) -> Result<ExportPage, ConversationError> {
    // Table is selected exclusively by the four fixed internal calls below.
    if let Some(id) = before {
        tx.query_opt(
            &format!("SELECT id FROM {table} WHERE account_id=$1 AND id=$2"),
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let json = if table == "workflow_context_versions" {
        "(to_jsonb(t)-'envelope')||jsonb_build_object('envelope_hex',encode(envelope,'hex'))"
    } else {
        "to_jsonb(t)"
    };
    let rows=tx.query(&format!("SELECT id,({json})::text FROM {table} t WHERE account_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 21 FOR SHARE"),&[&account,&before]).await?;
    let next_cursor = if rows.len() > PAGE {
        Some(rows[PAGE - 1].get(0))
    } else {
        None
    };
    let items = rows
        .iter()
        .take(PAGE)
        .map(|r| {
            serde_json::from_str::<Value>(&r.get::<_, String>(1))
                .map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<_, _>>()?;
    Ok(ExportPage { items, next_cursor })
}
/// Owner takeout exports opaque ciphertext, including revoked-reader history.
/// It grants no decryption or current content-reader authority.
pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<Uuid>; 4],
) -> Result<WorkflowExport, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let result = WorkflowExport {
        contexts: page(&tx, account, "workflow_contexts", cursors[0]).await?,
        versions: page(&tx, account, "workflow_context_versions", cursors[1]).await?,
        exceptions: page(&tx, account, "workflow_exceptions", cursors[2]).await?,
        audit: page(&tx, account, "workflow_context_audit", cursors[3]).await?,
    };
    super::super::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}

/// Bounded account-before-context purge and subsequent metadata erasure.
pub(crate) async fn prune(
    client: &mut Client,
    days: i32,
    limit: i64,
) -> Result<u64, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    if !installed(&tx).await? {
        return Ok(0);
    }
    let limit = limit.clamp(1, 500);
    let accounts=tx.query("SELECT a.id FROM accounts a WHERE EXISTS(SELECT 1 FROM workflow_contexts c JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id) WHERE c.account_id=a.id AND ((c.purged_at IS NULL AND (c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR i.phase IN ('withdrawn','expired'))) OR c.purged_at<=clock_timestamp()-$1::int*interval '1 day')) ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT $2",&[&days,&limit]).await?;
    let mut changed = 0;
    for a in accounts {
        if changed >= limit as u64 {
            break;
        }
        let account: Uuid = a.get(0);
        let rows=tx.query("SELECT c.id,c.purged_at IS NOT NULL FROM workflow_contexts c JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id) WHERE c.account_id=$1 AND ((c.purged_at IS NULL AND (c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR i.phase IN ('withdrawn','expired'))) OR c.purged_at<=clock_timestamp()-$2::int*interval '1 day') ORDER BY c.id FOR UPDATE OF c SKIP LOCKED LIMIT $3",&[&account,&days,&(limit-changed as i64)]).await?;
        for row in rows {
            let id: Uuid = row.get(0);
            if row.get::<_, bool>(1) {
                if !super::decisions::lifecycle::erase_context(&tx, account, id).await? {
                    continue;
                }
                crate::workflow_runtime::lifecycle::erase_context(&tx, account, id).await?;
                for table in [
                    "workflow_context_audit",
                    "workflow_exceptions",
                    "workflow_context_versions",
                ] {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE account_id=$1 AND context_id=$2"),
                        &[&account, &id],
                    )
                    .await?;
                }
                tx.execute(
                    "DELETE FROM workflow_contexts WHERE account_id=$1 AND id=$2",
                    &[&account, &id],
                )
                .await?;
            } else {
                crate::workflow_runtime::lifecycle::scrub_context(&tx, account, id).await?;
                tx.execute("UPDATE workflow_context_versions SET envelope=NULL WHERE account_id=$1 AND context_id=$2",&[&account,&id]).await?;
                tx.execute("UPDATE workflow_contexts SET purged_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&id]).await?;
            }
            changed += 1;
        }
    }
    tx.commit().await?;
    Ok(changed)
}

/// Whether the optional context schema is available in the current search path.
pub(crate) async fn installed(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_one("SELECT to_regclass('workflow_contexts') IS NOT NULL", &[])
        .await?
        .get(0))
}
