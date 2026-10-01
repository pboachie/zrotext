// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded metadata export inside the existing live-owner export transaction.
use crate::auth::SessionPrincipal;
use crate::http_owner_conversations::ConversationError;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

const PAGE: usize = 20;
#[derive(Default)]
pub(crate) struct Cursors {
    pub policies: Option<String>,
    pub series: Option<Uuid>,
    pub occurrences: Option<Uuid>,
    pub audit: Option<Uuid>,
}
#[derive(Serialize)]
pub(crate) struct Page {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct ScheduleExport {
    pub policies: Page,
    pub series: Page,
    pub occurrences: Page,
    pub audit: Page,
}

async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: &str,
    before: Option<String>,
) -> Result<Page, ConversationError> {
    if let Some(id) = before.as_ref() {
        // Fixed internal table names only; the cursor remains a SQL parameter.
        tx.query_opt(
            &format!("SELECT 1 FROM {table} WHERE account_id=$1 AND id::text=$2"),
            &[&account, id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let json = match table {
        "workflow_schedule_occurrences" => {
            "(to_jsonb(t)-ARRAY['binding_digest','request_digest'])||jsonb_build_object('binding_digest_hex',encode(binding_digest,'hex'),'request_digest_hex',encode(request_digest,'hex'))"
        }
        "workflow_schedule_audit" => {
            "(to_jsonb(t)-'request_digest')||jsonb_build_object('request_digest_hex',encode(request_digest,'hex'))"
        }
        _ => "to_jsonb(t)",
    };
    let rows=tx.query(&format!("SELECT id::text,({json})::text FROM {table} t WHERE account_id=$1 AND ($2::text IS NULL OR id::text COLLATE \"C\">$2) ORDER BY id::text COLLATE \"C\" LIMIT 21 FOR SHARE"),&[&account,&before]).await?;
    let next_cursor = if rows.len() > PAGE {
        Some(rows[PAGE - 1].get(0))
    } else {
        None
    };
    let items = rows
        .iter()
        .take(PAGE)
        .map(|r| {
            serde_json::from_str(&r.get::<_, String>(1)).map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<_, _>>()?;
    Ok(Page { items, next_cursor })
}

async fn export_pages(
    tx: &Transaction<'_>,
    account: Uuid,
    cursors: Cursors,
) -> Result<ScheduleExport, ConversationError> {
    Ok(ScheduleExport {
        policies: page(tx, account, "workflow_schedule_policies", cursors.policies).await?,
        series: page(
            tx,
            account,
            "workflow_schedule_series",
            cursors.series.map(|v| v.to_string()),
        )
        .await?,
        occurrences: page(
            tx,
            account,
            "workflow_schedule_occurrences",
            cursors.occurrences.map(|v| v.to_string()),
        )
        .await?,
        audit: page(
            tx,
            account,
            "workflow_schedule_audit",
            cursors.audit.map(|v| v.to_string()),
        )
        .await?,
    })
}

/// Prune only ended, expired work. A still-live action retains its replay
/// identity even after cancellation; cleanup cannot revive its occurrence.
pub(crate) async fn retain(
    tx: &Transaction<'_>,
    account: Uuid,
    days: i32,
    limit: i64,
) -> Result<u64, tokio_postgres::Error> {
    let rows=tx.query("SELECT id FROM workflow_schedule_occurrences WHERE account_id=$1 AND phase IN ('completed','failed','cancelled','expired','missed_window') AND expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND updated_at<clock_timestamp()-$3::int*interval '1 day' ORDER BY updated_at,id LIMIT $2 FOR UPDATE SKIP LOCKED",&[&account,&limit,&days]).await?;
    let mut removed = 0;
    for row in rows {
        let id: Uuid = row.get(0);
        removed += tx
            .execute(
                "DELETE FROM workflow_schedule_occurrences WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?;
    }
    let audit=tx.query("SELECT id FROM workflow_schedule_audit WHERE account_id=$1 AND created_at<clock_timestamp()-$3::int*interval '1 day' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE o.account_id=$1 AND o.id=workflow_schedule_audit.occurrence_id) ORDER BY created_at,id LIMIT $2 FOR UPDATE SKIP LOCKED",&[&account,&(limit-removed as i64),&days]).await?;
    for row in audit {
        let id: Uuid = row.get(0);
        removed += tx
            .execute(
                "DELETE FROM workflow_schedule_audit WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?;
    }
    let series=tx.query("SELECT s.id FROM workflow_schedule_series s JOIN workflow_contexts c ON (c.account_id,c.id)=(s.account_id,s.context_id) WHERE s.account_id=$1 AND (c.purged_at IS NOT NULL OR c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint) AND NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE (o.account_id,o.series_id)=(s.account_id,s.id)) ORDER BY s.created_at,s.id LIMIT $2 FOR UPDATE OF s SKIP LOCKED",&[&account,&(limit-removed as i64)]).await?;
    for row in series {
        let id: Uuid = row.get(0);
        removed += tx
            .execute(
                "DELETE FROM workflow_schedule_series WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?;
    }
    let policies=tx.query("SELECT p.id FROM workflow_schedule_policies p WHERE p.account_id=$1 AND p.created_at<clock_timestamp()-$3::int*interval '1 day' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_series s WHERE (s.account_id,s.policy_id)=(p.account_id,p.id)) ORDER BY p.created_at,p.id LIMIT $2 FOR UPDATE OF p SKIP LOCKED",&[&account,&(limit-removed as i64),&days]).await?;
    for row in policies {
        let id: String = row.get(0);
        removed += tx
            .execute(
                "DELETE FROM workflow_schedule_policies WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?;
    }
    Ok(removed)
}

pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: Cursors,
) -> Result<ScheduleExport, ConversationError> {
    let tx = client.transaction().await?;
    crate::http_owner_conversations::lock_owner(&tx, owner).await?;
    let result = export_pages(&tx, owner.tenant.account_id(), cursors).await?;
    crate::http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}

/// One globally bounded batch under account locks, preserving live replay rows.
pub(crate) async fn prune(
    client: &mut Client,
    days: i32,
    limit: i64,
) -> Result<u64, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    let accounts = tx.query("SELECT a.id FROM accounts a WHERE EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE o.account_id=a.id AND o.phase IN ('completed','failed','cancelled','expired','missed_window') AND o.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND o.updated_at<clock_timestamp()-$1::int*interval '1 day') OR EXISTS(SELECT 1 FROM workflow_schedule_audit x WHERE x.account_id=a.id AND x.created_at<clock_timestamp()-$1::int*interval '1 day' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE o.account_id=x.account_id AND o.id=x.occurrence_id)) OR EXISTS(SELECT 1 FROM workflow_schedule_policies p WHERE p.account_id=a.id AND p.created_at<clock_timestamp()-$1::int*interval '1 day' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_series s WHERE (s.account_id,s.policy_id)=(p.account_id,p.id))) OR EXISTS(SELECT 1 FROM workflow_schedule_series s JOIN workflow_contexts c ON(c.account_id,c.id)=(s.account_id,s.context_id) WHERE s.account_id=a.id AND (c.purged_at IS NOT NULL OR c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint) AND NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE(o.account_id,o.series_id)=(s.account_id,s.id))) ORDER BY a.id LIMIT $2 FOR UPDATE OF a SKIP LOCKED", &[&days,&limit]).await?;
    let mut removed = 0;
    for account in accounts {
        if removed >= limit as u64 {
            break;
        }
        removed += retain(&tx, account.get(0), days, limit - removed as i64).await?;
    }
    tx.commit().await?;
    Ok(removed)
}
