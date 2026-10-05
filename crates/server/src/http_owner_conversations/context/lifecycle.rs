// SPDX-License-Identifier: AGPL-3.0-only
use super::super::lock_owner;
use super::{ConversationError, SessionPrincipal, authorize, load};
use crate::sealed_manifest_store::outbound::lock_current;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;
const PAGE: usize = 20;

#[derive(Serialize)]
pub struct ExceptionsPage {
    pub account_id: Uuid,
    pub context_id: Uuid,
    pub items: Vec<ExceptionRow>,
    pub next_cursor: Option<Uuid>,
}

/// Closed metadata projection; ciphertext and arbitrary database columns stay private.
#[derive(Serialize)]
pub struct ExceptionRow {
    account_id: Uuid,
    context_id: Uuid,
    id: Uuid,
    context_revision: i64,
    source_kind: i16,
    source_id: Uuid,
    reason: i16,
    request_digest: String,
    revision: i64,
    state: String,
    resolution_request_id: Option<Uuid>,
    resolved_at: Option<String>,
    created_at: String,
}

struct ExceptionRecord {
    account_id: Uuid,
    context_id: Uuid,
    id: Uuid,
    context_revision: i64,
    source_kind: i16,
    source_id: Uuid,
    reason: i16,
    request_digest: Vec<u8>,
    revision: i64,
    state: String,
    resolution_request_id: Option<Uuid>,
    resolved_at: Option<String>,
    created_at: String,
}

impl ExceptionRecord {
    fn from_row(row: &Row) -> Result<Self, ConversationError> {
        Ok(Self {
            account_id: row.try_get(0)?,
            context_id: row.try_get(1)?,
            id: row.try_get(2)?,
            context_revision: row.try_get(3)?,
            source_kind: row.try_get(4)?,
            source_id: row.try_get(5)?,
            reason: row.try_get(6)?,
            request_digest: row.try_get(7)?,
            revision: row.try_get(8)?,
            state: row.try_get(9)?,
            resolution_request_id: row.try_get(10)?,
            resolved_at: row.try_get(11)?,
            created_at: row.try_get(12)?,
        })
    }

    fn into_wire(self, account: Uuid, context: Uuid) -> Result<ExceptionRow, ConversationError> {
        let resolution_valid = match (self.revision, self.state.as_str()) {
            (1, "pending") => self.resolution_request_id.is_none() && self.resolved_at.is_none(),
            (2, "resolved") => {
                self.resolution_request_id.is_some_and(|id| !id.is_nil())
                    && self.resolved_at.as_deref().is_some_and(canonical_timestamp)
            }
            _ => false,
        };
        if self.account_id != account
            || self.context_id != context
            || [account, context, self.id, self.source_id]
                .iter()
                .any(Uuid::is_nil)
            || !(1..=128).contains(&self.context_revision)
            || !matches!((self.source_kind, self.reason), (1, 1 | 5) | (2, 2..=4))
            || self.request_digest.len() != 32
            || !resolution_valid
            || !canonical_timestamp(&self.created_at)
        {
            return Err(ConversationError::Unavailable);
        }
        let mut request_digest = String::with_capacity(66);
        request_digest.push_str("\\x");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.request_digest {
            request_digest.push(char::from(HEX[usize::from(byte >> 4)]));
            request_digest.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(ExceptionRow {
            account_id: account,
            context_id: context,
            id: self.id,
            context_revision: self.context_revision,
            source_kind: self.source_kind,
            source_id: self.source_id,
            reason: self.reason,
            request_digest,
            revision: self.revision,
            state: self.state,
            resolution_request_id: self.resolution_request_id,
            resolved_at: self.resolved_at,
            created_at: self.created_at,
        })
    }
}

fn canonical_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 27
        || [
            (4, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'.'),
            (26, b'Z'),
        ]
        .iter()
        .any(|&(at, expected)| b[at] != expected)
        || b.iter().enumerate().any(|(at, digit)| {
            ![4, 7, 10, 13, 16, 19, 26].contains(&at) && !digit.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |from: usize, to: usize| {
        b[from..to]
            .iter()
            .fold(0u32, |n, digit| n * 10 + u32::from(digit - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0
        && day > 0
        && day <= days
        && number(11, 13) <= 23
        && number(14, 16) <= 59
        && number(17, 19) <= 59
}

// CASE distinguishes a SQL NULL resolution from unsupported non-null timestamps.
// Both timestamps are explicitly UTC, independent of TimeZone, DateStyle and bytea_output.
const EXCEPTIONS_QUERY: &str = r#"
SELECT account_id, context_id, id, context_revision, source_kind, source_id, reason,
       request_digest, revision, state, resolution_request_id,
       CASE WHEN resolved_at IS NULL THEN NULL
            WHEN isfinite(resolved_at)
                 AND extract(year FROM resolved_at AT TIME ZONE 'UTC') BETWEEN 1 AND 9999
            THEN to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ELSE '' END,
       CASE WHEN isfinite(created_at)
                 AND extract(year FROM created_at AT TIME ZONE 'UTC') BETWEEN 1 AND 9999
            THEN to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ELSE '' END
FROM workflow_exceptions
WHERE account_id=$1 AND context_id=$2 AND ($3::uuid IS NULL OR id>$3)
ORDER BY id LIMIT 21 FOR SHARE
"#;
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
    let rows = tx
        .query(EXCEPTIONS_QUERY, &[&account, &context, &before])
        .await?;
    // Validate the lookahead too: an unsupported selected row cannot yield partial success.
    let mut items = rows
        .iter()
        .map(|row| ExceptionRecord::from_row(row)?.into_wire(account, h.context))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if items.len() > PAGE {
        Some(items[PAGE - 1].id)
    } else {
        None
    };
    items.truncate(PAGE);
    authorize(&tx, owner, &mut authority, &h, false).await?;
    drop(authority);
    tx.commit().await?;
    Ok(ExceptionsPage {
        account_id: account,
        context_id: h.context,
        items,
        next_cursor,
    })
}

#[cfg(test)]
mod tests;

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
