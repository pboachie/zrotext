// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{ConversationError, SessionPrincipal};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    id: Uuid,
    revision: i64,
}
#[derive(Serialize)]
pub(crate) struct Page {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct Export {
    pub actions: Page,
    pub versions: Page,
    pub mutations: Page,
    pub correlations: Page,
    pub message_links: Page,
    pub routines: Page,
    pub context_fences: Page,
}
const TABLES: [(&str, &str, &str); 7] = [
    ("workflow_actions", "id", "0::bigint"),
    ("workflow_action_versions", "action_id", "revision"),
    ("workflow_action_mutations", "request_id", "0::bigint"),
    ("workflow_reply_correlations", "event_id", "0::bigint"),
    ("workflow_message_links", "action_id", "revision"),
    ("workflow_routines", "id", "0::bigint"),
    ("workflow_context_fences", "context_id", "0::bigint"),
];
fn decode(value: Option<&str>) -> Result<Option<Cursor>, ConversationError> {
    value
        .map(|value| {
            if value.len() > 128 {
                return Err(ConversationError::Invalid);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| ConversationError::Invalid)?;
            if URL_SAFE_NO_PAD.encode(&bytes) != value {
                return Err(ConversationError::Invalid);
            }
            let cursor: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| ConversationError::Invalid)?;
            if cursor.id.is_nil() || !(0..=128).contains(&cursor.revision) {
                return Err(ConversationError::Invalid);
            }
            Ok(cursor)
        })
        .transpose()
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    index: usize,
    cursor: Option<&str>,
) -> Result<Page, ConversationError> {
    let (table, id, revision) = TABLES[index];
    let cursor = decode(cursor)?;
    if let Some(c) = cursor {
        tx.query_opt(
            &format!("SELECT 1 FROM {table} WHERE account_id=$1 AND {id}=$2 AND {revision}=$3"),
            &[&account, &c.id, &c.revision],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let before = cursor.map(|c| c.id);
    let rev = cursor.map_or(0, |c| c.revision);
    let rows=tx.query(&format!("SELECT {id},{revision},to_jsonb(t)::text FROM {table} t WHERE account_id=$1 AND ($2::uuid IS NULL OR ({id},{revision})>($2,$3::bigint)) ORDER BY {id},{revision} LIMIT 21 FOR SHARE"),&[&account,&before,&rev]).await?;
    let next_cursor = if rows.len() > 20 {
        let c = Cursor {
            id: rows[19].get(0),
            revision: rows[19].get(1),
        };
        Some(
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&c).map_err(|_| ConversationError::Unavailable)?),
        )
    } else {
        None
    };
    let items = rows
        .iter()
        .take(20)
        .map(|row| {
            serde_json::from_str(&row.get::<_, String>(2))
                .map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page { items, next_cursor })
}
pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<&str>; 7],
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    super::super::super::lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let result = Export {
        actions: page(&tx, account, 0, cursors[0]).await?,
        versions: page(&tx, account, 1, cursors[1]).await?,
        mutations: page(&tx, account, 2, cursors[2]).await?,
        correlations: page(&tx, account, 3, cursors[3]).await?,
        message_links: page(&tx, account, 4, cursors[4]).await?,
        routines: page(&tx, account, 5, cursors[5]).await?,
        context_fences: page(&tx, account, 6, cursors[6]).await?,
    };
    super::super::super::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}

/// Retains the exact message binding while a referenced message still exists.
/// Removing it earlier could let a surviving message lose its automation fence.
pub(crate) async fn erase_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<bool, tokio_postgres::Error> {
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM messages m JOIN workflow_message_links l ON (l.account_id,l.message_id)=(m.account_id,m.id) JOIN workflow_action_versions v ON (v.account_id,v.action_id,v.revision)=(l.account_id,l.action_id,l.revision) WHERE v.account_id=$1 AND v.context_id=$2)",&[&account,&context]).await?.get::<_,bool>(0) { return Ok(false); }
    for sql in [
        "DELETE FROM workflow_message_links WHERE account_id=$1 AND action_id IN (SELECT id FROM workflow_actions WHERE account_id=$1 AND context_id=$2)",
        "DELETE FROM workflow_reply_correlations WHERE account_id=$1 AND context_id=$2",
        "DELETE FROM workflow_action_mutations WHERE account_id=$1 AND context_id=$2",
        "DELETE FROM workflow_action_versions WHERE account_id=$1 AND context_id=$2",
        "DELETE FROM workflow_actions WHERE account_id=$1 AND context_id=$2",
        "DELETE FROM workflow_routines WHERE account_id=$1 AND context_id=$2",
        "DELETE FROM workflow_context_fences WHERE account_id=$1 AND context_id=$2",
    ] {
        tx.execute(sql, &[&account, &context]).await?;
    }
    Ok(true)
}
