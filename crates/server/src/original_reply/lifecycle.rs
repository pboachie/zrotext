// SPDX-License-Identifier: AGPL-3.0-only
//! Minimal replay, turn and source identities survive content retention.
use super::*;
use crate::auth::SessionPrincipal;
#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    #[default]
    Grants,
    Requests,
    Consumptions,
    Sources,
    Access,
    Manifests,
}
#[derive(Default, Serialize)]
pub struct Export {
    pub items: Vec<serde_json::Value>,
    pub next_cursor: Option<String>,
}
pub async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    section: Section,
    before: Option<String>,
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    crate::http_owner_conversations::lock_owner(&tx, owner).await?;
    let mut result = Export::default();
    if installed(&tx).await? {
        let (table, key, kind) = match section {
            Section::Grants => ("original_reply_grants", "grant_id", "uuid"),
            Section::Requests => ("original_reply_requests", "request_id", "uuid"),
            Section::Consumptions => ("original_reply_consumptions", "consumption_id", "uuid"),
            Section::Sources => (
                "original_reply_sources",
                "action_id::text||':'||lpad(revision::text,20,'0')",
                "text",
            ),
            Section::Access => ("original_reply_access", "id", "uuid"),
            Section::Manifests => (
                "original_reply_manifest_history",
                "lpad(root_generation::text,20,'0')||':'||lpad(version::text,20,'0')",
                "text",
            ),
        };
        if let Some(c) = before.as_ref() {
            if c.is_empty()
                || c.len() > 100
                || !c
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b':')
                || (kind == "uuid" && Uuid::parse_str(c).is_err())
                || (kind == "bigint" && c.parse::<i64>().is_err())
            {
                return Err(ConversationError::Invalid);
            }
            if !tx.query_one(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE account_id=$1 AND {key}=$2::text::{kind})"),&[&owner.tenant.account_id(),c]).await?.get::<_,bool>(0){return Err(ConversationError::NotFound)}
        }
        // Credential hashes are authenticators, never part of an owner takeout.
        let rows=tx.query(&format!("SELECT {key}::text,(to_jsonb(t)-'credential_hash')::text FROM {table} t WHERE account_id=$1 AND ($2::text IS NULL OR {key}<$2::text::{kind}) ORDER BY {key} DESC LIMIT 101"),&[&owner.tenant.account_id(),&before]).await?;
        if rows.len() > 100 {
            result.next_cursor = Some(rows[99].get(0))
        }
        for r in rows.iter().take(100) {
            result.items.push(
                serde_json::from_str(r.get::<_, String>(1).as_str())
                    .map_err(|_| ConversationError::Invalid)?,
            )
        }
    }
    crate::http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
pub async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_one(
            "SELECT to_regclass('original_reply_grants') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}
pub async fn prune(client: &mut Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    let mut n = 0;
    if installed(&tx).await? {
        // Expiry only removes authority. It never removes replay/turn identities.
        n+=tx.execute("WITH due AS (SELECT account_id,grant_id FROM original_reply_grants WHERE revoked_ms IS NULL AND expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY expires_ms,account_id,grant_id FOR UPDATE SKIP LOCKED LIMIT $1) UPDATE original_reply_grants g SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM due WHERE (g.account_id,g.grant_id)=(due.account_id,due.grant_id)",&[&limit]).await?;
        n+=tx.execute("WITH due AS (SELECT account_id,id FROM original_reply_access WHERE recorded_ms<floor(extract(epoch FROM clock_timestamp()-interval '30 days')*1000)::bigint ORDER BY recorded_ms,account_id,id FOR UPDATE SKIP LOCKED LIMIT $1) DELETE FROM original_reply_access a USING due WHERE (a.account_id,a.id)=(due.account_id,due.id)",&[&limit]).await?;
    }
    tx.commit().await?;
    Ok(n)
}
