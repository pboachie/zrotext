// SPDX-License-Identifier: AGPL-3.0-only
//! Opaque bounded takeout and irreversible ciphertext expiry. Bounded version
//! identities remain as replay tombstones until explicit owner account erasure.
use super::*;
use serde::Serialize;
use serde_json::Value;
#[derive(Serialize)]
pub struct Page {
    pub items: Vec<Value>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Serialize)]
pub(crate) struct Export {
    pub templates: Page,
    pub versions: Page,
}
pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_one("SELECT to_regclass('encrypted_templates') IS NOT NULL", &[])
        .await?
        .get(0))
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    versions: bool,
    after: Option<Uuid>,
) -> Result<Page, ConversationError> {
    let (table, json) = if versions {
        (
            "encrypted_template_versions",
            "(to_jsonb(t)-'envelope')||jsonb_build_object('envelope_hex',encode(envelope,'hex'))",
        )
    } else {
        ("encrypted_templates", "to_jsonb(t)")
    };
    if let Some(id) = after {
        tx.query_opt(
            &format!("SELECT id FROM {table} WHERE account_id=$1 AND id=$2"),
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query(&format!("SELECT id,({json})::text FROM {table} t WHERE account_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 21 FOR SHARE"),&[&account,&after]).await?;
    Ok(Page {
        next_cursor: (rows.len() > 20).then(|| rows[19].get(0)),
        items: rows
            .iter()
            .take(20)
            .map(|r| {
                serde_json::from_str(&r.get::<_, String>(1))
                    .map_err(|_| ConversationError::Unavailable)
            })
            .collect::<Result<_, _>>()?,
    })
}
/// Account takeout is owner-authorized ciphertext portability, not a reader or
/// decryption grant. Revoked-reader history remains opaque to the relay.
pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<Uuid>; 2],
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    let result = if installed(&tx).await? {
        Export {
            templates: page(&tx, owner.tenant.account_id(), false, cursors[0]).await?,
            versions: page(&tx, owner.tenant.account_id(), true, cursors[1]).await?,
        }
    } else {
        Export {
            templates: Page {
                items: vec![],
                next_cursor: None,
            },
            versions: Page {
                items: vec![],
                next_cursor: None,
            },
        }
    };
    crate::http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn erase(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(vec![]);
    }
    // Remove the head constraint atomically at account deletion by deferring it.
    let versions = tx
        .execute(
            "DELETE FROM encrypted_template_versions WHERE account_id=$1",
            &[&account],
        )
        .await?;
    let templates = tx
        .execute(
            "DELETE FROM encrypted_templates WHERE account_id=$1",
            &[&account],
        )
        .await?;
    Ok(vec![
        ("encrypted_template_versions", versions),
        ("encrypted_templates", templates),
    ])
}
pub(crate) async fn prune(client: &mut Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    if !installed(&tx).await? {
        return Ok(0);
    }
    let limit = limit.clamp(1, 500);
    // Account before template matches owner erasure; no root lock is requested. Expiry,
    // explicit withdrawal and removed interval erase bodies.
    let accounts=tx.query("SELECT a.id FROM accounts a WHERE EXISTS(SELECT 1 FROM encrypted_templates t WHERE t.account_id=a.id AND t.purged_at IS NULL AND ((t.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR NOT EXISTS(SELECT 1 FROM conversation_intervals i WHERE (i.account_id,i.id)=(t.account_id,t.interval_id) AND i.phase IN ('active','history'))) OR EXISTS(SELECT 1 FROM encrypted_template_versions v WHERE (v.account_id,v.template_id)=(t.account_id,t.id) AND v.envelope IS NOT NULL AND v.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint))) ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT $1",&[&limit]).await?;
    let mut changed = 0;
    for a in accounts {
        let account: Uuid = a.get(0);
        let rows=tx.query("SELECT t.id,(t.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR NOT EXISTS(SELECT 1 FROM conversation_intervals i WHERE (i.account_id,i.id)=(t.account_id,t.interval_id) AND i.phase IN ('active','history'))) FROM encrypted_templates t WHERE t.account_id=$1 AND t.purged_at IS NULL AND ((t.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR NOT EXISTS(SELECT 1 FROM conversation_intervals i WHERE (i.account_id,i.id)=(t.account_id,t.interval_id) AND i.phase IN ('active','history'))) OR EXISTS(SELECT 1 FROM encrypted_template_versions v WHERE (v.account_id,v.template_id)=(t.account_id,t.id) AND v.envelope IS NOT NULL AND v.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint)) ORDER BY t.id FOR UPDATE OF t SKIP LOCKED LIMIT $2",&[&account,&(limit-changed)]).await?;
        for row in rows {
            let id: Uuid = row.get(0);
            let purge: bool = row.get(1);
            tx.execute("UPDATE encrypted_template_versions SET envelope=NULL WHERE account_id=$1 AND template_id=$2 AND ($3 OR expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",&[&account,&id,&purge]).await?;
            if purge {
                tx.execute("UPDATE encrypted_templates SET purged_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&id]).await?;
            }
            changed += 1;
        }
        if changed >= limit {
            break;
        }
    }
    tx.commit().await?;
    Ok(changed as u64)
}
