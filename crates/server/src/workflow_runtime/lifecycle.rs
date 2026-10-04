// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    auth::{self, SessionPrincipal},
    http_owner_conversations::{ConversationError, lock_owner},
};
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub(crate) mod consent;

#[derive(Default, Serialize)]
pub struct Page {
    pub items: Vec<Value>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Default, Serialize)]
pub struct Export {
    pub grants: Page,
    pub envelopes: Page,
    pub access: Page,
}

#[derive(Clone, Copy)]
enum Table {
    Grants,
    Envelopes,
    Access,
}
impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Grants => "workflow_integration_grants",
            Self::Envelopes => "workflow_connector_context_envelopes",
            Self::Access => "workflow_integration_access",
        }
    }
    fn id(self) -> &'static str {
        match self {
            Self::Grants => "grant_id",
            Self::Envelopes | Self::Access => "id",
        }
    }
    fn json(self) -> &'static str {
        match self {
            Self::Grants => "to_jsonb(t)-'credential_hash'",
            Self::Envelopes => {
                "(to_jsonb(t)-'envelope')||jsonb_build_object('envelope_hex',encode(envelope,'hex'))"
            }
            Self::Access => "to_jsonb(t)",
        }
    }
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: Table,
    before: Option<Uuid>,
) -> Result<Page, ConversationError> {
    let name = table.name();
    let id = table.id();
    if let Some(cursor) = before {
        tx.query_opt(
            &format!("SELECT {id} FROM {name} WHERE account_id=$1 AND {id}=$2"),
            &[&account, &cursor],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query(&format!("SELECT {id},({})::text FROM {name} t WHERE account_id=$1 AND ($2::uuid IS NULL OR {id}>$2) ORDER BY {id} LIMIT 21 FOR SHARE",table.json()), &[&account,&before]).await?;
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

/// Owner takeout contains encrypted representations and metadata, never the
/// credential or its verifier. Old-reader export conveys no decryption grant.
pub async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<Uuid>; 3],
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx).await? {
        if cursors.iter().any(Option::is_some) {
            return Err(ConversationError::NotFound);
        }
        return Ok(Export::default());
    }
    let account = owner.tenant.account_id();
    let result = Export {
        grants: page(&tx, account, Table::Grants, cursors[0]).await?,
        envelopes: page(&tx, account, Table::Envelopes, cursors[1]).await?,
        access: page(&tx, account, Table::Access, cursors[2]).await?,
    };
    auth::require_current_owner(&tx, owner)
        .await
        .map_err(|error| match error {
            auth::AuthError::Database(error) => ConversationError::Database(error),
            _ => ConversationError::Forbidden,
        })?;
    tx.commit().await?;
    Ok(result)
}

/// Called within the existing context retention transaction before archive
/// versions are purged. Digest tombstones remain; bytes cannot be restored.
pub async fn scrub_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<u64, tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(0);
    }
    tx.execute("UPDATE workflow_connector_context_envelopes SET envelope=NULL WHERE account_id=$1 AND context_id=$2 AND envelope IS NOT NULL", &[&account,&context]).await
}

/// Called before deleting a retained context version/head. The existing
/// account lock serializes this reduction of authority with workflow effects.
pub async fn erase_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<(), tokio_postgres::Error> {
    super::routines::lifecycle::erase_context(tx, account, context).await?;
    if !installed(tx).await? {
        return Ok(());
    }
    tx.execute("DELETE FROM workflow_integration_access a USING workflow_integration_grants g WHERE (a.account_id,a.grant_id)=(g.account_id,g.grant_id) AND g.account_id=$1 AND g.context_id=$2", &[&account,&context]).await?;
    tx.execute(
        "DELETE FROM workflow_connector_context_envelopes WHERE account_id=$1 AND context_id=$2",
        &[&account, &context],
    )
    .await?;
    tx.execute(
        "DELETE FROM workflow_integration_grants WHERE account_id=$1 AND context_id=$2",
        &[&account, &context],
    )
    .await?;
    Ok(())
}

/// Bounded expiry/revocation scrub. Removing old records is handled alongside
/// their source context so replay identities cannot become reusable grants.
pub async fn prune(client: &mut Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    let routine_changes = super::routines::lifecycle::prune(client, limit).await?
        + crate::original_reply::lifecycle::prune(client, limit).await?;
    let tx = client.transaction().await?;
    if !installed(&tx).await? {
        return Ok(routine_changes);
    }
    let limit = limit.clamp(1, 500);
    let accounts = tx.query(&format!("SELECT a.id FROM accounts a WHERE EXISTS(SELECT 1 {CANDIDATE_FROM} AND g.account_id=a.id) ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT $1"), &[&limit]).await?;
    let mut changed = 0;
    for row in accounts {
        if changed >= limit as u64 {
            break;
        }
        let account: Uuid = row.get(0);
        let grants = tx.query(&format!("SELECT g.grant_id {CANDIDATE_FROM} AND g.account_id=$1 ORDER BY g.grant_id FOR UPDATE OF g SKIP LOCKED LIMIT $2"), &[&account, &(limit-changed as i64)]).await?;
        for grant in grants {
            let grant: Uuid = grant.get(0);
            tx.execute("UPDATE workflow_integration_grants SET revoked_ms=COALESCE(revoked_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND grant_id=$2", &[&account,&grant]).await?;
            tx.execute("UPDATE workflow_connector_context_envelopes SET envelope=NULL WHERE account_id=$1 AND grant_id=$2 AND envelope IS NOT NULL", &[&account,&grant]).await?;
            changed += 1;
        }
    }
    tx.commit().await?;
    Ok(changed + routine_changes)
}

/// Optional housekeeping only; authentication always requires the real schema.
pub async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_one(
            "SELECT to_regclass('workflow_integration_grants') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

const CANDIDATE_FROM: &str = r#" FROM workflow_integration_grants g              JOIN workflow_contexts c ON (c.account_id,c.id)=(g.account_id,g.context_id)              JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id)              WHERE EXISTS(SELECT 1 FROM workflow_connector_context_envelopes e WHERE e.account_id=g.account_id AND e.grant_id=g.grant_id AND e.envelope IS NOT NULL)              AND (g.revoked_ms IS NOT NULL OR g.expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint                  OR c.purged_at IS NOT NULL OR c.revision<>g.context_revision OR c.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR i.phase IN ('withdrawn','expired')                  OR NOT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id)                      WHERE (s.account_id,s.user_id,s.id)=(g.account_id,g.created_by_user,g.created_session) AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()                      AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND m.role='owner' AND m.revoked_at IS NULL)                  OR NOT EXISTS(SELECT 1 FROM connector_registrations r JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id)                      WHERE (r.account_id,r.connector_id,r.key_id)=(g.account_id,g.connector_id,g.reader_key_id) AND r.state='active' AND k.retired_ms IS NULL                      AND r.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint))  "#;

/// Contact erasure removes only grants bound to that account and contact.
/// The caller holds the existing owner/account lock in the same transaction.
pub async fn erase_contact(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
) -> Result<(), tokio_postgres::Error> {
    super::routines::lifecycle::erase_contact(tx, account, contact).await?;
    if !installed(tx).await? {
        return Ok(());
    }
    for table in [
        "workflow_integration_access",
        "workflow_connector_context_envelopes",
    ] {
        tx.execute(&format!("DELETE FROM {table} t USING workflow_integration_grants g WHERE (t.account_id,t.grant_id)=(g.account_id,g.grant_id) AND g.account_id=$1 AND g.contact_id=$2"), &[&account, &contact]).await?;
    }
    tx.execute(
        "DELETE FROM workflow_integration_grants WHERE account_id=$1 AND contact_id=$2",
        &[&account, &contact],
    )
    .await?;
    Ok(())
}
