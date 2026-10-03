// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{ConversationError, fresh_owner, lock_owner},
};
use serde::Serialize;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub(crate) const TABLES: [&str; 6] = [
    "managed_reader_events",
    "managed_reader_selections",
    "managed_reader_grant_versions",
    "managed_reader_grants",
    "managed_reader_policies",
    "managed_reader_keys",
];
pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM unnest($1::text[]) t(name) WHERE to_regclass(name) IS NOT NULL",
            &[&TABLES.as_slice()],
        )
        .await?
        .get(0);
    if count != 0 && count != 6 {
        // A partly installed proposal must fail closed, including erasure counts.
        tx.batch_execute(
            "DO $$ BEGIN RAISE EXCEPTION 'incomplete managed reader proposal'; END $$",
        )
        .await?;
    }
    Ok(count == 6)
}

/// Called inside the existing contact-consent transaction, under its account
/// and contact locks. Expired grants are also permanently withdrawn.
pub(crate) async fn withdraw(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
    purpose: &str,
) -> Result<(), tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(());
    }
    let rows = tx.query("SELECT id,current_version FROM managed_reader_grants WHERE account_id=$1 AND contact_id=$2 AND purpose=$3 AND revoked_ms IS NULL ORDER BY id FOR UPDATE", &[&account,&contact,&purpose]).await?;
    for r in rows {
        let id: Uuid = r.get(0);
        let version: i64 = r.get(1);
        tx.execute("UPDATE managed_reader_grants SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint,revocation_generation=1 WHERE account_id=$1 AND id=$2", &[&account,&id]).await?;
        tx.execute("INSERT INTO managed_reader_events(account_id,id,grant_id,grant_version,operation,created_ms) VALUES($1,$2,$3,$4,'withdraw',floor(extract(epoch FROM clock_timestamp())*1000)::bigint)", &[&account,&Uuid::new_v4(),&id,&version]).await?;
    }
    Ok(())
}

#[derive(Default, Serialize)]
pub(crate) struct Page {
    items: Vec<serde_json::Value>,
    next_cursor: Option<String>,
}
#[derive(Default, Serialize)]
pub(crate) struct Export {
    events: Page,
    selections: Page,
    versions: Page,
    grants: Page,
    policies: Page,
    readers: Page,
}
async fn page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: &str,
    suffix: Option<&str>,
    after: Option<&str>,
) -> Result<Page, ConversationError> {
    if after.is_some_and(|v| {
        v.len() > 80
            || !v
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b':')
    }) {
        return Err(ConversationError::Invalid);
    }
    // Both SQL identifiers come exclusively from this module's constants.
    let key = suffix.map_or_else(
        || "id::text".to_owned(),
        |column| format!("id::text||':'||{column}::text"),
    );
    let rows = tx.query(&format!("SELECT to_jsonb(r)::text,{key} AS cursor FROM {table} r WHERE account_id=$1 AND ($2::text IS NULL OR ({key})>$2) ORDER BY cursor LIMIT 21"), &[&account,&after]).await?;
    let next_cursor = if rows.len() > 20 {
        Some(rows[19].get(1))
    } else {
        None
    };
    Ok(Page {
        items: rows
            .iter()
            .take(20)
            .map(|r| {
                serde_json::from_str(&r.get::<_, String>(0))
                    .map_err(|_| ConversationError::Unavailable)
            })
            .collect::<Result<_, _>>()?,
        next_cursor,
    })
}
pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    cursors: [Option<String>; 6],
) -> Result<Export, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx).await? {
        if cursors.iter().any(Option::is_some) {
            return Err(ConversationError::NotFound);
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Export::default());
    }
    let account = owner.tenant.account_id();
    let result = Export {
        events: page(&tx, account, TABLES[0], None, cursors[0].as_deref()).await?,
        selections: page(&tx, account, TABLES[1], None, cursors[1].as_deref()).await?,
        versions: page(&tx, account, TABLES[2], None, cursors[2].as_deref()).await?,
        grants: page(&tx, account, TABLES[3], None, cursors[3].as_deref()).await?,
        policies: page(
            &tx,
            account,
            TABLES[4],
            Some("version"),
            cursors[4].as_deref(),
        )
        .await?,
        readers: page(
            &tx,
            account,
            TABLES[5],
            Some("generation"),
            cursors[5].as_deref(),
        )
        .await?,
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
