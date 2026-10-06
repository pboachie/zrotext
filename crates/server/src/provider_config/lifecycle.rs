// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{fresh_owner, lock_owner},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool> {
    let row=tx.query_one("SELECT to_regclass('provider_configuration_heads') IS NOT NULL,to_regclass('provider_configuration_versions') IS NOT NULL,to_regclass('provider_configuration_mutations') IS NOT NULL", &[]).await?;
    match (
        row.get::<_, bool>(0),
        row.get::<_, bool>(1),
        row.get::<_, bool>(2),
    ) {
        (false, false, false) => Ok(false),
        (true, true, true) => Ok(true),
        _ => Err(ConversationError::Unavailable),
    }
}
#[derive(Default, Serialize)]
pub struct Page {
    pub items: Vec<Acknowledgment>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Default, Serialize)]
pub struct VersionPage {
    pub items: Vec<VersionMetadata>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize)]
pub struct VersionMetadata {
    config_id: Uuid,
    version: i16,
    declaration_digest: String,
}
#[derive(Default, Serialize)]
pub struct MutationPage {
    pub items: Vec<MutationMetadata>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Serialize)]
pub struct MutationMetadata {
    request_id: Uuid,
    operation: String,
    #[serde(flatten)]
    acknowledgment: Acknowledgment,
}
#[derive(Default, Serialize)]
pub struct Export {
    pub heads: Page,
    pub versions: VersionPage,
    pub mutations: MutationPage,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionCursor {
    config_id: Uuid,
    version: i16,
}
fn cursor(raw: &str) -> Result<VersionCursor> {
    if raw.len() > 128 {
        return Err(ConversationError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ConversationError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != raw {
        return Err(ConversationError::Invalid);
    }
    let value: VersionCursor =
        serde_json::from_slice(&bytes).map_err(|_| ConversationError::Invalid)?;
    if value.config_id.is_nil() || !(1..=model::VERSIONS).contains(&value.version) {
        return Err(ConversationError::Invalid);
    }
    Ok(value)
}
async fn head_page(tx: &Transaction<'_>, account: Uuid, after: Option<Uuid>) -> Result<Page> {
    if let Some(id) = after {
        tx.query_opt(
            "SELECT 1 FROM provider_configuration_heads WHERE account_id=$1 AND config_id=$2",
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query("SELECT config_id,config_version,record_version,state FROM provider_configuration_heads WHERE account_id=$1 AND ($2::uuid IS NULL OR config_id>$2) ORDER BY config_id LIMIT 21 FOR SHARE", &[&account,&after]).await?;
    let next_cursor = rows.get(20).map(|_| rows[19].get(0));
    let items = rows
        .iter()
        .take(20)
        .map(Acknowledgment::row)
        .collect::<Result<Vec<_>>>()?;
    Ok(Page { items, next_cursor })
}
pub(crate) async fn heads(
    client: &mut Client,
    owner: &SessionPrincipal,
    after: Option<Uuid>,
    optional: bool,
) -> Result<Page> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    lock_owner(&tx, owner).await?;
    let result = if installed(&tx).await? {
        head_page(&tx, owner.tenant.account_id(), after).await?
    } else if !optional {
        return Err(ConversationError::Unavailable);
    } else if after.is_some() {
        return Err(ConversationError::NotFound);
    } else {
        Page::default()
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    heads: Option<Uuid>,
    versions: Option<&str>,
    mutations: Option<Uuid>,
) -> Result<Export> {
    let versions = versions.map(cursor).transpose()?;
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx).await? {
        if heads.is_some() || versions.is_some() || mutations.is_some() {
            return Err(ConversationError::NotFound);
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Export::default());
    }
    let account = owner.tenant.account_id();
    let heads = head_page(&tx, account, heads).await?;
    if let Some(c) = &versions {
        tx.query_opt("SELECT 1 FROM provider_configuration_versions WHERE account_id=$1 AND config_id=$2 AND version=$3", &[&account,&c.config_id,&c.version]).await?.ok_or(ConversationError::NotFound)?;
    }
    let id = versions.as_ref().map(|c| c.config_id);
    let version = versions.as_ref().map_or(0, |c| c.version);
    let rows=tx.query("SELECT config_id,version,declaration_digest FROM provider_configuration_versions WHERE account_id=$1 AND ($2::uuid IS NULL OR (config_id,version)>($2,$3::smallint)) ORDER BY config_id,version LIMIT 21 FOR SHARE", &[&account,&id,&version]).await?;
    let next_cursor = if rows.len() > 20 {
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&VersionCursor {
                    config_id: rows[19].get(0),
                    version: rows[19].get(1),
                })
                .map_err(|_| ConversationError::Unavailable)?,
            ),
        )
    } else {
        None
    };
    let versions = VersionPage {
        items: rows
            .iter()
            .take(20)
            .map(|r| VersionMetadata {
                config_id: r.get(0),
                version: r.get(1),
                declaration_digest: URL_SAFE_NO_PAD.encode(r.get::<_, Vec<u8>>(2)),
            })
            .collect(),
        next_cursor,
    };
    if let Some(id) = mutations {
        tx.query_opt(
            "SELECT 1 FROM provider_configuration_mutations WHERE account_id=$1 AND request_id=$2",
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows=tx.query("SELECT config_id,config_version,record_version,state,request_id,operation FROM provider_configuration_mutations WHERE account_id=$1 AND ($2::uuid IS NULL OR request_id>$2) ORDER BY request_id LIMIT 21 FOR SHARE", &[&account,&mutations]).await?;
    let next_cursor = rows.get(20).map(|_| rows[19].get(4));
    let items = rows
        .iter()
        .take(20)
        .map(|r| {
            Ok(MutationMetadata {
                request_id: r.get(4),
                operation: r.get(5),
                acknowledgment: Acknowledgment::row(r)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(Export {
        heads,
        versions,
        mutations: MutationPage { items, next_cursor },
    })
}
/// Called only inside maintained full account erasure, under its real owner/account fence.
pub(crate) async fn erase_account(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>> {
    if !installed(tx).await? {
        return Ok(Vec::new());
    }
    let mut counts = Vec::new();
    for table in [
        "provider_configuration_mutations",
        "provider_configuration_versions",
        "provider_configuration_heads",
    ] {
        let count = tx
            .execute(
                &format!("DELETE FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await?;
        counts.push((table, count));
    }
    Ok(counts)
}
