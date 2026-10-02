// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant encrypted template persistence. The relay never evaluates plaintext.
use crate::auth::SessionPrincipal;
use crate::http_owner_conversations::activation;
use crate::http_owner_conversations::context::authorize_selected_reader;
use crate::http_owner_conversations::{ConversationError, lock_owner};
use crate::sealed_manifest_store::outbound::lock_current;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
pub mod http;
pub(crate) mod lifecycle;
pub mod wire;
const TEMPLATE_LIMIT: i64 = 256;
const ACCOUNT_BYTES: i64 = 8 * 1024 * 1024;
pub async fn write(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    expected_revision: i64,
    envelope: &[u8],
) -> Result<i64, ConversationError> {
    let h = wire::parse(envelope)?;
    if request.is_nil()
        || expected_revision < 0
        || expected_revision.checked_add(1) != Some(h.revision)
        || h.revision > 128
    {
        return Err(ConversationError::Invalid);
    }
    let digest = Sha256::digest(envelope).to_vec();
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    authorize_selected_reader(&tx, owner, &mut authority, &h.authority_scope(), true).await?;
    if let Some(r)=tx.query_opt("SELECT template_id,revision,request_digest FROM encrypted_template_versions WHERE account_id=$1 AND request_id=$2",&[&h.account,&request]).await? {
        if r.get::<_,Uuid>(0)!=h.template || r.get::<_,i64>(1)!=h.revision || r.get::<_,Vec<u8>>(2)!=digest {return Err(ConversationError::Conflict);}
        // A replay cannot report a retained/purged body as a saved live version.
        load(&tx,h.account,h.template,Some(h.revision)).await?;
        authorize_selected_reader(&tx,owner,&mut authority,&h.authority_scope(),true).await?; drop(authority);tx.commit().await?; return Ok(h.revision);
    }
    let row=tx.query_opt("SELECT interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,revision,expires_at_ms,purged_at IS NOT NULL FROM encrypted_templates WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&h.account,&h.template]).await?;
    match row {
        Some(r) => {
            if r.get::<_, Uuid>(0) != h.interval
                || r.get::<_, Uuid>(1) != h.device
                || r.get::<_, Uuid>(2) != h.line
                || r.get::<_, i64>(3) != h.binding_generation
                || r.get::<_, Vec<u8>>(4) != h.peer_digest
                || r.get::<_, Vec<u8>>(5) != h.reader
                || r.get::<_, i64>(6) != h.trust_generation
                || r.get::<_, i64>(7) != expected_revision
                || r.get::<_, i64>(8) <= activation::now(&tx).await?
                || r.get::<_, bool>(9)
            {
                return Err(ConversationError::Conflict);
            }
            tx.execute("UPDATE encrypted_templates SET revision=$3,expires_at_ms=$4 WHERE account_id=$1 AND id=$2",&[&h.account,&h.template,&h.revision,&h.expires_ms]).await?;
        }
        None => {
            if expected_revision != 0 {
                return Err(ConversationError::NotFound);
            }
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM encrypted_templates WHERE account_id=$1",
                    &[&h.account],
                )
                .await?
                .get(0);
            if count >= TEMPLATE_LIMIT {
                return Err(ConversationError::Conflict);
            }
            tx.execute("INSERT INTO encrypted_templates(account_id,id,interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,revision,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                &[&h.account,&h.template,&h.interval,&h.device,&h.line,&h.binding_generation,&h.peer_digest.as_slice(),&h.reader.as_slice(),&h.trust_generation,&h.revision,&h.expires_ms]).await?;
        }
    }
    let bytes:i64=tx.query_one("SELECT COALESCE(sum(octet_length(envelope)),0)::bigint FROM encrypted_template_versions WHERE account_id=$1",&[&h.account]).await?.get(0);
    if bytes + envelope.len() as i64 > ACCOUNT_BYTES {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO encrypted_template_versions(account_id,template_id,id,revision,request_id,request_digest,envelope,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&h.account,&h.template,&Uuid::new_v4(),&h.revision,&request,&digest,&envelope,&h.expires_ms]).await?;
    authorize_selected_reader(&tx, owner, &mut authority, &h.authority_scope(), true).await?;
    drop(authority);
    tx.commit().await?;
    Ok(h.revision)
}

async fn load(
    tx: &Transaction<'_>,
    account: Uuid,
    id: Uuid,
    revision: Option<i64>,
) -> Result<Vec<u8>, ConversationError> {
    let row=tx.query_opt("SELECT v.envelope,v.revision,c.interval_id,c.device_id,c.line_id,c.binding_generation,c.peer_digest,c.reader_key_id,c.trust_generation,v.request_digest FROM encrypted_templates c JOIN encrypted_template_versions v ON (v.account_id,v.template_id)=(c.account_id,c.id) AND v.revision=COALESCE($3,c.revision) WHERE c.account_id=$1 AND c.id=$2 AND c.purged_at IS NULL AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR UPDATE OF c FOR SHARE OF v",&[&account,&id,&revision]).await?.ok_or(ConversationError::NotFound)?;
    let bytes = row
        .get::<_, Option<Vec<u8>>>(0)
        .ok_or(ConversationError::NotFound)?;
    let h = wire::parse(&bytes)?;
    if Sha256::digest(&bytes).as_slice() != row.get::<_, Vec<u8>>(9)
        || h.account != account
        || h.template != id
        || h.revision != row.get::<_, i64>(1)
        || h.interval != row.get::<_, Uuid>(2)
        || h.device != row.get::<_, Uuid>(3)
        || h.line != row.get::<_, Uuid>(4)
        || h.binding_generation != row.get::<_, i64>(5)
        || row.get::<_, Vec<u8>>(6) != h.peer_digest
        || row.get::<_, Vec<u8>>(7) != h.reader
        || h.trust_generation != row.get::<_, i64>(8)
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(bytes)
}

pub async fn read(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
    revision: Option<i64>,
) -> Result<Vec<u8>, ConversationError> {
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    lock_owner(&tx, owner).await?;
    let bytes = load(&tx, owner.tenant.account_id(), id, revision).await?;
    let h = wire::parse(&bytes)?;
    authorize_selected_reader(&tx, owner, &mut authority, &h.authority_scope(), false).await?;
    drop(authority);
    tx.commit().await?;
    Ok(bytes)
}

#[derive(serde::Serialize)]
pub struct Entry {
    pub id: Uuid,
    pub revision: i64,
    pub encrypted_digest_hex: String,
}
#[derive(serde::Serialize)]
pub struct TemplatesPage {
    pub items: Vec<Entry>,
    pub next_cursor: Option<Uuid>,
}
/// Discovery is explicitly scoped to one currently authorized interval. Every
/// returned head is verified against its stored authenticated encrypted header.
pub async fn list(
    client: &mut Client,
    owner: &SessionPrincipal,
    interval: Uuid,
    after: Option<Uuid>,
) -> Result<TemplatesPage, ConversationError> {
    if interval.is_nil() || after.is_some_and(|id| id.is_nil()) {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let account = owner.tenant.account_id();
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    // Even empty lists must validate real owner/session, interval and reader.
    let selected = activation::load(&tx, account, interval).await?;
    if !matches!(selected.phase.as_str(), "active" | "history") {
        return Err(ConversationError::Forbidden);
    }
    let statement = &selected.statement;
    crate::http_owner_conversations::lock_line(
        &tx,
        account,
        statement.device,
        statement.line,
        statement.generation,
    )
    .await?;
    let readers = activation::readers(statement);
    let wanted = activation::wanted(statement, Uuid::new_v4(), &readers);
    authority.snapshot(&wanted).await?;
    let rows=tx.query("SELECT c.id,c.revision,v.request_digest FROM encrypted_templates c JOIN encrypted_template_versions v ON (v.account_id,v.template_id,v.revision)=(c.account_id,c.id,c.revision) WHERE c.account_id=$1 AND c.interval_id=$2 AND c.purged_at IS NULL AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND ($3::uuid IS NULL OR c.id>$3) ORDER BY c.id LIMIT 21 FOR UPDATE OF c FOR SHARE OF v",&[&account,&interval,&after]).await?;
    if let Some(id) = after {
        tx.query_opt(
            "SELECT id FROM encrypted_templates WHERE account_id=$1 AND interval_id=$2 AND id=$3",
            &[&account, &interval, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let mut items = vec![];
    for r in rows.iter().take(20) {
        let id: Uuid = r.get(0);
        let bytes = load(&tx, account, id, None).await?;
        let h = wire::parse(&bytes)?;
        authorize_selected_reader(&tx, owner, &mut authority, &h.authority_scope(), false).await?;
        items.push(Entry {
            id,
            revision: r.get(1),
            encrypted_digest_hex: r
                .get::<_, Vec<u8>>(2)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        });
    }
    crate::http_owner_conversations::fresh_owner(&tx, owner).await?;
    drop(authority);
    tx.commit().await?;
    Ok(TemplatesPage {
        items,
        next_cursor: (rows.len() > 20).then(|| rows[19].get(0)),
    })
}
#[cfg(test)]
mod tests;
