// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit ciphertext drafting grants. Membership, owner authority and agent
//! permissions are independent; this module never decrypts or sends a draft.
use super::{AuthError, SessionPrincipal, TokenHasher, account, mfa::MfaCipher};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;

pub const ROLE: &str = "encrypted_drafter";
pub const MAX_CIPHERTEXT_BYTES: usize = 8192;
pub const MAX_LIVE_DRAFTS: i64 = 20;
pub const MAX_DRAFT_IDS: i64 = 100;
pub const MAX_GRANTS: i64 = 100;
pub const PAGE_SIZE: i64 = 20;

#[derive(Serialize)]
pub struct GrantView {
    pub grant_id: Uuid,
    pub user_id: Uuid,
    pub role: &'static str,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Serialize)]
pub struct DraftView {
    pub draft_id: Uuid,
    pub grant_id: Uuid,
    pub author_user_id: Uuid,
    pub ciphertext_base64: Option<String>,
    pub created_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

fn grant_view(row: Row) -> GrantView {
    GrantView {
        grant_id: row.get(0),
        user_id: row.get(1),
        role: ROLE,
        created_at_ms: row.get(2),
        revoked_at_ms: row.get(3),
    }
}
fn draft_view(row: Row) -> DraftView {
    DraftView {
        draft_id: row.get(0),
        grant_id: row.get(1),
        author_user_id: row.get(2),
        ciphertext_base64: row
            .get::<_, Option<Vec<u8>>>(3)
            .map(|bytes| STANDARD.encode(bytes)),
        created_at_ms: row.get(4),
        deleted_at_ms: row.get(5),
    }
}

pub fn decode_ciphertext(encoded: &str) -> Result<Vec<u8>, AuthError> {
    if encoded.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err(AuthError::InvalidInput);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| AuthError::InvalidInput)?;
    // An opaque AEAD artifact needs room for a nonce and authentication tag.
    // The server cannot prove encryption or authenticity and does not claim to.
    if !(28..=MAX_CIPHERTEXT_BYTES).contains(&bytes.len()) || STANDARD.encode(&bytes) != encoded {
        return Err(AuthError::InvalidInput);
    }
    Ok(bytes)
}

/// Lock and recheck current database authority, including after lock waits.
/// No bearer/API key or cached SessionPrincipal can satisfy this fence alone.
async fn member_fence(tx: &Transaction<'_>, member: &SessionPrincipal) -> Result<(), AuthError> {
    tx.query_opt("SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id JOIN sessions s ON (s.account_id,s.user_id)=(m.account_id,m.user_id) JOIN accounts a ON a.id=m.account_id WHERE s.id=$1 AND u.id=$2 AND a.id=$3 AND m.revoked_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL FOR SHARE OF u,m,s,a", &[&member.session_id,&member.user_id,&member.tenant.account_id()]).await?.ok_or(AuthError::Unauthorized)?;
    super::require_current_member(tx, member).await
}
async fn owner_fence(tx: &Transaction<'_>, owner: &SessionPrincipal) -> Result<(), AuthError> {
    member_fence(tx, owner).await?;
    super::require_current_owner(tx, owner).await
}
async fn draft_fence(tx: &Transaction<'_>, member: &SessionPrincipal) -> Result<Uuid, AuthError> {
    member_fence(tx, member).await?;
    let row=tx.query_opt("SELECT id FROM collaboration_draft_grants WHERE account_id=$1 AND user_id=$2 AND role='encrypted_drafter' AND revoked_at IS NULL FOR UPDATE", &[&member.tenant.account_id(),&member.user_id]).await?.ok_or(AuthError::Forbidden)?;
    // A lock wait must not turn an expired session into a valid draft grant.
    super::require_current_member(tx, member).await?;
    Ok(row.get(0))
}

// The initial locks order revocation against the operation, but wall-clock
// expiry can still pass during a later query/write. Check again before any
// mutation commits or any buffered ciphertext leaves the transaction.
async fn commit_member(tx: Transaction<'_>, member: &SessionPrincipal) -> Result<(), AuthError> {
    super::require_current_member(&tx, member).await?;
    tx.commit().await?;
    Ok(())
}
async fn commit_owner(tx: Transaction<'_>, owner: &SessionPrincipal) -> Result<(), AuthError> {
    super::require_current_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(())
}

/// Canonical composite position, scoped by the owner's account in SQL.
pub fn decode_export_cursor(value: Option<&str>) -> Result<Option<(Uuid, Uuid)>, AuthError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() != 73 {
        return Err(AuthError::InvalidInput);
    }
    let (draft, author) = value.split_once(':').ok_or(AuthError::InvalidInput)?;
    let draft = Uuid::parse_str(draft).map_err(|_| AuthError::InvalidInput)?;
    let author = Uuid::parse_str(author).map_err(|_| AuthError::InvalidInput)?;
    if draft.is_nil() || author.is_nil() || format!("{draft}:{author}") != value {
        return Err(AuthError::InvalidInput);
    }
    Ok(Some((draft, author)))
}

pub struct GrantRequest<'a> {
    pub target: Uuid,
    pub confirmed: bool,
    pub password: &'a str,
    pub code: Option<&'a str>,
}
pub async fn grant_with_proof(
    client: &mut Client,
    cipher: Option<&MfaCipher>,
    hasher: &TokenHasher,
    owner: &SessionPrincipal,
    request: GrantRequest<'_>,
) -> Result<GrantView, AuthError> {
    let target = request.target;
    if !request.confirmed || target.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let tx = account::begin_owner_step_up(
        client,
        cipher,
        hasher,
        owner,
        request.password,
        request.code,
    )
    .await?;
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&owner.tenant.account_id()],
    )
    .await?;
    super::require_current_owner(&tx, owner).await?;
    tx.query_opt("SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.account_id=$1 AND m.user_id=$2 AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE OF m,u", &[&owner.tenant.account_id(),&target]).await?.ok_or(AuthError::Forbidden)?;
    if let Some(row)=tx.query_opt("SELECT id,user_id,(extract(epoch FROM created_at)*1000)::bigint,NULL::bigint FROM collaboration_draft_grants WHERE account_id=$1 AND user_id=$2 AND revoked_at IS NULL", &[&owner.tenant.account_id(),&target]).await? {commit_owner(tx, owner).await?;return Ok(grant_view(row));}
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM collaboration_draft_grants WHERE account_id=$1",
            &[&owner.tenant.account_id()],
        )
        .await?
        .get(0);
    if count >= MAX_GRANTS {
        return Err(AuthError::RateLimited);
    }
    let row=tx.query_one("INSERT INTO collaboration_draft_grants(id,account_id,user_id,role) VALUES($1,$2,$3,'encrypted_drafter') RETURNING id,user_id,(extract(epoch FROM created_at)*1000)::bigint,NULL::bigint", &[&Uuid::new_v4(),&owner.tenant.account_id(),&target]).await?;
    let view = grant_view(row);
    commit_owner(tx, owner).await?;
    Ok(view)
}

pub async fn revoke(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
) -> Result<bool, AuthError> {
    let tx = client.transaction().await?;
    owner_fence(&tx, owner).await?;
    let row=tx.query_opt("UPDATE collaboration_draft_grants SET revoked_at=coalesce(revoked_at,clock_timestamp()) WHERE account_id=$1 AND id=$2 RETURNING id", &[&owner.tenant.account_id(),&id]).await?;
    if row.is_some() {
        tx.execute("UPDATE collaboration_drafts SET ciphertext=NULL,deleted_at=coalesce(deleted_at,clock_timestamp()) WHERE account_id=$1 AND grant_id=$2", &[&owner.tenant.account_id(),&id]).await?;
    }
    commit_owner(tx, owner).await?;
    Ok(row.is_some())
}

pub async fn create(
    client: &mut Client,
    member: &SessionPrincipal,
    id: Uuid,
    bytes: Vec<u8>,
) -> Result<(DraftView, bool), AuthError> {
    if id.is_nil() || !(28..=MAX_CIPHERTEXT_BYTES).contains(&bytes.len()) {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    let grant = draft_fence(&tx, member).await?;
    let digest = Sha256::digest(&bytes).to_vec();
    if let Some(row)=tx.query_opt("SELECT id,grant_id,user_id,ciphertext,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM deleted_at)*1000)::bigint,ciphertext_digest FROM collaboration_drafts WHERE account_id=$1 AND user_id=$2 AND id=$3", &[&member.tenant.account_id(),&member.user_id,&id]).await?{
        if row.get::<_,Uuid>(1)!=grant || row.get::<_,Option<i64>>(5).is_some() || row.get::<_,Vec<u8>>(6)!=digest{return Err(AuthError::Conflict);}
        let view=draft_view(row);commit_member(tx, member).await?;return Ok((view,false));
    }
    let row=tx.query_one("SELECT count(*),count(*) FILTER(WHERE deleted_at IS NULL) FROM collaboration_drafts WHERE account_id=$1 AND grant_id=$2", &[&member.tenant.account_id(),&grant]).await?;
    if row.get::<_, i64>(0) >= MAX_DRAFT_IDS || row.get::<_, i64>(1) >= MAX_LIVE_DRAFTS {
        return Err(AuthError::RateLimited);
    }
    let row=tx.query_one("INSERT INTO collaboration_drafts(id,account_id,user_id,grant_id,ciphertext,ciphertext_digest) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,grant_id,user_id,ciphertext,(extract(epoch FROM created_at)*1000)::bigint,NULL::bigint", &[&id,&member.tenant.account_id(),&member.user_id,&grant,&bytes,&digest]).await?;
    let view = draft_view(row);
    commit_member(tx, member).await?;
    Ok((view, true))
}

pub async fn own_drafts(
    client: &mut Client,
    member: &SessionPrincipal,
    id: Option<Uuid>,
) -> Result<Vec<DraftView>, AuthError> {
    let tx = client.transaction().await?;
    let grant = draft_fence(&tx, member).await?;
    let rows=tx.query("SELECT id,grant_id,user_id,ciphertext,(extract(epoch FROM created_at)*1000)::bigint,NULL::bigint FROM collaboration_drafts WHERE account_id=$1 AND user_id=$2 AND grant_id=$3 AND deleted_at IS NULL AND($4::uuid IS NULL OR id=$4) ORDER BY id LIMIT 20", &[&member.tenant.account_id(),&member.user_id,&grant,&id]).await?;
    let views = rows.into_iter().map(draft_view).collect();
    commit_member(tx, member).await?;
    Ok(views)
}
pub async fn delete_own(
    client: &mut Client,
    member: &SessionPrincipal,
    id: Uuid,
) -> Result<(), AuthError> {
    let tx = client.transaction().await?;
    let grant = draft_fence(&tx, member).await?;
    tx.execute("UPDATE collaboration_drafts SET ciphertext=NULL,deleted_at=coalesce(deleted_at,clock_timestamp()) WHERE account_id=$1 AND user_id=$2 AND grant_id=$3 AND id=$4", &[&member.tenant.account_id(),&member.user_id,&grant,&id]).await?;
    commit_member(tx, member).await?;
    Ok(())
}

#[derive(Serialize)]
pub struct ExportPage {
    pub grants: Vec<GrantView>,
    pub drafts: Vec<DraftView>,
    pub drafts_truncated: bool,
    pub next_cursor: Option<String>,
}
pub async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    before: Option<(Uuid, Uuid)>,
) -> Result<ExportPage, AuthError> {
    let tx = client.transaction().await?;
    owner_fence(&tx, owner).await?;
    let grants=tx.query("SELECT id,user_id,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM revoked_at)*1000)::bigint FROM collaboration_draft_grants WHERE account_id=$1 ORDER BY id LIMIT 100", &[&owner.tenant.account_id()]).await?.into_iter().map(grant_view).collect();
    let before_id = before.map(|position| position.0);
    let before_author = before.map(|position| position.1);
    let rows=tx.query("SELECT id,grant_id,user_id,ciphertext,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM deleted_at)*1000)::bigint FROM collaboration_drafts WHERE account_id=$1 AND($2::uuid IS NULL OR (id,user_id)<($2,$3::uuid)) ORDER BY id DESC,user_id DESC LIMIT 21", &[&owner.tenant.account_id(),&before_id,&before_author]).await?;
    let truncated = rows.len() > PAGE_SIZE as usize;
    let drafts: Vec<_> = rows
        .into_iter()
        .take(PAGE_SIZE as usize)
        .map(draft_view)
        .collect();
    let next_cursor = if truncated {
        drafts
            .last()
            .map(|draft| format!("{}:{}", draft.draft_id, draft.author_user_id))
    } else {
        None
    };
    commit_owner(tx, owner).await?;
    Ok(ExportPage {
        grants,
        drafts,
        drafts_truncated: truncated,
        next_cursor,
    })
}

pub async fn list_grants(
    client: &mut Client,
    owner: &SessionPrincipal,
) -> Result<Vec<GrantView>, AuthError> {
    let tx = client.transaction().await?;
    owner_fence(&tx, owner).await?;
    let rows=tx.query("SELECT id,user_id,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM revoked_at)*1000)::bigint FROM collaboration_draft_grants WHERE account_id=$1 ORDER BY id LIMIT 100", &[&owner.tenant.account_id()]).await?;
    let views = rows.into_iter().map(grant_view).collect();
    commit_owner(tx, owner).await?;
    Ok(views)
}
