// SPDX-License-Identifier: AGPL-3.0-only
//! Proposed owner-entered workflow context. No main-mounted route or external effects.
use super::{ConversationError, SessionPrincipal, activation, fresh_owner, lock_line, lock_owner};
use crate::sealed_manifest_store::outbound::{CurrentAuthority, lock_current};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod decisions;
pub mod http;
pub(crate) mod lifecycle;
pub mod wire;
const CONTEXT_LIMIT: i64 = 1000;
const ACCOUNT_BYTES: i64 = 8 * 1024 * 1024;
const EXCEPTION_LIMIT: i64 = 32;
const AUDIT_LIMIT: i64 = 8192;

#[derive(Clone)]
pub(crate) struct SelectedReaderScope {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub interval: Uuid,
    pub context: Uuid,
    pub binding_generation: i64,
    pub expires_ms: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
    pub peer_digest: [u8; 32],
    pub reader: [u8; 32],
    pub manifest_digest: [u8; 32],
}
async fn authorize(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    h: &wire::Header,
    writing: bool,
) -> Result<(), ConversationError> {
    authorize_selected_reader(
        tx,
        owner,
        authority,
        &SelectedReaderScope {
            account: h.account,
            device: h.device,
            line: h.line,
            interval: h.interval,
            context: h.context,
            binding_generation: h.binding_generation,
            expires_ms: h.expires_ms,
            trust_generation: h.trust_generation,
            manifest_version: h.manifest_version,
            peer_digest: h.peer_digest,
            reader: h.reader,
            manifest_digest: h.manifest_digest,
        },
        writing,
    )
    .await
}
pub(crate) async fn authorize_selected_reader(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    h: &SelectedReaderScope,
    writing: bool,
) -> Result<(), ConversationError> {
    if h.account != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    lock_owner(tx, owner).await?;
    let interval = activation::load(tx, h.account, h.interval).await?;
    if if writing {
        interval.phase != "active"
    } else {
        !matches!(interval.phase.as_str(), "active" | "history")
    } {
        return Err(ConversationError::Forbidden);
    }
    let s = interval.statement;
    if (s.device, s.line, s.generation, s.trust_generation, s.reader)
        != (
            h.device,
            h.line,
            h.binding_generation,
            h.trust_generation,
            h.reader,
        )
        || Sha256::digest(s.peer.as_bytes()).as_slice() != h.peer_digest
    {
        return Err(ConversationError::Forbidden);
    }
    lock_line(tx, h.account, h.device, h.line, h.binding_generation).await?;
    let readers = activation::readers(&s);
    let wanted = activation::wanted(&s, h.context, &readers);
    let current = authority.snapshot(&wanted).await?;
    if (current.generation, current.version, current.digest)
        != (h.trust_generation, h.manifest_version, h.manifest_digest)
    {
        return Err(ConversationError::Forbidden);
    }
    let now = activation::now(tx).await?;
    if now >= h.expires_ms || h.expires_ms.saturating_sub(now) > 30 * 86_400_000 {
        return Err(ConversationError::Forbidden);
    }
    if writing {
        // An active row alone cannot outlive the approval's owner-session fence.
        activation::origin(tx, &s).await?;
    }
    fresh_owner(tx, owner).await
}

async fn audit(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    scope: (Uuid, Uuid),
    revision: i64,
    request: Uuid,
    operation: i16,
    digest: &[u8],
) -> Result<(), ConversationError> {
    let (context, subject) = scope;
    let account = owner.tenant.account_id();
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_context_audit WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= AUDIT_LIMIT {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_context_audit(account_id,context_id,id,operation,subject_id,revision,request_id,request_digest,actor_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[&account,&context,&Uuid::new_v4(),&operation,&subject,&revision,&request,&digest,&owner.user_id]).await?;
    Ok(())
}

/// Exact retries cannot rewrite bytes, advance versions or rehydrate retention tombstones.
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
    authorize(&tx, owner, &mut authority, &h, true).await?;
    if let Some(r)=tx.query_opt("SELECT context_id,revision,request_digest FROM workflow_context_versions WHERE account_id=$1 AND request_id=$2",&[&h.account,&request]).await? {
        if r.get::<_,Uuid>(0)!=h.context || r.get::<_,i64>(1)!=h.revision || r.get::<_,Vec<u8>>(2)!=digest {return Err(ConversationError::Conflict);}
        authorize(&tx,owner,&mut authority,&h,true).await?; drop(authority);tx.commit().await?; return Ok(h.revision);
    }
    let row=tx.query_opt("SELECT interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,kind,revision,expires_at_ms,purged_at IS NOT NULL FROM workflow_contexts WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&h.account,&h.context]).await?;
    match row {
        Some(r) => {
            if r.get::<_, Uuid>(0) != h.interval
                || r.get::<_, Uuid>(1) != h.device
                || r.get::<_, Uuid>(2) != h.line
                || r.get::<_, i64>(3) != h.binding_generation
                || r.get::<_, Vec<u8>>(4) != h.peer_digest
                || r.get::<_, Vec<u8>>(5) != h.reader
                || r.get::<_, i64>(6) != h.trust_generation
                || r.get::<_, i16>(7) != i16::from(h.kind)
                || r.get::<_, i64>(8) != expected_revision
                || r.get::<_, i64>(9) <= activation::now(&tx).await?
                || r.get::<_, bool>(10)
            {
                return Err(ConversationError::Conflict);
            }
            tx.execute("UPDATE workflow_contexts SET revision=$3,expires_at_ms=$4 WHERE account_id=$1 AND id=$2",&[&h.account,&h.context,&h.revision,&h.expires_ms]).await?;
        }
        None => {
            if expected_revision != 0 {
                return Err(ConversationError::NotFound);
            }
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM workflow_contexts WHERE account_id=$1",
                    &[&h.account],
                )
                .await?
                .get(0);
            if count >= CONTEXT_LIMIT {
                return Err(ConversationError::Conflict);
            }
            tx.execute("INSERT INTO workflow_contexts(account_id,id,interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,kind,revision,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[&h.account,&h.context,&h.interval,&h.device,&h.line,&h.binding_generation,&h.peer_digest.as_slice(),&h.reader.as_slice(),&h.trust_generation,&i16::from(h.kind),&h.revision,&h.expires_ms]).await?;
        }
    }
    let bytes:i64=tx.query_one("SELECT COALESCE(sum(octet_length(envelope)),0)::bigint FROM workflow_context_versions WHERE account_id=$1",&[&h.account]).await?.get(0);
    if bytes + envelope.len() as i64 > ACCOUNT_BYTES {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_context_versions(account_id,context_id,id,revision,request_id,request_digest,envelope) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&h.account,&h.context,&Uuid::new_v4(),&h.revision,&request,&digest,&envelope]).await?;
    audit(
        &tx,
        owner,
        (h.context, h.context),
        h.revision,
        request,
        1,
        &digest,
    )
    .await?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
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
    let row=tx.query_opt("SELECT v.envelope,v.revision,c.interval_id,c.device_id,c.line_id,c.binding_generation,c.peer_digest,c.reader_key_id,c.trust_generation,c.kind FROM workflow_contexts c JOIN workflow_context_versions v ON (v.account_id,v.context_id)=(c.account_id,c.id) AND v.revision=COALESCE($3,c.revision) WHERE c.account_id=$1 AND c.id=$2 AND c.purged_at IS NULL AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR UPDATE OF c FOR SHARE OF v",&[&account,&id,&revision]).await?.ok_or(ConversationError::NotFound)?;
    let bytes = row
        .get::<_, Option<Vec<u8>>>(0)
        .ok_or(ConversationError::NotFound)?;
    let h = wire::parse(&bytes)?;
    if h.account != account
        || h.context != id
        || h.revision != row.get::<_, i64>(1)
        || h.interval != row.get::<_, Uuid>(2)
        || h.device != row.get::<_, Uuid>(3)
        || h.line != row.get::<_, Uuid>(4)
        || h.binding_generation != row.get::<_, i64>(5)
        || row.get::<_, Vec<u8>>(6) != h.peer_digest
        || row.get::<_, Vec<u8>>(7) != h.reader
        || h.trust_generation != row.get::<_, i64>(8)
        || i16::from(h.kind) != row.get::<_, i16>(9)
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(bytes)
}

/// Load only the current immutable head and authorize the actual archive reader.
/// Grant references intentionally do not keep purged archive bytes alive.
pub(crate) async fn managed_grant_source(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    id: Uuid,
    revision: i64,
    digest: &[u8; 32],
) -> Result<(wire::Header, i64), ConversationError> {
    let bytes = load(tx, owner.tenant.account_id(), id, None).await?;
    let header = wire::parse(&bytes)?;
    if header.revision != revision || Sha256::digest(&bytes).as_slice() != digest {
        return Err(ConversationError::Forbidden);
    }
    authorize(tx, owner, authority, &header, true).await?;
    let interval = activation::load(tx, header.account, header.interval).await?;
    let readers = activation::readers(&interval.statement);
    let wanted = activation::wanted(&interval.statement, header.context, &readers);
    let deadline = authority
        .admission_deadline(&wanted)
        .await?
        .min(header.expires_ms)
        .min(interval.statement.expires_ms);
    Ok((header, deadline))
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
    authorize(&tx, owner, &mut authority, &h, false).await?;
    drop(authority);
    tx.commit().await?;
    Ok(bytes)
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionInput {
    pub context_id: Uuid,
    pub context_revision: i64,
    pub source_kind: i16,
    pub source_id: Uuid,
    pub reason: i16,
}
impl ExceptionInput {
    fn digest(self, account: Uuid) -> Result<Vec<u8>, ConversationError> {
        // 1 ambiguous client reply, 2 unknown, 3 expired, 4 cancelled, 5 client approval mismatch.
        if self.context_id.is_nil()
            || self.source_id.is_nil()
            || self.context_revision <= 0
            || !matches!((self.source_kind, self.reason), (1, 1 | 5) | (2, 2..=4))
        {
            return Err(ConversationError::Invalid);
        }
        let mut b = b"ZT/workflow-exception/v1\0".to_vec();
        for id in [account, self.context_id, self.source_id] {
            b.extend(id.as_bytes());
        }
        b.extend(self.context_revision.to_be_bytes());
        b.extend(self.source_kind.to_be_bytes());
        b.extend(self.reason.to_be_bytes());
        Ok(Sha256::digest(b).to_vec())
    }
}
fn exception_id(account: Uuid, input: ExceptionInput) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"ZT/workflow-exception/id/v1\0");
    for id in [account, input.context_id, input.source_id] {
        hash.update(id.as_bytes());
    }
    hash.update(input.source_kind.to_be_bytes());
    hash.update(input.reason.to_be_bytes());
    let mut id: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    id[6] = (id[6] & 15) | 0x80;
    id[8] = (id[8] & 63) | 0x80;
    Uuid::from_bytes(id)
}

/// The relay verifies source provenance/state only. It does not classify plaintext replies.
pub async fn exception(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: ExceptionInput,
) -> Result<Uuid, ConversationError> {
    let account = owner.tenant.account_id();
    let digest = input.digest(account)?;
    let id = exception_id(account, input);
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    let bytes = load(&tx, account, input.context_id, Some(input.context_revision)).await?;
    let h = wire::parse(&bytes)?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    if let Some(r) = tx
        .query_opt(
            "SELECT request_digest FROM workflow_exceptions WHERE account_id=$1 AND id=$2",
            &[&account, &id],
        )
        .await?
    {
        if r.get::<_, Vec<u8>>(0) != digest {
            return Err(ConversationError::Conflict);
        }
        authorize(&tx, owner, &mut authority, &h, true).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(id);
    }
    let current: i64 = tx
        .query_one(
            "SELECT revision FROM workflow_contexts WHERE account_id=$1 AND id=$2",
            &[&account, &input.context_id],
        )
        .await?
        .get(0);
    if current != input.context_revision {
        return Err(ConversationError::Conflict);
    }
    if input.source_kind == 1 {
        tx.query_opt("SELECT p.event_id FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND p.interval_id=$3 AND e.device_id=$4 AND e.line_id=$5 AND e.binding_generation=$6 FOR SHARE OF p,e",&[&account,&input.source_id,&h.interval,&h.device,&h.line,&h.binding_generation]).await?.ok_or(ConversationError::NotFound)?;
    } else {
        let state = match input.reason {
            2 => "unknown",
            3 => "expired",
            4 => "cancelled",
            _ => return Err(ConversationError::Invalid),
        };
        let r=tx.query_opt("SELECT recipient_e164 FROM messages WHERE account_id=$1 AND id=$2 AND device_id=$3 AND sealed_line_id=$4 AND sealed_binding_generation=$5 AND transport_mode='sealed_candidate02' AND state=$6 FOR SHARE",&[&account,&input.source_id,&h.device,&h.line,&h.binding_generation,&state]).await?.ok_or(ConversationError::NotFound)?;
        let peer: Option<String> = r.get(0);
        if peer
            .map(|p| Sha256::digest(p.as_bytes()).to_vec())
            .as_deref()
            != Some(h.peer_digest.as_slice())
        {
            return Err(ConversationError::NotFound);
        }
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_exceptions WHERE account_id=$1 AND context_id=$2",
            &[&account, &input.context_id],
        )
        .await?
        .get(0);
    if count >= EXCEPTION_LIMIT {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&account,&input.context_id,&id,&input.context_revision,&input.source_kind,&input.source_id,&input.reason,&digest]).await?;
    audit(&tx, owner, (h.context, id), 1, id, 2, &digest).await?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    drop(authority);
    tx.commit().await?;
    Ok(id)
}

pub async fn resolve(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
    request: Uuid,
    expected_revision: i64,
) -> Result<i64, ConversationError> {
    if request.is_nil() || expected_revision != 1 {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    let r=tx.query_opt("SELECT context_id,context_revision,revision,resolution_request_id FROM workflow_exceptions WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&account,&id]).await?.ok_or(ConversationError::NotFound)?;
    let context: Uuid = r.get(0);
    let bytes = load(&tx, account, context, None).await?;
    let h = wire::parse(&bytes)?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    if r.get::<_, i64>(2) == 2 {
        if r.get::<_, Option<Uuid>>(3) != Some(request) {
            return Err(ConversationError::Conflict);
        }
    } else {
        tx.execute("UPDATE workflow_exceptions SET revision=2,state='resolved',resolution_request_id=$3,resolved_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&id,&request]).await?;
        let mut digest = Sha256::new();
        digest.update(b"ZT/workflow-exception/resolve/v1\0");
        digest.update(id.as_bytes());
        digest.update(request.as_bytes());
        audit(&tx, owner, (context, id), 2, request, 3, &digest.finalize()).await?;
    }
    authorize(&tx, owner, &mut authority, &h, true).await?;
    drop(authority);
    tx.commit().await?;
    Ok(2)
}

#[cfg(test)]
pub(crate) mod tests;
