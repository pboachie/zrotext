// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated agent credentials never become an ordinary API principal.

use super::{ApiPrincipal, AuthError, Scope, Tenant, TokenHasher, valid_token};
use crate::agent_authority::{Operation, Permissions};
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio_postgres::Client;
use uuid::Uuid;

/// Constructed only after verifying the credential and its current grant.
/// Consumers must still lock and recheck exact effect authority in their transaction.
pub struct AgentPrincipal {
    pub(crate) account: Uuid,
    pub(crate) grant_id: Uuid,
    pub(crate) key_id: Uuid,
    pub(crate) device_id: Uuid,
    permissions: Permissions,
    scopes: Vec<Scope>,
}

impl AgentPrincipal {
    pub(crate) fn sealed_principal(&self) -> ApiPrincipal {
        ApiPrincipal {
            tenant: Tenant {
                account_id: self.account,
            },
            key_id: self.key_id,
            scopes: self.scopes.clone(),
            bound_device_id: Some(self.device_id),
        }
    }
    pub(crate) fn require(&self, operation: Operation) -> Result<(), AuthError> {
        let allowed = match operation {
            Operation::Metadata => self.permissions.metadata,
            Operation::ReadContent => self.permissions.read_content,
            Operation::Draft => self.permissions.draft,
            Operation::Send => self.permissions.send,
        };
        if allowed {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
    pub fn account_id(&self) -> Uuid {
        self.account
    }
    pub fn grant_id(&self) -> Uuid {
        self.grant_id
    }
    pub fn key_id(&self) -> Uuid {
        self.key_id
    }
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }
}

impl TokenHasher {
    /// Account-bound routing identity; callers provide an already validated peer.
    pub(crate) fn agent_recipient_digest(&self, account: Uuid, peer: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts all key sizes");
        mac.update(b"ZT/agent-recipient/v1\0");
        mac.update(account.as_bytes());
        mac.update(&(peer.len() as u64).to_be_bytes());
        mac.update(peer.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

pub(crate) async fn authenticate_agent(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<AgentPrincipal, AuthError> {
    if !valid_token(token, "ztk_") {
        return Err(AuthError::Unauthorized);
    }
    let prefix: String = token.chars().skip(4).take(12).collect();
    let row = client.query_opt(
        "SELECT k.id,k.account_id,k.token_hash,g.grant_id,g.device_id,\
         g.metadata_allowed,g.content_allowed,g.draft_allowed,g.send_allowed,k.scopes \
         FROM api_keys k JOIN agent_authority_grants g ON g.api_key_id=k.id AND g.account_id=k.account_id \
         JOIN memberships m ON m.account_id=k.account_id AND m.user_id=k.created_by_user_id \
         JOIN users u ON u.id=m.user_id JOIN accounts a ON a.id=k.account_id \
         JOIN devices d ON d.account_id=g.account_id AND d.id=g.device_id \
         WHERE k.public_prefix=$1 AND k.revoked_at IS NULL \
         AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) \
         AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL \
         AND a.disabled_at IS NULL AND d.revoked_at IS NULL AND k.bound_device_id=g.device_id \
         AND g.revoked_ms IS NULL AND g.taken_over_ms IS NULL \
         AND g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[&prefix],
    ).await?.ok_or(AuthError::Unauthorized)?;
    let stored: Vec<u8> = row.get(2);
    let actual = hasher.digest(b"api-key-v1", token);
    if stored.len() != 32 || !bool::from(actual.as_slice().ct_eq(stored.as_slice())) {
        return Err(AuthError::Unauthorized);
    }
    let permissions = Permissions {
        metadata: row.get(5),
        read_content: row.get(6),
        draft: row.get(7),
        send: row.get(8),
    };
    let names: Vec<String> = row.get(9);
    let scopes = names
        .iter()
        .map(|name| Scope::from_str(name).ok_or(AuthError::Unauthorized))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AgentPrincipal {
        key_id: row.get(0),
        account: row.get(1),
        grant_id: row.get(3),
        device_id: row.get(4),
        permissions,
        scopes,
    })
}

pub(crate) struct OwnerProof<'a> {
    pub owner: &'a super::SessionPrincipal,
    pub password: &'a str,
    pub code: Option<&'a str>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantRequest {
    pub connector_id: Uuid,
    pub connector_key_id: [u8; 32],
    pub signer_key_id: [u8; 32],
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub recipient: String,
    pub metadata_allowed: bool,
    pub content_allowed: bool,
    pub draft_allowed: bool,
    pub send_allowed: bool,
    pub reader_identity: Option<Uuid>,
    pub model_provider_identity: Option<Uuid>,
    pub model_reads_content: bool,
    pub owner_self_notification: bool,
    pub expires_ms: i64,
    pub message_limit: i32,
    pub turn_limit: i32,
}

impl GrantRequest {
    fn validate(&self, now: i64) -> Result<(), AuthError> {
        let peer = self.recipient.as_bytes();
        if !self.owner_self_notification
            || self.model_provider_identity.is_some()
            || self.model_reads_content
            || !(self.metadata_allowed
                || self.content_allowed
                || self.draft_allowed
                || self.send_allowed)
            || (self.content_allowed && self.reader_identity.is_none())
            || self.reader_identity.is_some_and(|id| id.is_nil())
            || [self.connector_id, self.device_id, self.line_id]
                .iter()
                .any(Uuid::is_nil)
            || self.connector_key_id == [0; 32]
            || self.signer_key_id == [0; 32]
            || self.binding_generation <= 0
            || !(1..=100).contains(&self.message_limit)
            || !(1..=3).contains(&self.turn_limit)
            || self.expires_ms <= now
            || self.expires_ms.saturating_sub(now) > 86_400_000
            || !(3..=16).contains(&peer.len())
            || peer[0] != b'+'
            || !(b'1'..=b'9').contains(&peer[1])
            || !peer[2..].iter().all(u8::is_ascii_digit)
        {
            return Err(AuthError::InvalidInput);
        }
        Ok(())
    }
}

async fn fence(
    tx: &tokio_postgres::Transaction<'_>,
    cipher: Option<&super::mfa::MfaCipher>,
    hasher: &TokenHasher,
    proof: &OwnerProof<'_>,
    hash: &str,
) -> Result<bool, AuthError> {
    Ok(matches!(
        super::account::fence_owner_mutation(tx, cipher, hasher, proof.owner, hash, proof.code)
            .await?,
        super::account::OwnerMutationFence::Cleared
    ))
}

pub(crate) async fn revoke(
    client: &mut Client,
    cipher: Option<&super::mfa::MfaCipher>,
    hasher: &TokenHasher,
    proof: OwnerProof<'_>,
    grant: Uuid,
    takeover: bool,
) -> Result<(), AuthError> {
    let hash = super::account::verify_current_password(client, proof.owner, proof.password).await?;
    let account = proof.owner.tenant.account_id();
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&account],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    let row=tx.query_opt("SELECT api_key_id FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2 FOR UPDATE",&[&account,&grant])
        .await?.ok_or(AuthError::Forbidden)?;
    let key: Uuid = row.get(0);
    if !fence(&tx, cipher, hasher, &proof, &hash).await? {
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    tx.execute(if takeover {
        "UPDATE agent_authority_grants SET taken_over_ms=COALESCE(taken_over_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND grant_id=$2"
    } else {
        "UPDATE agent_authority_grants SET revoked_ms=COALESCE(revoked_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND grant_id=$2"
    },&[&account,&grant]).await?;
    tx.execute("UPDATE api_keys SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE account_id=$1 AND id=$2",&[&account,&key]).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) struct ApprovalRequest<'a> {
    pub grant: Uuid,
    pub action: Uuid,
    pub envelope: &'a [u8],
    pub not_before_ms: i64,
}

pub(crate) async fn approve(
    client: &mut Client,
    cipher: Option<&super::mfa::MfaCipher>,
    hasher: &TokenHasher,
    proof: OwnerProof<'_>,
    request: ApprovalRequest<'_>,
) -> Result<[u8; 32], AuthError> {
    let hash = super::account::verify_current_password(client, proof.owner, proof.password).await?;
    let account = proof.owner.tenant.account_id();
    let tx = client.transaction().await?;
    let action = crate::agent_authority::store::validate_owner_action(
        &tx,
        hasher,
        account,
        request.grant,
        request.action,
        request.envelope,
        request.not_before_ms,
    )
    .await
    .map_err(|error| match error {
        crate::agent_authority::store::StoreError::Database(db) => AuthError::Database(db),
        _ => AuthError::Forbidden,
    })?;
    let digest = action.digest();
    if !fence(&tx, cipher, hasher, &proof, &hash).await? {
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    let inserted=tx.execute(
        "INSERT INTO agent_authority_approvals(account_id,action_id,grant_id,message_id,device_id,line_id,binding_generation,recipient_digest,unsigned_digest,action_digest,not_before_ms,expires_ms,approved_by_user,approved_session,approved_ms) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE $12>floor(extract(epoch FROM clock_timestamp())*1000)::bigint ON CONFLICT(account_id,action_id) DO NOTHING",
        &[&account,&action.action,&action.grant,&action.message,&action.device,&action.line,&action.binding_generation,&action.recipient.as_slice(),&action.unsigned_envelope.as_slice(),&digest.as_slice(),&action.not_before_ms,&action.expires_ms,&proof.owner.user_id,&proof.owner.session_id],
    ).await?;
    if inserted == 0 {
        let same:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM agent_authority_approvals WHERE account_id=$1 AND action_id=$2 AND action_digest=$3 AND revoked_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",&[&account,&action.action,&digest.as_slice()]).await?.get(0);
        if !same {
            return Err(AuthError::Conflict);
        }
    }
    tx.commit().await?;
    Ok(digest)
}

pub(crate) async fn create(
    client: &mut Client,
    cipher: Option<&super::mfa::MfaCipher>,
    hasher: &TokenHasher,
    proof: OwnerProof<'_>,
    request: GrantRequest,
) -> Result<(Uuid, super::ApiKeyCredentials), AuthError> {
    let hash = super::account::verify_current_password(client, proof.owner, proof.password).await?;
    let account = proof.owner.tenant.account_id();
    let tx = client.transaction().await?;
    let mut manifest = crate::sealed_manifest_store::outbound::lock_current(&tx, account)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&account],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    request.validate(now)?;
    tx.query_opt(
        "SELECT l.id FROM phone_lines l JOIN device_line_bindings b ON b.account_id=l.account_id AND b.line_id=l.id AND b.generation=l.current_binding_generation JOIN devices d ON d.account_id=l.account_id AND d.id=b.device_id WHERE l.account_id=$1 AND l.id=$2 AND d.id=$3 AND b.generation=$4 AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL AND b.activated_at IS NOT NULL AND d.revoked_at IS NULL FOR SHARE OF l,b,d",
        &[&account,&request.line_id,&request.device_id,&request.binding_generation],
    ).await?.ok_or(AuthError::Forbidden)?;
    lock_connector(
        &tx,
        account,
        request.connector_id,
        &request.connector_key_id,
        request.line_id,
        manifest.generation(),
        (request.send_allowed, false),
    )
    .await?;
    manifest
        .authorize_agent_reader(&request.connector_key_id, 0)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    manifest
        .authorize_agent_signer(request.line_id, &request.signer_key_id)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if request.content_allowed {
        let reader = request.reader_identity.ok_or(AuthError::InvalidInput)?;
        let reader_key:Vec<u8>=tx.query_opt("SELECT key_id FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",&[&account,&reader]).await?.ok_or(AuthError::Forbidden)?.get(0);
        let reader_key: [u8; 32] = reader_key.try_into().map_err(|_| AuthError::Forbidden)?;
        lock_connector(
            &tx,
            account,
            reader,
            &reader_key,
            request.line_id,
            manifest.generation(),
            (false, true),
        )
        .await?;
        manifest
            .authorize_agent_reader(&reader_key, 4)
            .await
            .map_err(|_| AuthError::Forbidden)?;
    }
    if !fence(&tx, cipher, hasher, &proof, &hash).await? {
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    let scopes = if request.send_allowed {
        vec![Scope::MessagesSend, Scope::MessagesRead]
    } else {
        vec![Scope::MessagesRead]
    };
    let key = super::insert_api_key(
        &tx,
        hasher,
        proof.owner,
        &scopes,
        Some(request.device_id),
        super::ApiKeyLifetime::Days(1),
    )
    .await?;
    tx.execute(
        "UPDATE api_keys SET expires_at=to_timestamp($2::double precision/1000) WHERE id=$1",
        &[&key.id, &(request.expires_ms as f64)],
    )
    .await?;
    let grant = Uuid::new_v4();
    let recipient = hasher.agent_recipient_digest(account, &request.recipient);
    let inserted=tx.execute(
        "INSERT INTO agent_authority_grants(account_id,grant_id,api_key_id,connector_id,connector_key_id,signer_key_id,device_id,line_id,binding_generation,recipient_digest,metadata_allowed,content_allowed,draft_allowed,send_allowed,reader_identity,model_provider_identity,model_reads_content,owner_self_notification,created_by_user,created_session,created_ms,expires_ms,message_limit,turn_limit) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,false,true,$16,$17,floor(extract(epoch FROM clock_timestamp())*1000)::bigint,$18,$19,$20 WHERE $18>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND $18-floor(extract(epoch FROM clock_timestamp())*1000)::bigint<=86400000",
        &[&account,&grant,&key.id,&request.connector_id,&request.connector_key_id.as_slice(),&request.signer_key_id.as_slice(),&request.device_id,&request.line_id,&request.binding_generation,&recipient.as_slice(),&request.metadata_allowed,&request.content_allowed,&request.draft_allowed,&request.send_allowed,&request.reader_identity,&proof.owner.user_id,&proof.owner.session_id,&request.expires_ms,&request.message_limit,&request.turn_limit],
    ).await?;
    if inserted != 1 {
        return Err(AuthError::InvalidInput);
    }
    tx.commit().await?;
    Ok((grant, key))
}

async fn lock_connector(
    tx: &tokio_postgres::Transaction<'_>,
    account: Uuid,
    connector: Uuid,
    key: &[u8; 32],
    line: Uuid,
    generation: i64,
    permissions: (bool, bool),
) -> Result<(), AuthError> {
    tx.query_opt(
        "SELECT c.connector_id FROM connector_registrations c JOIN connector_keys k ON k.account_id=c.account_id AND k.connector_id=c.connector_id AND k.key_id=c.key_id WHERE c.account_id=$1 AND c.connector_id=$2 AND c.key_id=$3 AND c.state='active' AND c.manifest_generation=$4 AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.retired_ms IS NULL AND k.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR SHARE OF c,k",
        &[&account,&connector,&key.as_slice(),&generation],
    ).await?.ok_or(AuthError::Forbidden)?;
    for kind in [
        permissions.0.then_some("send"),
        permissions.1.then_some("read"),
    ]
    .into_iter()
    .flatten()
    {
        tx.query_opt(
            "SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 AND line_id=$3 AND kind=$4 AND revoked_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND ($4='send' OR (read_directions & 4=4 AND cardinality(conversation_restriction)=0)) ORDER BY created_ms DESC,grant_id DESC LIMIT 1 FOR SHARE",
            &[&account,&connector,&line,&kind],
        ).await?.ok_or(AuthError::Forbidden)?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct GrantView {
    pub grant_id: Uuid,
    pub api_key_id: Uuid,
    pub connector_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub metadata_allowed: bool,
    pub content_allowed: bool,
    pub draft_allowed: bool,
    pub send_allowed: bool,
    pub reader_identity: Option<Uuid>,
    pub model_provider_identity: Option<Uuid>,
    pub model_reads_content: bool,
    pub expires_ms: i64,
    pub revoked_ms: Option<i64>,
    pub taken_over_ms: Option<i64>,
    pub message_limit: i32,
    pub turn_limit: i32,
    pub messages_reserved: i32,
    pub turns_consumed: i32,
    pub segment_limit: u8,
}

#[derive(serde::Serialize)]
pub(crate) struct GrantPage {
    pub grants: Vec<GrantView>,
    pub next_cursor: Option<Uuid>,
    pub truncated: bool,
}

pub(crate) async fn list(
    client: &Client,
    owner: &super::SessionPrincipal,
    before: Option<Uuid>,
) -> Result<Option<GrantPage>, AuthError> {
    super::require_unlocked_owner(client, owner).await?;
    let account = owner.tenant.account_id();
    let cursor = match before {
        Some(id) => {
            let Some(row) = client.query_opt("SELECT created_ms FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2", &[&account, &id]).await? else {
                return Ok(None);
            };
            Some((row.get::<_, i64>(0), id))
        }
        None => None,
    };
    let created = cursor.map(|value| value.0);
    let id = cursor.map(|value| value.1);
    let mut rows=client.query("SELECT grant_id,api_key_id,connector_id,device_id,line_id,metadata_allowed,content_allowed,draft_allowed,send_allowed,reader_identity,model_provider_identity,model_reads_content,expires_ms,revoked_ms,taken_over_ms,message_limit,turn_limit,messages_reserved,turns_consumed FROM agent_authority_grants WHERE account_id=$1 AND ($2::bigint IS NULL OR (created_ms,grant_id)<($2,$3::uuid)) ORDER BY created_ms DESC,grant_id DESC LIMIT 101",&[&account,&created,&id]).await?;
    let truncated = rows.len() > 100;
    rows.truncate(100);
    let next_cursor = if truncated {
        rows.last().map(|row| row.get(0))
    } else {
        None
    };
    let grants = rows
        .into_iter()
        .map(|row| GrantView {
            segment_limit: 1,
            grant_id: row.get(0),
            api_key_id: row.get(1),
            connector_id: row.get(2),
            device_id: row.get(3),
            line_id: row.get(4),
            metadata_allowed: row.get(5),
            content_allowed: row.get(6),
            draft_allowed: row.get(7),
            send_allowed: row.get(8),
            reader_identity: row.get(9),
            model_provider_identity: row.get(10),
            model_reads_content: row.get(11),
            expires_ms: row.get(12),
            revoked_ms: row.get(13),
            taken_over_ms: row.get(14),
            message_limit: row.get(15),
            turn_limit: row.get(16),
            messages_reserved: row.get(17),
            turns_consumed: row.get(18),
        })
        .collect();
    Ok(Some(GrantPage {
        grants,
        next_cursor,
        truncated,
    }))
}

#[cfg(test)]
mod tests;
