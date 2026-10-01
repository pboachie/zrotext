// SPDX-License-Identifier: AGPL-3.0-only
use super::{Operation, Permissions, Purpose};
use crate::{
    auth::{self, AuthError, SessionPrincipal, TokenHasher, account, mfa},
    http_owner_conversations::{activation, context::wire},
    sealed_connector_registry::{RegistryError, owner_fence},
    sealed_manifest_store::outbound::lock_current,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct GrantRequest {
    pub connector: Uuid,
    pub context: Uuid,
    pub contact: Uuid,
    pub purpose: Purpose,
    pub permissions: Permissions,
    pub signer: Option<[u8; 32]>,
    pub expires_ms: i64,
    /// Separately client-encrypted representation for the selected role-3
    /// reader. Owner confirmation declares its source revision; the server
    /// cannot prove plaintext equivalence and never decrypts either envelope.
    pub content_envelope: Option<Vec<u8>>,
}

/// Returned once after commit. Deliberately has no Debug or Serialize that
/// could accidentally put the credential in a journal or owner export.
pub struct IssuedCredential {
    pub grant_id: Uuid,
    pub token: Zeroizing<String>,
}

fn registry_error(error: RegistryError) -> AuthError {
    match error {
        RegistryError::Database(error) => AuthError::Database(error),
        RegistryError::Authentication(error) => error,
        RegistryError::Rejected(_) => AuthError::Forbidden,
    }
}

async fn current_connector_grants(
    tx: &Transaction<'_>,
    account: Uuid,
    connector: Uuid,
    header: &wire::Header,
    permissions: Permissions,
) -> Result<(), AuthError> {
    let read = permissions.bits() & 6 != 0;
    let send = permissions.allows(Operation::Send) || permissions.allows(Operation::Schedule);
    for kind in ["read", "send"] {
        if (kind == "read" && !read) || (kind == "send" && !send) {
            continue;
        }
        tx.query_opt(
            "SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 \
             AND line_id=$3 AND kind=$4 AND revoked_ms IS NULL \
             AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
             AND ($4='send' OR (read_directions & 8)=8) \
             AND (cardinality(conversation_restriction)=0 OR $5=ANY(conversation_restriction)) FOR SHARE",
            &[&account,&connector,&header.line,&kind,&header.interval]
        ).await?.ok_or(AuthError::Forbidden)?;
    }
    Ok(())
}

/// An actual current owner password and MFA ceremony narrows the existing
/// connector identity; this does not create manifest keys or approve actions.
pub async fn issue_grant(
    client: &mut Client,
    owner: &SessionPrincipal,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    password: &str,
    factor: &str,
    request: &GrantRequest,
) -> Result<IssuedCredential, AuthError> {
    if [request.connector, request.context, request.contact]
        .iter()
        .any(Uuid::is_nil)
        || (request.permissions.bits() & 72 != 0 && request.signer.is_none())
    {
        return Err(AuthError::InvalidInput);
    }
    let verified = account::verify_current_password(client, owner, password).await?;
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut authority = lock_current(&tx, account)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    owner_fence(&tx, owner).await.map_err(registry_error)?;
    let stored: String = tx
        .query_one(
            "SELECT password_hash FROM users WHERE id=$1",
            &[&owner.user_id],
        )
        .await?
        .get(0);
    if stored != verified {
        return Err(AuthError::InvalidCredentials);
    }
    let row=tx.query_opt(
        "SELECT v.envelope FROM workflow_contexts c JOIN workflow_context_versions v \
         ON (v.account_id,v.context_id,v.revision)=(c.account_id,c.id,c.revision) \
         WHERE c.account_id=$1 AND c.id=$2 AND c.purged_at IS NULL AND v.envelope IS NOT NULL FOR SHARE OF c,v",
        &[&account,&request.context]).await?.ok_or(AuthError::Forbidden)?;
    let header = wire::parse(&row.get::<_, Vec<u8>>(0)).map_err(|_| AuthError::Forbidden)?;
    let interval = activation::load(&tx, account, header.interval)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let s = interval.statement;
    if interval.phase != "active"
        || (s.device, s.line, s.generation, s.trust_generation)
            != (
                header.device,
                header.line,
                header.binding_generation,
                header.trust_generation,
            )
        || Sha256::digest(s.peer.as_bytes()).as_slice() != header.peer_digest
    {
        return Err(AuthError::Forbidden);
    }
    let peer: String = tx
        .query_opt(
            "SELECT recipient_e164 FROM contacts WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&account, &request.contact],
        )
        .await?
        .ok_or(AuthError::Forbidden)?
        .get(0);
    if peer != s.peer {
        return Err(AuthError::Forbidden);
    }
    // The shared current binding has both owner and device confirmation.
    tx.query_opt("SELECT 1 FROM phone_lines l JOIN device_line_bindings b \
        ON (b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation) \
        JOIN devices d ON (d.account_id,d.id)=(b.account_id,b.device_id) \
        JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
        WHERE l.account_id=$1 AND l.id=$2 AND b.device_id=$3 AND b.generation=$4 \
        AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' \
        AND b.activated_at IS NOT NULL AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL \
        AND d.revoked_at IS NULL AND k.revoked_at IS NULL FOR SHARE OF l,b,d,k",
        &[&account,&header.line,&header.device,&header.binding_generation]).await?.ok_or(AuthError::Forbidden)?;
    let registration=tx.query_opt("SELECT r.key_id,r.key_point,r.manifest_generation,r.manifest_version,r.manifest_digest \
        FROM connector_registrations r JOIN connector_keys k \
        ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) \
        WHERE r.account_id=$1 AND r.connector_id=$2 AND r.state='active' AND k.retired_ms IS NULL \
        AND r.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        AND k.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR SHARE OF r,k",
        &[&account,&request.connector]).await?.ok_or(AuthError::Forbidden)?;
    let point: Vec<u8> = registration.get(1);
    let (snapshot, reader, scope) = authority
        .integration_snapshot(header.device, header.line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if (request.permissions.bits() & 6 != 0 && scope & 8 != 8)
        || reader.as_slice() != registration.get::<_, Vec<u8>>(0)
        || request.signer == Some(reader)
        || (snapshot.generation, snapshot.version, snapshot.digest)
            != (
                header.trust_generation,
                header.manifest_version,
                header.manifest_digest,
            )
        || (
            snapshot.generation,
            snapshot.version,
            snapshot.digest.as_slice(),
        ) != (
            registration.get(2),
            registration.get(3),
            registration.get::<_, Vec<u8>>(4).as_slice(),
        )
    {
        return Err(AuthError::Forbidden);
    }
    if let Some(signer) = request.signer {
        authority
            .workflow_signer(header.device, header.line, &signer)
            .await
            .map_err(|_| AuthError::Forbidden)?;
    }
    if let Some(envelope) = &request.content_envelope {
        if !request.permissions.allows(Operation::ContextContent) {
            return Err(AuthError::InvalidInput);
        }
        let mut expected = header.clone();
        expected.reader = reader;
        if wire::parse(envelope).map_err(|_| AuthError::InvalidInput)? != expected {
            return Err(AuthError::Forbidden);
        }
        let bytes: i64=tx.query_one("SELECT COALESCE(sum(octet_length(envelope)),0)::bigint FROM workflow_connector_context_envelopes WHERE account_id=$1", &[&account]).await?.get(0);
        if bytes + envelope.len() as i64 > 4 * 1024 * 1024 {
            return Err(AuthError::RateLimited);
        }
    }
    if request.expires_ms <= snapshot.accepted_ms
        || request.expires_ms - snapshot.accepted_ms > 86_400_000
        || request.expires_ms > header.expires_ms
        || request.expires_ms > s.expires_ms
    {
        return Err(AuthError::InvalidInput);
    }
    current_connector_grants(
        &tx,
        account,
        request.connector,
        &header,
        request.permissions,
    )
    .await?;
    let factor = mfa::consume_ceremony_factor(
        &tx,
        cipher,
        hasher,
        owner,
        factor,
        snapshot.accepted_ms as u64,
    )
    .await?;
    let Some(factor) = factor else {
        drop(authority);
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    };
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_integration_grants WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 128 {
        return Err(AuthError::RateLimited);
    }
    let token = Zeroizing::new(format!(
        "ztw_{}",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    ));
    let hash = hasher.workflow_credential_hash(&token);
    let grant = Uuid::new_v4();
    let signer = request.signer.map(|value| value.to_vec());
    tx.execute("INSERT INTO workflow_integration_grants(account_id,grant_id,credential_hash,connector_id,reader_key_id,signer_key_id,device_id,line_id,binding_generation,trust_generation,manifest_version,manifest_digest,context_id,context_revision,contact_id,purpose,permissions,created_by_user,created_session,created_ms,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
        &[&account,&grant,&hash.as_slice(),&request.connector,&reader.as_slice(),&signer,&header.device,&header.line,&header.binding_generation,&snapshot.generation,&snapshot.version,&snapshot.digest.as_slice(),&header.context,&header.revision,&request.contact,&request.purpose.slug(),&request.permissions.bits(),&owner.user_id,&owner.session_id,&snapshot.accepted_ms,&request.expires_ms]).await?;
    if let Some(envelope) = &request.content_envelope {
        let digest = Sha256::digest(envelope);
        tx.execute("INSERT INTO workflow_connector_context_envelopes(account_id,grant_id,context_id,context_revision,request_id,envelope_digest,envelope,created_by_user,created_ms) VALUES($1,$2,$3,$4,$2,$5,$6,$7,$8)",
            &[&account,&grant,&header.context,&header.revision,&digest.as_slice(),&envelope,&owner.user_id,&snapshot.accepted_ms]).await?;
    }
    let (final_snapshot, _, _) = authority
        .integration_snapshot(header.device, header.line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if final_snapshot.accepted_ms >= request.expires_ms
        || final_snapshot.accepted_ms >= s.expires_ms
        || !factor.current_at(final_snapshot.accepted_ms as u64)
    {
        return Err(AuthError::Forbidden);
    }
    if let Some(signer) = request.signer {
        authority
            .workflow_signer(header.device, header.line, &signer)
            .await
            .map_err(|_| AuthError::Forbidden)?;
    }
    current_connector_grants(
        &tx,
        account,
        request.connector,
        &header,
        request.permissions,
    )
    .await?;
    owner_fence(&tx, owner).await.map_err(registry_error)?;
    // Recheck the ceremony window and every expiring authority after all waits.
    let (final_snapshot, _, _) = authority
        .integration_snapshot(header.device, header.line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if final_snapshot.accepted_ms >= request.expires_ms
        || final_snapshot.accepted_ms >= s.expires_ms
        || !factor.current_at(final_snapshot.accepted_ms as u64)
    {
        return Err(AuthError::Forbidden);
    }
    if let Some(signer) = request.signer {
        authority
            .workflow_signer(header.device, header.line, &signer)
            .await
            .map_err(|_| AuthError::Forbidden)?;
    }
    tx.query_opt("SELECT 1 FROM connector_registrations r JOIN connector_keys k \
        ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) \
        WHERE r.account_id=$1 AND r.connector_id=$2 AND r.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        AND k.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[&account,&request.connector]).await?.ok_or(AuthError::Forbidden)?;
    drop(authority);
    tx.commit().await?;
    Ok(IssuedCredential {
        grant_id: grant,
        token,
    })
}

/// Withdrawal needs a live owner and works even when the manifest is stale.
/// It never restores permissions, renews a grant or refunds workflow budgets.
pub async fn revoke_grant(
    client: &mut Client,
    owner: &SessionPrincipal,
    grant: Uuid,
) -> Result<(), AuthError> {
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[&account],
    )
    .await?;
    crate::http_owner_conversations::lock_owner(&tx, owner)
        .await
        .map_err(|error| match error {
            crate::http_owner_conversations::ConversationError::Database(error) => {
                AuthError::Database(error)
            }
            _ => AuthError::Forbidden,
        })?;
    let changed=tx.execute("UPDATE workflow_integration_grants SET revoked_ms=COALESCE(revoked_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND grant_id=$2", &[&account,&grant]).await?;
    if changed != 1 {
        return Err(AuthError::Forbidden);
    }
    auth::require_current_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(())
}
