// SPDX-License-Identifier: AGPL-3.0-only
use super::{IntegrationPrincipal, Operation};
use crate::{
    auth::AuthError,
    http_owner_conversations::{activation, context::wire},
    sealed_manifest_store::outbound::lock_current,
};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;

/// Return authenticated public context metadata only. Context ciphertext,
/// contact notes and credentials are never placed in access records.
pub async fn read_context_metadata(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<wire::Header, AuthError> {
    Ok(read_context(
        client,
        principal,
        request,
        context,
        Operation::ContextMetadata,
    )
    .await?
    .0)
}

/// The only content returned is the separately owner-declared role-3 envelope.
/// The archive-reader representation never serves as a fallback.
pub async fn read_context_content(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<Vec<u8>, AuthError> {
    read_context(
        client,
        principal,
        request,
        context,
        Operation::ContextContent,
    )
    .await?
    .1
    .ok_or(AuthError::Forbidden)
}

async fn read_context(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
    operation: Operation,
) -> Result<(wire::Header, Option<Vec<u8>>), AuthError> {
    principal.require(operation)?;
    let operation_bit = operation.bit();
    let permission_bit = i32::from(operation_bit);
    if request.is_nil() || context.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let account = principal.account_id();
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut authority = lock_current(&tx, account)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    // Match existing authority order: manifest, account, owner, line/context,
    // connector and grant. These locks remain held through final revalidation.
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account],
    )
    .await?
    .ok_or(AuthError::Forbidden)?;
    let row = tx.query_opt(
        "SELECT g.device_id,g.line_id,g.binding_generation,g.trust_generation,g.manifest_version,g.manifest_digest,\
         g.reader_key_id,r.key_point,v.envelope,c.interval_id,g.connector_id,g.expires_ms \
         FROM workflow_integration_grants g \
         JOIN memberships m ON (m.account_id,m.user_id)=(g.account_id,g.created_by_user) \
         JOIN users u ON u.id=m.user_id \
         JOIN sessions s ON (s.account_id,s.user_id,s.id)=(g.account_id,g.created_by_user,g.created_session) \
         JOIN workflow_contexts c ON (c.account_id,c.id,c.revision)=(g.account_id,g.context_id,g.context_revision) \
         JOIN workflow_context_versions v ON (v.account_id,v.context_id,v.revision)=(c.account_id,c.id,c.revision) \
         JOIN connector_registrations r ON (r.account_id,r.connector_id)=(g.account_id,g.connector_id) \
         JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) \
         WHERE g.account_id=$1 AND g.grant_id=$2 AND g.credential_hash=$3 AND g.context_id=$4 \
         AND g.revoked_ms IS NULL AND (g.permissions::integer & $5)=$5 AND m.role='owner' AND m.revoked_at IS NULL \
         AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND s.revoked_at IS NULL \
         AND c.purged_at IS NULL AND v.envelope IS NOT NULL AND r.state='active' AND r.key_id=g.reader_key_id \
         AND (r.manifest_generation,r.manifest_version,r.manifest_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest) \
         AND k.retired_ms IS NULL \
         FOR SHARE OF g,m,u,s,c,v,r,k",
        &[&account,&principal.grant_id(),&principal.credential_hash().as_slice(),&context,&permission_bit]
    ).await?.ok_or(AuthError::Forbidden)?;
    let device: Uuid = row.get(0);
    let line: Uuid = row.get(1);
    let generation: i64 = row.get(2);
    tx.query_opt(
        "SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
         JOIN phone_lines l ON l.account_id=d.account_id AND l.id=$3 \
         JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(l.account_id,l.id,d.id,$4) \
         WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
         AND l.state='active' AND l.approved_at IS NOT NULL AND l.current_binding_generation=$4 \
         AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL \
         AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL FOR SHARE OF d,k,l,b",
        &[&account,&device,&line,&generation]
    ).await?.ok_or(AuthError::Forbidden)?;
    let header = wire::parse(&row.get::<_, Vec<u8>>(8)).map_err(|_| AuthError::Forbidden)?;
    if (
        header.account,
        header.context,
        header.device,
        header.line,
        header.binding_generation,
        header.interval,
    ) != (account, context, device, line, generation, row.get(9))
    {
        return Err(AuthError::Forbidden);
    }
    let interval = activation::load(&tx, account, header.interval)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let statement = interval.statement;
    if interval.phase != "active"
        || (
            statement.device,
            statement.line,
            statement.generation,
            statement.trust_generation,
            statement.reader,
        ) != (
            header.device,
            header.line,
            header.binding_generation,
            header.trust_generation,
            header.reader,
        )
        || Sha256::digest(statement.peer.as_bytes()).as_slice() != header.peer_digest
    {
        return Err(AuthError::Forbidden);
    }
    activation::origin(&tx, &statement)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let point: Vec<u8> = row.get(7);
    let (snapshot, reader, scope) = authority
        .integration_snapshot(device, line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if scope & 8 != 8
        || reader.as_slice() != row.get::<_, Vec<u8>>(6)
        || (
            snapshot.generation,
            snapshot.version,
            snapshot.digest.as_slice(),
        ) != (row.get(3), row.get(4), row.get::<_, Vec<u8>>(5).as_slice())
        || (
            header.trust_generation,
            header.manifest_version,
            header.manifest_digest,
        ) != (snapshot.generation, snapshot.version, snapshot.digest)
    {
        return Err(AuthError::Forbidden);
    }
    let connector: Uuid = row.get(10);
    tx.query_opt(
        "SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 \
         AND line_id=$3 AND kind='read' AND (read_directions & 8)=8 AND revoked_ms IS NULL \
         AND (cardinality(conversation_restriction)=0 OR $4=ANY(conversation_restriction)) \
         AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR SHARE",
        &[&account, &connector, &line, &header.interval],
    )
    .await?
    .ok_or(AuthError::Forbidden)?;
    let projection = if operation == Operation::ContextContent {
        let stored=tx.query_opt("SELECT envelope,envelope_digest FROM workflow_connector_context_envelopes WHERE account_id=$1 AND grant_id=$2 AND context_id=$3 AND context_revision=$4 AND envelope IS NOT NULL FOR SHARE",
            &[&account,&principal.grant_id(),&context,&header.revision]).await?.ok_or(AuthError::Forbidden)?;
        let projection = stored.get::<_, Vec<u8>>(0);
        if Sha256::digest(&projection).as_slice() != stored.get::<_, Vec<u8>>(1) {
            return Err(AuthError::Forbidden);
        }
        let mut expected = header.clone();
        expected.reader = reader;
        if wire::parse(&projection).map_err(|_| AuthError::Forbidden)? != expected {
            return Err(AuthError::Forbidden);
        }
        Some(projection)
    } else {
        None
    };
    let digest = Sha256::digest(
        [
            b"ZT/workflow/context-read/v1\0".as_slice(),
            &operation_bit.to_be_bytes(),
            context.as_bytes(),
        ]
        .concat(),
    );
    if let Some(previous)=tx.query_opt("SELECT operation,subject_id,request_digest FROM workflow_integration_access WHERE account_id=$1 AND grant_id=$2 AND request_id=$3",
        &[&account,&principal.grant_id(),&request]).await? {
        if previous.get::<_,i16>(0)!=operation_bit || previous.get::<_,Uuid>(1)!=context || previous.get::<_,Vec<u8>>(2)!=digest.as_slice() {
            return Err(AuthError::Conflict);
        }
    } else {
        let count: i64=tx.query_one("SELECT count(*) FROM workflow_integration_access WHERE account_id=$1", &[&account]).await?.get(0);
        if count>=8192 { return Err(AuthError::RateLimited); }
        tx.execute("INSERT INTO workflow_integration_access(account_id,grant_id,request_id,operation,request_digest,subject_id,outcome,recorded_ms) VALUES($1,$2,$3,$4,$5,$6,'accepted',floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",
            &[&account,&principal.grant_id(),&request,&operation_bit,&digest.as_slice(),&context]).await?;
    }
    // All preceding statements may wait. Clock-sensitive predicates are read
    // again after the last audit write and current crypto is rechecked.
    let (current, _, _) = authority
        .integration_snapshot(device, line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if current.accepted_ms >= header.expires_ms
        || current.accepted_ms >= row.get::<_, i64>(11)
        || current.accepted_ms >= statement.expires_ms
    {
        return Err(AuthError::Forbidden);
    }
    tx.query_opt(
        "SELECT 1 FROM workflow_integration_grants g JOIN sessions s ON s.id=g.created_session \
         JOIN connector_registrations r ON (r.account_id,r.connector_id)=(g.account_id,g.connector_id) \
         JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) \
         WHERE g.account_id=$1 AND g.grant_id=$2 AND s.expires_at>clock_timestamp() \
         AND r.expires_ms>$3 AND k.valid_from_ms<=$3 AND k.valid_until_ms>$3 \
         AND EXISTS(SELECT 1 FROM connector_grants cg WHERE cg.account_id=g.account_id AND cg.connector_id=g.connector_id \
             AND cg.line_id=g.line_id AND cg.kind='read' AND (cg.read_directions & 8)=8 AND cg.revoked_ms IS NULL AND cg.expires_ms>$3 \
             AND (cardinality(cg.conversation_restriction)=0 OR $4=ANY(cg.conversation_restriction)))",
        &[&account,&principal.grant_id(),&current.accepted_ms,&header.interval]
    ).await?.ok_or(AuthError::Forbidden)?;
    activation::origin(&tx, &statement)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    drop(authority);
    tx.commit().await?;
    Ok((header, projection))
}
