// SPDX-License-Identifier: AGPL-3.0-only
//! Private transaction-bound integration proof, shared by service operations.
use super::{IntegrationPrincipal, Operation};
use crate::{
    auth::AuthError,
    http_owner_conversations::{activation, context::wire},
    sealed_manifest_store::outbound::{CurrentAuthority, lock_current},
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(super) struct CheckedScope<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    principal: IntegrationPrincipal,
    operation: Operation,
    authority: CurrentAuthority<'tx, 'connection>,
    pub(super) header: wire::Header,
    pub(super) reader: [u8; 32],
    row: Row,
    statement: activation::Statement,
}
pub(super) async fn lock_scope<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    principal: &IntegrationPrincipal,
    context: Uuid,
    operation: Operation,
) -> Result<CheckedScope<'tx, 'connection>, AuthError> {
    principal.require(operation)?;
    if context.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let account = principal.account_id();
    let permission_bit = i32::from(operation.bit());
    let mut authority = lock_current(tx, account)
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
         g.reader_key_id,r.key_point,v.envelope,c.interval_id,g.connector_id,g.expires_ms,g.contact_id,g.purpose,g.signer_key_id,g.context_revision \
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
    let interval = activation::load(tx, account, header.interval)
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
    activation::origin(tx, &statement)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let point: Vec<u8> = row.get(7);
    let (snapshot, reader, scope) = authority
        .integration_snapshot(device, line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    if (matches!(
        operation,
        Operation::ContextMetadata | Operation::ContextContent
    ) && scope & 8 != 8)
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
    if header.revision != row.get::<_, i64>(15) {
        return Err(AuthError::Forbidden);
    }
    let connector: Uuid = row.get(10);
    if matches!(
        operation,
        Operation::ContextMetadata | Operation::ContextContent
    ) {
        tx.query_opt(
            "SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 \
         AND line_id=$3 AND kind='read' AND (read_directions & 8)=8 AND revoked_ms IS NULL \
         AND (cardinality(conversation_restriction)=0 OR $4=ANY(conversation_restriction)) \
         AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR SHARE",
            &[&account, &connector, &line, &header.interval],
        )
        .await?
        .ok_or(AuthError::Forbidden)?;
    }
    if matches!(operation, Operation::Schedule | Operation::Send) {
        tx.query_opt("SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 AND line_id=$3 AND kind='send' AND revoked_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND (cardinality(conversation_restriction)=0 OR $4=ANY(conversation_restriction)) FOR SHARE", &[&account, &connector, &line, &header.interval]).await?.ok_or(AuthError::Forbidden)?;
    }
    if matches!(operation, Operation::Propose | Operation::Send) {
        let signer: [u8; 32] = row
            .get::<_, Option<Vec<u8>>>(14)
            .ok_or(AuthError::Forbidden)?
            .try_into()
            .map_err(|_| AuthError::Forbidden)?;
        authority
            .workflow_signer(device, line, &signer)
            .await
            .map_err(|_| AuthError::Forbidden)?;
    }
    let mut result = CheckedScope {
        tx,
        principal: principal.clone(),
        operation,
        authority,
        header,
        reader,
        row,
        statement,
    };
    result.recheck().await?;
    Ok(result)
}
impl CheckedScope<'_, '_> {
    pub(super) fn contact(&self) -> Uuid {
        self.row.get(12)
    }
    pub(super) fn check_descriptor(
        &self,
        descriptor: &crate::http_owner_conversations::context::decisions::Descriptor,
    ) -> Result<(), AuthError> {
        let ids = descriptor
            .identities()
            .map_err(|_| AuthError::InvalidInput)?;
        let digest =
            crate::http_owner_conversations::context::decisions::descriptor::decode_digest(
                &descriptor.content_digest,
            )
            .map_err(|_| AuthError::InvalidInput)?;
        if descriptor
            .key()
            .map_err(|_| AuthError::InvalidInput)?
            .account_id
            != self.principal.account_id()
            || ids.content != self.header.context
            || ids.line != self.header.line
            || ids.recipient != self.contact()
            || descriptor.content_version != self.header.revision
            || descriptor.purpose().map_err(|_| AuthError::InvalidInput)? != self.purpose()
            || descriptor
                .expires_at_ms()
                .map_err(|_| AuthError::InvalidInput)?
                > self.header.expires_ms
            || Sha256::digest(self.row.get::<_, Vec<u8>>(8)).as_slice() != digest
        {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }
    pub(super) fn purpose(&self) -> String {
        self.row.get(13)
    }
    pub(super) async fn record_access(
        &self,
        request: Uuid,
        subject: Uuid,
        digest: &[u8],
    ) -> Result<(), AuthError> {
        if request.is_nil() {
            return Err(AuthError::InvalidInput);
        }
        let account = self.principal.account_id();
        let grant = self.principal.grant_id();
        let operation = self.operation.bit();
        if let Some(previous) = self.tx.query_opt("SELECT operation,subject_id,request_digest FROM workflow_integration_access WHERE account_id=$1 AND grant_id=$2 AND request_id=$3", &[&account,&grant,&request]).await? {
            if previous.get::<_,i16>(0) != operation || previous.get::<_,Uuid>(1) != subject || previous.get::<_,Vec<u8>>(2) != digest { return Err(AuthError::Conflict); }
        } else {
            let count: i64 = self.tx.query_one("SELECT count(*) FROM workflow_integration_access WHERE account_id=$1", &[&account]).await?.get(0);
            if count >= 8192 { return Err(AuthError::RateLimited); }
            self.tx.execute("INSERT INTO workflow_integration_access(account_id,grant_id,request_id,operation,request_digest,subject_id,outcome,recorded_ms) VALUES($1,$2,$3,$4,$5,$6,'accepted',floor(extract(epoch FROM clock_timestamp())*1000)::bigint)", &[&account,&grant,&request,&operation,&digest,&subject]).await?;
        }
        Ok(())
    }
    pub(super) async fn recheck(&mut self) -> Result<(), AuthError> {
        let account = self.principal.account_id();
        let principal = &self.principal;
        let device = self.header.device;
        let line = self.header.line;
        let point: Vec<u8> = self.row.get(7);
        let read = matches!(
            self.operation,
            Operation::ContextMetadata | Operation::ContextContent
        );
        let send = matches!(self.operation, Operation::Schedule | Operation::Send);
        let permission = i32::from(self.operation.bit());
        let content = self.operation == Operation::ContextContent;
        // All preceding statements may wait. Clock-sensitive predicates are read
        // again after the last audit write and current crypto is rechecked.
        let (current, _, _) = self
            .authority
            .integration_snapshot(device, line, &point)
            .await
            .map_err(|_| AuthError::Forbidden)?;
        if current.accepted_ms >= self.header.expires_ms
            || current.accepted_ms >= self.row.get::<_, i64>(11)
            || current.accepted_ms >= self.statement.expires_ms
        {
            return Err(AuthError::Forbidden);
        }
        self.tx.query_opt(
        "SELECT 1 FROM workflow_integration_grants g JOIN sessions s ON s.id=g.created_session \
         JOIN accounts a ON a.id=g.account_id \
         JOIN users u ON u.id=g.created_by_user \
         JOIN memberships m ON (m.account_id,m.user_id)=(g.account_id,g.created_by_user) \
         JOIN connector_registrations r ON (r.account_id,r.connector_id)=(g.account_id,g.connector_id) \
         JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) \
         WHERE g.account_id=$1 AND g.grant_id=$2 AND s.expires_at>clock_timestamp() \
         AND g.credential_hash=$8 AND g.revoked_ms IS NULL AND g.expires_ms>$3 AND (g.permissions::integer & $7)=$7 \
         AND a.disabled_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND m.role='owner' AND m.revoked_at IS NULL \
         AND s.account_id=g.account_id AND s.user_id=g.created_by_user AND s.revoked_at IS NULL \
         AND EXISTS(SELECT 1 FROM workflow_contexts c WHERE (c.account_id,c.id,c.revision)=(g.account_id,g.context_id,g.context_revision) AND c.purged_at IS NULL AND c.expires_at_ms>$3) \
         AND EXISTS(SELECT 1 FROM workflow_context_versions v WHERE (v.account_id,v.context_id,v.revision)=(g.account_id,g.context_id,g.context_revision) AND v.envelope IS NOT NULL) \
         AND (NOT $9::boolean OR EXISTS(SELECT 1 FROM workflow_connector_context_envelopes e WHERE (e.account_id,e.grant_id,e.context_id,e.context_revision)=(g.account_id,g.grant_id,g.context_id,g.context_revision) AND e.envelope IS NOT NULL)) \
         AND EXISTS(SELECT 1 FROM devices d JOIN device_keys dk ON (dk.account_id,dk.device_id)=(d.account_id,d.id) \
             JOIN phone_lines l ON l.account_id=d.account_id AND l.id=g.line_id \
             JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(l.account_id,l.id,d.id,g.binding_generation) \
             WHERE d.account_id=g.account_id AND d.id=g.device_id AND d.revoked_at IS NULL AND dk.revoked_at IS NULL \
             AND l.state='active' AND l.approved_at IS NOT NULL AND l.current_binding_generation=g.binding_generation \
             AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL) \
         AND EXISTS(SELECT 1 FROM conversation_intervals i WHERE i.account_id=g.account_id AND i.id=$4 AND i.phase='active' AND i.expires_at_ms>$3) \
         AND r.state='active' AND r.key_id=g.reader_key_id AND (r.manifest_generation,r.manifest_version,r.manifest_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest) \
         AND k.retired_ms IS NULL AND r.expires_ms>$3 AND k.valid_from_ms<=$3 AND k.valid_until_ms>$3 \
         AND (NOT $5::boolean OR EXISTS(SELECT 1 FROM connector_grants cg WHERE cg.account_id=g.account_id AND cg.connector_id=g.connector_id \
             AND cg.line_id=g.line_id AND cg.kind='read' AND (cg.read_directions & 8)=8 AND cg.revoked_ms IS NULL AND cg.expires_ms>$3 \
             AND (cardinality(cg.conversation_restriction)=0 OR $4=ANY(cg.conversation_restriction)))) \
         AND (NOT $6::boolean OR EXISTS(SELECT 1 FROM connector_grants cg WHERE cg.account_id=g.account_id AND cg.connector_id=g.connector_id AND cg.line_id=g.line_id AND cg.kind='send' AND cg.revoked_ms IS NULL AND cg.expires_ms>$3 AND (cardinality(cg.conversation_restriction)=0 OR $4=ANY(cg.conversation_restriction))))",
        &[&account,&principal.grant_id(),&current.accepted_ms,&self.header.interval, &read, &send, &permission, &principal.credential_hash().as_slice(), &content]
    ).await?.ok_or(AuthError::Forbidden)?;
        activation::origin(self.tx, &self.statement)
            .await
            .map_err(|_| AuthError::Forbidden)?;
        if matches!(self.operation, Operation::Propose | Operation::Send) {
            let signer: [u8; 32] = self
                .row
                .get::<_, Option<Vec<u8>>>(14)
                .ok_or(AuthError::Forbidden)?
                .try_into()
                .map_err(|_| AuthError::Forbidden)?;
            self.authority
                .workflow_signer(device, line, &signer)
                .await
                .map_err(|_| AuthError::Forbidden)?;
        }
        Ok(())
    }
}
