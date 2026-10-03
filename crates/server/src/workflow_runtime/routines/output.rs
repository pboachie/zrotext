// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::{
    decisions::proposal::{Actor, ProposalFence},
    wire,
};

fn same_scope(a: &wire::Header, b: &wire::Header) -> bool {
    a.context != b.context
        && a.kind == b.kind
        && (
            a.account,
            a.device,
            a.line,
            a.interval,
            a.binding_generation,
            a.trust_generation,
            a.manifest_version,
            a.peer_digest,
            a.reader,
            a.manifest_digest,
        ) == (
            b.account,
            b.device,
            b.line,
            b.interval,
            b.binding_generation,
            b.trust_generation,
            b.manifest_version,
            b.peer_digest,
            b.reader,
            b.manifest_digest,
        )
}
async fn connector_match(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    output: &IntegrationPrincipal,
) -> Result<(), AuthError> {
    tx.query_opt("SELECT 1 FROM workflow_integration_grants i JOIN workflow_integration_grants o ON o.account_id=i.account_id AND o.connector_id=i.connector_id AND o.reader_key_id=i.reader_key_id WHERE i.account_id=$1 AND i.grant_id=$2 AND o.grant_id=$3 FOR SHARE OF i,o",&[&input.account_id(),&input.grant_id(),&output.grant_id()]).await?.ok_or(AuthError::Forbidden)?;
    Ok(())
}
pub(super) async fn publication_live(
    tx: &Transaction<'_>,
    account: Uuid,
    call: Uuid,
) -> Result<(), AuthError> {
    let row = tx.query_opt("SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint FROM workflow_routine_calls c JOIN memberships m ON (m.account_id,m.user_id)=(c.account_id,c.published_by_user) JOIN users u ON u.id=m.user_id JOIN sessions s ON (s.account_id,s.user_id,s.id)=(c.account_id,c.published_by_user,c.published_session) WHERE c.account_id=$1 AND c.id=$2 AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR SHARE OF m,u,s",&[&account,&call]).await?.ok_or(AuthError::Forbidden)?;
    // The WHERE predicate can precede a session-row lock wait.
    if row.get::<_, i64>(0) <= activation::now(tx).await.map_err(error)? {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}
async fn projection(
    tx: &Transaction<'_>,
    principal: &IntegrationPrincipal,
    checked: &CheckedScope<'_, '_>,
) -> Result<(), AuthError> {
    principal.require(Operation::ContextContent)?;
    let bytes=tx.query_opt("SELECT envelope,envelope_digest FROM workflow_connector_context_envelopes WHERE account_id=$1 AND grant_id=$2 AND context_id=$3 AND context_revision=$4 AND envelope IS NOT NULL FOR SHARE",&[&principal.account_id(),&principal.grant_id(),&checked.header.context,&checked.header.revision]).await?.ok_or(AuthError::Forbidden)?;
    let envelope: Vec<u8> = bytes.get(0);
    let mut expected = checked.header.clone();
    expected.reader = checked.reader;
    if Sha256::digest(&envelope).as_slice() != bytes.get::<_, Vec<u8>>(1)
        || wire::parse(&envelope).map_err(error)? != expected
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

/// This binding follows actual owner context publication and independent grant
/// issuance. It neither writes ciphertext nor issues/widens either credential.
pub async fn bind_output(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: &IntegrationPrincipal,
    output: &IntegrationPrincipal,
    v: OutputBinding,
) -> Result<Call, AuthError> {
    if v.request_id.is_nil()
        || v.output_context_id != v.call_id
        || input.account_id() != output.account_id()
        || owner.tenant.account_id() != input.account_id()
        || input.grant_id() == output.grant_id()
    {
        return Err(AuthError::Forbidden);
    }
    let tx = begin(client).await?;
    let input_context:Uuid=tx.query_opt("SELECT p.context_id FROM workflow_routine_calls c JOIN workflow_routine_policies p ON (p.account_id,p.id)=(c.account_id,c.policy_id) WHERE c.account_id=$1 AND c.id=$2",&[&input.account_id(),&v.call_id]).await?.ok_or(AuthError::Forbidden)?.get(0);
    let mut source =
        scope::lock_scope(&tx, input, input_context, Operation::ContextContent).await?;
    let mut target =
        scope::lock_scope(&tx, output, v.output_context_id, Operation::Propose).await?;
    let mut target_read =
        scope::lock_scope(&tx, output, v.output_context_id, Operation::ContextContent).await?;
    connector_match(&tx, input, output).await?;
    owner::lock_owner(&tx, owner).await.map_err(error)?;
    let p = store::call_policy(&tx, input, v.call_id).await?;
    live(&tx, &mut source, &p).await?;
    if !same_scope(&source.header, &target.header)
        || source.contact() != target.contact()
        || source.purpose() != target.purpose()
        || target.header.revision != v.output_revision
        || decode(&v.output_source_digest)?.as_slice() != target.source_digest()
    {
        return Err(AuthError::Forbidden);
    }
    projection(&tx, output, &target).await?;
    let mut output_policy = p.clone();
    // The separately owner-published output creates its own fresh routine.
    // Input generation remains checked only against the original input fence.
    output_policy.generation = 1;
    let d = descriptor(&tx, &target, &output_policy, v.call_id, v.call_id).await?;
    tx.execute("INSERT INTO workflow_context_fences(account_id,context_id) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&input.account_id(),&v.output_context_id]).await?;
    tx.execute("INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$3,1) ON CONFLICT DO NOTHING",&[&input.account_id(),&v.call_id,&v.output_context_id]).await?;
    decisions::fence::live_routine(&tx, &d, &target.header)
        .await
        .map_err(error)?;
    decisions::fence::contact(&tx, &d, &target.header)
        .await
        .map_err(error)?;
    let row = store::load(&tx, input.account_id(), v.call_id).await?;
    if v.produced_digest != v.output_source_digest
        || row.get::<_, Option<Vec<u8>>>(8).as_deref()
            != Some(decode(&v.produced_digest)?.as_slice())
    {
        return Err(AuthError::Conflict);
    }
    let hash = digest(&(output.grant_id(), &v, owner.user_id, owner.session_id))?;
    if row.get::<_, String>(2) == "produced" {
        tx.execute("UPDATE workflow_routine_calls SET phase='published',output_grant_id=$3,output_context_id=$4,output_revision=$5,output_digest=$6,publication_request=$7,publication_digest=$8,published_by_user=$9,published_session=$10 WHERE account_id=$1 AND id=$2",&[&input.account_id(),&v.call_id,&output.grant_id(),&v.output_context_id,&v.output_revision,&target.source_digest().as_slice(),&v.request_id,&hash,&owner.user_id,&owner.session_id]).await?;
    } else if row.get::<_, Option<Vec<u8>>>(12).as_deref() != Some(hash.as_slice()) {
        return Err(AuthError::Conflict);
    }
    live(&tx, &mut source, &p).await?;
    target.recheck().await?;
    target_read.recheck().await?;
    decisions::fence::contact(&tx, &d, &target.header)
        .await
        .map_err(error)?;
    store::policy(&tx, input, p.policy_id).await?;
    owner::fresh_owner(&tx, owner).await.map_err(error)?;
    let result = store::response(&store::load(&tx, input.account_id(), v.call_id).await?)?;
    drop(source);
    drop(target);
    drop(target_read);
    tx.commit().await?;
    Ok(result)
}

struct Permit<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    source: CheckedScope<'tx, 'connection>,
    target: CheckedScope<'tx, 'connection>,
    target_read: CheckedScope<'tx, 'connection>,
    input: &'tx IntegrationPrincipal,
    policy: Policy,
    descriptor: Descriptor,
    grant: Uuid,
    call: Uuid,
}
impl<'connection> ProposalFence<'connection> for Permit<'_, 'connection> {
    fn transaction(&self) -> &Transaction<'connection> {
        self.tx
    }
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    fn header(&self) -> &wire::Header {
        &self.target.header
    }
    fn actor(&self) -> Actor {
        Actor::Integration(self.grant)
    }
    fn recheck(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), owner::ConversationError>> + Send + '_>,
    > {
        Box::pin(async move {
            let check = async {
                live(self.tx, &mut self.source, &self.policy).await?;
                store::policy(self.tx, self.input, self.policy.policy_id).await?;
                publication_live(self.tx, self.input.account_id(), self.call).await?;
                self.target.check_descriptor(&self.descriptor)?;
                decisions::fence::contact(self.tx, &self.descriptor, &self.target.header)
                    .await
                    .map_err(error)?;
                let now = activation::now(self.tx).await.map_err(error)?;
                if now >= self.descriptor.expires_at_ms().map_err(error)? {
                    return Err(AuthError::Forbidden);
                }
                self.target.recheck().await?;
                self.target_read.recheck().await
            }
            .await;
            check.map_err(|e| match e {
                AuthError::Database(e) => owner::ConversationError::Database(e),
                AuthError::Conflict => owner::ConversationError::Conflict,
                _ => owner::ConversationError::Forbidden,
            })
        })
    }
}

/// Both independently authenticated exact credentials are required; neither
/// becomes an owner nor restores a superseded input revision or reader grant.
pub async fn resume(
    client: &mut Client,
    input: &IntegrationPrincipal,
    output: &IntegrationPrincipal,
    call: Uuid,
) -> Result<Call, AuthError> {
    if input.account_id() != output.account_id() || input.grant_id() == output.grant_id() {
        return Err(AuthError::Forbidden);
    }
    let tx = begin(client).await?;
    let input_context:Uuid=tx.query_opt("SELECT p.context_id FROM workflow_routine_calls c JOIN workflow_routine_policies p ON (p.account_id,p.id)=(c.account_id,c.policy_id) WHERE c.account_id=$1 AND c.id=$2",&[&input.account_id(),&call]).await?.ok_or(AuthError::Forbidden)?.get(0);
    let output_context:Uuid=tx.query_opt("SELECT output_context_id FROM workflow_routine_calls WHERE account_id=$1 AND id=$2 AND output_grant_id=$3",&[&input.account_id(),&call,&output.grant_id()]).await?.ok_or(AuthError::Forbidden)?.get(0);
    let source = scope::lock_scope(&tx, input, input_context, Operation::ContextContent).await?;
    let target = scope::lock_scope(&tx, output, output_context, Operation::Propose).await?;
    let target_read =
        scope::lock_scope(&tx, output, output_context, Operation::ContextContent).await?;
    connector_match(&tx, input, output).await?;
    let p = store::call_policy(&tx, input, call).await?;
    let row = store::load(&tx, input.account_id(), call).await?;
    if !same_scope(&source.header, &target.header)
        || source.contact() != target.contact()
        || source.purpose() != target.purpose()
        || row.get::<_, Option<i64>>(4) != Some(target.header.revision)
        || row.get::<_, Option<Vec<u8>>>(10).as_deref() != Some(target.source_digest().as_slice())
    {
        return Err(AuthError::Forbidden);
    }
    projection(&tx, output, &target).await?;
    let mut output_policy = p.clone();
    output_policy.generation = 1;
    let descriptor = descriptor(&tx, &target, &output_policy, call, call).await?;
    let mut permit = Permit {
        tx: &tx,
        source,
        target,
        target_read,
        input,
        policy: p,
        descriptor,
        grant: output.grant_id(),
        call,
    };
    let result = decisions::store::register_core(&mut permit, call)
        .await
        .map_err(error)?;
    let hash = result.key.binding_digest.to_vec();
    if row.get::<_, String>(2) == "published" {
        tx.execute("UPDATE workflow_routine_calls SET phase='proposed',action_id=$3,binding_digest=$4 WHERE account_id=$1 AND id=$2",&[&input.account_id(),&call,&result.key.action_id,&hash]).await?;
    } else if row.get::<_, String>(2) != "proposed"
        || row.get::<_, Option<Vec<u8>>>(6).as_deref() != Some(hash.as_slice())
    {
        return Err(AuthError::Conflict);
    }
    permit.recheck().await.map_err(error)?;
    let response = store::response(&store::load(&tx, input.account_id(), call).await?)?;
    drop(permit);
    tx.commit().await?;
    Ok(response)
}
