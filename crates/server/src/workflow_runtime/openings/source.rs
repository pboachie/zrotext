// SPDX-License-Identifier: AGPL-3.0-only
use super::contracts::Source;
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{ConversationError, context},
    sealed_manifest_store::outbound::CurrentAuthority,
};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

/// Borrowed actual stored source. No request DTO can manufacture this permit.
pub(super) struct CheckedSource<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    expected: &'tx Source,
    header: context::wire::Header,
    deadline_ms: i64,
}

pub(super) async fn check<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    authority: &mut CurrentAuthority<'tx, 'connection>,
    expected: &'tx Source,
) -> Result<CheckedSource<'tx, 'connection>, ConversationError> {
    if !expected.validate() {
        return Err(ConversationError::Invalid);
    }
    // None selects the actual current head under the maintained source lock.
    let bytes = context::load(tx, owner.tenant.account_id(), expected.context_id, None).await?;
    let header = context::wire::parse(&bytes)?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    if header.revision != expected.revision || digest != expected.digest {
        return Err(ConversationError::Conflict);
    }
    authorize(tx, owner, authority, &header).await?;
    let interval =
        crate::http_owner_conversations::activation::load(tx, header.account, header.interval)
            .await?;
    let readers = crate::http_owner_conversations::activation::readers(&interval.statement);
    let wanted = crate::http_owner_conversations::activation::wanted(
        &interval.statement,
        header.context,
        &readers,
    );
    let deadline_ms = authority
        .admission_deadline(&wanted)
        .await?
        .min(header.expires_ms)
        .min(interval.statement.expires_ms);
    // A source-only fence does not fabricate a routine or SEND action. Never
    // replace a stopped fence: the existing immutable stop trigger also guards it.
    tx.execute("INSERT INTO workflow_context_fences(account_id,context_id,actor_user_id) VALUES($1,$2,$3) ON CONFLICT(account_id,context_id) DO NOTHING",
        &[&header.account,&header.context,&owner.user_id]).await?;
    live(tx, &header).await?;
    Ok(CheckedSource {
        tx,
        owner,
        expected,
        header,
        deadline_ms,
    })
}

async fn authorize(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    h: &context::wire::Header,
) -> Result<(), ConversationError> {
    context::authorize_selected_reader(
        tx,
        owner,
        authority,
        &context::SelectedReaderScope {
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
        true,
    )
    .await
}

async fn live(tx: &Transaction<'_>, h: &context::wire::Header) -> Result<(), ConversationError> {
    let row = tx.query_opt("SELECT stopped_at IS NULL FROM workflow_context_fences WHERE account_id=$1 AND context_id=$2 FOR UPDATE",
        &[&h.account,&h.context]).await?.ok_or(ConversationError::NotFound)?;
    if !row.get::<_, bool>(0) {
        return Err(ConversationError::Forbidden);
    }
    Ok(())
}

impl<'tx, 'connection> CheckedSource<'tx, 'connection> {
    pub(super) fn header(&self) -> &context::wire::Header {
        &self.header
    }
    pub(super) fn deadline_ms(&self) -> i64 {
        self.deadline_ms
    }

    pub(super) async fn recheck(
        &self,
        authority: &mut CurrentAuthority<'tx, 'connection>,
    ) -> Result<(), ConversationError> {
        let bytes = context::load(self.tx, self.header.account, self.header.context, None).await?;
        let header = context::wire::parse(&bytes)?;
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        if header.revision != self.expected.revision || digest != self.expected.digest {
            return Err(ConversationError::Conflict);
        }
        authorize(self.tx, self.owner, authority, &header).await?;
        live(self.tx, &header).await?;
        if crate::http_owner_conversations::activation::now(self.tx).await? >= self.deadline_ms {
            return Err(ConversationError::Forbidden);
        }
        Ok(())
    }
}
