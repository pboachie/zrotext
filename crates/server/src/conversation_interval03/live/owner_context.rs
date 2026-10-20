// SPDX-License-Identifier: AGPL-3.0-only
//! Purpose-specific current context and passive interrupted-opening recovery.
//! Neither read signs, renews, adopts an old session or installs permission.
use super::*;

pub(crate) async fn opening_status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx) || opening.is_nil() {
        return Err(Error::Authentication);
    }
    ready(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let row=tx.query_opt("SELECT * FROM public.conversation_profile03_intervals WHERE account_id=$1 AND opening_id=$2 FOR SHARE NOWAIT", &[&who.account,&opening]).await?.ok_or(Error::NotFound)?;
    let prior = StoredInterval03::from_row(&row)?;
    if prior.statement.opening_id() != opening || prior.selected_owner().user != who.user {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(prior.receipt())
}

pub(crate) struct ContextRead03 {
    pub request: Uuid,
    pub opening: Uuid,
    pub interval: Uuid,
}
pub(crate) async fn owner_context<'held, 'db>(
    tx: &'held Transaction<'db>,
    owner: &mut HeldOrdinaryOwner03<'held, 'db>,
    input: ContextRead03,
    origin: &str,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx)
        || [input.request, input.opening, input.interval]
            .iter()
            .any(Uuid::is_nil)
    {
        return Err(Error::Authentication);
    }
    ready(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let prior = StoredInterval03::read(tx, who.account, input.interval).await?;
    if prior.statement.opening_id() != input.opening || prior.selected_owner() != who {
        return Err(Error::Authentication);
    }
    let mut held =
        selected::hold_owner_selection(tx, owner, prior.statement.line_id(), origin).await?;
    let pending = prior.phase != "active";
    let mappings = prior.validate(&mut held, pending).await?;
    held.revalidate().await?;
    mappings.require_current(held.now_ms())?;
    let (_, setup, _, end) = prior.statement.times();
    let deadline = held
        .authority()
        .permission_expires_at_ms
        .min(end)
        .min(mappings.deadline());
    if held.now_ms() >= deadline || pending && held.now_ms() >= setup {
        return Err(Error::Expired);
    }
    // The final actual primary comparison supplies every projection below;
    // no awaited work, phase change or renewed timestamp follows it.
    let selection = held.owner_projection(deadline)?;
    Ok(
        serde_json::json!({"v":1,"kind":"owner_conversation_context03","request_id":input.request,"opening_id":input.opening,"interval_id":input.interval,"statement_sha256":B.encode(prior.statement.digest()),"selection":selection,"owner_session_expires_ms":held.owner_deadline_ms().to_string(),"physical_selection_digest":B.encode(held.physical_digest()),"compared_ms":held.now_ms().to_string(),"permission_expires_ms":deadline.to_string(),"readers":mappings.projection()}),
    )
}
