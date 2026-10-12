// SPDX-License-Identifier: AGPL-3.0-only
//! Original-session typed proposal inspection. The separate router is opt-in;
//! packets and directory context never create consent, private keys or dispatch.
mod public_inputs;
pub use public_inputs::{Binding as GenesisBinding, GenesisInputs, inspect_genesis_inputs};
mod authority;
mod http;
pub(crate) mod lifecycle;
mod packet;
mod store;
pub use http::router;

use super::{ConversationError, OwnerConversationsState, SessionPrincipal};
use authority::{Current, Selection};
use store::Record;
use tokio_postgres::Transaction;
use uuid::Uuid;

async fn operation_live(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
    r: &Record,
) -> Result<Option<i64>, ConversationError> {
    let mut originating_deadline = None;
    if r.kind == 3 {
        let inputs = packet::retained_genesis(&r.expected)?;
        authority::reject_known_alias(
            tx,
            p.tenant.account_id(),
            &[inputs.phone_reader, inputs.archive_reader],
        )
        .await?;
    } else {
        tx.query_opt("SELECT 1 FROM owner_conversation_consents WHERE account_id=$1 AND device_id=$2 AND line_id=$3 AND binding_generation=$4 AND peer=$5 AND disclosure_version='conversation-content-v1' AND revoked_at IS NULL FOR SHARE",&[&p.tenant.account_id(),&s.device,&s.line,&s.generation,&s.peer]).await?.ok_or(ConversationError::Forbidden)?;
        if r.kind == 4 {
            if !tx.query("SELECT 1 FROM conversation_intervals WHERE account_id=$1 AND phase IN ('pending','install_pending','active') FOR SHARE",&[&p.tenant.account_id()]).await?.is_empty(){return Err(ConversationError::Conflict);}
        } else {
            let id = r.interval.ok_or(ConversationError::Forbidden)?;
            let interval = super::activation::load(tx, p.tenant.account_id(), id).await?;
            let st = &interval.statement;
            if interval.phase != "active"
                || st.device != s.device
                || st.line != s.line
                || st.generation != s.generation
                || st.peer != s.peer
                || st.trust_generation != 1
                || st.activation_version > c.version
            {
                return Err(ConversationError::Forbidden);
            }
            super::activation::origin(tx, st).await?;
            let deadline=tx.query_opt("SELECT floor(extract(epoch FROM LEAST(expires_at,COALESCE(last_used_at,created_at)+interval '72 hours'))*1000)::bigint FROM sessions WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND COALESCE(last_used_at,created_at)>clock_timestamp()-interval '72 hours'",&[&p.tenant.account_id(),&st.originating_session]).await?.ok_or(ConversationError::Forbidden)?;
            originating_deadline = Some(deadline.get::<_, i64>(0));
            // A selected new role-5 point cannot reuse any known signing role history.
            let point = packet::signer_point(&r.expected)?;
            authority::reject_known_alias(tx, p.tenant.account_id(), &[point]).await?;
        }
    }
    Ok(originating_deadline)
}

async fn final_record(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    s: &Selection,
    c: &Current,
    origin: &str,
    r: &Record,
) -> Result<i64, ConversationError> {
    let originating_deadline = operation_live(tx, p, s, c, r).await?;
    let now = authority::fresh(tx, p, s, c).await?;
    if now < r.issued || now >= r.expires || originating_deadline.is_some_and(|until| now >= until)
    {
        return Err(ConversationError::Forbidden);
    }
    let inputs = if r.kind == 3 {
        Some(packet::retained_genesis(&r.expected)?)
    } else {
        None
    };
    let checked = packet::validate(
        r.kind,
        packet::Context {
            p,
            s,
            c,
            origin,
            now,
        },
        &r.packet,
        inputs.as_ref(),
    )?;
    if checked.expected != r.expected
        || checked.issued != r.issued
        || checked.expires != r.expires
        || checked.interval != r.interval
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(now)
}
