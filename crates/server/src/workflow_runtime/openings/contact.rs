// SPDX-License-Identifier: AGPL-3.0-only
//! Actual peer-specific contact and latest purpose episode for an allocation.
//! This is not a SEND descriptor or integration/routine permission.
use crate::http_owner_conversations::{ConversationError, context::wire::Header};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) async fn check(
    tx: &Transaction<'_>,
    header: &Header,
    contact: Uuid,
    purpose: &str,
) -> Result<(Uuid, Option<i64>), ConversationError> {
    let row = tx
        .query_opt(
            "SELECT recipient_e164 FROM contacts WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&header.account, &contact],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    let peer: String = row.get(0);
    if Sha256::digest(peer.as_bytes()).as_slice() != header.peer_digest {
        return Err(ConversationError::Forbidden);
    }
    let row=tx.query_opt("SELECT id,action,effective_at<=clock_timestamp(),expires_at IS NULL OR expires_at>clock_timestamp(),floor(extract(epoch FROM expires_at)*1000)::bigint FROM contact_consent_records WHERE account_id=$1 AND contact_id=$2 AND purpose=$3 ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1 FOR SHARE", &[&header.account,&contact,&purpose]).await?.ok_or(ConversationError::Forbidden)?;
    if row.get::<_, String>(1) != "grant" || !row.get::<_, bool>(2) || !row.get::<_, bool>(3) {
        return Err(ConversationError::Forbidden);
    }
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active) OR EXISTS(SELECT 1 FROM owner_recipient_holds WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL)", &[&header.account,&peer]).await?.get::<_,bool>(0){return Err(ConversationError::Forbidden);}
    Ok((row.get(0), row.get(4)))
}
