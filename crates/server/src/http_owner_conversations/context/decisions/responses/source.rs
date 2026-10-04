// SPDX-License-Identifier: AGPL-3.0-only
//! Shared retained original capture verification. Provenance does not classify
//! plaintext or cryptographically bind a response to a business offer.
use crate::{
    http_owner_conversations::{ConversationError, activation, context::wire},
    sealed_manifest_store::outbound::{CurrentAuthority, ManifestSnapshot},
};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct VerifiedSource {
    pub(crate) observed_ms: i64,
    pub(crate) accepted_ms: i64,
    pub(crate) envelope_digest: [u8; 32],
}

/// Caller holds actual current owner/context authority in this transaction.
/// The maintained historical verifier checks the signed envelope and actual
/// interval/readers/peer; request digests and phone identities cannot replace it.
pub(crate) async fn verify(
    tx: &Transaction<'_>,
    authority: &mut CurrentAuthority<'_, '_>,
    h: &wire::Header,
    event_id: Uuid,
) -> Result<VerifiedSource, ConversationError> {
    let event=tx.query_opt("SELECT p.trust_generation,p.manifest_version,p.manifest_digest,p.verified_manifest,p.accepted_at_ms,e.envelope FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND p.interval_id=$3 AND e.device_id=$4 AND e.line_id=$5 AND e.binding_generation=$6 FOR SHARE OF p,e",
        &[&h.account,&event_id,&h.interval,&h.device,&h.line,&h.binding_generation]).await?.ok_or(ConversationError::NotFound)?;
    let interval = activation::load(tx, h.account, h.interval).await?;
    let bytes: Vec<u8> = event
        .get::<_, Option<Vec<u8>>>(5)
        .ok_or(ConversationError::NotFound)?;
    let claims =
        crate::sealed_envelope::parse(&bytes, crate::sealed_envelope::Profile::Draft02Candidate)
            .map_err(|_| ConversationError::Forbidden)?;
    let observed_ms =
        i64::try_from(claims.observed_ms).map_err(|_| ConversationError::Forbidden)?;
    let readers = activation::readers(&interval.statement);
    let wanted = activation::wanted(&interval.statement, event_id, &readers);
    let snapshot = ManifestSnapshot {
        generation: event.get(0),
        version: event.get(1),
        digest: event
            .get::<_, Vec<u8>>(2)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        bytes: event.get(3),
        accepted_ms: event.get(4),
    };
    authority.verify_history(&wanted, &snapshot, &bytes).await?;
    Ok(VerifiedSource {
        observed_ms,
        accepted_ms: snapshot.accepted_ms,
        envelope_digest: Sha256::digest(&bytes).into(),
    })
}
