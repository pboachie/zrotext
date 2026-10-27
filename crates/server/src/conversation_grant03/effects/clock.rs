// SPDX-License-Identifier: AGPL-3.0-only
//! Fresh passive assertion clock. This returns no content or submit authority.
use super::history::{HeldHistory03, Scope03};
use super::*;
use crate::conversation_effect03::history_clock::Request03;

pub(super) async fn read(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &Request03,
) -> Result<serde_json::Value> {
    let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
    if held.original.grant.ids[1] != request.message_id {
        return Err(Error::Conflict);
    }
    // No owner, content, physical, current03 or suppression-health dependency.
    // Actual original enrolled actor/point, current full lease and primary time
    // are checked again after every preceding wait. No await follows this
    // final comparison before the reply candidate is built.
    held.revalidate(scope).await?;
    let sampled = held.now_ms();
    let expires = sampled
        .checked_add(30_000)
        .ok_or(Error::Unsupported)?
        .min(held.lease_end);
    if expires <= sampled {
        return Err(Error::Expired);
    }
    let reply = serde_json::json!({
        "v":1,"type":"payload_profile_history_clock03",
        "connection_epoch":scope.session.connection_epoch,
        "request_id":request.request_id,"message_id":request.message_id,
        "attempt_id":request.attempt_id,"account_id":scope.session.account_id,
        "device_id":scope.session.device_id,"server_time_ms":sampled.to_string(),
        "sample_expires_ms":expires.to_string(),
        "lease":{
            "site_id":scope.site,"instance_id":scope.instance,
            "deployment_epoch":scope.deployment.to_string(),
            "line_activation_version":held.lease_version,
            "enrolled_signing_key_id":B.encode(held.original.key),
            "device_session_digest":B.encode(held.proof_session),
            "expires_ms":held.lease_end.to_string()
        }
    });
    // This passive reply uses the ordinary socket's unchanged four-KiB cap.
    // The transaction-owning caller commits before transmission.
    if serde_json::to_vec(&reply)
        .map_err(|_| Error::Unavailable)?
        .len()
        > crate::conversation_effect03::history_clock::MAX_JSON_BYTES
    {
        return Err(Error::Unavailable);
    }
    Ok(reply)
}
