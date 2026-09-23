// SPDX-License-Identifier: AGPL-3.0-only
//! Fail-closed identity prerequisite for a future sealed inbound route.
//! This module cannot ingest content. A valid line binding does not verify a
//! sealed envelope, prove which SIM received an SMS, or authorize a webhook.

use crate::inbound::InboundSession;
use tokio_postgres::Client;
use uuid::Uuid;

pub mod line_activation;

/// Checks the current writer session and a line binding marked active with
/// both evidence digest fields. A future route must verify those enrollment
/// proofs and additionally verify the complete owner-signed
/// manifest and exact device-signed sealed envelope before storage. The
/// caller must keep this preflight and its insert in one transaction, or
/// recheck the session in the insert transaction; the insert trigger checks
/// active line state but not the session epoch.
pub async fn line_binding_ready(
    client: &Client,
    session: InboundSession<'_>,
    line_id: Uuid,
    binding_generation: i64,
) -> Result<bool, tokio_postgres::Error> {
    if line_id.is_nil() || binding_generation <= 0 {
        return Ok(false);
    }
    Ok(client
        .query_opt(
            "SELECT 1 FROM device_sessions s \
             JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
             JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
             JOIN accounts a ON a.id=d.account_id \
             JOIN sites t ON t.site_id=s.site_id \
             JOIN deployment_authority p ON p.singleton=TRUE \
             JOIN phone_lines l ON l.account_id=d.account_id AND l.id=$7 \
             JOIN device_line_bindings b ON \
               (b.account_id,b.line_id,b.device_id)=(d.account_id,l.id,d.id) \
             WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 \
               AND s.instance_id=$4 AND s.connection_epoch=$5 \
               AND s.deployment_epoch=$6 AND s.lease_until>now() \
               AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
               AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE \
               AND p.epoch=$6 AND NOT pg_is_in_recovery() \
               AND l.state='active' AND l.approved_at IS NOT NULL \
               AND l.current_binding_generation=$8 \
               AND b.generation=$8 AND b.state='active' \
               AND b.owner_approval_digest IS NOT NULL \
               AND b.device_confirmation_digest IS NOT NULL \
               AND b.activated_at IS NOT NULL \
             FOR SHARE OF s,d,k,a,t,p,l,b",
            &[
                &session.account_id,
                &session.device_id,
                &session.site_id,
                &session.instance_id,
                &session.connection_epoch,
                &session.deployment_epoch,
                &line_id,
                &binding_generation,
            ],
        )
        .await?
        .is_some())
}

#[cfg(test)]
mod tests;
