// SPDX-License-Identifier: AGPL-3.0-only
//! Socket-local proof provenance. UUID-only legacy fixtures cannot mint it.

use super::{DeviceSession, DeviceSocketState, line_activation_v2};
use crate::enrollment::{AuthenticatedDevice, VerifiedDevice};
use std::sync::atomic::Ordering;
use tokio_postgres::{Client, types::Type};

pub(super) enum ClaimActor {
    Verified(VerifiedDevice),
    #[cfg(test)]
    TestIdentity(AuthenticatedDevice),
}
impl ClaimActor {
    pub(super) fn identity(&self) -> AuthenticatedDevice {
        match self {
            Self::Verified(proof) => proof.identity(),
            #[cfg(test)]
            Self::TestIdentity(identity) => *identity,
        }
    }
    pub(super) fn matches_point(&self, point: &[u8]) -> bool {
        match self {
            Self::Verified(proof) => proof.matches_point(point),
            #[cfg(test)]
            Self::TestIdentity(_) => true,
        }
    }
}

/// Only the real session-claim path can bind a verified signing point to an
/// actual claimed epoch. This does not itself establish current permission.
#[derive(Clone, Copy)]
pub(super) struct SocketActor {
    proof: VerifiedDevice,
    session: DeviceSession,
}
impl SocketActor {
    pub(super) fn session(&self) -> DeviceSession {
        self.session
    }
    pub(super) async fn current(
        &self,
        client: &Client,
        state: &DeviceSocketState,
    ) -> Result<bool, tokio_postgres::Error> {
        if state.draining.load(Ordering::Acquire) {
            return Ok(false);
        }
        let session = self.session;
        Ok(client.query_typed_opt(
            "SELECT 1 FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND k.signing_key_sec1=$7 AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery()",
            &[(&session.account_id,Type::UUID),(&session.device_id,Type::UUID),
              (&state.site_id,Type::TEXT),(&state.instance_id,Type::TEXT),
              (&session.connection_epoch,Type::INT8),(&state.deployment_epoch,Type::INT8),
              (&&self.proof.signing_point()[..],Type::BYTEA)],
        ).await?.is_some())
    }
    pub(super) async fn renew(
        &self,
        client: &Client,
        state: &DeviceSocketState,
    ) -> Result<bool, tokio_postgres::Error> {
        if state.draining.load(Ordering::Acquire) {
            return Ok(false);
        }
        let session = self.session;
        Ok(client.execute_typed(
            "UPDATE device_sessions s SET lease_until=clock_timestamp()+($7::integer * interval '1 second') WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>clock_timestamp() AND EXISTS (SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=$3 JOIN deployment_authority p ON p.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND k.signing_key_sec1=$8 AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery())",
            &[(&session.account_id,Type::UUID),(&session.device_id,Type::UUID),
              (&state.site_id,Type::TEXT),(&state.instance_id,Type::TEXT),
              (&session.connection_epoch,Type::INT8),(&state.deployment_epoch,Type::INT8),
              (&super::SESSION_LEASE_SECONDS,Type::INT4),(&&self.proof.signing_point()[..],Type::BYTEA)],
        ).await?==1)
    }
}

pub(super) async fn claim(
    client: &mut Client,
    proof: VerifiedDevice,
    state: &DeviceSocketState,
    protocol: line_activation_v2::LineProtocol,
) -> Result<Option<SocketActor>, tokio_postgres::Error> {
    Ok(
        super::claim_session_for_actor(client, ClaimActor::Verified(proof), state, protocol)
            .await?
            .map(|session| SocketActor { proof, session }),
    )
}

#[cfg(test)]
mod tests;
