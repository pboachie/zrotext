// SPDX-License-Identifier: AGPL-3.0-only
//! Historical fresh-selection signatures, not live physical availability.
//! Only the actual111 reader/held lease and local opaque issuer establish that.
use crate::sealed_inbound::line_activation::v2::ObservationV2;
use crate::sealed_manifest03::{self as crypto, Check};
use uuid::Uuid;

pub(crate) struct ExpectedRefresh03<'a> {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub binding: Uuid,
    pub refresh: Uuid,
    pub binding_generation: u64,
    pub manifest_version: u64,
    pub selection_epoch: u64,
    pub election: &'a [u8; 32],
    pub election_bundle: &'a [u8; 32],
    pub reader: &'a [u8; 32],
    pub device_point: &'a [u8; 65],
    pub owner_point: &'a [u8; 65],
    pub root: &'a [u8; 32],
    pub manifest: &'a [u8; 32],
    pub device_session: &'a [u8; 32],
    pub owner_session: &'a [u8; 32],
    pub origin: &'a [u8; 32],
    pub original_subscription: i32,
}
mod core;
pub(crate) mod live;

pub(crate) fn verify_installed(
    bundle: &[u8],
    accepted_ms: u64,
    installed_ms: u64,
    installed_signature: &[u8],
    e: &ExpectedRefresh03<'_>,
) -> Check<()> {
    let core = core::approved(bundle, accepted_ms, e)?;
    crypto::time(installed_ms)?;
    if installed_ms < accepted_ms || installed_ms >= core.expires {
        return Err("refresh original installation time");
    }
    crypto::signature(
        e.device_point,
        installed_signature,
        &crypto::framed(
            b"ZTSE/line/payload-profile/selection-refresh/installed/v1\0",
            &[
                e.refresh.as_bytes().as_slice(),
                &crypto::sha(bundle),
                e.device_session,
            ]
            .concat(),
        )?,
    )
}

#[cfg(test)]
mod tests;
