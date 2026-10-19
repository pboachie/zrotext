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
pub(crate) fn verify_installed(
    bundle: &[u8],
    accepted_ms: u64,
    installed_ms: u64,
    installed_signature: &[u8],
    e: &ExpectedRefresh03<'_>,
) -> Check<()> {
    if bundle.len() != 745 {
        return Err("refresh bundle width");
    }
    let c = &bundle[..496];
    if &c[..8] != b"ZTSR\x01\x03\x03\0" || c[488..] != [0; 8] {
        return Err("refresh core/profile");
    }
    for (at, id) in [
        (8, e.account),
        (24, e.device),
        (40, e.line),
        (56, e.refresh),
        (72, e.binding),
    ] {
        if id.is_nil() || c[at..at + 16] != *id.as_bytes() {
            return Err("refresh identity");
        }
    }
    for (at, n) in [
        (88, e.binding_generation),
        (96, 1),
        (104, e.manifest_version),
        (112, e.selection_epoch),
    ] {
        crypto::time(n)?;
        if crypto::number(&c[at..at + 8])? != n {
            return Err("refresh selection counter");
        }
    }
    let device_id = crate::sealed_manifest::key_id(4, e.device_point);
    let owner_id = crate::sealed_manifest::key_id(4, e.owner_point);
    for (at, digest) in [
        (120, e.election),
        (152, e.election_bundle),
        (184, e.reader),
        (216, &device_id),
        (248, &owner_id),
        (280, e.root),
        (312, e.manifest),
        (344, e.device_session),
        (376, e.owner_session),
        (408, e.origin),
    ] {
        if *digest == [0; 32] || c[at..at + 32] != *digest {
            return Err("refresh selected digest");
        }
    }
    let issued = crypto::number(&c[472..480])?;
    let expires = crypto::number(&c[480..488])?;
    crypto::time(issued)?;
    crypto::time(expires)?;
    crypto::time(accepted_ms)?;
    crypto::time(installed_ms)?;
    if c[440..472] == [0; 32]
        || expires <= issued
        || expires - issued > 300_000
        || accepted_ms < issued
        || accepted_ms >= expires
        || installed_ms < accepted_ms
        || installed_ms >= expires
    {
        return Err("refresh original acceptance time");
    }
    let observation =
        ObservationV2::decode(&bundle[496..617]).map_err(|_| "refresh complete observation")?;
    if e.original_subscription < 0
        || observation.selected_subscription_id() != e.original_subscription
    {
        return Err("refresh original subscription");
    }
    let device = &bundle[617..681];
    let owner = &bundle[681..745];
    crypto::signature(
        e.device_point,
        device,
        &crypto::framed(
            b"ZTSE/line/payload-profile/selection-refresh/device/v1\0",
            &bundle[..617],
        )?,
    )?;
    crypto::signature(
        e.owner_point,
        owner,
        &crypto::framed(
            b"ZTSE/line/payload-profile/selection-refresh/owner/v1\0",
            &[&bundle[..617], &crypto::sha(device)].concat(),
        )?,
    )?;
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
