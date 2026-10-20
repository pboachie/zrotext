// SPDX-License-Identifier: AGPL-3.0-only
//! Exact immutable refresh bytes and independent signature phases. No parsed
//! object establishes a current lease, owner factor or physical selection.
use super::*;

pub(super) struct Core03 {
    pub(super) bytes: [u8; 496],
    pub(super) ids: [Uuid; 5],
    pub(super) numbers: [u64; 4],
    pub(super) digests: [[u8; 32]; 11],
    pub(super) issued: u64,
    pub(super) expires: u64,
}
impl Core03 {
    pub(super) fn decode(raw: &[u8]) -> Check<Self> {
        let bytes: [u8; 496] = raw.try_into().map_err(|_| "refresh core width")?;
        if &bytes[..8] != b"ZTSR\x01\x03\x03\0" || bytes[488..] != [0; 8] {
            return Err("refresh core/profile");
        }
        let ids = std::array::from_fn(|i| {
            Uuid::from_bytes(bytes[8 + 16 * i..24 + 16 * i].try_into().unwrap())
        });
        if ids.iter().any(Uuid::is_nil) {
            return Err("refresh identity");
        }
        let mut numbers = [0; 4];
        for (i, value) in numbers.iter_mut().enumerate() {
            *value = crypto::number(&bytes[88 + i * 8..96 + i * 8])?;
            crypto::time(*value)?;
        }
        if numbers[1] != 1 || numbers[3] != 1 {
            return Err("refresh unsupported generation/epoch");
        }
        let digests =
            std::array::from_fn(|i| bytes[120 + 32 * i..152 + 32 * i].try_into().unwrap());
        if digests.contains(&[0; 32]) {
            return Err("refresh selected digest");
        }
        let issued = crypto::number(&bytes[472..480])?;
        let expires = crypto::number(&bytes[480..488])?;
        crypto::time(issued)?;
        crypto::time(expires)?;
        if expires <= issued || expires - issued > 300_000 {
            return Err("refresh original lifetime");
        }
        Ok(Self {
            bytes,
            ids,
            numbers,
            digests,
            issued,
            expires,
        })
    }
    pub(super) fn matches(&self, e: &ExpectedRefresh03<'_>) -> Check<()> {
        if self.ids != [e.account, e.device, e.line, e.refresh, e.binding]
            || self.numbers
                != [
                    e.binding_generation,
                    1,
                    e.manifest_version,
                    e.selection_epoch,
                ]
        {
            return Err("refresh selected identity/counter");
        }
        let device_id = crate::sealed_manifest::key_id(4, e.device_point);
        let owner_id = crate::sealed_manifest::key_id(4, e.owner_point);
        let expected = [
            e.election,
            e.election_bundle,
            e.reader,
            &device_id,
            &owner_id,
            e.root,
            e.manifest,
            e.device_session,
            e.owner_session,
            e.origin,
        ];
        if self.digests[..10].iter().zip(expected).any(|(a, b)| a != b) {
            return Err("refresh selected digest");
        }
        Ok(())
    }
    pub(super) fn fresh(&self, now: u64) -> Check<()> {
        crypto::time(now)?;
        if now < self.issued || now >= self.expires {
            return Err("refresh original deadline");
        }
        Ok(())
    }
    pub(super) fn verify_device(
        &self,
        observation: &[u8],
        signature: &[u8],
        e: &ExpectedRefresh03<'_>,
    ) -> Check<()> {
        self.matches(e)?;
        let parsed =
            ObservationV2::decode(observation).map_err(|_| "refresh complete observation")?;
        if e.original_subscription < 0
            || parsed.selected_subscription_id() != e.original_subscription
        {
            return Err("refresh original subscription");
        }
        crypto::signature(
            e.device_point,
            signature,
            &crypto::framed(
                b"ZTSE/line/payload-profile/selection-refresh/device/v1\0",
                &[self.bytes.as_slice(), observation].concat(),
            )?,
        )
    }
}

pub(super) fn approved(bundle: &[u8], accepted: u64, e: &ExpectedRefresh03<'_>) -> Check<Core03> {
    if bundle.len() != 745 {
        return Err("refresh bundle width");
    }
    let core = Core03::decode(&bundle[..496])?;
    core.fresh(accepted)?;
    core.verify_device(&bundle[496..617], &bundle[617..681], e)?;
    crypto::signature(
        e.owner_point,
        &bundle[681..],
        &crypto::framed(
            b"ZTSE/line/payload-profile/selection-refresh/owner/v1\0",
            &[&bundle[..617], &crypto::sha(&bundle[617..681])].concat(),
        )?,
    )?;
    Ok(core)
}
