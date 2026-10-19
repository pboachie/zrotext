// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest03::tests::hex;

#[test]
fn exact_independent_android_vector_checks_all_three_original_signatures() {
    // BYTE-IDENTICAL vector produced independently by the Android source lane;
    // no private key or acceptance/current-custody assertion is present.
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-selection-refresh-01.json"
    ))
    .unwrap();
    let bundle = hex(&v["bundle"]);
    let core = &bundle[..496];
    let point: [u8; 65] = hex(&v["device_signing_point"]).try_into().unwrap();
    let owner: [u8; 65] = hex(&v["owner_approval_point"]).try_into().unwrap();
    let digest = |at| core[at..at + 32].try_into().unwrap();
    let number = |at| crypto::number(&core[at..at + 8]).unwrap();
    let uuid = |at| Uuid::from_slice(&core[at..at + 16]).unwrap();
    let election = digest(120);
    let election_bundle = digest(152);
    let reader = digest(184);
    let root = digest(280);
    let manifest = digest(312);
    let device_session = digest(344);
    let owner_session = digest(376);
    let origin = digest(408);
    let e = ExpectedRefresh03 {
        account: uuid(8),
        device: uuid(24),
        line: uuid(40),
        binding: uuid(72),
        refresh: uuid(56),
        binding_generation: number(88),
        manifest_version: number(104),
        selection_epoch: number(112),
        election: &election,
        election_bundle: &election_bundle,
        reader: &reader,
        device_point: &point,
        owner_point: &owner,
        root: &root,
        manifest: &manifest,
        device_session: &device_session,
        owner_session: &owner_session,
        origin: &origin,
        original_subscription: 8,
    };
    let installed = hex(&v["installed_signature"]);
    let issued = number(472);
    let expires = number(480);
    verify_installed(&bundle, issued + 1, issued + 2, &installed, &e).unwrap();
    for at in [
        0, 4, 5, 6, 7, 8, 24, 40, 56, 72, 88, 96, 104, 112, 120, 152, 184, 216, 248, 280, 312, 344,
        376, 408, 440, 472, 480, 488, 496, 504, 617, 681,
    ] {
        let mut changed = bundle.clone();
        changed[at] ^= 1;
        assert!(
            verify_installed(&changed, issued + 1, issued + 2, &installed, &e).is_err(),
            "offset {at}"
        );
    }
    for (accepted, installed_ms) in [
        (issued - 1, issued),
        (expires, expires),
        (issued + 2, issued + 1),
        (issued + 1, expires),
    ] {
        assert!(verify_installed(&bundle, accepted, installed_ms, &installed, &e).is_err());
    }
    let mut changed = installed.clone();
    changed[0] ^= 1;
    assert!(verify_installed(&bundle, issued + 1, issued + 2, &changed, &e).is_err());
    let changed = ExpectedRefresh03 {
        original_subscription: 9,
        ..e
    };
    assert!(verify_installed(&bundle, issued + 1, issued + 2, &installed, &changed).is_err());
}
