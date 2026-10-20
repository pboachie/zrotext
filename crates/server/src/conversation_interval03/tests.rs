// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
mod fixture;
use crate::sealed_manifest03::tests::{NOW, sign};
use fixture::Packet;

fn statement(p: &Packet) -> Vec<u8> {
    let mut b = HEADER.to_vec();
    let c = &p.current;
    for id in [
        c.account_id,
        c.device_id,
        c.line_id,
        c.binding_id,
        [20; 16],
        [21; 16],
        [7; 16],
        [8; 16],
        [22; 16],
    ] {
        b.extend(id);
    }
    for n in [
        c.binding_generation,
        1,
        2,
        1,
        NOW,
        NOW + 100,
        NOW,
        NOW + 500,
    ] {
        b.extend(n.to_be_bytes());
    }
    let owner = election::adapter_contract::OwnerSessionIdentity03 {
        account_id: c.account_id,
        user_id: [7; 16],
        session_id: [8; 16],
    }
    .digest()
    .unwrap();
    for d in [
        c.selected_reader_key_id,
        p.f.records[1][1..33].try_into().unwrap(),
        p.f.records[3][1..33].try_into().unwrap(),
        p.f.records[4][1..33].try_into().unwrap(),
        c.root_fingerprint,
        c.manifest_digest,
        c.election_commitment,
        c.election_bundle_sha256,
        owner,
        election::adapter_contract::origin_digest("https://owner.example").unwrap(),
        [24; 32],
        [25; 32],
        [26; 32],
    ] {
        b.extend(d);
    }
    b.push(DISCLOSURE_VERSION.len() as u8);
    b.extend(DISCLOSURE_VERSION.as_bytes());
    b.extend(crypto::sha(DISCLOSURE.as_bytes()));
    b.push(3);
    b.extend(b"+12");
    b.push(0);
    b
}
fn expected<'a>(p: &'a Packet, s: &'a Statement03) -> ExpectedConsent03<'a> {
    ExpectedConsent03 {
        current: &p.current,
        election: &p.proof,
        manifest: &p.manifest,
        selection_epoch: 1,
        user: Uuid::from_bytes([7; 16]),
        session: Uuid::from_bytes([8; 16]),
        canonical_origin: "https://owner.example",
        device_session_digest: &s.digests[10],
        physical_digest: &s.digests[11],
        archive_reader: &s.digests[1],
        phone_signer: &s.digests[2],
        browser_signer: &s.digests[3],
        owner_deadline_ms: NOW + 80_000,
        peer: b"+12",
        integrations: &[],
    }
}
fn signatures(p: &Packet, s: &Statement03) -> ([u8; 64], [u8; 64], [u8; 64]) {
    let owner: [u8; 64] = sign(&p.f.keys[4], REQUEST, s.bytes()).try_into().unwrap();
    let phone: [u8; 64] = sign(
        &p.f.keys[3],
        APPROVE,
        &[s.bytes(), &crypto::sha(&owner)].concat(),
    )
    .try_into()
    .unwrap();
    let installed: [u8; 64] = sign(
        &p.f.keys[3],
        INSTALL,
        &[s.bytes(), &crypto::sha(&owner), &crypto::sha(&phone)].concat(),
    )
    .try_into()
    .unwrap();
    (owner, phone, installed)
}
#[test]
fn actual_distinct_role_five_request_and_role_four_phone_proofs_verify_exact_statement() {
    let p = Packet::new();
    let b = statement(&p);
    assert_eq!(b.len(), 695);
    let s = Statement03::decode(&b).unwrap();
    assert_eq!(s.bytes(), b);
    let (owner, phone, installed) = signatures(&p, &s);
    let e = expected(&p, &s);
    verify_request(&s, &owner, &e, NOW).unwrap();
    verify_approval(&s, &owner, &phone, &e, NOW).unwrap();
    verify_install(&s, &owner, &phone, &installed, &e, NOW).unwrap();
    assert!(verify_approval(&s, &phone, &owner, &e, NOW).is_err());
    assert!(verify_install(&s, &owner, &installed, &phone, &e, NOW).is_err());
    assert!(verify_request(&s, &owner, &e, NOW + 100).is_err());
    // Historical setup deadline is not a renewed authority or interval end.
    context(&s, &e, NOW + 100, false).unwrap();
}
#[test]
fn retained_original_install_remains_verifiable_after_setup_without_renewing_any_time() {
    let p = Packet::new();
    let s = Statement03::decode(&statement(&p)).unwrap();
    let e = expected(&p, &s);
    let (owner, phone, installed) = signatures(&p, &s);
    verify_retained(
        &s,
        Some((&owner, NOW)),
        Some((&phone, NOW + 1)),
        Some((&installed, NOW + 2)),
        &e,
        NOW + 100,
    )
    .unwrap();
    for (requested, approved, installed_at, now) in [
        (NOW - 1, NOW + 1, NOW + 2, NOW + 100),
        (NOW, NOW - 1, NOW + 2, NOW + 100),
        (NOW, NOW + 1, NOW, NOW + 100),
        (NOW, NOW + 1, NOW + 100, NOW + 101),
        (NOW, NOW + 1, NOW + 2, NOW + 1),
        (NOW, NOW + 1, NOW + 2, NOW + 500),
    ] {
        assert!(
            verify_retained(
                &s,
                Some((&owner, requested)),
                Some((&phone, approved)),
                Some((&installed, installed_at)),
                &e,
                now
            )
            .is_err()
        );
    }
    assert!(verify_retained(&s, None, Some((&phone, NOW)), None, &e, NOW).is_err());
    assert!(
        verify_retained(
            &s,
            Some((&owner, NOW)),
            None,
            Some((&installed, NOW)),
            &e,
            NOW
        )
        .is_err()
    );
}
#[test]
fn composed_original_bytes_are_exact_and_cannot_select_an_unverified_role_or_deadline() {
    let p = Packet::new();
    let bytes = statement(&p);
    let s = Statement03::decode(&bytes).unwrap();
    let e = expected(&p, &s);
    let make = |interval, expires| Reservation03 {
        interval,
        receipt: s.receipt_id(),
        opening: s.opening_id(),
        issued: NOW,
        setup: NOW + 100,
        expires,
        nonce: [26; 32],
    };
    let made = compose(&e, make(s.interval_id(), NOW + 500)).unwrap();
    assert_eq!(made.bytes(), bytes);
    assert!(compose(&e, make(Uuid::from_bytes(s.ids[3]), NOW + 500)).is_err());
    assert!(compose(&e, make(s.interval_id(), NOW + 80_001)).is_err());
}
#[test]
fn disclosure_original_scope_and_prior_proof_hashes_cannot_be_replaced() {
    let p = Packet::new();
    let bytes = statement(&p);
    let s = Statement03::decode(&bytes).unwrap();
    let e = expected(&p, &s);
    let (owner, phone, installed) = signatures(&p, &s);
    for at in [
        0, 4, 5, 6, 7, 8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 160, 168, 176, 184, 192, 200,
        208, 216, 248, 280, 312, 344, 376, 408, 440, 472, 504, 536, 568, 600, 632, 658, 693,
    ] {
        let mut b = bytes.clone();
        b[at] ^= 1;
        let result = Statement03::decode(&b)
            .and_then(|bad| verify_install(&bad, &owner, &phone, &installed, &e, NOW));
        assert!(result.is_err(), "offset {at}");
    }
    let mut changed = owner;
    changed[0] ^= 1;
    assert!(verify_install(&s, &changed, &phone, &installed, &e, NOW).is_err());
    for b in [
        &bytes[..bytes.len() - 1],
        &[bytes.as_slice(), &[0]].concat(),
    ] {
        assert!(Statement03::decode(b).is_err());
    }
}
#[test]
fn selected_mapping_and_real_device_physical_context_are_independent_requirements() {
    let p = Packet::new();
    let s = Statement03::decode(&statement(&p)).unwrap();
    let (owner, _, _) = signatures(&p, &s);
    for mode in 0..8 {
        let mut e = expected(&p, &s);
        let bad = [9; 32];
        match mode {
            0 => e.user = Uuid::new_v4(),
            1 => e.session = Uuid::new_v4(),
            2 => e.selection_epoch = 2,
            3 => e.device_session_digest = &bad,
            4 => e.physical_digest = &bad,
            5 => e.phone_signer = &bad,
            6 => e.browser_signer = &bad,
            _ => e.owner_deadline_ms = NOW + 499,
        }
        assert!(verify_request(&s, &owner, &e, NOW).is_err());
    }
}
#[test]
fn physical_commitments_bind_exact_source_and_actual_full_session_without_claiming_custody() {
    let ids = [
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    ];
    let original = Uuid::new_v4();
    let a = physical_digest(
        ids[0],
        ids[1],
        ids[2],
        ids[3],
        &[1; 32],
        &[2; 32],
        PhysicalSource03::OriginalV2 {
            original_binding: original,
            activation_evidence: b"synthetic public candidate",
        },
    )
    .unwrap();
    let b = physical_digest(
        ids[0],
        ids[1],
        ids[2],
        ids[3],
        &[1; 32],
        &[3; 32],
        PhysicalSource03::OriginalV2 {
            original_binding: original,
            activation_evidence: b"synthetic public candidate",
        },
    )
    .unwrap();
    assert_ne!(a, b);
    assert!(
        physical_digest(
            ids[0],
            ids[1],
            ids[2],
            ids[3],
            &[1; 32],
            &[2; 32],
            PhysicalSource03::OwnerRefresh03 {
                refresh_id: Uuid::new_v4(),
                bundle: &[1; 745],
                accepted_ms: 2,
                installed_ms: 1
            }
        )
        .is_err()
    );
}
