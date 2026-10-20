// SPDX-License-Identifier: AGPL-3.0-only
//! Real root/election/manifest/envelope signatures, not database provenance.
use super::*;
use crate::reviewed_intent03::{RetainedTiming03, tests::Packet};
use crate::sealed_manifest03::tests::{NOW, sign};

fn packet() -> (Packet, Vec<u8>, Vec<u8>) {
    let p = Packet::new();
    let e = p.expected();
    let c = &p.current;
    // Independently produce the explicit V2 from selected fixture facts. No
    // V1 body slot is removed, copied, replaced or used to prepare this packet.
    let mut bytes = HEADER.to_vec();
    for id in [
        c.account_id,
        c.device_id,
        c.line_id,
        c.binding_id,
        *e.user.as_bytes(),
        *e.session.as_bytes(),
        *e.interval.as_bytes(),
        [4; 16],
    ] {
        bytes.extend(id);
    }
    for n in [
        c.binding_generation,
        1,
        2,
        1,
        NOW,
        NOW + 500,
        NOW,
        NOW + 200,
    ] {
        bytes.extend(n.to_be_bytes());
    }
    let owner = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
        account_id: c.account_id,
        user_id: *e.user.as_bytes(),
        session_id: *e.session.as_bytes(),
    }
    .digest()
    .unwrap();
    let origin =
        crate::sealed_payload_election03::adapter_contract::origin_digest(e.canonical_origin)
            .unwrap();
    for digest in [
        c.selected_reader_key_id,
        c.root_fingerprint,
        c.manifest_digest,
        c.election_commitment,
        c.election_bundle_sha256,
        owner,
        origin,
        *e.signer,
        crypto::sha(&p.envelope),
        crypto::sha(&p.envelope[..p.envelope.len() - 64]),
    ] {
        bytes.extend(digest);
    }
    bytes.push(e.peer.len() as u8);
    bytes.extend(e.peer);
    bytes.push(e.recipients.len() as u8);
    for (role, id) in e.recipients {
        bytes.push(*role);
        bytes.extend(id);
    }
    bytes.push(1);
    let signature = sign(&p.f.keys[4], DOMAIN, &bytes);
    (p, bytes, signature)
}

#[test]
fn genuine_current_v2_binds_selected_context_exact_ciphertext_and_signed_ceiling() {
    let (p, mut bytes, _) = packet();
    for ceiling in [1, 6] {
        *bytes.last_mut().unwrap() = ceiling;
        let signature = sign(&p.f.keys[4], DOMAIN, &bytes);
        let checked = verify(
            Intent03V2::decode(&bytes).unwrap(),
            &signature,
            &p.envelope,
            &p.expected(),
            NOW,
        )
        .unwrap();
        assert_eq!(checked.intent().bytes(), bytes);
        assert_eq!(checked.signature().as_slice(), signature);
        assert_eq!(checked.envelope().bytes(), p.envelope);
        assert_eq!(checked.expires_ms(), NOW + 500);
        assert_eq!(checked.intent().sms_ceiling(), ceiling);
    }
    for at in [
        8, 24, 40, 56, 72, 88, 104, 120, 136, 144, 152, 160, 168, 176, 184, 192, 200, 232, 264,
        296, 328, 360, 392, 424, 456, 488,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        let signed = sign(&p.f.keys[4], DOMAIN, &bad);
        assert!(
            Intent03V2::decode(&bad)
                .and_then(|i| verify(i, &signed, &p.envelope, &p.expected(), NOW))
                .is_err(),
            "offset {at}"
        );
    }
    // The same genuine signer can sign another envelope, but that new exact
    // ciphertext is not the ciphertext committed by this owner's old review.
    let mut changed = p.envelope[..p.envelope.len() - 64].to_vec();
    changed[200] ^= 1;
    changed.extend(sign(&p.f.keys[4], b"ZTSE/sign/v3\0", &changed));
    let signature = sign(&p.f.keys[4], DOMAIN, &bytes);
    assert!(
        verify(
            Intent03V2::decode(&bytes).unwrap(),
            &signature,
            &changed,
            &p.expected(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn received_owner_origin_interval_reader_and_time_never_select_their_own_authority() {
    let (p, bytes, signature) = packet();
    for mode in 0..9 {
        let mut expected = p.expected();
        let wrong = [9; 32];
        match mode {
            0 => expected.selection_epoch = 2,
            1 => expected.user = Uuid::new_v4(),
            2 => expected.session = Uuid::new_v4(),
            3 => expected.canonical_origin = "https://other.example",
            4 => expected.interval = Uuid::new_v4(),
            5 => expected.peer = b"+34",
            6 => expected.signer = &wrong,
            7 => expected.interval_starts_ms = NOW + 1,
            _ => expected.interval_expires_ms = NOW + 499,
        }
        assert!(
            verify(
                Intent03V2::decode(&bytes).unwrap(),
                &signature,
                &p.envelope,
                &expected,
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn retained_v2_preserves_original_review_time_and_present_grant_permission() {
    let (mut p, bytes, signature) = packet();
    let now = NOW + 250;
    p.current.compared_at_ms = now;
    p.current.permission_expires_at_ms = NOW + 450;
    assert!(
        verify(
            Intent03V2::decode(&bytes).unwrap(),
            &signature,
            &p.envelope,
            &p.expected(),
            now
        )
        .is_err()
    );
    let original = |admitted_ms, installed_ms, required_until_ms| RetainedTiming03 {
        admitted_ms,
        installed_ms,
        required_until_ms,
    };
    verify_retained(
        Intent03V2::decode(&bytes).unwrap(),
        &signature,
        &p.envelope,
        &p.expected(),
        now,
        original(NOW + 50, NOW, NOW + 400),
    )
    .unwrap();
    for old in [
        original(NOW + 200, NOW, NOW + 400),
        original(NOW + 50, NOW + 51, NOW + 400),
        original(NOW + 251, NOW, NOW + 400),
        original(NOW + 50, NOW, now),
        original(NOW + 50, NOW, NOW + 451),
        original(NOW + 50, NOW, NOW + 501),
    ] {
        assert!(
            verify_retained(
                Intent03V2::decode(&bytes).unwrap(),
                &signature,
                &p.envelope,
                &p.expected(),
                now,
                old
            )
            .is_err()
        );
    }
}
