// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest;
use crate::sealed_manifest03::VerifiedManifest03;
use crate::sealed_manifest03::tests::{Fixture, NOW, corpus, hex, sign};
use aes_gcm::aead::Generate;
use p256::ecdsa::SigningKey;

pub(crate) fn readers(f: &Fixture, kind: u8) -> Vec<(u8, [u8; 32])> {
    let mut r: Vec<_> = f
        .records
        .iter()
        .filter(|r| r[0] <= 3 && (kind == 1 || r[0] != 1))
        .map(|r| (r[0], r[1..33].try_into().unwrap()))
        .collect();
    r.sort();
    r
}
pub(crate) fn envelope(
    f: &Fixture,
    manifest: &VerifiedManifest03,
    kind: u8,
    body_len: usize,
    peer: &[u8],
) -> Vec<u8> {
    let id = manifest.identity_at(NOW).unwrap();
    let signer = if kind == 1 { 4 } else { 3 };
    let mut p = f.account.to_vec();
    p.extend([4; 16]);
    p.extend(f.device);
    p.extend(f.line);
    let signer_record = f
        .records
        .iter()
        .find(|r| usize::from(r[0]) == signer + 1)
        .unwrap();
    p.extend(id.version.to_be_bytes());
    p.extend(id.digest);
    p.extend(&signer_record[1..33]);
    p.extend(NOW.to_be_bytes());
    if kind == 1 {
        p.extend((NOW + 500).to_be_bytes());
        p.push(1);
    } else {
        p.extend([4; 16]);
        p.extend(1u64.to_be_bytes());
    }
    p.push(peer.len() as u8);
    p.extend(peer);
    let mut b = b"ZTSE\x03".to_vec();
    b.extend([kind, 0, 0]);
    b.extend((p.len() as u16).to_be_bytes());
    b.extend(p);
    b.extend([7; 12]);
    b.extend((body_len as u32).to_be_bytes());
    b.extend(vec![8; body_len]);
    let requested = readers(f, kind);
    b.push(requested.len() as u8);
    for (role, key) in requested {
        b.push(role);
        b.extend(key);
        b.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
        b.extend([9; 48]);
    }
    b.extend(sign(&f.keys[signer], b"ZTSE/sign/v3\0", &b));
    b
}
fn expected<'a>(
    f: &Fixture,
    kind: u8,
    peer: &'a [u8],
    recipients: &'a [(u8, [u8; 32])],
) -> ExpectedContext03<'a> {
    ExpectedContext03 {
        kind,
        account_id: f.account,
        message_id: [4; 16],
        device_id: f.device,
        line_id: f.line,
        peer,
        recipients,
    }
}

#[test]
fn exact_signed_outbound_and_inbound_roles_and_contexts_verify() {
    let f = Fixture::new();
    let (_, _, manifest) = f.pair();
    for kind in [1, 2] {
        let bytes = envelope(&f, &manifest, kind, 17, b"+12");
        let r = readers(&f, kind);
        let e = expected(&f, kind, b"+12", &r);
        let verified = verify(&bytes, &manifest, &e, NOW).unwrap();
        assert_eq!(verified.bytes(), bytes);
        assert_eq!(*verified.envelope_digest(), sha(&bytes));
        let p = parse(&bytes).unwrap();
        assert_eq!(*verified.unsigned_digest(), sha(&bytes[..p.unsigned_end]));
        assert_eq!(
            verified.body_aad(),
            [b"ZTSE/body/v3\0".as_slice(), &bytes[..p.prefix_end]].concat()
        );
        for (i, (role, id)) in r.iter().enumerate() {
            let suffix = [&bytes[..p.prefix_end], &[*role], id].concat();
            assert_eq!(
                verified.wrap_info(i).unwrap(),
                [b"ZTSE/wrap/v3\0".as_slice(), &suffix].concat()
            );
            assert_eq!(
                verified.wrap_aad(i).unwrap(),
                [b"ZTSE/wrap-aad/v3\0".as_slice(), &suffix].concat()
            );
            assert_ne!(
                verified.wrap_info(i).unwrap(),
                verified.wrap_aad(i).unwrap()
            );
        }
        assert!(verified.wrap_info(r.len()).is_err());
        let wrong = ExpectedContext03 {
            message_id: [5; 16],
            ..e
        };
        assert!(verify(&bytes, &manifest, &wrong, NOW).is_err());
    }
}

#[test]
fn canonical_public_context_domains_are_exact_without_claiming_a_valid_envelope() {
    let v = corpus();
    let context = &v["hpkeContext"];
    let prefix = [hex(&context["headerHex"]), hex(&context["protectedHex"])].concat();
    let id = hex(&context["recipientKeyIdHex"]);
    let suffix = [prefix.as_slice(), &[1], &id].concat();
    assert_eq!(
        [b"ZTSE/wrap/v3\0".as_slice(), &suffix].concat(),
        hex(&context["infoHex"])
    );
    assert_eq!(
        [b"ZTSE/wrap-aad/v3\0".as_slice(), &suffix].concat(),
        hex(&context["aadHex"])
    );
    assert_eq!(
        [b"ZTSE/body/v3\0".as_slice(), &prefix].concat(),
        hex(&context["bodyAadHex"])
    );
}

#[test]
fn kind_bounds_cardinality_and_all_length_prefixes_fail_closed() {
    let mut f = Fixture::new();
    f.records.retain(|r| r[0] != 3); // minimum outbound readers
    let (_, _, manifest) = f.pair();
    let minimum = envelope(&f, &manifest, 1, 17, b"+12");
    assert_eq!(minimum.len(), 557);
    let r = readers(&f, 1);
    let e = expected(&f, 1, b"+12", &r);
    verify(&minimum, &manifest, &e, NOW).unwrap();
    let inbound = envelope(&f, &manifest, 2, 17, b"+12");
    assert_eq!(inbound.len(), 426);
    verify(
        &inbound,
        &manifest,
        &expected(&f, 2, b"+12", &readers(&f, 2)),
        NOW,
    )
    .unwrap();
    // Fixture signer key indices are independent of the retained public records.
    let f = Fixture::new();
    let (_, _, manifest) = f.pair();
    let valid = envelope(&f, &manifest, 1, 17, b"+12");
    for at in [0, 4, 5, 6, 8, 9, 10, 163] {
        let mut changed = valid.clone();
        changed[at] ^= 0x80;
        assert!(
            parse(&changed).is_err()
                || verify(
                    &changed,
                    &manifest,
                    &expected(&f, 1, b"+12", &readers(&f, 1)),
                    NOW
                )
                .is_err()
        );
    }
    for bytes in [
        vec![0; 425],
        vec![0; 36865],
        valid[..valid.len() - 1].to_vec(),
        [valid.as_slice(), &[0]].concat(),
    ] {
        assert!(parse(&bytes).is_err());
    }
    let parsed = parse(&valid).unwrap();
    let wrap_at = parsed.prefix_end + 16 + 17 + 1;
    for count in [0, 1, 9] {
        let mut changed = valid.clone();
        changed[wrap_at - 1] = count;
        assert!(parse(&changed).is_err());
    }
    for point in [[0; 65], [5; 65], {
        let mut off_curve = [0; 65];
        off_curve[0] = 4;
        off_curve
    }] {
        let mut changed = valid.clone();
        changed[wrap_at + 33..wrap_at + 98].copy_from_slice(&point);
        assert!(parse(&changed).is_err());
    }
    let mut swapped = valid.clone();
    let first = valid[wrap_at..wrap_at + 146].to_vec();
    swapped[wrap_at..wrap_at + 146].copy_from_slice(&valid[wrap_at + 146..wrap_at + 292]);
    swapped[wrap_at + 146..wrap_at + 292].copy_from_slice(&first);
    assert!(parse(&swapped).is_err());
    let mut duplicate = valid.clone();
    duplicate[wrap_at + 146..wrap_at + 179].copy_from_slice(&valid[wrap_at..wrap_at + 33]);
    assert!(parse(&duplicate).is_err());
    let mut role = valid.clone();
    role[wrap_at] = 4;
    assert!(parse(&role).is_err());
    for n in [0u32, 16, 32785, u32::MAX] {
        let mut changed = valid.clone();
        changed[parsed.prefix_end + 12..parsed.prefix_end + 16].copy_from_slice(&n.to_be_bytes());
        assert!(parse(&changed).is_err());
    }
    let mut maximum = Fixture::new();
    for _ in 0..5 {
        let k = SigningKey::generate_from_rng(&mut rand::rng());
        let point = k.verifying_key().to_sec1_point(false);
        let mut r = maximum.records[2].clone();
        r[1..33].copy_from_slice(&sealed_manifest::key_id(3, point.as_bytes()));
        r[33..98].copy_from_slice(point.as_bytes());
        maximum.records.push(r);
    }
    let (_, _, manifest) = maximum.pair();
    let peer = b"+111111111111111";
    let bytes = envelope(&maximum, &manifest, 1, 32784, peer);
    assert_eq!(bytes.len(), 34213);
    verify(
        &bytes,
        &manifest,
        &expected(&maximum, 1, peer, &readers(&maximum, 1)),
        NOW,
    )
    .unwrap();
    let inbound = envelope(&maximum, &manifest, 2, 32784, peer);
    assert_eq!(inbound.len(), 34082);
    verify(
        &inbound,
        &manifest,
        &expected(&maximum, 2, peer, &readers(&maximum, 2)),
        NOW,
    )
    .unwrap();
}

#[test]
fn genuine_signature_cannot_override_manifest_roles_deadlines_or_old_domains() {
    let f = Fixture::new();
    let (_, _, manifest) = f.pair();
    let bytes = envelope(&f, &manifest, 1, 17, b"+12");
    let r = readers(&f, 1);
    let e = expected(&f, 1, b"+12", &r);
    assert!(verify(&bytes, &manifest, &e, NOW + 500).is_err());
    let end = bytes.len() - 64;
    let mut wrong = bytes.clone();
    wrong[end..].copy_from_slice(&sign(&f.keys[4], b"ZTSE/sign/v2\0", &bytes[..end]));
    assert!(verify(&wrong, &manifest, &e, NOW).is_err());
    wrong[end..].fill(0);
    assert!(verify(&wrong, &manifest, &e, NOW).is_err());
    for (index, replacement) in [(0, 2), (2, 2), (4, 2)] {
        let mut changed = Fixture::new();
        changed.records[index][148] = replacement;
        let (_, _, m) = changed.pair();
        let b = envelope(&changed, &m, 1, 17, b"+12");
        assert!(
            verify(
                &b,
                &m,
                &expected(&changed, 1, b"+12", &readers(&changed, 1)),
                NOW
            )
            .is_err()
        );
    }
}

fn observed_envelope(f: &Fixture, m: &VerifiedManifest03, kind: u8, observed: u64) -> Vec<u8> {
    let mut bytes = envelope(f, m, kind, 17, b"+12");
    bytes[146..154].copy_from_slice(&observed.to_be_bytes());
    let end = bytes.len() - 64;
    let signer = if kind == 1 { 4 } else { 3 };
    let signature = sign(&f.keys[signer], b"ZTSE/sign/v3\0", &bytes[..end]);
    bytes[end..].copy_from_slice(&signature);
    bytes
}

#[test]
fn outbound_lifetime_rejects_each_late_selected_key_despite_valid_current_signature() {
    for late_role in [1, 2, 3, 5] {
        let mut f = Fixture::new();
        for record in &mut f.records {
            if record[0] != 6 && record[0] != late_role {
                record[132..140].copy_from_slice(&(NOW - 2000).to_be_bytes());
            }
        }
        let (_, _, m) = f.pair();
        let bytes = observed_envelope(&f, &m, 1, NOW - 1500);
        let result = verify(&bytes, &m, &expected(&f, 1, b"+12", &readers(&f, 1)), NOW);
        assert_eq!(
            result.err(),
            Some("envelope authority deadline"),
            "role {late_role}"
        );
    }
}

#[test]
fn outbound_lifetime_allows_preissuance_and_ignores_unselected_event_key() {
    let mut f = Fixture::new();
    for record in &mut f.records {
        if [1, 2, 3, 5].contains(&record[0]) {
            record[132..140].copy_from_slice(&(NOW - 2000).to_be_bytes());
        }
    }
    let (_, _, m) = f.pair();
    // The signed manifest and unselected role-4 key start at NOW - 1000.
    // Only selected key intervals bound the outbound observation.
    for observed in [NOW - 2000, NOW - 1500, NOW] {
        let bytes = observed_envelope(&f, &m, 1, observed);
        verify(&bytes, &m, &expected(&f, 1, b"+12", &readers(&f, 1)), NOW).unwrap();
    }
}

#[test]
fn outbound_lifetime_end_is_inclusive_for_each_selected_key() {
    for role in [1, 2, 3, 5] {
        for until in [NOW + 499, NOW + 500] {
            let mut f = Fixture::new();
            f.records.iter_mut().find(|r| r[0] == role).unwrap()[140..148]
                .copy_from_slice(&until.to_be_bytes());
            let (_, _, m) = f.pair();
            let bytes = envelope(&f, &m, 1, 17, b"+12");
            let result = verify(&bytes, &m, &expected(&f, 1, b"+12", &readers(&f, 1)), NOW);
            assert_eq!(result.is_ok(), until == NOW + 500, "role {role}");
        }
    }
}

#[test]
fn outbound_lifetime_change_preserves_inbound_current_time_authorization() {
    let f = Fixture::new();
    let (_, _, m) = f.pair();
    let bytes = observed_envelope(&f, &m, 2, NOW - 1500);
    verify(&bytes, &m, &expected(&f, 2, b"+12", &readers(&f, 2)), NOW).unwrap();
}
