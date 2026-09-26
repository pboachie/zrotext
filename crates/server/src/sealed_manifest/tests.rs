// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

const VECTOR: &str = include_str!("../../../../sdk/typescript/test/vectors/draft02-genesis.json");
const ROTATION_VECTOR: &str =
    include_str!("../../../../sdk/typescript/test/vectors/draft02-rotation.json");
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("committed synthetic vector")
}

fn field(vector: &Value, name: &str) -> Vec<u8> {
    STANDARD
        .decode(vector[name].as_str().expect("base64 field"))
        .expect("base64")
}

fn validate(
    pin: &[u8],
    fingerprint: &[u8],
    manifest: &[u8],
    now: u64,
) -> Result<VerifiedManifest, &'static str> {
    validate_chain(pin, fingerprint, manifest, now, 1, 1, &[0; 32])
}
fn validate_chain(
    pin: &[u8],
    fingerprint: &[u8],
    manifest: &[u8],
    now: u64,
    generation: u64,
    version: u64,
    previous: &[u8; 32],
) -> Result<VerifiedManifest, &'static str> {
    let position = if version == 1 {
        ChainPosition::Genesis {
            anchor_digest: *previous,
        }
    } else {
        ChainPosition::After {
            version: version - 1,
            digest: *previous,
        }
    };
    verify(
        pin,
        manifest,
        &ManifestTrust {
            account_id: pin[5..21].try_into().unwrap(),
            root_fingerprint: fingerprint.try_into().unwrap(),
            generation,
            position,
        },
        now,
    )
}

fn validate_transition(
    transition: &[u8],
    old: &VerifiedManifest,
    old_root: &[u8],
    expected_new_root: &[u8],
    now: u64,
) -> Result<[u8; 32], &'static str> {
    if transition.len() != 343 || &transition[..5] != b"ZTRT\x02" {
        return Err("transition shape");
    }
    if transition[5..21] != old.account
        || u64_be(&transition[21..29])? != old.generation
        || u64_be(&transition[29..37])? != old.generation + 1
        || transition[37..102] != old_root[..]
        || transition[102..167] != expected_new_root[..]
        || transition[102..167] == transition[37..102]
        || transition[167..199] != old.digest
    {
        return Err("transition pin/chain");
    }
    let issued = u64_be(&transition[199..207])?;
    let expires = u64_be(&transition[207..215])?;
    if issued == 0
        || expires <= issued
        || expires - issued > DAY_MS
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err("transition freshness");
    }
    let unsigned = &transition[..215];
    verify_signature(
        old_root,
        &transition[215..279],
        b"ZTSE/root-transition/v2\0",
        unsigned,
    )?;
    verify_signature(
        expected_new_root,
        &transition[279..343],
        b"ZTSE/root-transition/v2\0",
        unsigned,
    )?;
    Ok(Sha256::digest(unsigned).into())
}

fn high_s_twin(manifest: &mut [u8]) {
    let start = manifest.len() - 32;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let difference = i16::from(ORDER[i]) - i16::from(manifest[start + i]) - borrow;
        manifest[start + i] = difference as u8;
        borrow = if difference < 0 { 1 } else { 0 };
    }
    assert_eq!(borrow, 0);
}

#[test]
fn python_generated_manifest_is_independently_verified_in_rust() {
    let vector = vector();
    let pin = field(&vector, "root_pin_b64");
    let fingerprint = field(&vector, "root_fingerprint_b64");
    let manifest = field(&vector, "manifest_b64");
    let now = vector["now_ms"].as_u64().expect("now");
    let verified = validate(&pin, &fingerprint, &manifest, now).expect("valid genesis");
    assert_eq!(
        verified.digest.as_slice(),
        field(&vector, "semantic_manifest_digest_b64")
    );
    assert_eq!(verified.account.as_slice(), &pin[5..21]);
    assert_eq!((verified.generation, verified.version), (1, 1));
    assert_eq!(
        verified
            .roles
            .iter()
            .map(|record| record.role)
            .collect::<Vec<_>>(),
        [1, 2, 5, 6]
    );
    let selected = verified
        .roles
        .iter()
        .find(|record| record.role == 1)
        .expect("device role");
    assert_eq!(selected.device.as_slice(), field(&vector, "device_id_b64"));
    assert_eq!(selected.line.as_slice(), field(&vector, "line_id_b64"));
    let signer = verified
        .roles
        .iter()
        .find(|record| record.role == 5)
        .expect("integration signer role");
    assert_eq!(signer.device, [0; 16]);
    assert_eq!(signer.line.as_slice(), field(&vector, "line_id_b64"));
    let readers = readers(&verified, Kind::Outbound);
    let wanted = request(&verified, Kind::Outbound, &readers);
    let context = verified.envelope_context(&wanted, now).unwrap();
    assert_eq!(
        context.signer_public_point,
        &manifest[151 + 2 * 149 + 33..151 + 2 * 149 + 98]
    );
    assert_eq!(
        context.manifest_digest.as_slice(),
        field(&vector, "semantic_manifest_digest_b64")
    );
    assert_eq!(context.keyset_version, 1);
}

#[test]
fn rust_rejects_pin_mismatch_high_s_twin_and_changed_record() {
    let vector = vector();
    let pin = field(&vector, "root_pin_b64");
    let mut fingerprint = field(&vector, "root_fingerprint_b64");
    let mut manifest = field(&vector, "manifest_b64");
    let now = vector["now_ms"].as_u64().expect("now");

    fingerprint[0] ^= 1;
    assert_eq!(
        validate(&pin, &fingerprint, &manifest, now).unwrap_err(),
        "pin fingerprint"
    );
    fingerprint[0] ^= 1;
    high_s_twin(&mut manifest);
    assert_eq!(
        validate(&pin, &fingerprint, &manifest, now).unwrap_err(),
        "high-s signature"
    );
    high_s_twin(&mut manifest);
    manifest[151 + 130] ^= 1;
    assert_eq!(
        validate(&pin, &fingerprint, &manifest, now).unwrap_err(),
        "role/scope/subject"
    );
    let mut zero_signer_line = field(&vector, "manifest_b64");
    let role_05_at = 151 + 2 * 149;
    assert_eq!(zero_signer_line[role_05_at], 5);
    zero_signer_line[role_05_at + 114..role_05_at + 130].fill(0);
    assert_eq!(
        validate(&pin, &fingerprint, &zero_signer_line, now).unwrap_err(),
        "role/scope/subject"
    );
}

#[test]
fn python_generated_dual_signed_rotation_is_independently_verified_in_rust() {
    let rotation: Value = serde_json::from_str(ROTATION_VECTOR).expect("public rotation vector");
    let pin = field(&rotation, "old_root_pin_b64");
    let fingerprint = field(&rotation, "old_root_fingerprint_b64");
    let old_manifest = field(&rotation, "old_manifest_b64");
    let transition = field(&rotation, "transition_b64");
    let new_root = field(&rotation, "new_root_point_b64");
    let new_pin = field(&rotation, "new_root_pin_b64");
    let new_fingerprint = field(&rotation, "new_root_fingerprint_b64");
    let new_manifest = field(&rotation, "new_manifest_b64");
    let now = rotation["now_ms"].as_u64().expect("now");

    let old = validate(&pin, &fingerprint, &old_manifest, now).expect("old genesis");
    assert_eq!(
        old.digest.as_slice(),
        field(&rotation, "old_semantic_manifest_digest_b64")
    );
    let anchor = validate_transition(&transition, &old, &pin[29..94], &new_root, now)
        .expect("dual-signed rotation");
    assert_eq!(
        anchor.as_slice(),
        field(&rotation, "transition_anchor_digest_b64")
    );
    assert_eq!(&new_pin[29..94], new_root);
    let new = validate_chain(
        &new_pin,
        &new_fingerprint,
        &new_manifest,
        now,
        2,
        1,
        &anchor,
    )
    .expect("linked new-generation manifest");
    assert_eq!(
        new.digest.as_slice(),
        field(&rotation, "new_semantic_manifest_digest_b64")
    );
    assert_eq!((new.generation, new.version), (2, 1));
    assert_eq!(
        new.roles.iter().map(|key| key.role).collect::<Vec<_>>(),
        [1, 2, 5, 6]
    );
}

#[test]
fn rust_rejects_rotation_substitution_high_s_and_broken_anchor() {
    let rotation: Value = serde_json::from_str(ROTATION_VECTOR).expect("public rotation vector");
    let pin = field(&rotation, "old_root_pin_b64");
    let fingerprint = field(&rotation, "old_root_fingerprint_b64");
    let old_manifest = field(&rotation, "old_manifest_b64");
    let transition = field(&rotation, "transition_b64");
    let new_root = field(&rotation, "new_root_point_b64");
    let new_pin = field(&rotation, "new_root_pin_b64");
    let new_fingerprint = field(&rotation, "new_root_fingerprint_b64");
    let new_manifest = field(&rotation, "new_manifest_b64");
    let now = rotation["now_ms"].as_u64().expect("now");
    let old = validate(&pin, &fingerprint, &old_manifest, now).expect("old genesis");

    assert_eq!(
        validate_transition(&transition, &old, &pin[29..94], &pin[29..94], now).unwrap_err(),
        "transition pin/chain"
    );
    for offset in [215, 279] {
        let mut twin = transition.clone();
        high_s_twin(&mut twin[..offset + 64]);
        assert_eq!(
            validate_transition(&twin, &old, &pin[29..94], &new_root, now).unwrap_err(),
            "high-s signature"
        );
    }
    let mut broken_digest = old.digest;
    broken_digest[0] ^= 1;
    let broken_old = VerifiedManifest {
        digest: broken_digest,
        ..old
    };
    assert_eq!(
        validate_transition(&transition, &broken_old, &pin[29..94], &new_root, now).unwrap_err(),
        "transition pin/chain"
    );
    let anchor: [u8; 32] = Sha256::digest(&transition[..215]).into();
    let mut wrong_anchor = anchor;
    wrong_anchor[0] ^= 1;
    assert_eq!(
        validate_chain(
            &new_pin,
            &new_fingerprint,
            &new_manifest,
            now,
            2,
            1,
            &wrong_anchor
        )
        .unwrap_err(),
        "manifest chain"
    );
}
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};

struct SignedFixture {
    pin: Vec<u8>,
    manifest: Vec<u8>,
    root: SigningKey,
    signers: Vec<(u8, SigningKey)>,
    now: u64,
}
impl SignedFixture {
    fn new() -> Self {
        let source = vector();
        let old_pin = field(&source, "root_pin_b64");
        let old_manifest = field(&source, "manifest_b64");
        let now = source["now_ms"].as_u64().unwrap();
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let point = root.verifying_key().to_sec1_point(false);
        let mut pin = old_pin;
        pin[29..94].copy_from_slice(point.as_bytes());
        let device = field(&source, "device_id_b64");
        let line = field(&source, "line_id_b64");
        let mut manifest = old_manifest[..151].to_vec();
        manifest[85..150].copy_from_slice(point.as_bytes());
        let mut records = Vec::new();
        let mut signers = Vec::new();
        for (role, scope) in [(1, 4u16), (2, 12), (3, 4), (3, 8), (4, 2), (5, 1), (6, 0)] {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = if role == 6 {
                root.verifying_key().to_sec1_point(false)
            } else {
                key.verifying_key().to_sec1_point(false)
            };
            let mut record = vec![role];
            record.extend_from_slice(&key_id(role, point.as_bytes()));
            record.extend_from_slice(point.as_bytes());
            record.extend_from_slice(if [1, 4].contains(&role) {
                &device
            } else {
                &[0; 16]
            });
            record.extend_from_slice(if [1, 4, 5].contains(&role) {
                &line
            } else {
                &[0; 16]
            });
            record.extend_from_slice(&scope.to_be_bytes());
            record.extend_from_slice(&(now - 1000).to_be_bytes());
            record.extend_from_slice(&(now + DAY_MS).to_be_bytes());
            record.push(1);
            records.push(record);
            if [4, 5].contains(&role) {
                signers.push((role, key));
            }
        }
        records.sort_by(|a, b| a[..33].cmp(&b[..33]));
        manifest[150] = records.len() as u8;
        for record in records {
            manifest.extend(record);
        }
        manifest.extend_from_slice(&[0; 64]);
        let mut fixture = Self {
            pin,
            manifest,
            root,
            signers,
            now,
        };
        fixture.resign();
        fixture
    }
    fn resign(&mut self) {
        let unsigned_end = self.manifest.len() - 64;
        let transcript = [
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned_end as u32).to_be_bytes(),
            &self.manifest[..unsigned_end],
        ]
        .concat();
        let signature: Signature = self.root.sign(&transcript);
        self.manifest[unsigned_end..].copy_from_slice(&signature.normalize_s().to_bytes());
    }
    fn trust(&self) -> ManifestTrust {
        ManifestTrust {
            account_id: self.pin[5..21].try_into().unwrap(),
            root_fingerprint: Sha256::digest(
                [b"ZTSE/root-pin/v2\0".as_slice(), &self.pin].concat(),
            )
            .into(),
            generation: 1,
            position: ChainPosition::Genesis {
                anchor_digest: [0; 32],
            },
        }
    }
    fn verified(&self) -> VerifiedManifest {
        verify(&self.pin, &self.manifest, &self.trust(), self.now).unwrap()
    }
    fn record(&self, role: u8) -> usize {
        (0..self.manifest[150] as usize)
            .map(|i| 151 + 149 * i)
            .find(|at| self.manifest[*at] == role)
            .unwrap()
    }
}

fn readers(manifest: &VerifiedManifest, kind: Kind) -> Vec<ExpectedRecipient> {
    let scope = if kind == Kind::Inbound { 8 } else { 4 };
    manifest
        .roles
        .iter()
        .filter(|key| key.role <= 3 && key.scope & scope != 0)
        .map(|key| ExpectedRecipient {
            role: key.role,
            key_id: key.id,
        })
        .collect()
}
fn request<'a>(
    manifest: &VerifiedManifest,
    kind: Kind,
    recipients: &'a [ExpectedRecipient],
) -> EnvelopeAuthority<'a> {
    let device = manifest.roles.iter().find(|key| key.role == 1).unwrap();
    let signer = manifest
        .roles
        .iter()
        .find(|key| key.role == if kind == Kind::Inbound { 4 } else { 5 })
        .unwrap();
    EnvelopeAuthority {
        kind,
        account_id: manifest.account,
        message_id: [0x32; 16],
        device_id: device.device,
        line_id: device.line,
        signer_key_id: signer.id,
        peer: b"+12",
        recipients,
    }
}

#[test]
fn signed_authority_builds_context_for_both_kinds_and_verifies_exact_envelopes() {
    let fixture = SignedFixture::new();
    let manifest = fixture.verified();
    let structural: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/ztse-draft-01.json"
    ))
    .unwrap();
    for (kind, name, signer_role) in [
        (Kind::Outbound, "outbound", 5),
        (Kind::Inbound, "inbound", 4),
    ] {
        let mut recipients = readers(&manifest, kind);
        // The structural examples include only device/archive readers. Additional
        // integration readers are separately exercised in the authority tests.
        recipients.retain(|reader| reader.role != 3);
        let wanted = request(&manifest, kind, &recipients);
        let context = manifest.envelope_context(&wanted, fixture.now).unwrap();
        assert_eq!(context.profile, Profile::Draft02Candidate);
        assert_eq!(context.manifest_digest, manifest.digest);
        let hex = structural[name]["envelopeHex"].as_str().unwrap();
        let mut envelope: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        envelope[4] = 2;
        envelope[10..26].copy_from_slice(&context.account_id);
        envelope[26..42].copy_from_slice(&context.message_id);
        envelope[42..58].copy_from_slice(&context.device_id);
        envelope[58..74].copy_from_slice(&context.line_id);
        envelope[74..82].copy_from_slice(&context.keyset_version.to_be_bytes());
        envelope[82..114].copy_from_slice(&context.manifest_digest);
        envelope[114..146].copy_from_slice(&wanted.signer_key_id);
        let unsigned_end = envelope.len() - 64;
        for (index, reader) in recipients.iter().enumerate() {
            let at = unsigned_end - recipients.len() * 146 + index * 146;
            assert_eq!(envelope[at], reader.role);
            envelope[at + 1..at + 33].copy_from_slice(&reader.key_id);
        }
        let key = &fixture
            .signers
            .iter()
            .find(|(role, _)| *role == signer_role)
            .unwrap()
            .1;
        let transcript = [
            b"ZTSE/sign/v2\0".as_slice(),
            &(unsigned_end as u32).to_be_bytes(),
            &envelope[..unsigned_end],
        ]
        .concat();
        let signature: Signature = key.sign(&transcript);
        envelope[unsigned_end..].copy_from_slice(&signature.normalize_s().to_bytes());
        crate::sealed_envelope::verify(&envelope, &context).unwrap();
        let wrong = ExpectedContext {
            manifest_digest: [0; 32],
            ..context
        };
        assert!(crate::sealed_envelope::verify(&envelope, &wrong).is_err());
    }
    assert_eq!(format!("{manifest:?}"), "VerifiedManifest { .. }");
}

#[test]
fn manifest_chain_rejects_forks_gaps_rollback_and_cross_account_trust() {
    let mut fixture = SignedFixture::new();
    let original = fixture.verified();
    let mut trust = fixture.trust();
    trust.position = ChainPosition::Current {
        version: 1,
        digest: original.digest,
    };
    verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap();
    let at = fixture.record(5);
    fixture.manifest[at + 140..at + 148].copy_from_slice(&(fixture.now + 1000).to_be_bytes());
    fixture.resign();
    assert_eq!(
        verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap_err(),
        "manifest chain"
    );
    trust.position = ChainPosition::After {
        version: 1,
        digest: original.digest,
    };
    fixture.manifest[29..37].copy_from_slice(&2u64.to_be_bytes());
    fixture.manifest[53..85].copy_from_slice(&original.digest);
    fixture.resign();
    verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap();
    for version in [0u64, 1, 3, i64::MAX as u64 + 1] {
        fixture.manifest[29..37].copy_from_slice(&version.to_be_bytes());
        fixture.resign();
        assert!(verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).is_err());
    }
    fixture.manifest[29..37].copy_from_slice(&2u64.to_be_bytes());
    fixture.resign();
    trust.account_id[0] ^= 1;
    assert_eq!(
        verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap_err(),
        "pin identity"
    );
}

#[test]
fn expired_revoked_future_or_wrong_subject_signers_never_authorize() {
    for role in [4, 5] {
        for mutation in 0..5 {
            let mut fixture = SignedFixture::new();
            let original = fixture.verified();
            let kind = if role == 4 {
                Kind::Inbound
            } else {
                Kind::Outbound
            };
            let recipients = readers(&original, kind);
            let wanted = request(&original, kind, &recipients);
            let at = fixture.record(role);
            match mutation {
                0 => fixture.manifest[at + 148] = 2,
                1 => {
                    fixture.manifest[at + 140..at + 148].copy_from_slice(&fixture.now.to_be_bytes())
                }
                2 => fixture.manifest[at + 132..at + 140]
                    .copy_from_slice(&(fixture.now + 1).to_be_bytes()),
                3 => fixture.manifest[at + 114] ^= 1,
                4 if role == 4 => fixture.manifest[at + 98] ^= 1,
                _ => fixture.manifest[at + 130..at + 132].copy_from_slice(&2u16.to_be_bytes()),
            }
            fixture.resign();
            if let Ok(verified) = verify(
                &fixture.pin,
                &fixture.manifest,
                &fixture.trust(),
                fixture.now,
            ) {
                assert!(verified.envelope_context(&wanted, fixture.now).is_err());
            }
        }
    }
}

#[test]
fn readers_require_active_scoped_exact_subjects_without_expansion() {
    let fixture = SignedFixture::new();
    let verified = fixture.verified();
    for kind in [Kind::Outbound, Kind::Inbound] {
        let recipients = readers(&verified, kind);
        let wanted = request(&verified, kind, &recipients);
        let context = verified.envelope_context(&wanted, fixture.now).unwrap();
        assert_eq!(context.recipients.len(), recipients.len());
        for mutation in 0..7 {
            let mut changed = recipients.clone();
            match mutation {
                0 => changed.retain(|r| r.role != 2),
                1 => changed.push(recipients[0]),
                2 => changed[0].key_id[0] ^= 1,
                3 => changed.reverse(),
                4 => {
                    let wrong = verified
                        .roles
                        .iter()
                        .find(|r| {
                            r.role == 3 && r.scope == if kind == Kind::Inbound { 4 } else { 8 }
                        })
                        .unwrap();
                    changed.retain(|r| r.role != 3);
                    changed.push(ExpectedRecipient {
                        role: 3,
                        key_id: wrong.id,
                    });
                }
                5 => changed.clear(),
                _ => changed.resize(9, recipients[0]),
            }
            let request = EnvelopeAuthority {
                recipients: &changed,
                ..wanted.clone()
            };
            assert!(verified.envelope_context(&request, fixture.now).is_err());
        }
        for mutation in 0..4 {
            let mut changed = wanted.clone();
            match mutation {
                0 => changed.account_id[0] ^= 1,
                1 => changed.device_id[0] ^= 1,
                2 => changed.line_id[0] ^= 1,
                _ => changed.signer_key_id[0] ^= 1,
            }
            assert!(verified.envelope_context(&changed, fixture.now).is_err());
        }
    }
    for role in [1, 2, 3] {
        for mutation in 0..3 {
            let mut fixture = SignedFixture::new();
            let original = fixture.verified();
            let at = fixture.record(role);
            let scope =
                u16::from_be_bytes(fixture.manifest[at + 130..at + 132].try_into().unwrap());
            let kind = if scope & 4 != 0 {
                Kind::Outbound
            } else {
                Kind::Inbound
            };
            let recipients = readers(&original, kind);
            let wanted = request(&original, kind, &recipients);
            match mutation {
                0 => fixture.manifest[at + 148] = 2,
                1 => {
                    fixture.manifest[at + 140..at + 148].copy_from_slice(&fixture.now.to_be_bytes())
                }
                _ => fixture.manifest[at + 132..at + 140]
                    .copy_from_slice(&(fixture.now + 1).to_be_bytes()),
            }
            fixture.resign();
            if let Ok(verified) = verify(
                &fixture.pin,
                &fixture.manifest,
                &fixture.trust(),
                fixture.now,
            ) {
                assert!(verified.envelope_context(&wanted, fixture.now).is_err());
            }
        }
    }
}

#[test]
fn freshness_is_checked_at_verification_and_every_authority_use() {
    let fixture = SignedFixture::new();
    let verified = fixture.verified();
    let recipients = readers(&verified, Kind::Outbound);
    let wanted = request(&verified, Kind::Outbound, &recipients);
    for now in [
        0,
        verified.issued - 300_001,
        verified.expires,
        i64::MAX as u64 + 1,
    ] {
        assert!(verify(&fixture.pin, &fixture.manifest, &fixture.trust(), now).is_err());
        assert!(verified.envelope_context(&wanted, now).is_err());
    }
    let mut changed = fixture.manifest.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(verify(&fixture.pin, &changed, &fixture.trust(), fixture.now).is_err());
    for cut in [0, 4, 93, 150, 363, fixture.manifest.len() - 1] {
        assert!(
            verify(
                &fixture.pin,
                &fixture.manifest[..cut],
                &fixture.trust(),
                fixture.now
            )
            .is_err()
        );
    }
}

#[test]
fn selected_device_reader_cannot_borrow_another_subject_binding() {
    for offset in [98, 114] {
        let mut fixture = SignedFixture::new();
        let original = fixture.verified();
        let recipients = readers(&original, Kind::Outbound);
        let wanted = request(&original, Kind::Outbound, &recipients);
        let at = fixture.record(1);
        fixture.manifest[at + offset] ^= 1;
        fixture.resign();
        let changed = fixture.verified();
        assert_eq!(
            changed.envelope_context(&wanted, fixture.now).err(),
            Some("reader role/subject")
        );
    }
}

#[test]
fn first_generation_requires_zero_genesis_anchor_even_with_valid_owner_signature() {
    let mut fixture = SignedFixture::new();
    fixture.manifest[53..85].fill(1);
    fixture.resign();
    let mut trust = fixture.trust();
    trust.position = ChainPosition::Genesis {
        anchor_digest: [1; 32],
    };
    assert_eq!(
        verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap_err(),
        "manifest chain"
    );
}

#[test]
fn signed_manifest_freshness_bounds_are_exclusive_and_lifetime_is_bounded() {
    let mut fixture = SignedFixture::new();
    for (issued, expires) in [
        (fixture.now, fixture.now),
        (fixture.now, fixture.now + DAY_MS + 1),
        (fixture.now + 300_001, fixture.now + DAY_MS),
    ] {
        fixture.manifest[37..45].copy_from_slice(&issued.to_be_bytes());
        fixture.manifest[45..53].copy_from_slice(&expires.to_be_bytes());
        fixture.resign();
        assert_eq!(
            verify(
                &fixture.pin,
                &fixture.manifest,
                &fixture.trust(),
                fixture.now
            )
            .unwrap_err(),
            "manifest freshness"
        );
    }
    fixture.manifest[37..45].copy_from_slice(&fixture.now.to_be_bytes());
    fixture.manifest[45..53].copy_from_slice(&(fixture.now + DAY_MS).to_be_bytes());
    fixture.resign();
    fixture.verified();
    fixture.manifest[37..45].copy_from_slice(&(fixture.now + 300_000).to_be_bytes());
    fixture.resign();
    fixture.verified();
}

#[test]
fn later_generation_requires_transition_anchor_even_with_valid_owner_signature() {
    let mut fixture = SignedFixture::new();
    fixture.pin[21..29].copy_from_slice(&2u64.to_be_bytes());
    fixture.manifest[21..29].copy_from_slice(&2u64.to_be_bytes());
    fixture.resign();
    let mut trust = fixture.trust();
    trust.generation = 2;
    assert_eq!(
        verify(&fixture.pin, &fixture.manifest, &trust, fixture.now).unwrap_err(),
        "manifest chain"
    );
}
