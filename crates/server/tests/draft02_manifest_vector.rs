// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only cross-language profile-02 vector. No production sealed route uses this parser.

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("../../../sdk/typescript/test/vectors/draft02-genesis.json");
const ROTATION_VECTOR: &str =
    include_str!("../../../sdk/typescript/test/vectors/draft02-rotation.json");
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const DAY_MS: u64 = 86_400_000;

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("committed synthetic vector")
}

fn field(vector: &Value, name: &str) -> Vec<u8> {
    STANDARD
        .decode(vector[name].as_str().expect("base64 field"))
        .expect("base64")
}

fn u64_be(data: &[u8]) -> Result<u64, &'static str> {
    let value = u64::from_be_bytes(data.try_into().map_err(|_| "u64 width")?);
    if value > i64::MAX as u64 {
        return Err("signed storage range");
    }
    Ok(value)
}

fn key_id(role: u8, point: &[u8]) -> [u8; 32] {
    let algorithm = if role <= 3 { [0, 0x10] } else { [1, 1] };
    Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, point].concat()).into()
}

fn verify_signature(
    point: &[u8],
    signature: &[u8],
    label: &[u8],
    unsigned: &[u8],
) -> Result<(), &'static str> {
    let signature = Signature::from_slice(signature).map_err(|_| "signature scalar")?;
    if signature.to_bytes()[32..] > HALF_ORDER[..] {
        return Err("high-s signature");
    }
    let key = VerifyingKey::from_sec1_bytes(point).map_err(|_| "root point")?;
    let transcript = [label, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat();
    key.verify(&transcript, &signature)
        .map_err(|_| "owner signature")
}

#[derive(Debug)]
struct RoleRecord {
    role: u8,
    id: [u8; 32],
    device: [u8; 16],
    line: [u8; 16],
}

#[derive(Debug)]
struct Validated {
    digest: [u8; 32],
    account: [u8; 16],
    generation: u64,
    version: u64,
    roles: Vec<RoleRecord>,
}

fn validate(
    pin: &[u8],
    fingerprint: &[u8],
    manifest: &[u8],
    now: u64,
) -> Result<Validated, &'static str> {
    validate_chain(pin, fingerprint, manifest, now, 1, 1, &[0; 32])
}

fn validate_chain(
    pin: &[u8],
    fingerprint: &[u8],
    manifest: &[u8],
    now: u64,
    expected_generation: u64,
    expected_version: u64,
    expected_previous: &[u8; 32],
) -> Result<Validated, &'static str> {
    if pin.len() != 94 || &pin[..5] != b"ZTRP\x02" {
        return Err("pin shape");
    }
    if fingerprint.len() != 32
        || Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), pin].concat()).as_slice()
            != fingerprint
    {
        return Err("pin fingerprint");
    }
    let account: [u8; 16] = pin[5..21].try_into().map_err(|_| "pin account")?;
    if account == [0; 16] || u64_be(&pin[21..29])? != expected_generation {
        return Err("pin identity");
    }
    VerifyingKey::from_sec1_bytes(&pin[29..94]).map_err(|_| "pin curve")?;

    if !(364..=9751).contains(&manifest.len()) || &manifest[..5] != b"ZTMA\x02" {
        return Err("manifest shape");
    }
    let count = usize::from(manifest[150]);
    if !(1..=64).contains(&count) || manifest.len() != 215 + 149 * count {
        return Err("manifest size/count");
    }
    if manifest[5..21] != account || manifest[85..150] != pin[29..94] {
        return Err("manifest pin");
    }
    let generation = u64_be(&manifest[21..29])?;
    let version = u64_be(&manifest[29..37])?;
    let issued = u64_be(&manifest[37..45])?;
    let expires = u64_be(&manifest[45..53])?;
    if generation != expected_generation
        || version != expected_version
        || manifest[53..85] != expected_previous[..]
    {
        return Err("manifest chain");
    }
    if issued == 0
        || expires <= issued
        || expires - issued > DAY_MS
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err("manifest freshness");
    }

    let mut roles: Vec<RoleRecord> = Vec::with_capacity(count);
    let mut seen_points = HashSet::new();
    let mut owner_count = 0;
    let mut archive_count = 0;
    for index in 0..count {
        let at = 151 + 149 * index;
        let role = manifest[at];
        let id: [u8; 32] = manifest[at + 1..at + 33]
            .try_into()
            .map_err(|_| "key id width")?;
        let point = &manifest[at + 33..at + 98];
        let device: [u8; 16] = manifest[at + 98..at + 114]
            .try_into()
            .map_err(|_| "device width")?;
        let line: [u8; 16] = manifest[at + 114..at + 130]
            .try_into()
            .map_err(|_| "line width")?;
        let scope = u16::from_be_bytes(
            manifest[at + 130..at + 132]
                .try_into()
                .map_err(|_| "scope")?,
        );
        let from = u64_be(&manifest[at + 132..at + 140])?;
        let until = u64_be(&manifest[at + 140..at + 148])?;
        let state = manifest[at + 148];
        if !(1..=6).contains(&role)
            || !match role {
                1 => scope == 4 && device != [0; 16] && line != [0; 16],
                2 => scope == 12 && device == [0; 16] && line == [0; 16],
                3 => [4, 8, 12].contains(&scope) && device == [0; 16] && line == [0; 16],
                4 => scope == 2 && device != [0; 16] && line != [0; 16],
                5 => scope == 1 && device == [0; 16] && line != [0; 16],
                6 => scope == 0 && device == [0; 16] && line == [0; 16],
                _ => false,
            }
        {
            return Err("role/scope/subject");
        }
        if from > until || ![1, 2].contains(&state) {
            return Err("key interval/state");
        }
        if roles
            .last()
            .is_some_and(|previous| (role, id) <= (previous.role, previous.id))
        {
            return Err("record order");
        }
        VerifyingKey::from_sec1_bytes(point).map_err(|_| "record point")?;
        if id != key_id(role, point) || !seen_points.insert(point.to_vec()) {
            return Err("key identity or point reuse");
        }
        if role == 6 {
            owner_count += 1;
            if point != &pin[29..94] || state != 1 || from > issued || until < expires {
                return Err("owner root record");
            }
        }
        if role == 2 && state == 1 {
            archive_count += 1;
        }
        roles.push(RoleRecord {
            role,
            id,
            device,
            line,
        });
    }
    if owner_count != 1 || archive_count != 1 {
        return Err("root/archive cardinality");
    }
    let unsigned = &manifest[..manifest.len() - 64];
    verify_signature(
        &pin[29..94],
        &manifest[unsigned.len()..],
        b"ZTSE/manifest/v2\0",
        unsigned,
    )?;
    Ok(Validated {
        digest: Sha256::digest(unsigned).into(),
        account,
        generation,
        version,
        roles,
    })
}

fn validate_transition(
    transition: &[u8],
    old: &Validated,
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
    let broken_old = Validated {
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
