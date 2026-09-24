// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only cross-language profile-02 vector. No production sealed route uses this parser.

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("../../../sdk/typescript/test/vectors/draft02-genesis.json");
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
    if account == [0; 16] || u64_be(&pin[21..29])? != 1 {
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
    if generation != 1 || version != 1 || manifest[53..85] != [0; 32] {
        return Err("genesis chain");
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
                5 => scope == 1 && device == [0; 16] && line == [0; 16],
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
}
