// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn prepare() -> Value {
    json!({"version":1,"synthetic":true,"operation":"prepareRootFixture","expected":{"account":"01010101-0101-0101-0101-010101010101","origin":"https://owner.invalid"}})
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../root-material/src/line_key_registration/vector.json"
    ))
    .unwrap()
}
fn line_request() -> Value {
    let vector = vector();
    let selection = &vector["selection"];
    let id = |name: &str| {
        uuid::Uuid::from_bytes(hex::<16>(selection[name].as_str().unwrap().as_bytes()).unwrap())
            .to_string()
    };
    json!({"version":1,"synthetic":true,"operation":"signLineRegistration","expected":{
  "account":id("account"),"user":id("user"),"session":id("ownerSession"),"device":id("device"),"line":id("line"),"challenge":id("challenge"),"origin":selection["origin"],"rootFingerprint":vector["rootFingerprint"],"generation":selection["nextGeneration"],"nonce":selection["nonce"],"issued":selection["issuedMs"],"expires":selection["expiresMs"],"approvalFingerprint":vector["approvalFingerprint"],"pairedSigningFingerprint":vector["pairedSigningFingerprint"],"connectionEpoch":selection["connectionEpoch"],"deploymentEpoch":selection["deploymentEpoch"],"site":selection["siteId"],"instance":selection["instanceId"]},"artifacts":public_artifacts(),"transcript":vector["transcript"]})
}
fn public_artifacts() -> Value {
    let identity = fake_identity(prepare()["expected"].as_object().unwrap()).unwrap();
    let root = fake_root();
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let pin = fake_pin(&identity.account_id).unwrap();
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card =
        recovery_kit::encode_public_card(&pin, &identity, &Sha256::digest(&backup).into()).unwrap();
    Artifacts {
        pin,
        id,
        backup,
        card,
    }
    .public(&identity)
}
fn parse(value: &Value) -> Result<Request> {
    parse_request(&serde_json::to_vec(value).unwrap())
}
#[test]
fn callback_transport_rejects_paths_secrets_unknown_operations_and_unbounded_input() {
    assert!(parse(&prepare()).is_ok());
    for key in ["path", "recoveryToken", "rootScalar", "privateKey"] {
        let mut v = prepare();
        v[key] = json!("forbidden");
        assert!(parse(&v).is_err());
    }
    for operation in ["sign", "signEnrollment", "signManifest", "openUserKit"] {
        let mut v = prepare();
        v["operation"] = json!(operation);
        assert!(parse(&v).is_err());
    }
    let mut v = prepare();
    v["synthetic"] = json!(false);
    assert!(parse(&v).is_err());
    let mut v = prepare();
    v["version"] = json!(2);
    assert!(parse(&v).is_err());
    let mut v = prepare();
    v["expected"]["account"] = json!("00000000-0000-0000-0000-000000000000");
    assert!(parse(&v).is_err());
    assert!(parse_request(&[]).is_err());
    assert!(parse_request(&vec![b' '; MAX_REQUEST + 1]).is_err());
    assert!(hex_bytes("a", MAX_REQUEST).is_err());
    assert!(hex_bytes("AA", MAX_REQUEST).is_err());
    assert!(hex_bytes(&"00".repeat(MAX_REQUEST + 1), MAX_REQUEST).is_err());
}
#[test]
fn callback_origin_is_independent_and_limited_to_reserved_fixture_hosts() {
    for origin in [
        "https://owner.invalid",
        "https://owner.example.test",
        "https://owner.example.test:12345",
        "https://owner.invalid:65535",
    ] {
        assert!(fixture_origin(origin));
    }
    for origin in [
        "https://localhost",
        "https://other.example.test",
        "https://owner.example.test.evil.invalid",
        "https://owner.example.test:443",
        "https://owner.example.test:0",
        "https://owner.example.test:0123",
        "https://owner.example.test:65536",
        "https://owner.example.test/",
        "https://user@owner.example.test",
        "https://owner.example.test?x",
        "https://owner.example.test#x",
        "http://owner.example.test",
    ] {
        assert!(!fixture_origin(origin));
    }
    let mut v = prepare();
    v["expected"]["origin"] = json!("https://other.invalid");
    assert!(parse(&v).is_err());
}
#[test]
fn dynamic_line_callback_compares_separate_scope_before_store_or_secret_entry() {
    let v = line_request();
    assert!(parse(&v).is_ok());
    for key in ["account", "user", "session", "device", "line", "challenge"] {
        let mut changed = v.clone();
        changed["expected"][key] = json!("08080808-0808-0808-0808-080808080808");
        assert!(parse(&changed).is_err());
    }
    for key in [
        "rootFingerprint",
        "approvalFingerprint",
        "pairedSigningFingerprint",
        "nonce",
    ] {
        let mut changed = v.clone();
        changed["expected"][key] = json!(display_hex(&[8; 32]));
        assert!(parse(&changed).is_err());
    }
    for key in [
        "generation",
        "issued",
        "expires",
        "connectionEpoch",
        "deploymentEpoch",
    ] {
        let mut changed = v.clone();
        changed["expected"][key] = json!("11");
        assert!(parse(&changed).is_err());
    }
    for key in ["site", "instance"] {
        let mut changed = v.clone();
        changed["expected"][key] = json!("other");
        assert!(parse(&changed).is_err());
    }
    let mut changed = v.clone();
    changed["transcript"] = json!("00");
    assert!(parse(&changed).is_err());
    let mut changed = v;
    changed["expected"]["privateKey"] = json!("forbidden");
    assert!(parse(&changed).is_err());
}
#[test]
fn cached_artifacts_are_exact_and_authenticate_only_under_the_known_fixture_material() {
    let identity = fake_identity(prepare()["expected"].as_object().unwrap()).unwrap();
    let value = public_artifacts();
    let artifacts = Artifacts::from_request(value.as_object().unwrap(), &identity).unwrap();
    assert_eq!(artifacts.public(&identity), value);
    for key in [
        "rootPin",
        "rootFingerprint",
        "bundleId",
        "encryptedBackup",
        "publicCard",
    ] {
        let mut changed = value.clone();
        let mut bytes = hex_bytes(changed[key].as_str().unwrap(), 748).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        changed[key] = json!(display_hex(&bytes));
        assert!(Artifacts::from_request(changed.as_object().unwrap(), &identity).is_err());
    }
    let root = fake_root();
    let wrong = RecoverySecret::new(Zeroizing::new([8; 32]));
    let backup = root_backup::seal(&root, &wrong, &identity).unwrap();
    let id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card = recovery_kit::encode_public_card(
        &artifacts.pin,
        &identity,
        &Sha256::digest(&backup).into(),
    )
    .unwrap();
    let different = Artifacts {
        pin: artifacts.pin,
        id,
        backup,
        card,
    }
    .public(&identity);
    assert!(Artifacts::from_request(different.as_object().unwrap(), &identity).is_err());
}

#[test]
fn custody_verification_requires_an_original_canonical_low_s_signature() {
    let mut raw = [0; 64];
    raw[31] = 1;
    raw[63] = 1;
    assert!(canonical_signature(&raw));
    raw[32..].fill(0xff);
    assert!(!canonical_signature(&raw));
    let half: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92,
        0xa8,
    ];
    raw[32..].copy_from_slice(&half);
    assert!(canonical_signature(&raw));
    raw[63] += 1;
    assert!(!canonical_signature(&raw));
}

#[test]
fn dynamic_custody_callback_compares_separate_identity_nonce_and_time() {
    let identity = fake_identity(prepare()["expected"].as_object().unwrap()).unwrap();
    let challenge = enrollment::Challenge {
        account_id: identity.account_id,
        user_id: [2; 16],
        session_id: [3; 16],
        challenge_id: [4; 16],
        nonce: [5; 32],
        root_fingerprint: identity.root_fingerprint,
        issued_ms: 2000,
        expires_ms: 62000,
        origin: identity.origin.clone(),
    };
    let id = |bytes| uuid::Uuid::from_bytes(bytes).to_string();
    let value = json!({"version":1,"synthetic":true,"operation":"signCustody",
        "expected":{"account":id(challenge.account_id),"user":id(challenge.user_id),
        "session":id(challenge.session_id),"challenge":id(challenge.challenge_id),
        "nonce":display_hex(&challenge.nonce),"rootFingerprint":display_hex(&identity.root_fingerprint),
        "origin":identity.origin,"issued":"2000","expires":"62000"},
        "artifacts":public_artifacts(),"transcript":display_hex(&enrollment::encode(&challenge).unwrap())});
    assert!(parse(&value).is_ok());
    for key in ["account", "user", "session", "challenge"] {
        let mut changed = value.clone();
        changed["expected"][key] = json!("08080808-0808-0808-0808-080808080808");
        assert!(parse(&changed).is_err());
    }
    for key in ["nonce", "rootFingerprint"] {
        let mut changed = value.clone();
        changed["expected"][key] = json!(display_hex(&[8; 32]));
        assert!(parse(&changed).is_err());
    }
    for (key, different) in [
        ("issued", "2001"),
        ("expires", "62001"),
        ("origin", "https://owner.example.test"),
    ] {
        let mut changed = value.clone();
        changed["expected"][key] = json!(different);
        assert!(parse(&changed).is_err());
    }
    let mut changed = value.clone();
    changed["transcript"] = json!("00");
    assert!(parse(&changed).is_err());
}
