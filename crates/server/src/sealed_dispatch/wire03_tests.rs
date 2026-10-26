// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use aes_gcm::aead::Generate;
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::{Value, json};

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-contract-01.json"
    ))
    .unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn frame() -> Value {
    corpus()["grant"]["frame"].clone()
}
fn ready() -> Value {
    corpus()["readyFrame"].clone()
}
fn public_key() -> VerifyingKey {
    VerifyingKey::from_sec1_bytes(&hex(corpus()["publicPointsHex"]["deviceEnrollment"]
        .as_str()
        .unwrap()))
    .unwrap()
}
fn fetch(grant: &Value, signature_der: &str) -> Value {
    json!({"grant": grant, "signature_der": signature_der})
}
fn public_fetch() -> Value {
    fetch(
        &frame(),
        corpus()["grant"]["signatureDerBase64url"].as_str().unwrap(),
    )
}
fn encoded_der(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

const GRANT_NUMBERS: [&str; 7] = [
    "connection_epoch",
    "deployment_epoch",
    "binding_generation",
    "attempt_generation",
    "expires_at_ms",
    "trust_generation",
    "manifest_version",
];
const READY_NUMBERS: [&str; 5] = [
    "connection_epoch",
    "deployment_epoch",
    "binding_generation",
    "trust_generation",
    "manifest_version",
];
const IDS: [&str; 5] = [
    "account_id",
    "device_id",
    "line_id",
    "message_id",
    "attempt_id",
];
const DIGESTS: [&str; 6] = [
    "reader_key_id",
    "envelope_sha256",
    "unsigned_sha256",
    "manifest_digest",
    "root_fingerprint",
    "election_digest",
];

#[test]
fn complete_positional_grant_ready_fetch_and_nested_grant_arrays_are_refused() {
    // Exact declaration order accepted by the original derived visit_seq.
    // Reconstructing the same object proves every element is otherwise valid.
    let grant_fields = [
        "v",
        "type",
        "grant_version",
        "envelope_profile",
        "manifest_profile",
        "reader_role",
        "segment_count",
        "account_id",
        "device_id",
        "line_id",
        "message_id",
        "attempt_id",
        "connection_epoch",
        "deployment_epoch",
        "binding_generation",
        "attempt_generation",
        "expires_at_ms",
        "trust_generation",
        "manifest_version",
        "reader_key_id",
        "envelope_sha256",
        "unsigned_sha256",
        "manifest_digest",
        "root_fingerprint",
        "election_digest",
    ];
    let ready_fields = [
        "v",
        "type",
        "grant_version",
        "envelope_profile",
        "manifest_profile",
        "connection_epoch",
        "deployment_epoch",
        "binding_generation",
        "trust_generation",
        "manifest_version",
        "line_id",
        "reader_key_id",
        "manifest_digest",
        "root_fingerprint",
        "election_digest",
    ];
    let positional = |object: &Value, fields: &[&str]| {
        assert_eq!(object.as_object().unwrap().len(), fields.len());
        let elements: Vec<_> = fields.iter().map(|name| object[*name].clone()).collect();
        let reconstructed: serde_json::Map<_, _> = fields
            .iter()
            .zip(elements.iter())
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect();
        assert_eq!(Value::Object(reconstructed), *object);
        Value::Array(elements)
    };
    let grant = frame();
    let ready = ready();
    let signed = public_fetch();
    GrantFrame03::parse(&bytes(&grant)).unwrap();
    ReadyFrame03::parse(&bytes(&ready)).unwrap();
    Fetch03::parse(&bytes(&signed))
        .unwrap()
        .verify(&public_key())
        .unwrap();
    let grant_array = positional(&grant, &grant_fields);
    let ready_array = positional(&ready, &ready_fields);
    assert_eq!(grant_array.as_array().unwrap().len(), 25);
    assert_eq!(ready_array.as_array().unwrap().len(), 15);
    assert_eq!(
        GrantFrame03::parse(&bytes(&grant_array)).unwrap_err(),
        "wire03 closed JSON"
    );
    assert_eq!(
        ReadyFrame03::parse(&bytes(&ready_array)).unwrap_err(),
        "wire03 closed JSON"
    );
    let fetch_array = positional(&signed, &["grant", "signature_der"]);
    assert_eq!(
        Fetch03::parse(&bytes(&fetch_array)).unwrap_err(),
        "wire03 closed JSON"
    );
    let nested = fetch(&grant_array, signed["signature_der"].as_str().unwrap());
    assert_eq!(
        Fetch03::parse(&bytes(&nested)).unwrap_err(),
        "wire03 closed JSON"
    );
    let both_arrays = positional(&nested, &["grant", "signature_der"]);
    assert_eq!(
        Fetch03::parse(&bytes(&both_arrays)).unwrap_err(),
        "wire03 closed JSON"
    );
}

#[test]
fn public_vector_proves_exact_transcript_signature_and_closed_readiness() {
    let v = corpus();
    assert_eq!(frame().as_object().unwrap().len(), 25);
    assert_eq!(ready().as_object().unwrap().len(), 15);
    let g = GrantFrame03::parse(&bytes(&frame())).unwrap();
    let transcript = g.fetch_transcript();
    assert_eq!(transcript.len(), 362);
    assert_eq!(&transcript[..28], FETCH_DOMAIN);
    assert_eq!(
        transcript.as_slice(),
        hex(v["grant"]["transcriptHex"].as_str().unwrap())
    );
    let f = Fetch03::parse(&bytes(&public_fetch())).unwrap();
    assert_eq!(f.signature_der().len(), 71);
    let proof = f.verify(&public_key()).unwrap();
    assert_eq!(proof.fetch().grant().claims(), g.claims());
    assert_eq!(proof.fetch().signature_der(), f.signature_der());
    let r = ReadyFrame03::parse(&bytes(&ready())).unwrap();
    assert_eq!(r.claims().line_id, g.claims().line_id);
    assert_eq!(r.claims().election_digest, g.claims().election_digest);
    assert_eq!(
        ReadyFrame03::parse(&r.to_json().unwrap()).unwrap().claims(),
        r.claims()
    );
    assert_eq!(
        GrantFrame03::parse(&g.to_json().unwrap()).unwrap().claims(),
        g.claims()
    );
    let mut detached = g.claims().clone();
    detached.connection_epoch += 1;
    assert_ne!(detached, g.claims().clone());
    assert_eq!(g.fetch_transcript(), transcript);
    // Member order changes formatting, never the binary signature identity.
    let mut entries: Vec<_> = frame()
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{}:{}", json!(k), v))
        .collect();
    entries.reverse();
    let reversed = format!("{{{}}}", entries.join(","));
    assert_eq!(
        GrantFrame03::parse(reversed.as_bytes())
            .unwrap()
            .fetch_transcript(),
        transcript
    );
}

fn parse_ok(value: &Value, is_ready: bool) -> bool {
    if is_ready {
        ReadyFrame03::parse(&bytes(value)).is_ok()
    } else {
        GrantFrame03::parse(&bytes(value)).is_ok()
    }
}
fn parse_raw_ok(value: &[u8], is_ready: bool) -> bool {
    if is_ready {
        ReadyFrame03::parse(value).is_ok()
    } else {
        GrantFrame03::parse(value).is_ok()
    }
}

#[test]
fn every_required_member_refuses_missing_null_wrong_type_and_literal_duplicates() {
    for (original, is_ready) in [(frame(), false), (ready(), true)] {
        for (name, value) in original.as_object().unwrap() {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(name);
            assert!(!parse_ok(&changed, is_ready), "missing {name}");
            for bad in [
                Value::Null,
                if value.is_string() {
                    json!(1)
                } else {
                    json!("1")
                },
                json!([]),
                json!({}),
            ] {
                let mut changed = original.clone();
                changed[name] = bad;
                assert!(!parse_ok(&changed, is_ready), "wrong type {name}");
            }
            let text = serde_json::to_string(&original).unwrap();
            let duplicate = format!("{{{}:{},{}", json!(name), value, &text[1..]);
            assert!(
                !parse_raw_ok(duplicate.as_bytes(), is_ready),
                "duplicate {name}"
            );
        }
        let mut unknown = original.clone();
        unknown["unsupported_extension"] = true.into();
        assert!(!parse_ok(&unknown, is_ready));
        let text = serde_json::to_string(&original).unwrap();
        assert!(!parse_raw_ok(format!("{text} {{}}").as_bytes(), is_ready));
        assert!(!parse_raw_ok(format!("{text} null").as_bytes(), is_ready));
        for raw in [
            b"".as_slice(),
            b"null",
            b"[]",
            b"{}",
            b"{",
            &[b' '; MAX_JSON_BYTES + 1],
        ] {
            assert!(!parse_raw_ok(raw, is_ready));
        }
        let mut exact_bound = bytes(&original);
        exact_bound.resize(MAX_JSON_BYTES, b' ');
        assert!(parse_raw_ok(&exact_bound, is_ready));
        exact_bound.push(b' ');
        assert!(!parse_raw_ok(&exact_bound, is_ready));
    }
    let text = serde_json::to_string(&frame()).unwrap();
    assert!(text.contains("\"v\":1"));
    let escaped_name = *b"\\u0076";
    let escaped_duplicate = format!(
        "{{\"{}\":1,{}",
        std::str::from_utf8(&escaped_name).unwrap(),
        &text[1..]
    );
    assert!(GrantFrame03::parse(escaped_duplicate.as_bytes()).is_err());
}

#[test]
fn exact_storage_integers_refuse_aliases_and_keep_the_full_positive_boundary() {
    for (original, is_ready, numbers) in [
        (frame(), false, GRANT_NUMBERS.as_slice()),
        (ready(), true, READY_NUMBERS.as_slice()),
    ] {
        for name in numbers {
            for number in [1, i64::MAX] {
                let mut changed = original.clone();
                changed[*name] = number.into();
                assert!(parse_ok(&changed, is_ready), "positive boundary {name}");
            }
            for number in [0, -1, i64::MIN] {
                let mut changed = original.clone();
                changed[*name] = number.into();
                assert!(!parse_ok(&changed, is_ready), "nonpositive {name}");
            }
            let mut without = original.clone();
            without.as_object_mut().unwrap().remove(*name);
            let text = serde_json::to_string(&without).unwrap();
            for bad in [
                "1.0".to_owned(),
                "1e0".to_owned(),
                "true".to_owned(),
                "\"1\"".to_owned(),
                format!("{}0", i64::MAX),
                format!("{}0", u64::MAX),
            ] {
                let literal = format!("{{{}:{bad},{}", json!(name), &text[1..]);
                assert!(
                    !parse_raw_ok(literal.as_bytes(), is_ready),
                    "integer alias {name} {bad}"
                );
            }
        }
    }
    let mut maximum = frame();
    for name in GRANT_NUMBERS {
        maximum[name] = i64::MAX.into();
    }
    let g = GrantFrame03::parse(&bytes(&maximum)).unwrap();
    let t = g.fetch_transcript();
    for offset in (114..170).step_by(8) {
        assert_eq!(&t[offset..offset + 8], &i64::MAX.to_be_bytes());
    }
    assert_eq!(g.claims().manifest_version, i64::MAX);
}

#[test]
fn profile_roles_segments_and_ready_headers_never_infer_defaults() {
    for (original, is_ready) in [(frame(), false), (ready(), true)] {
        for name in ["v", "grant_version", "envelope_profile", "manifest_profile"] {
            let mut changed = original.clone();
            changed[name] = 2.into();
            assert!(!parse_ok(&changed, is_ready));
        }
        let mut changed = original.clone();
        changed["type"] = "sealed_other".into();
        assert!(!parse_ok(&changed, is_ready));
    }
    let mut grant = frame();
    grant["reader_role"] = 2.into();
    assert!(GrantFrame03::parse(&bytes(&grant)).is_err());
    for segment in [0, 7, 255] {
        let mut g = frame();
        g["segment_count"] = segment.into();
        assert!(GrantFrame03::parse(&bytes(&g)).is_err());
    }
    for segment in 1..=6 {
        let mut g = frame();
        g["segment_count"] = segment.into();
        assert_eq!(
            GrantFrame03::parse(&bytes(&g)).unwrap().fetch_transcript()[33],
            segment as u8
        );
    }
}

#[test]
fn all_uuid_slots_refuse_alternative_spellings_and_nil() {
    for (original, is_ready) in [(frame(), false), (ready(), true)] {
        for name in IDS.into_iter().filter(|name| original.get(*name).is_some()) {
            let value = original[name].as_str().unwrap();
            for invalid in [
                value.to_uppercase(),
                value.replace('-', ""),
                format!("{{{value}}}"),
                format!("urn:uuid:{value}"),
                format!(" {value}"),
                Uuid::nil().hyphenated().to_string(),
                "invalid".to_owned(),
            ] {
                let mut changed = original.clone();
                changed[name] = invalid.into();
                assert!(!parse_ok(&changed, is_ready), "UUID {name}");
            }
        }
    }
}

#[test]
fn every_digest_slot_requires_exact_unpadded_roundtrip_bytes() {
    for (original, is_ready) in [(frame(), false), (ready(), true)] {
        for name in DIGESTS
            .into_iter()
            .filter(|name| original.get(*name).is_some())
        {
            for invalid in [
                "A".repeat(42),
                "A".repeat(44),
                format!("{}=", original[name].as_str().unwrap()),
                format!("{}B", "A".repeat(42)),
                "/".repeat(43),
                "+".repeat(43),
                encoded_der(&[0; 31]),
                encoded_der(&[0; 33]),
            ] {
                let mut changed = original.clone();
                changed[name] = invalid.into();
                assert!(!parse_ok(&changed, is_ready), "digest {name}");
            }
        }
    }
}

#[test]
fn original_device_proof_binds_every_variable_field_and_refuses_old_domains() {
    let signed = public_fetch();
    let key = public_key();
    for name in IDS {
        let mut changed = signed.clone();
        changed["grant"][name] = Uuid::from_bytes([99; 16]).hyphenated().to_string().into();
        assert_eq!(
            Fetch03::parse(&bytes(&changed))
                .unwrap()
                .verify(&key)
                .unwrap_err(),
            "wire03 fetch signature mismatch"
        );
    }
    for name in GRANT_NUMBERS {
        let mut changed = signed.clone();
        changed["grant"][name] = (signed["grant"][name].as_i64().unwrap() + 1).into();
        assert!(
            Fetch03::parse(&bytes(&changed))
                .unwrap()
                .verify(&key)
                .is_err()
        );
    }
    for name in DIGESTS {
        let mut changed = signed.clone();
        changed["grant"][name] = encoded_der(&[9; 32]).into();
        assert!(
            Fetch03::parse(&bytes(&changed))
                .unwrap()
                .verify(&key)
                .is_err()
        );
    }
    let mut changed = signed;
    changed["grant"]["segment_count"] = 2.into();
    assert!(
        Fetch03::parse(&bytes(&changed))
            .unwrap()
            .verify(&key)
            .is_err()
    );
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let grant = GrantFrame03::parse(&bytes(&frame())).unwrap();
    let transcript = grant.fetch_transcript();
    let sig: Signature = key.sign(&transcript);
    let positive = fetch(
        &frame(),
        &encoded_der(sig.normalize_s().to_der().as_bytes()),
    );
    Fetch03::parse(&bytes(&positive))
        .unwrap()
        .verify(key.verifying_key())
        .unwrap();
    assert!(
        Fetch03::parse(&bytes(&positive))
            .unwrap()
            .verify(&public_key())
            .is_err()
    );
    let mut wrong_domain = transcript;
    wrong_domain[26] = b'1';
    let sig: Signature = key.sign(&wrong_domain);
    let wrong = fetch(
        &frame(),
        &encoded_der(sig.normalize_s().to_der().as_bytes()),
    );
    assert!(
        Fetch03::parse(&bytes(&wrong))
            .unwrap()
            .verify(key.verifying_key())
            .is_err()
    );
    let old_vector: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-execution-grant-01.json"
    ))
    .unwrap();
    let old: super::super::wire::GrantFrame =
        serde_json::from_value(old_vector["frame"].clone()).unwrap();
    let old_transcript = super::super::wire::fetch_transcript(&old).unwrap();
    let sig: Signature = key.sign(&old_transcript);
    let old_proof = fetch(
        &frame(),
        &encoded_der(sig.normalize_s().to_der().as_bytes()),
    );
    assert!(
        Fetch03::parse(&bytes(&old_proof))
            .unwrap()
            .verify(key.verifying_key())
            .is_err()
    );
    assert!(GrantFrame03::parse(&bytes(&old_vector["frame"])).is_err());
}

#[test]
fn fetch_outer_and_nested_objects_remain_closed_and_bounded() {
    let original = public_fetch();
    for name in ["grant", "signature_der"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(name);
        assert!(Fetch03::parse(&bytes(&changed)).is_err());
        for bad in [Value::Null, json!(1), json!([]), json!(true)] {
            let mut changed = original.clone();
            changed[name] = bad;
            assert!(Fetch03::parse(&bytes(&changed)).is_err());
        }
        let text = serde_json::to_string(&original).unwrap();
        let duplicate = format!("{{{}:{},{}", json!(name), original[name], &text[1..]);
        assert!(Fetch03::parse(duplicate.as_bytes()).is_err());
    }
    let mut unknown = original.clone();
    unknown["extra"] = true.into();
    assert!(Fetch03::parse(&bytes(&unknown)).is_err());
    let mut nested = original.clone();
    nested["grant"]["extra"] = true.into();
    assert!(Fetch03::parse(&bytes(&nested)).is_err());
    let duplicate = serde_json::to_string(&original)
        .unwrap()
        .replace("\"grant\":{", "\"grant\":{\"v\":1,");
    assert!(Fetch03::parse(duplicate.as_bytes()).is_err());
    let mut exact = bytes(&original);
    exact.resize(MAX_JSON_BYTES, b' ');
    assert!(Fetch03::parse(&exact).is_ok());
    exact.push(b' ');
    assert!(Fetch03::parse(&exact).is_err());
    assert!(Fetch03::parse(format!("{} {{}}", original).as_bytes()).is_err());
    assert!(Fetch03::parse(b"null").is_err());
}

#[test]
fn der_refuses_nonminimal_negative_zero_out_of_range_and_noncanonical_encoding() {
    let original = public_fetch();
    let der = Fetch03::parse(&bytes(&original)).unwrap().signature_der();
    let zero = [0x30, 0x06, 0x02, 0x01, 0, 0x02, 0x01, 1];
    let negative = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 1];
    let overpadded = [0x30, 0x07, 0x02, 0x02, 0, 1, 0x02, 0x01, 1];
    let long_length = [0x30, 0x81, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1];
    let curve_order = [
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let mut out_of_range = vec![0x30, 0x26, 0x02, 0x21, 0];
    out_of_range.extend(curve_order);
    out_of_range.extend([0x02, 0x01, 1]);
    for bad in [
        vec![0; 7],
        vec![0; 72],
        [der.as_slice(), &[0]].concat(),
        zero.to_vec(),
        negative.to_vec(),
        overpadded.to_vec(),
        long_length.to_vec(),
        out_of_range,
    ] {
        assert!(Fetch03::parse(&bytes(&fetch(&frame(), &encoded_der(&bad)))).is_err());
    }
    let valid = original["signature_der"].as_str().unwrap();
    for bad in [
        format!("{valid}="),
        valid.replace('-', "+").replace('_', "/"),
        format!("{valid}\n"),
    ] {
        assert!(Fetch03::parse(&bytes(&fetch(&frame(), &bad))).is_err());
    }
    let minimum = [0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1];
    let f = Fetch03::parse(&bytes(&fetch(&frame(), &encoded_der(&minimum)))).unwrap();
    assert_eq!(f.signature_der(), minimum);
    assert!(f.verify(&public_key()).is_err());
}

#[test]
fn high_s_is_refused_before_signature_verification_even_within_der_length_limit() {
    let order = [
        0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let transcript = GrantFrame03::parse(&bytes(&frame()))
        .unwrap()
        .fetch_transcript();
    let mut qualified = false;
    for _ in 0..128 {
        let key = SigningKey::generate_from_rng(&mut rand::rng());
        let sig: Signature = key.sign(&transcript);
        let low = sig.normalize_s();
        let mut raw = low.to_bytes();
        if raw[0] & 0x80 != 0 {
            continue;
        }
        let mut borrow = 0i16;
        for at in (0..32).rev() {
            let n = i16::from(order[at]) - i16::from(raw[32 + at]) - borrow;
            raw[32 + at] = n.rem_euclid(256) as u8;
            borrow = if n < 0 { 1 } else { 0 };
        }
        assert_eq!(borrow, 0);
        let high = Signature::from_slice(&raw).unwrap();
        assert_ne!(high.normalize_s().to_bytes(), high.to_bytes());
        assert_eq!(high.normalize_s().to_bytes(), low.to_bytes());
        let high_der = high.to_der();
        assert!(high_der.as_bytes().len() <= 71);
        let positive = fetch(&frame(), &encoded_der(low.to_der().as_bytes()));
        Fetch03::parse(&bytes(&positive))
            .unwrap()
            .verify(key.verifying_key())
            .unwrap();
        let negative = fetch(&frame(), &encoded_der(high_der.as_bytes()));
        assert_eq!(
            Fetch03::parse(&bytes(&negative)).unwrap_err(),
            "wire03 low-S DER"
        );
        qualified = true;
        break;
    }
    assert!(
        qualified,
        "expected ordinary generated signature with short r"
    );
}
