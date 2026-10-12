// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;

#[test]
fn selected_single_protocol_is_the_only_line_version_admission() {
    for token in [PROTOCOL, SEALED_PROTOCOL] {
        let n = Negotiated::selected(Some(token));
        assert_eq!(n.line, LineProtocol::Complete);
        assert_eq!(n.status, Some(preconditions::PROTOCOL_V2));
        assert_eq!(
            n.sealed_version,
            if token == SEALED_PROTOCOL {
                Some(2)
            } else {
                None
            }
        );
    }
    for token in [
        None,
        Some(preconditions::PROTOCOL),
        Some(preconditions::PROTOCOL_V2),
        Some(crate::sealed_dispatch::wire::PROTOCOL),
        Some(crate::sealed_dispatch::wire::PROTOCOL_V2),
        Some("line-activation-v2"),
        Some("zrotext-device-status-v2, line-activation-v2"),
    ] {
        assert_eq!(Negotiated::selected(token).line, LineProtocol::Legacy);
    }
}
fn proof() -> Value {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let signature: Signature = key.sign(b"synthetic parser signature");
    serde_json::json!({"type":"sms_line_proof_v2","v":2,"connection_epoch":"1","challenge_id":Uuid::new_v4(),"observation_b64url":URL_SAFE_NO_PAD.encode([0u8;121]),"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())})
}
#[test]
fn raw_proofs_are_closed_and_canonical_before_cryptographic_runtime_admission() {
    let frame = proof();
    assert!(matches!(
        parse(&frame.to_string()),
        Ok(Some(Incoming::Proof {
            purpose: Purpose::Sms,
            epoch: 1,
            ..
        }))
    ));
    for (field, value) in [
        ("v", serde_json::json!(1)),
        ("v", serde_json::json!("2")),
        ("connection_epoch", serde_json::json!(1)),
        ("connection_epoch", serde_json::json!("01")),
        ("connection_epoch", serde_json::json!("9223372036854775808")),
        ("challenge_id", serde_json::json!(Uuid::nil())),
        ("observation_b64url", serde_json::json!("AA==")),
        ("signature_der", serde_json::json!("AAAAAAAAAAA")),
        ("type", serde_json::json!("sms_line_activated_v2")),
    ] {
        let mut changed = frame.clone();
        changed[field] = value;
        assert!(parse(&changed.to_string()).is_err(), "{field}");
    }
    let mut changed = frame.clone();
    changed["trusted"] = serde_json::json!(true);
    assert!(parse(&changed.to_string()).is_err());
    let duplicate = frame.to_string().replacen('{', "{\"v\":2,", 1);
    assert!(parse(&duplicate).is_err());
    let numeric = frame.to_string().replace("\"v\":2", "\"v\":2.0");
    assert!(parse(&numeric).is_err());
    assert!(matches!(
        parse("{\"v\":1,\"type\":\"heartbeat\"}"),
        Ok(None)
    ));
}
#[test]
fn final_and_challenge_frames_match_string_epochs_and_numeric_expiry() {
    let tuple = crate::sealed_inbound::line_activation::LineChallenge {
        id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        line_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        generation: 9007199254740993,
        nonce: [7; 32],
    };
    let c = challenge_frame(
        runtime::Challenge {
            tuple,
            expires_at_ms: 1700000000000,
        },
        Purpose::Sealed,
        9007199254740993,
    );
    assert_eq!(c["expires_at_ms"].as_i64(), Some(1700000000000));
    assert_eq!(c["generation"], "9007199254740993");
    assert_eq!(c["connection_epoch"], "9007199254740993");
    let a = Ack {
        challenge_id: tuple.id,
        account_id: tuple.account_id,
        line_id: tuple.line_id,
        device_id: tuple.device_id,
        generation: tuple.generation,
        device_statement_sha256: [8; 32],
        device_signature_sha256: [9; 32],
    };
    let mut installed = ack_frame(a, Purpose::Sealed, 2);
    installed["type"] = serde_json::json!("sealed_line_installed_v2");
    assert!(matches!(
        parse(&installed.to_string()),
        Ok(Some(Incoming::Installed { epoch: 2, .. }))
    ));
    installed["type"] = serde_json::json!("sms_line_installed_v2");
    assert!(parse(&installed.to_string()).is_err());
    let sms = ack_frame(a, Purpose::Sms, 2);
    assert!(sms.get("connection_epoch").is_none());
    assert!(sms.get("nonce").is_none());
}

#[test]
fn every_proof_field_preserves_raw_duplicate_null_and_object_shape_refusals() {
    let frame = proof();
    let raw = frame.to_string();
    let positional: Vec<_> = frame.as_object().unwrap().values().cloned().collect();
    assert!(parse(&serde_json::to_string(&positional).unwrap()).is_err());
    for (key, value) in frame.as_object().unwrap() {
        let escaped = format!("\\u{:04x}{}", key.as_bytes()[0], &key[1..]);
        for name in [key.clone(), escaped] {
            let duplicate = format!("{{\"{name}\":{value},{}", &raw[1..]);
            assert!(parse(&duplicate).is_err(), "duplicate {key}");
        }
        let mut missing = frame.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(parse(&missing.to_string()).is_err(), "missing {key}");
        let mut null = frame.clone();
        null[key] = Value::Null;
        assert!(parse(&null.to_string()).is_err(), "null {key}");
    }
    for literal in ["2.0", "2e0", "2E+0", "true", "\"2\"", "null"] {
        assert!(parse(&raw.replace("\"v\":2", &format!("\"v\":{literal}"))).is_err());
    }
    for epoch in [
        "0",
        "-1",
        "01",
        "+1",
        "1.0",
        "1e0",
        "1\n",
        "9223372036854775808",
    ] {
        let mut changed = frame.clone();
        changed["connection_epoch"] = serde_json::json!(epoch);
        assert!(parse(&changed.to_string()).is_err(), "epoch {epoch:?}");
    }
    for field in [
        "connection_epoch",
        "challenge_id",
        "observation_b64url",
        "signature_der",
    ] {
        for value in [
            serde_json::json!(1),
            serde_json::json!(true),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let mut changed = frame.clone();
            changed[field] = value;
            assert!(parse(&changed.to_string()).is_err(), "type {field}");
        }
    }
    let mut oversized = raw.clone();
    oversized.push_str(&" ".repeat(MAX_FRAME_BYTES));
    assert!(parse(&oversized).is_err());
    assert!(parse(&(raw.clone() + "{} ")).is_err());
    let mut sealed = frame;
    sealed["type"] = serde_json::json!("sealed_line_proof_v2");
    assert!(matches!(
        parse(&sealed.to_string()),
        Ok(Some(Incoming::Proof {
            purpose: Purpose::Sealed,
            ..
        }))
    ));
}

#[test]
fn installed_tuple_requires_closed_canonical_fields_and_both_full_digests() {
    let ack = Ack {
        challenge_id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        line_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        generation: i64::MAX,
        device_statement_sha256: [8; 32],
        device_signature_sha256: [9; 32],
    };
    let mut frame = ack_frame(ack, Purpose::Sealed, i64::MAX);
    frame["type"] = serde_json::json!("sealed_line_installed_v2");
    assert!(matches!(
        parse(&frame.to_string()),
        Ok(Some(Incoming::Installed {
            epoch: i64::MAX,
            ..
        }))
    ));
    let raw = frame.to_string();
    for (key, value) in frame.as_object().unwrap() {
        let escaped = format!("\\u{:04x}{}", key.as_bytes()[0], &key[1..]);
        assert!(parse(&format!("{{\"{escaped}\":{value},{}", &raw[1..])).is_err());
        let mut missing = frame.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(parse(&missing.to_string()).is_err());
        let mut null = frame.clone();
        null[key] = Value::Null;
        assert!(parse(&null.to_string()).is_err());
    }
    for field in ["challenge_id", "account_id", "line_id", "device_id"] {
        for bad in [
            Uuid::nil().to_string(),
            Uuid::new_v4().simple().to_string(),
            "AABBCCDD-1122-3344-5566-778899AABBCC".to_owned(),
        ] {
            let mut changed = frame.clone();
            changed[field] = serde_json::json!(bad);
            assert!(parse(&changed.to_string()).is_err());
        }
    }
    for field in ["device_statement_sha256", "device_signature_sha256"] {
        for size in [31, 33] {
            let mut changed = frame.clone();
            changed[field] = serde_json::json!(URL_SAFE_NO_PAD.encode(vec![7; size]));
            assert!(parse(&changed.to_string()).is_err());
        }
        let mut padded = frame.clone();
        padded[field] = serde_json::json!(format!("{}=", frame[field].as_str().unwrap()));
        assert!(parse(&padded.to_string()).is_err());
    }
    let mut future = frame.clone();
    future["v"] = serde_json::json!(3);
    assert!(parse(&future.to_string()).is_err());
    let mut extra = frame;
    extra["accepted"] = serde_json::json!(true);
    assert!(parse(&extra.to_string()).is_err());
}
