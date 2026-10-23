// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::elliptic_curve::Generate;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn uuid(value: u8) -> Uuid {
    Uuid::from_bytes([value; 16])
}
fn submit() -> Value {
    json!({"v":1,"type":"payload_profile_submit03","connection_epoch":3,"event_id":uuid(3),"message_id":uuid(4),"attempt_id":uuid(5),"fetch_transcript_sha256":B.encode([7;32]),"segment_count":2,"observed_ms":"5000"})
}
fn parsed_submit(body: &Value) -> Submit03 {
    match Request03::parse(&body.to_string()).unwrap().unwrap() {
        Request03::Submit(value) => value,
        _ => panic!("submit variant"),
    }
}
fn command_sha() -> [u8; 32] {
    parsed_submit(&submit())
        .candidate_command(uuid(1), uuid(2), &[8; 32])
        .unwrap()
        .digest()
        .unwrap()
}
fn outcome() -> Value {
    json!({"v":1,"type":"payload_profile_outcome03","connection_epoch":9,"event_id":uuid(6),"message_id":uuid(4),"attempt_id":uuid(5),"submit_event_id":uuid(3),"submit_command_sha256":B.encode(command_sha()),"fetch_transcript_sha256":B.encode([7;32]),"submit_observed_ms":"5000","segment_count":2,"evidence":"sent_callback_ok","observed_ms":"6000","segment_index":0})
}
fn closure() -> Value {
    let mut bytes = Vec::new();
    for id in [uuid(1), uuid(2), uuid(3), uuid(4), uuid(5), uuid(6)] {
        bytes.extend(id.as_bytes());
    }
    bytes.extend([7; 32]);
    bytes.extend(command_sha());
    bytes.extend([8; 32]);
    bytes.push(2);
    bytes.extend(5000_u64.to_be_bytes());
    bytes.push(1);
    bytes.extend(6000_u64.to_be_bytes());
    let mut h = Sha256::new();
    h.update(b"ZTSE/conversation/no-submit-record03/v1\0");
    h.update(210_u32.to_be_bytes());
    h.update(&bytes);
    json!({"v":1,"type":"payload_profile_no_submit_challenge03_request","connection_epoch":9,"proof_request_id":uuid(7),"closure_id":uuid(6),"event_id":uuid(3),"message_id":uuid(4),"attempt_id":uuid(5),"submit_command_sha256":B.encode(command_sha()),"fetch_transcript_sha256":B.encode([7;32]),"segment_count":2,"submit_observed_ms":"5000","closed_from":"ack_authorized","closed_ms":"6000","closure_record_sha256":B.encode(h.finalize()),"previous_challenge_id":null})
}

#[test]
fn canonical_submit_bytes_use_selected_original_identity_and_not_reporting_epoch() {
    let body = submit();
    let candidate = parsed_submit(&body);
    let cmd = candidate
        .candidate_command(uuid(1), uuid(2), &[8; 32])
        .unwrap();
    let mut manual = Vec::new();
    for id in [uuid(1), uuid(2), uuid(3), uuid(4), uuid(5)] {
        manual.extend(id.as_bytes());
    }
    manual.extend([7; 32]);
    manual.extend([8; 32]);
    manual.push(2);
    manual.extend(5000_u64.to_be_bytes());
    assert_eq!(cmd.bytes().as_slice(), manual);
    let mut other = body;
    other["connection_epoch"] = json!(4);
    assert_eq!(
        parsed_submit(&other)
            .candidate_command(uuid(1), uuid(2), &[8; 32])
            .unwrap()
            .digest()
            .unwrap(),
        cmd.digest().unwrap()
    );
    assert_ne!(
        candidate
            .candidate_command(uuid(1), uuid(9), &[8; 32])
            .unwrap()
            .digest()
            .unwrap(),
        cmd.digest().unwrap()
    );
    assert_ne!(
        candidate
            .candidate_command(uuid(1), uuid(2), &[9; 32])
            .unwrap()
            .digest()
            .unwrap(),
        cmd.digest().unwrap()
    );
}

#[test]
fn object_only_closed_fields_and_escaped_duplicates_do_not_collapse() {
    let body = submit();
    let raw = body.to_string();
    assert!(Request03::parse(&format!("[{raw}] ")).is_err());
    assert!(Request03::parse(&format!("{raw}{{}}")).is_err());
    for (name, value) in [
        ("account_id", json!(uuid(1))),
        ("submit_permitted", json!(true)),
        ("no_submit", json!(true)),
    ] {
        let mut bad = body.clone();
        bad[name] = value;
        assert!(Request03::parse(&bad.to_string()).is_err());
    }
    let slash = char::from(92);
    // Construct the escaped key at runtime: source contains no path-like literal.
    let duplicate = format!(
        "{},\"e{slash}u0076ent_id\":\"{}\"}}",
        &raw[..raw.len() - 1],
        uuid(3)
    );
    assert!(Request03::parse(&duplicate).is_err());
    assert!(
        Request03::parse("{\"type\":\"radio_event\"}")
            .unwrap()
            .is_none()
    );
    assert!(Request03::parse(&format!("{raw}{}", " ".repeat(4096))).is_err());
}

#[test]
fn numeric_uuid_binary_and_segment_boundaries_are_exact() {
    let body = submit();
    for value in [
        json!(5000),
        json!("05000"),
        json!("+5000"),
        json!("5e3"),
        json!("0"),
        json!("9223372036854775808"),
    ] {
        let mut bad = body.clone();
        bad["observed_ms"] = value;
        assert!(Request03::parse(&bad.to_string()).is_err());
    }
    for (name, value) in [
        ("connection_epoch", json!("3")),
        ("connection_epoch", json!(0)),
        ("segment_count", json!(0)),
        ("segment_count", json!(7)),
        ("segment_count", json!(2.0)),
        ("event_id", json!(Uuid::nil())),
        ("event_id", json!("03030303030303030303030303030303")),
        (
            "fetch_transcript_sha256",
            json!(format!("{}=", B.encode([7; 32]))),
        ),
        ("fetch_transcript_sha256", json!(B.encode([0; 32]))),
    ] {
        let mut bad = body.clone();
        bad[name] = value;
        assert!(
            Request03::parse(&bad.to_string()).is_err(),
            "{name}:{}",
            bad[name]
        );
    }
    let mut good = body;
    good["observed_ms"] = json!(i64::MAX.to_string());
    good["segment_count"] = json!(6);
    assert!(Request03::parse(&good.to_string()).is_ok());
}

#[test]
fn outcomes_preserve_original_submit_commitment_and_exact_segment_aggregate_shape() {
    let body = outcome();
    let Request03::Outcome(value) = Request03::parse(&body.to_string()).unwrap().unwrap() else {
        panic!("outcome")
    };
    let command = value.candidate_command(uuid(1), uuid(2), &[8; 32]).unwrap();
    assert_eq!(command.bytes().len(), 211);
    assert_eq!(command.segment_index(), Some(0));
    assert!(value.candidate_command(uuid(1), uuid(2), &[9; 32]).is_err());
    for evidence in ["sent_callback_ok", "sent_callback_failed"] {
        for index in [json!(null), json!(2), json!("0"), json!(-1), json!(0.0)] {
            let mut bad = body.clone();
            bad["evidence"] = json!(evidence);
            bad["segment_index"] = index;
            assert!(Request03::parse(&bad.to_string()).is_err());
        }
    }
    for evidence in [
        "delivery_callback_ok",
        "delivery_timeout",
        "crash_without_callback",
        "callback_conflict",
    ] {
        let mut good = body.clone();
        good["evidence"] = json!(evidence);
        good["segment_index"] = Value::Null;
        assert!(Request03::parse(&good.to_string()).is_ok());
        good.as_object_mut().unwrap().remove("segment_index");
        assert!(Request03::parse(&good.to_string()).is_err());
    }
    let mut bad = body;
    bad["evidence"] = json!("proved_no_submit");
    assert!(Request03::parse(&bad.to_string()).is_err());
}

#[test]
fn only_pre_entry_closure_can_build_the_exact_original_record() {
    let body = closure();
    let Request03::Challenge(value) = Request03::parse(&body.to_string()).unwrap().unwrap() else {
        panic!("closure")
    };
    assert_eq!(
        value
            .candidate_record(uuid(1), uuid(2), &[8; 32])
            .unwrap()
            .bytes()
            .len(),
        210
    );
    assert!(value.candidate_record(uuid(1), uuid(9), &[8; 32]).is_err());
    let mut missing = body.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("previous_challenge_id");
    assert!(Request03::parse(&missing.to_string()).is_err());
    for phase in [
        "platform_entry_reserved",
        "outcome",
        "closed_no_submit",
        "no_submit",
    ] {
        let mut bad = body.clone();
        bad["closed_from"] = json!(phase);
        assert!(Request03::parse(&bad.to_string()).is_err());
    }
    let mut changed = body;
    changed["closed_ms"] = json!("6001");
    let Request03::Challenge(value) = Request03::parse(&changed.to_string()).unwrap().unwrap()
    else {
        panic!("closure")
    };
    assert!(value.candidate_record(uuid(1), uuid(2), &[8; 32]).is_err());
}

#[test]
fn proof_outer_nonce_command_and_transport_correlations_are_distinct() {
    let key = p256::ecdsa::SigningKey::generate();
    let core = crate::conversation_effect03::tests::core(&key);
    let body = json!({"v":1,"type":"payload_profile_no_submit_proof03","connection_epoch":3,"proof_request_id":uuid(7),"closure_id":uuid(6),"challenge_id":uuid(8),"core":B.encode(core),"signature":B.encode([1;64])});
    assert!(Request03::parse(&body.to_string()).is_ok());
    for (name, value) in [
        ("connection_epoch", json!(4)),
        ("proof_request_id", json!(uuid(9))),
        ("closure_id", json!(uuid(9))),
        ("challenge_id", json!(uuid(9))),
    ] {
        let mut bad = body.clone();
        bad[name] = value;
        assert!(Request03::parse(&bad.to_string()).is_err());
    }
}

#[test]
fn all_typed_frames_share_rate_policy_without_throttling_message_traffic_as_management() {
    assert_eq!(Kind03::Submit.admission(), OrdinaryAdmission03::Evidence);
    assert_eq!(Kind03::Outcome.admission(), OrdinaryAdmission03::Evidence);
    assert_eq!(Kind03::Challenge.admission(), OrdinaryAdmission03::Manage);
    assert_eq!(Kind03::Proof.admission(), OrdinaryAdmission03::Manage);
    for (kind, body) in [
        (
            Kind03::SubmitStatus,
            json!({"v":1,"type":"payload_profile_submit_status03_request","connection_epoch":9,"request_id":uuid(9),"event_id":uuid(3),"message_id":uuid(4),"attempt_id":uuid(5),"submit_command_sha256":B.encode(command_sha())}),
        ),
        (
            Kind03::ProofStatus,
            json!({"v":1,"type":"payload_profile_no_submit_status03_request","connection_epoch":9,"request_id":uuid(9),"proof_request_id":uuid(7),"closure_id":uuid(6),"message_id":uuid(4),"attempt_id":uuid(5),"submit_command_sha256":B.encode(command_sha()),"closure_record_sha256":B.encode([10;32])}),
        ),
    ] {
        let value = Request03::parse(&body.to_string()).unwrap().unwrap();
        assert_eq!(value.kind(), kind);
        assert_eq!(value.kind().admission(), OrdinaryAdmission03::Read);
        assert_eq!(value.connection_epoch(), 9);
        let mut bad = body;
        bad["submit_once"] = json!(true);
        assert!(Request03::parse(&bad.to_string()).is_err());
    }
}
