// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn line_opt_out_transcript_matches_android_vector() {
    let session = InboundSession {
        account_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        device_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        site_id: "vector",
        instance_id: "vector",
        connection_epoch: 1,
        deployment_epoch: 1,
    };
    let event = LineOptOut {
        id: Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
        line_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
        binding_generation: 7,
        sequence: 42,
        recipient_e164: "+15551234567",
        action: unsolicited::Action::Stop,
        observed_at_ms: 1_700_000_000_000,
        signature_der: &[],
    };
    let digest = Sha256::digest(unsolicited::signed_line_opt_out_bytes(session, &event).unwrap());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "bd2e9c463936887cfa804c2a35ecf2be37004b9c6f2104f1f3e758a38fd5459a"
    );
}

#[test]
fn line_opt_out_frame_is_distinct_and_rejects_start_body_and_unknown_fields() {
    let event_id = Uuid::new_v4();
    let line_id = Uuid::new_v4();
    let frame = json!({
        "v":1,"type":"line_opt_out","connection_epoch":7,
        "event_id":event_id,"sequence":11,"line_id":line_id,
        "binding_generation":3,"action":"opt_out",
        "recipient_e164":"+15551234567","observed_at_ms":1_700_000_000_000_i64,
        "signature_der":"Ag"
    });
    assert!(matches!(
        serde_json::from_value::<ClientFrame>(frame.clone()),
        Ok(ClientFrame::LineOptOut {
            v: 1,
            connection_epoch: 7,
            event_id: id,
            sequence: 11,
            line_id: line,
            binding_generation: 3,
            action: LineOptOutAction::OptOut,
            ..
        }) if id == event_id && line == line_id
    ));
    for action in ["opt_in", "start", "captured_local"] {
        let mut altered = frame.clone();
        altered["action"] = json!(action);
        assert!(serde_json::from_value::<ClientFrame>(altered).is_err());
    }
    for extra in ["body", "attempt_id", "part_count", "suppression_cleared"] {
        let mut altered = frame.clone();
        altered[extra] = json!("forbidden");
        assert!(serde_json::from_value::<ClientFrame>(altered).is_err());
    }
    let mut missing = frame.clone();
    missing.as_object_mut().unwrap().remove("line_id");
    assert!(serde_json::from_value::<ClientFrame>(missing).is_err());
    let mut review = frame;
    review["action"] = json!("opt_out_review");
    assert!(matches!(
        serde_json::from_value::<ClientFrame>(review),
        Ok(ClientFrame::LineOptOut {
            action: LineOptOutAction::OptOutReview,
            ..
        })
    ));
    let ack = serde_json::to_value(ServerFrame::LineOptOutAck {
        v: 1,
        event_id,
        created: false,
    })
    .unwrap();
    assert_eq!(
        ack,
        json!({"v":1,"type":"line_opt_out_ack","event_id":event_id,"created":false})
    );
    assert!(ack.get("suppression_cleared").is_none());
}

#[test]
fn line_opt_out_rejection_codes_preserve_retry_and_policy_distinction() {
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::InvalidInput),
        EVIDENCE_REJECTED
    );
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::InvalidSignature),
        EVIDENCE_REJECTED
    );
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::EventConflict),
        EVIDENCE_REJECTED
    );
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::SequenceConflict),
        EVIDENCE_REJECTED
    );
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::Unauthorized),
        close_code::POLICY
    );
    assert_eq!(
        line_opt_out_close_code(&LineOptOutError::BudgetExhausted),
        RETRY_LATER
    );
}
