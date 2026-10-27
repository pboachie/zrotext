// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;

#[test]
fn recognized_typed_routes_defer_closed_body_decoding_until_request_admission() {
    for kind in [
        Kind03::Submit,
        Kind03::Outcome,
        Kind03::SubmitStatus,
        Kind03::Challenge,
        Kind03::Proof,
        Kind03::ProofStatus,
    ] {
        // No account/actor/attempt is inferred from this deliberately invalid
        // body. The genuine handler must charge its held actual socket first.
        let raw = json!({"type":kind.name(),"v":99,"extra":true}).to_string();
        let incoming = parse(&raw).unwrap().unwrap();
        assert!(matches!(incoming.route,Route03::Effect(found) if found==kind));
        assert_eq!(incoming.raw, raw);
        assert!(Request03::parse(&incoming.raw).is_err());
    }
    let raw = json!({"type":"payload_profile_history_clock03_request","current":true}).to_string();
    let incoming = parse(&raw).unwrap().unwrap();
    assert!(matches!(incoming.route, Route03::Clock));
    assert!(history_clock::Request03::parse(&incoming.raw).is_err());
}

#[test]
fn typed_route_does_not_take_over_legacy_radio_or_current_permission_kinds() {
    for name in [
        "radio_event",
        "radio_event_ack",
        "payload_profile_current03_request",
        "payload_profile_session03_request",
        "payload_profile_submit_ack03",
        "payload_profile_history_clock03",
        "submit_manifest_permission03",
    ] {
        assert!(parse(&json!({"type":name}).to_string()).unwrap().is_none());
    }
    let valid = json!({"v":1,"type":"payload_profile_history_clock03_request",
        "connection_epoch":1,"request_id":Uuid::from_u128(1),
        "message_id":Uuid::from_u128(2),"attempt_id":Uuid::from_u128(3)})
    .to_string();
    let incoming = parse(&valid).unwrap().unwrap();
    assert!(
        history_clock::Request03::parse(&incoming.raw)
            .unwrap()
            .is_some()
    );
    assert!(Request03::parse(&incoming.raw).unwrap().is_none());
}

#[test]
fn ambiguous_or_unbounded_route_syntax_closes_before_any_body_is_trusted() {
    for raw in [
        r#"{"type":"payload_profile_submit03","type":"radio_event"}"#.to_owned(),
        r#"{"type":"payload_profile_submit03","\u0074ype":"radio_event"}"#.to_owned(),
        r#"[{"type":"payload_profile_submit03"}]"#.to_owned(),
        r#"{"type":"payload_profile_submit03"}{}"#.to_owned(),
        " ".repeat(MAX_FRAME_BYTES + 1),
    ] {
        assert!(parse(&raw).is_err());
    }
}
