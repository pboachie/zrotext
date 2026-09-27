// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::sync::OnceLock;

const SENDER: &str = "+15551234567";
const RECIPIENT: &str = "+15557654321";
fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
fn route() -> Route {
    Route::telnyx(id(1), id(2), id(3), SENDER, 1).unwrap()
}
fn request() -> Request {
    Request::new(
        route(),
        RECIPIENT,
        Content::ProviderPlaintext("synthetic fixture"),
    )
    .unwrap()
}
fn gate() -> AdmissionSnapshot {
    AdmissionSnapshot {
        account: id(1),
        route_revision: 1,
        observed_ms: 10,
        expires_ms: 100,
        writer_enabled: true,
        suppressed: false,
    }
}
fn key() -> &'static Ed25519KeyPair {
    static KEY: OnceLock<Ed25519KeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
    })
}
fn signed(body: &[u8], timestamp: &str) -> String {
    let mut transcript = timestamp.as_bytes().to_vec();
    transcript.push(b'|');
    transcript.extend_from_slice(body);
    STANDARD.encode(key().sign(&transcript).as_ref())
}
fn verify(
    body: &[u8],
    timestamp: &str,
    signature: &str,
    current: u64,
    request: &Request,
) -> Result<VerifiedReceipt, Rejection> {
    verify_receipt(
        request,
        key().public_key().as_ref().try_into().unwrap(),
        timestamp,
        signature,
        body,
        current,
    )
}
// Structural subset of the official outbound webhook example. Keys are freshly
// generated per process and all identities/content are synthetic. No HTTP call.
fn fixture(status: &str, event: u128) -> Value {
    json!({"data": {"id": id(event), "event_type": if status == "sent" { "message.sent" } else { "message.finalized" }, "record_type":"event", "payload": {
        "id": id(4), "organization_id":id(2), "messaging_profile_id":id(3), "direction":"outbound", "type":"SMS",
        "from":{"phone_number":SENDER}, "to":[{"phone_number":RECIPIENT,"status":status}],
        "text":"synthetic fixture", "unknown_future_field":true
    }}, "meta":{"attempt":1}})
}
fn decode(value: &Value, request: &Request) -> Result<VerifiedReceipt, Rejection> {
    let body = serde_json::to_vec(value).unwrap();
    verify(&body, "1000", &signed(&body, "1000"), 1000, request)
}
fn begun() -> Attempt {
    let mut attempt = Attempt::new(request(), id(9)).unwrap();
    attempt.begin(&gate(), 10).unwrap();
    attempt
}
fn accepted() -> Attempt {
    let mut attempt = begun();
    attempt.accept_response(id(4)).unwrap();
    attempt
}

#[test]
fn explicit_plaintext_route_binds_all_request_identity() {
    let original = request();
    assert_eq!(original.check_replay(&request()), Ok(()));
    for changed in [
        Route::telnyx(id(10), id(2), id(3), SENDER, 1).unwrap(),
        Route::telnyx(id(1), id(10), id(3), SENDER, 1).unwrap(),
        Route::telnyx(id(1), id(2), id(10), SENDER, 1).unwrap(),
        Route::telnyx(id(1), id(2), id(3), RECIPIENT, 1).unwrap(),
        Route::telnyx(id(1), id(2), id(3), SENDER, 2).unwrap(),
    ] {
        let other = Request::new(
            changed,
            RECIPIENT,
            Content::ProviderPlaintext("synthetic fixture"),
        )
        .unwrap();
        assert_ne!(original.digest(), other.digest());
        assert_eq!(
            other.check_replay(&original),
            Err(Rejection::RequestConflict)
        );
    }
    for other in [
        Request::new(
            route(),
            SENDER,
            Content::ProviderPlaintext("synthetic fixture"),
        )
        .unwrap(),
        Request::new(
            route(),
            RECIPIENT,
            Content::ProviderPlaintext("different fixture"),
        )
        .unwrap(),
    ] {
        assert_ne!(original.digest(), other.digest());
    }
    assert_eq!(
        Request::new(route(), RECIPIENT, Content::SealedPhoneEnvelope(b"ZTSE")).err(),
        Some(Rejection::SealedContent)
    );
    assert_eq!(
        Request::new(route(), RECIPIENT, Content::ProviderPlaintext("")).err(),
        Some(Rejection::InvalidInput)
    );
    assert_eq!(
        Request::new(
            route(),
            RECIPIENT,
            Content::ProviderPlaintext(&"x".repeat(4097))
        )
        .err(),
        Some(Rejection::InvalidInput)
    );
    for bad in ["", "+0", "+01", "1555", "+1x", "+1234567890123456"] {
        assert!(Route::telnyx(id(1), id(2), id(3), bad, 1).is_err());
    }
    assert!(Route::telnyx(Uuid::nil(), id(2), id(3), SENDER, 1).is_err());
    assert!(Route::telnyx(id(1), id(2), id(3), SENDER, 0).is_err());
    assert_eq!(route().provider(), Provider::TelnyxSmsV2);
}

#[test]
fn authority_and_suppression_gate_every_begin_without_mutation() {
    for index in 0..8 {
        let mut attempt = Attempt::new(request(), id(9)).unwrap();
        let mut snapshot = gate();
        match index {
            0 => snapshot.account = id(8),
            1 => snapshot.route_revision = 2,
            2 => snapshot.writer_enabled = false,
            3 => snapshot.suppressed = true,
            4 => snapshot.observed_ms = 11,
            5 => snapshot.expires_ms = 10,
            6 => snapshot.expires_ms = 5011,
            _ => snapshot.expires_ms = 0,
        }
        assert!(attempt.begin(&snapshot, 10).is_err());
        assert_eq!(attempt.state(), MessageState::Queued);
    }
    for revision in [1, 2] {
        let route = Route::telnyx(id(1), id(2), id(3), SENDER, revision).unwrap();
        let mut attempt = Attempt::new(
            Request::new(route, RECIPIENT, Content::ProviderPlaintext("fixture")).unwrap(),
            id(9),
        )
        .unwrap();
        let mut snapshot = gate();
        snapshot.route_revision = revision;
        snapshot.suppressed = true;
        assert_eq!(attempt.begin(&snapshot, 10), Err(Rejection::Suppressed));
    }
}

#[test]
fn response_loss_never_reopens_an_attempt_or_claims_carrier_acceptance() {
    let mut attempt = begun();
    assert_eq!(attempt.id(), id(9));
    attempt.response_lost().unwrap();
    assert_eq!(attempt.state(), MessageState::Unknown);
    assert!(!attempt.provider_accepted());
    assert_eq!(attempt.begin(&gate(), 10), Err(Rejection::InvalidState));
    attempt.accept_response(id(4)).unwrap();
    assert!(attempt.provider_accepted());
    assert_eq!(attempt.state(), MessageState::Unknown);
    assert_eq!(attempt.begin(&gate(), 10), Err(Rejection::InvalidState));
    let event = decode(&fixture("sent", 11), &request()).unwrap();
    attempt.receipt(&event).unwrap();
    assert_eq!(attempt.state(), MessageState::Submitted);
    assert_eq!(
        attempt.accept_response(id(5)),
        Err(Rejection::MessageConflict)
    );
    let mut response_before_crash = accepted();
    assert_eq!(response_before_crash.state(), MessageState::Submitting);
    response_before_crash.response_lost().unwrap();
    assert_eq!(response_before_crash.state(), MessageState::Unknown);
    assert_eq!(
        response_before_crash.begin(&gate(), 10),
        Err(Rejection::InvalidState)
    );
}

#[test]
fn callback_before_response_cannot_guess_correlation_or_consume_event() {
    let mut attempt = begun();
    let event = decode(&fixture("delivered", 10), &request()).unwrap();
    assert_eq!(
        attempt.receipt(&event),
        Ok(ReceiptEffect::AwaitingCorrelation)
    );
    assert_eq!(attempt.state(), MessageState::Submitting);
    attempt.response_lost().unwrap();
    assert_eq!(
        attempt.receipt(&event),
        Ok(ReceiptEffect::AwaitingCorrelation)
    );
    attempt.accept_response(id(4)).unwrap();
    assert_eq!(attempt.receipt(&event), Ok(ReceiptEffect::Applied));
    assert_eq!(attempt.state(), MessageState::Delivered);
}

#[test]
fn callback_binding_rejects_wrong_account_profile_sender_recipient_and_message() {
    for field in ["organization_id", "messaging_profile_id"] {
        let mut value = fixture("sent", 10);
        value["data"]["payload"][field] = json!(id(99));
        assert_eq!(
            decode(&value, &request()).err(),
            Some(Rejection::RouteMismatch)
        );
    }
    let mut value = fixture("sent", 10);
    value["data"]["payload"]["from"]["phone_number"] = json!(RECIPIENT);
    assert_eq!(
        decode(&value, &request()).err(),
        Some(Rejection::RouteMismatch)
    );
    value = fixture("sent", 10);
    value["data"]["payload"]["to"][0]["phone_number"] = json!(SENDER);
    assert_eq!(
        decode(&value, &request()).err(),
        Some(Rejection::RouteMismatch)
    );
    let other = Request::new(
        Route::telnyx(id(99), id(2), id(3), SENDER, 1).unwrap(),
        RECIPIENT,
        Content::ProviderPlaintext("synthetic fixture"),
    )
    .unwrap();
    let mut attempt = accepted();
    let event = decode(&fixture("sent", 10), &other).unwrap();
    assert_eq!(attempt.receipt(&event), Err(Rejection::RouteMismatch));
    value = fixture("sent", 10);
    value["data"]["payload"]["id"] = json!(id(99));
    assert_eq!(
        attempt.receipt(&decode(&value, &request()).unwrap()),
        Err(Rejection::MessageConflict)
    );
    assert_eq!(attempt.state(), MessageState::Submitting);
}

#[test]
fn signature_authenticates_original_bytes_key_and_timestamp() {
    let body = serde_json::to_vec(&fixture("sent", 10)).unwrap();
    let signature = signed(&body, "1000");
    assert!(verify(&body, "1000", &signature, 1000, &request()).is_ok());
    let mut changed = body.clone();
    changed.push(b' ');
    assert_eq!(
        verify(&changed, "1000", &signature, 1000, &request()).err(),
        Some(Rejection::InvalidSignature)
    );
    assert_eq!(
        verify(&body, "1001", &signature, 1000, &request()).err(),
        Some(Rejection::InvalidSignature)
    );
    assert!(verify_receipt(&request(), &[0; 32], "1000", &signature, &body, 1000).is_err());
    assert!(verify(&body, "1000", &"!".repeat(88), 1000, &request()).is_err());
    for timestamp in [
        "",
        "0",
        "01000",
        " 1000",
        "+1000",
        "-1",
        "1000.0",
        "9999999999999999999",
    ] {
        assert_eq!(
            verify(&body, timestamp, &signature, 1000, &request()).err(),
            Some(Rejection::InvalidTimestamp)
        );
    }
    for (timestamp, current) in [("1000", 1301), ("1301", 1000), ("1000", u64::MAX)] {
        assert_eq!(
            verify(
                &body,
                timestamp,
                &signed(&body, timestamp),
                current,
                &request()
            )
            .err(),
            Some(Rejection::InvalidTimestamp)
        );
    }
}

#[test]
fn malformed_oversized_duplicate_fields_and_non_sms_are_rejected() {
    for body in [
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"invalid".to_vec(),
        vec![b'x'; 32769],
    ] {
        assert_eq!(
            verify(&body, "1000", &signed(&body, "1000"), 1000, &request()).err(),
            Some(Rejection::InvalidCallback)
        );
    }
    for (field, value) in [("direction", "inbound"), ("type", "MMS")] {
        let mut event = fixture("sent", 10);
        event["data"]["payload"][field] = json!(value);
        assert_eq!(
            decode(&event, &request()).err(),
            Some(Rejection::InvalidCallback)
        );
    }
    for recipients in [
        json!([]),
        json!([{"phone_number":RECIPIENT,"status":"sent"},{"phone_number":RECIPIENT,"status":"sent"}]),
    ] {
        let mut value = fixture("sent", 10);
        value["data"]["payload"]["to"] = recipients;
        assert_eq!(
            decode(&value, &request()).err(),
            Some(Rejection::InvalidCallback)
        );
    }
    let valid = serde_json::to_string(&fixture("sent", 10)).unwrap();
    let duplicate = valid.replace(
        "\"record_type\":\"event\"",
        "\"record_type\":\"event\",\"record_type\":\"event\"",
    );
    assert_ne!(valid, duplicate);
    assert_eq!(
        verify(
            duplicate.as_bytes(),
            "1000",
            &signed(duplicate.as_bytes(), "1000"),
            1000,
            &request()
        )
        .err(),
        Some(Rejection::InvalidCallback)
    );
}

#[test]
fn event_identity_deduplicates_retries_but_not_message_statuses() {
    let mut attempt = accepted();
    let first = fixture("sent", 10);
    assert_eq!(
        attempt.receipt(&decode(&first, &request()).unwrap()),
        Ok(ReceiptEffect::Applied)
    );
    let mut retry = first.clone();
    retry["meta"]["attempt"] = json!(2);
    assert_eq!(
        attempt.receipt(&decode(&retry, &request()).unwrap()),
        Ok(ReceiptEffect::Duplicate)
    );
    assert_eq!(
        attempt.receipt(&decode(&fixture("delivered", 10), &request()).unwrap()),
        Err(Rejection::EventConflict)
    );
    assert_eq!(attempt.state(), MessageState::Submitted);
    assert_eq!(
        attempt.receipt(&decode(&fixture("delivered", 11), &request()).unwrap()),
        Ok(ReceiptEffect::Applied)
    );
    assert_eq!(attempt.state(), MessageState::Delivered);
}

#[test]
fn out_of_order_delivery_facts_cannot_erase_delivered() {
    let mut attempt = accepted();
    attempt
        .receipt(&decode(&fixture("delivered", 10), &request()).unwrap())
        .unwrap();
    for (index, status) in ["sent", "delivery_unconfirmed", "future_provider_status"]
        .iter()
        .enumerate()
    {
        attempt
            .receipt(&decode(&fixture(status, 11 + index as u128), &request()).unwrap())
            .unwrap();
        assert_eq!(attempt.state(), MessageState::Delivered);
    }
    for (index, status) in ["sending_failed", "delivery_failed"].iter().enumerate() {
        assert_eq!(
            attempt.receipt(&decode(&fixture(status, 20 + index as u128), &request()).unwrap()),
            Err(Rejection::EvidenceConflict)
        );
        assert_eq!(attempt.state(), MessageState::Delivered);
    }
    assert_eq!(attempt.begin(&gate(), 10), Err(Rejection::InvalidState));
}

#[test]
fn missing_delivery_evidence_is_separate_from_unknown_submission() {
    let mut attempt = accepted();
    attempt
        .receipt(&decode(&fixture("delivery_unconfirmed", 10), &request()).unwrap())
        .unwrap();
    assert_eq!(attempt.state(), MessageState::DeliveryUnknown);
    assert!(attempt.provider_accepted());
    attempt
        .receipt(&decode(&fixture("delivered", 11), &request()).unwrap())
        .unwrap();
    assert_eq!(attempt.state(), MessageState::Delivered);
    let mut failed = accepted();
    failed
        .receipt(&decode(&fixture("delivery_failed", 10), &request()).unwrap())
        .unwrap();
    assert_eq!(failed.state(), MessageState::Submitted);
    assert!(failed.delivery_failed());
    assert_eq!(
        failed.receipt(&decode(&fixture("delivered", 11), &request()).unwrap()),
        Err(Rejection::EvidenceConflict)
    );
    assert!(failed.delivery_failed());
}

#[test]
fn provider_send_failure_and_unknown_status_never_enable_retry() {
    let mut attempt = accepted();
    attempt
        .receipt(&decode(&fixture("future_provider_status", 10), &request()).unwrap())
        .unwrap();
    assert_eq!(attempt.state(), MessageState::Submitting);
    attempt
        .receipt(&decode(&fixture("sending_failed", 11), &request()).unwrap())
        .unwrap();
    assert_eq!(attempt.state(), MessageState::Failed);
    assert_eq!(attempt.begin(&gate(), 10), Err(Rejection::InvalidState));
    assert_eq!(
        attempt.receipt(&decode(&fixture("sent", 12), &request()).unwrap()),
        Err(Rejection::EvidenceConflict)
    );
    assert_eq!(attempt.state(), MessageState::Failed);
}

#[test]
fn receipt_capacity_fails_closed_without_evicting_replay_identity() {
    let mut attempt = accepted();
    for event in 100..100 + MAX_EVENTS as u128 {
        attempt
            .receipt(&decode(&fixture("sent", event), &request()).unwrap())
            .unwrap();
    }
    assert_eq!(
        attempt.receipt(&decode(&fixture("delivered", 1000), &request()).unwrap()),
        Err(Rejection::EventCapacity)
    );
    assert_eq!(attempt.state(), MessageState::Submitted);
    assert_eq!(
        attempt.receipt(&decode(&fixture("sent", 100), &request()).unwrap()),
        Ok(ReceiptEffect::Duplicate)
    );
}

#[test]
fn independent_node_signature_accepts_the_documented_raw_body_transcript() {
    let vector: Value = serde_json::from_str(include_str!("telnyx-vector.json")).unwrap();
    let public_key: [u8; 32] = STANDARD
        .decode(vector["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let body = vector["body"].as_str().unwrap();
    let timestamp = vector["timestamp"].as_str().unwrap();
    let signature = vector["signature"].as_str().unwrap();
    let event = verify_receipt(
        &request(),
        &public_key,
        timestamp,
        signature,
        body.as_bytes(),
        1000,
    )
    .unwrap();
    let mut attempt = accepted();
    attempt.receipt(&event).unwrap();
    assert_eq!(attempt.state(), MessageState::Delivered);
    let compact = serde_json::to_vec(&serde_json::from_str::<Value>(body).unwrap()).unwrap();
    assert_eq!(
        verify_receipt(
            &request(),
            &public_key,
            timestamp,
            signature,
            &compact,
            1000
        )
        .err(),
        Some(Rejection::InvalidSignature)
    );
}
