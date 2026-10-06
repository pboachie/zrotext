// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::provider_sms::Route;
use serde_json::Value;
use uuid::Uuid;

const SENDER: &str = "+15550000100";
const RECIPIENT: &str = "+15550000101";
const TEXT: &str = "Synthetic SMS";

fn route() -> Route {
    Route::telnyx(
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        SENDER,
        1,
    )
    .unwrap()
}

fn request(text: &str) -> Request {
    Request::new(route(), RECIPIENT, Content::ProviderPlaintext(text)).unwrap()
}

fn bytes(text: &str) -> EncodedBody {
    encode(&request(text), RECIPIENT, Content::ProviderPlaintext(text)).unwrap()
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn ascii_has_exact_six_field_wire_bytes() {
    assert_eq!(
        bytes(TEXT).as_bytes(),
        br#"{"from":"+15550000100","messaging_profile_id":"00000000-0000-0000-0000-000000000003","to":"+15550000101","text":"Synthetic SMS","type":"SMS","encoding":"ucs2"}"#
    );
}

#[test]
fn independent_vectors_match_retained_digest_and_complete_wire() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/provider-submit-body-codec.json"
    ))
    .unwrap();
    for case in vectors["positive"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let retained = request(text);
        assert_eq!(
            retained.digest().as_slice(),
            unhex(case["request_digest_hex"].as_str().unwrap())
        );
        assert_eq!(
            retained.recipient.as_slice(),
            unhex(case["recipient_hash_hex"].as_str().unwrap())
        );
        assert_eq!(
            encode(&retained, RECIPIENT, Content::ProviderPlaintext(text))
                .unwrap()
                .as_bytes(),
            unhex(case["wire_utf8_hex"].as_str().unwrap())
        );
    }
    assert_eq!(vectors["positive"].as_array().unwrap().len(), 4);
}

#[test]
fn bmp_omega_stays_utf8_without_substitution() {
    assert_eq!(
        bytes("Synthetic Ω").as_bytes(),
        "{\"from\":\"+15550000100\",\"messaging_profile_id\":\"00000000-0000-0000-0000-000000000003\",\"to\":\"+15550000101\",\"text\":\"Synthetic Ω\",\"type\":\"SMS\",\"encoding\":\"ucs2\"}".as_bytes()
    );
}

#[test]
fn json_escapes_preserve_control_quote_and_slash_content() {
    let body = bytes("Synthetic \"quote\"\\ \n\t\0");
    let decoded: Value = serde_json::from_slice(body.as_bytes()).unwrap();
    assert_eq!(decoded["text"], "Synthetic \"quote\"\\ \n\t\0");
    assert!(body.as_bytes().windows(6).any(|part| part == b"\\u0000"));
    assert!(!body.as_bytes().contains(&0));
}

#[test]
fn upper_bmp_scalar_is_accepted_but_supplementary_is_refused() {
    let decoded: Value = serde_json::from_slice(bytes("\u{ffff}").as_bytes()).unwrap();
    assert_eq!(decoded["text"], "\u{ffff}");
    assert!(matches!(
        encode(
            &request("\u{10000}"),
            RECIPIENT,
            Content::ProviderPlaintext("\u{10000}")
        ),
        Err(CodecError::UnsupportedText)
    ));
}

#[test]
fn ascii_byte_and_ucs2_unit_limits_are_inclusive() {
    let text = "x".repeat(4096);
    let decoded: Value = serde_json::from_slice(bytes(&text).as_bytes()).unwrap();
    assert_eq!(decoded["text"].as_str().unwrap().len(), 4096);
    assert!(bytes(&text).as_bytes().len() <= MAX_BODY_BYTES);
    assert!(matches!(
        encode(
            &request(TEXT),
            RECIPIENT,
            Content::ProviderPlaintext(&"x".repeat(4097))
        ),
        Err(CodecError::InvalidInput)
    ));
}

#[test]
fn multibyte_text_limit_counts_utf8_bytes_not_characters() {
    let text = "Ω".repeat(2048);
    assert_eq!(text.len(), 4096);
    assert_eq!(text.chars().count(), 2048);
    assert!(bytes(&text).as_bytes().len() <= MAX_BODY_BYTES);
    assert!(matches!(
        encode(
            &request(TEXT),
            RECIPIENT,
            Content::ProviderPlaintext(&"Ω".repeat(2049))
        ),
        Err(CodecError::InvalidInput)
    ));
}

#[test]
fn maximum_json_expansion_stays_within_independent_bound() {
    let body = bytes(&"\0".repeat(4096));
    let decoded: Value = serde_json::from_slice(body.as_bytes()).unwrap();
    assert_eq!(decoded["text"].as_str().unwrap().len(), 4096);
    // Six output bytes per escaped input byte, plus independently bounded fixed fields.
    let maximum_for_text = 6 * decoded["text"].as_str().unwrap().len() + 256;
    assert!(body.as_bytes().len() <= maximum_for_text);
    assert!(maximum_for_text < MAX_BODY_BYTES);
}

#[test]
fn empty_text_is_refused_without_a_body() {
    assert!(matches!(
        encode(&request(TEXT), RECIPIENT, Content::ProviderPlaintext("")),
        Err(CodecError::InvalidInput)
    ));
}

#[test]
fn sealed_bytes_never_become_provider_plaintext() {
    assert!(matches!(
        encode(
            &request(TEXT),
            RECIPIENT,
            Content::SealedPhoneEnvelope(b"synthetic sealed")
        ),
        Err(CodecError::SealedContent)
    ));
}

#[test]
fn changed_recipient_is_an_exact_request_conflict() {
    assert!(matches!(
        encode(
            &request(TEXT),
            "+15550000102",
            Content::ProviderPlaintext(TEXT)
        ),
        Err(CodecError::RequestConflict)
    ));
}

#[test]
fn changed_text_is_an_exact_request_conflict() {
    assert!(matches!(
        encode(
            &request(TEXT),
            RECIPIENT,
            Content::ProviderPlaintext("Synthetic other")
        ),
        Err(CodecError::RequestConflict)
    ));
}

#[test]
fn stored_digest_and_recipient_hash_corruption_are_refused() {
    let mut retained = request(TEXT);
    retained.digest[0] ^= 1;
    assert!(matches!(
        encode(&retained, RECIPIENT, Content::ProviderPlaintext(TEXT)),
        Err(CodecError::RequestConflict)
    ));
    let mut retained = request(TEXT);
    retained.recipient[0] ^= 1;
    assert!(matches!(
        encode(&retained, RECIPIENT, Content::ProviderPlaintext(TEXT)),
        Err(CodecError::RequestConflict)
    ));
}

#[test]
fn each_stored_route_component_is_bound_by_original_digest() {
    // Private-field corruption models inconsistent retained identity, not a new caller setter.
    let original = request(TEXT);
    for changed in 0..5 {
        let mut retained = original.clone();
        match changed {
            0 => retained.route.account = Uuid::from_u128(99),
            1 => retained.route.organization = Uuid::from_u128(99),
            2 => retained.route.profile = Uuid::from_u128(99),
            3 => retained.route.revision = 2,
            _ => retained.route.sender = "+15550000102".into(),
        }
        assert!(matches!(
            encode(&retained, RECIPIENT, Content::ProviderPlaintext(TEXT)),
            Err(CodecError::RequestConflict)
        ));
    }
}

#[test]
fn existing_e164_lower_and_upper_lengths_are_preserved() {
    for phone in ["+12", "+155500001001234"] {
        let fixed = Route::telnyx(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            phone,
            1,
        )
        .unwrap();
        let expected = Request::new(fixed, phone, Content::ProviderPlaintext(TEXT)).unwrap();
        let body = encode(&expected, phone, Content::ProviderPlaintext(TEXT)).unwrap();
        let decoded: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        assert_eq!(decoded["from"], phone);
        assert_eq!(decoded["to"], phone);
    }
}

#[test]
fn malformed_and_unicode_recipient_forms_are_refused() {
    for phone in [
        "+1",
        "+012",
        "15550000101",
        "+1555000010012345",
        "+1 555",
        "+１２",
    ] {
        assert!(matches!(
            encode(&request(TEXT), phone, Content::ProviderPlaintext(TEXT)),
            Err(CodecError::InvalidInput)
        ));
    }
}

#[test]
fn invalid_sender_profile_and_revision_cannot_construct_a_route() {
    for sender in ["+1", "+012", "+1 555", "+１２"] {
        assert!(
            Route::telnyx(
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                Uuid::from_u128(3),
                sender,
                1
            )
            .is_err()
        );
    }
    assert!(
        Route::telnyx(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::nil(),
            SENDER,
            1
        )
        .is_err()
    );
    assert!(
        Route::telnyx(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            SENDER,
            0
        )
        .is_err()
    );
    // Even self-consistent retained hashes do not bypass route shape checks.
    // These private-field fixtures model corrupted storage, not a public route factory.
    for changed in 0..5 {
        let mut stored = route();
        match changed {
            0 => stored.account = Uuid::nil(),
            1 => stored.organization = Uuid::nil(),
            2 => stored.profile = Uuid::nil(),
            3 => stored.revision = 0,
            _ => stored.sender = "+012".into(),
        }
        let retained = Request::new(stored, RECIPIENT, Content::ProviderPlaintext(TEXT)).unwrap();
        assert!(matches!(
            encode(&retained, RECIPIENT, Content::ProviderPlaintext(TEXT)),
            Err(CodecError::InvalidInput)
        ));
    }
}

#[test]
fn output_has_no_optional_authority_or_transport_fields() {
    let body: Value = serde_json::from_slice(bytes(TEXT).as_bytes()).unwrap();
    let object = body.as_object().unwrap();
    assert_eq!(object.len(), 6);
    for key in [
        "from",
        "messaging_profile_id",
        "to",
        "text",
        "type",
        "encoding",
    ] {
        assert!(object.contains_key(key));
    }
    assert_eq!(object["type"], "SMS");
    assert_eq!(object["encoding"], "ucs2");
    assert!(!object.contains_key("organization_id"));
    assert!(!object.contains_key("send_at"));
    assert!(!object.contains_key("webhook_url"));
}

#[test]
fn internal_writer_never_exceeds_cap_or_accepts_extra_byte() {
    let mut writer = BoundedWriter {
        bytes: Zeroizing::new(Vec::new()),
    };
    assert_eq!(
        writer.write(&[b'x'; MAX_BODY_BYTES]).unwrap(),
        MAX_BODY_BYTES
    );
    assert_eq!(
        writer.write(b"x").unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(writer.bytes.len(), MAX_BODY_BYTES);
}

#[test]
fn serializer_failure_is_generic_and_has_no_returned_payload() {
    struct Rejecting;
    impl Write for Rejecting {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let body = WireBody {
        from: SENDER,
        messaging_profile_id: "00000000-0000-0000-0000-000000000003",
        to: RECIPIENT,
        text: TEXT,
        message_type: "SMS",
        encoding: "ucs2",
    };
    assert_eq!(
        write_body(&mut Rejecting, &body),
        Err(CodecError::OutputFailure)
    );
    assert_eq!(format!("{:?}", CodecError::OutputFailure), "OutputFailure");
}

#[test]
fn representation_does_not_mutate_or_promote_retained_identity() {
    let expected = request(TEXT);
    let before = expected.clone();
    let first = encode(&expected, RECIPIENT, Content::ProviderPlaintext(TEXT)).unwrap();
    let second = encode(&expected, RECIPIENT, Content::ProviderPlaintext(TEXT)).unwrap();
    assert!(expected == before);
    assert_eq!(first.as_bytes(), second.as_bytes());
    // Equal bytes are representation equality only; this test has no grant, attempt or network.
}
