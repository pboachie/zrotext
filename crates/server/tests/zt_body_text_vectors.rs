// SPDX-License-Identifier: AGPL-3.0-only
//! Cross-client ZT-009 Q9 vector for the strict body-text receive rules.
//!
//! The shared public fixture in `protocol/v1/vectors` carries plaintext body
//! corpus cases and independently signed sealed envelopes whose bodies were
//! encrypted with a fixed synthetic CEK. The Rust receiver must verify each
//! envelope against its fixture context, then open the body and reach the
//! same accept/reject verdicts as the TypeScript, Android and Python suites.
//! Test-only material; no production route may accept any of these bytes.

use serde_json::Value;
use zrotext_server::sealed_body::{
    BodyOpenError, BodyTextError, MAX_BODY_TEXT_BYTES, open, validate_body_text,
};
use zrotext_server::sealed_envelope::{ExpectedContext, ExpectedRecipient, Kind, Profile, verify};

const VECTOR: &str = include_str!("../../../protocol/v1/vectors/ztse-body-text-01.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("committed body text vector")
}

fn hex_field(value: &Value, name: &str) -> Vec<u8> {
    let text = value[name].as_str().expect("hex field");
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

fn text_error(reason: &str) -> BodyTextError {
    match reason {
        "length" => BodyTextError::Length,
        "nul" => BodyTextError::Nul,
        "bom" => BodyTextError::Bom,
        "utf8" => BodyTextError::Utf8,
        other => panic!("unknown fixture reason {other}"),
    }
}

#[test]
fn shared_text_cases_match_the_rust_receive_rules() {
    let vector = vector();
    assert_eq!(vector["status"], "UNAPPROVED_TEST_ONLY");
    assert_eq!(vector["maxBodyTextBytes"], MAX_BODY_TEXT_BYTES as u64);
    for case in vector["textCases"].as_array().expect("text cases") {
        let name = case["name"].as_str().expect("case name");
        let bytes = hex_field(case, "hex");
        match case["verdict"].as_str().expect("case verdict") {
            "accept" => {
                let text = validate_body_text(&bytes)
                    .unwrap_or_else(|error| panic!("case {name} must open: {error}"));
                if let Some(expected) = case.get("text").and_then(Value::as_str) {
                    assert_eq!(text, expected, "case {name} decoded text");
                }
                if let Some(expected) = case.get("textLength").and_then(Value::as_u64) {
                    assert_eq!(text.len() as u64, expected, "case {name} decoded length");
                }
            }
            "reject" => {
                let reason = case["reason"].as_str().expect("case reason");
                assert_eq!(
                    validate_body_text(&bytes),
                    Err(text_error(reason)),
                    "case {name} must fail closed with the stable reason"
                );
            }
            other => panic!("unknown fixture verdict {other}"),
        }
    }
}

#[test]
fn authenticated_envelopes_verify_then_open_with_expected_verdicts() {
    let vector = vector();
    for case in vector["authenticatedCases"]
        .as_array()
        .expect("authenticated cases")
    {
        let name = case["name"].as_str().expect("case name");
        let envelope_bytes = hex_field(case, "envelopeHex");
        let context = &case["context"];
        let mut account = [0_u8; 16];
        account.copy_from_slice(&hex_field(context, "accountIdHex"));
        let mut device = [0_u8; 16];
        device.copy_from_slice(&hex_field(context, "deviceIdHex"));
        let mut line = [0_u8; 16];
        line.copy_from_slice(&hex_field(context, "lineIdHex"));
        let mut message = [0_u8; 16];
        message.copy_from_slice(&hex_field(context, "messageIdHex"));
        let mut manifest_digest = [0_u8; 32];
        manifest_digest.copy_from_slice(&hex_field(context, "manifestDigestHex"));
        let signer_point = hex_field(context, "signerPublicPointHex");
        let recipients: Vec<ExpectedRecipient> = context["recipients"]
            .as_array()
            .expect("context recipients")
            .iter()
            .map(|entry| {
                let mut key_id = [0_u8; 32];
                key_id.copy_from_slice(&hex_field(entry, "keyIdHex"));
                ExpectedRecipient {
                    role: entry["role"].as_u64().expect("role") as u8,
                    key_id,
                }
            })
            .collect();
        let expected = ExpectedContext {
            profile: match case["profile"].as_u64().expect("profile") {
                1 => Profile::Draft01Proof,
                2 => Profile::Draft02Candidate,
                other => panic!("unknown fixture profile {other}"),
            },
            kind: match case["kind"].as_u64().expect("kind") {
                1 => Kind::Outbound,
                2 => Kind::Inbound,
                other => panic!("unknown fixture kind {other}"),
            },
            account_id: account,
            message_id: message,
            device_id: device,
            line_id: line,
            keyset_version: context["keysetVersion"].as_u64().expect("keyset version"),
            manifest_digest,
            peer: context["peer"].as_str().expect("peer").as_bytes(),
            signer_public_point: &signer_point,
            recipients: &recipients,
        };
        let verified = verify(&envelope_bytes, &expected)
            .unwrap_or_else(|error| panic!("case {name} must verify: {error}"));
        let mut cek = [0_u8; 32];
        cek.copy_from_slice(&hex_field(case, "cekHex"));
        match case["verdict"].as_str().expect("case verdict") {
            "accept" => {
                let text = open(&verified, cek)
                    .unwrap_or_else(|error| panic!("case {name} must open: {error}"));
                assert_eq!(
                    text.as_str(),
                    case["text"].as_str().expect("expected text"),
                    "case {name} opened text"
                );
            }
            "reject" => {
                let reason = case["reason"].as_str().expect("case reason");
                let error = open(&verified, cek)
                    .expect_err("case {name} must fail closed after authentication");
                let expected = match reason {
                    "authentication" => BodyOpenError::Authentication,
                    other => BodyOpenError::Text(text_error(other)),
                };
                assert_eq!(error, expected, "case {name} stable rejection");
            }
            other => panic!("unknown fixture verdict {other}"),
        }
    }
}
