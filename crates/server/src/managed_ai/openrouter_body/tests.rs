// SPDX-License-Identifier: AGPL-3.0-only
// Pure synthetic controls. No provider, grant, region or task authority.
use super::*;
use serde_json::{json, Value};
use zeroize::Zeroize;

fn profile() -> UnverifiedOpenRouterProfile<'static> {
    UnverifiedOpenRouterProfile {
        model: "synthetic/model-alpha",
        requested_provider: "synthetic-provider",
        max_completion_tokens: 17,
    }
}

fn value(body: &UnverifiedOpenRouterBody) -> Value {
    serde_json::from_slice(body.as_bytes()).expect("synthetic JSON")
}

fn expect_error(result: Result<UnverifiedOpenRouterBody, EncodeError>, expected: EncodeError) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("expected static refusal"),
    }
}

#[test]
fn exact_literal_bytes_have_closed_fields_and_requested_restrictions() {
    let body = encode_unverified_body(profile(), b"Summarize synthetic text.", b"Aster blooms.")
        .expect("synthetic body");
    let expected = br#"{"model":"synthetic/model-alpha","messages":[{"role":"system","content":"Summarize synthetic text."},{"role":"user","content":"Aster blooms."}],"max_completion_tokens":17,"stream":false,"provider":{"only":["synthetic-provider"],"allow_fallbacks":false,"require_parameters":true,"data_collection":"deny","zdr":true}}"#;
    assert_eq!(body.as_bytes(), expected);
    let parsed = value(&body);
    assert_eq!(parsed.as_object().unwrap().len(), 5);
    assert_eq!(parsed["provider"].as_object().unwrap().len(), 5);
    assert_eq!(parsed["messages"].as_array().unwrap().len(), 2);
    for message in parsed["messages"].as_array().unwrap() {
        assert_eq!(message.as_object().unwrap().len(), 2);
    }
    assert_eq!(parsed["messages"][0]["role"], "system");
    assert_eq!(parsed["messages"][1]["role"], "user");
    assert_eq!(parsed["provider"]["only"], json!(["synthetic-provider"]));
    assert_eq!(parsed["provider"]["allow_fallbacks"], false);
    assert_eq!(parsed["provider"]["require_parameters"], true);
    assert_eq!(parsed["provider"]["data_collection"], "deny");
    assert_eq!(parsed["provider"]["zdr"], true);
    assert_eq!(parsed["stream"], false);
}

#[test]
fn control_quotes_backslashes_and_multibyte_text_preserve_values() {
    let instructions = "\0\u{1}\n\r\t\"\\";
    let selected = "λ雪🙂";
    let body = encode_unverified_body(profile(), instructions.as_bytes(), selected.as_bytes())
        .expect("synthetic escaped body");
    let parsed = value(&body);
    assert_eq!(parsed["messages"][0]["content"], instructions);
    assert_eq!(parsed["messages"][1]["content"], selected);
    assert!(body.as_bytes().windows(6).any(|bytes| bytes == b"\\u0000"));
    assert!(!body.as_bytes().contains(&0));
    assert!(!body.as_bytes().contains(&1));
}

#[test]
fn json_like_text_cannot_add_fields_or_change_privacy() {
    let attack = br#""}],"stream":true,"provider":{"zdr":false},"messages":[{"content":""#;
    let body = encode_unverified_body(profile(), b"Synthetic instructions.", attack)
        .expect("text is data");
    let parsed = value(&body);
    assert_eq!(parsed.as_object().unwrap().len(), 5);
    assert_eq!(
        parsed["messages"][1]["content"],
        std::str::from_utf8(attack).unwrap()
    );
    assert_eq!(parsed["stream"], false);
    assert_eq!(parsed["provider"]["zdr"], true);
    assert_eq!(parsed["provider"].as_object().unwrap().len(), 5);
}

#[test]
fn each_supplied_field_changes_only_its_data_location() {
    let baseline =
        value(&encode_unverified_body(profile(), b"Instructions.", b"Selection.").unwrap());
    let cases = [
        ("model", "synthetic/model-beta", "synthetic-provider", 17),
        ("provider", "synthetic/model-alpha", "synthetic-other", 17),
        ("tokens", "synthetic/model-alpha", "synthetic-provider", 18),
    ];
    for (field, model, requested_provider, max_completion_tokens) in cases {
        let supplied = UnverifiedOpenRouterProfile {
            model,
            requested_provider,
            max_completion_tokens,
        };
        let mut actual =
            value(&encode_unverified_body(supplied, b"Instructions.", b"Selection.").unwrap());
        match field {
            "model" => {
                assert_eq!(actual["model"], model);
                actual["model"] = baseline["model"].clone();
            }
            "provider" => {
                assert_eq!(actual["provider"]["only"], json!([requested_provider]));
                actual["provider"]["only"] = baseline["provider"]["only"].clone();
            }
            _ => {
                assert_eq!(actual["max_completion_tokens"], max_completion_tokens);
                actual["max_completion_tokens"] = baseline["max_completion_tokens"].clone();
            }
        }
        assert_eq!(actual, baseline);
    }
    for (instructions, selected, index) in [
        (
            b"Other instructions.".as_slice(),
            b"Selection.".as_slice(),
            0,
        ),
        (
            b"Instructions.".as_slice(),
            b"Other selection.".as_slice(),
            1,
        ),
    ] {
        let mut actual = value(&encode_unverified_body(profile(), instructions, selected).unwrap());
        let expected_text = if index == 0 { instructions } else { selected };
        assert_eq!(
            actual["messages"][index]["content"],
            std::str::from_utf8(expected_text).unwrap()
        );
        actual["messages"][index]["content"] = baseline["messages"][index]["content"].clone();
        assert_eq!(actual, baseline);
    }
}

#[test]
fn malformed_utf8_in_either_buffer_refuses() {
    for bad in [
        &[0xff][..],
        &[0xc0, 0xaf][..],
        &[0xe2, 0x82][..],
        &[0xed, 0xa0, 0x80][..],
    ] {
        expect_error(
            encode_unverified_body(profile(), bad, b"Text."),
            EncodeError::InvalidUtf8,
        );
        expect_error(
            encode_unverified_body(profile(), b"Instructions.", bad),
            EncodeError::InvalidUtf8,
        );
    }
}

#[test]
fn empty_text_refuses_without_returning_a_partial_body() {
    for (instructions, selected) in [
        (b"".as_slice(), b"text".as_slice()),
        (b"instructions".as_slice(), b"".as_slice()),
        (b"".as_slice(), b"".as_slice()),
    ] {
        expect_error(
            encode_unverified_body(profile(), instructions, selected),
            EncodeError::EmptyInput,
        );
    }
}

#[test]
fn lexical_slug_refusals_apply_to_both_profile_locations() {
    let invalid = [
        "",
        "/model",
        "model/",
        "model//part",
        "model name",
        "model\n",
        "model\0",
        "model\\name",
        "model\"name",
        "model:*",
        "model@hint",
        "mødel",
    ];
    for slug in invalid {
        let model = UnverifiedOpenRouterProfile {
            model: slug,
            ..profile()
        };
        expect_error(
            encode_unverified_body(model, b"I", b"S"),
            EncodeError::InvalidProfile,
        );
        let provider = UnverifiedOpenRouterProfile {
            requested_provider: slug,
            ..profile()
        };
        expect_error(
            encode_unverified_body(provider, b"I", b"S"),
            EncodeError::InvalidProfile,
        );
    }
}

#[test]
fn lexical_profile_ceiling_does_not_choose_an_approved_model() {
    let exact = "x".repeat(128);
    let longer = "x".repeat(129);
    let supplied = UnverifiedOpenRouterProfile {
        model: &exact,
        requested_provider: &exact,
        max_completion_tokens: 1,
    };
    let body = encode_unverified_body(supplied, b"I", b"S").unwrap();
    assert_eq!(value(&body)["model"], exact);
    for model_too_long in [false, true] {
        let supplied = UnverifiedOpenRouterProfile {
            model: if model_too_long { &longer } else { &exact },
            requested_provider: if model_too_long { &exact } else { &longer },
            max_completion_tokens: 1,
        };
        expect_error(
            encode_unverified_body(supplied, b"I", b"S"),
            EncodeError::InvalidProfile,
        );
    }
    let supplied = UnverifiedOpenRouterProfile {
        model: "synthetic/model_alias-1.2",
        requested_provider: "synthetic/provider_endpoint-1",
        ..profile()
    };
    assert!(encode_unverified_body(supplied, b"I", b"S").is_ok());
}

#[test]
fn completion_token_ceiling_is_explicit_and_finite() {
    for tokens in [1, 65536] {
        let supplied = UnverifiedOpenRouterProfile {
            max_completion_tokens: tokens,
            ..profile()
        };
        assert_eq!(
            value(&encode_unverified_body(supplied, b"I", b"S").unwrap())
                ["max_completion_tokens"],
            tokens
        );
    }
    for tokens in [0, 65537, u32::MAX] {
        let supplied = UnverifiedOpenRouterProfile {
            max_completion_tokens: tokens,
            ..profile()
        };
        expect_error(
            encode_unverified_body(supplied, b"I", b"S"),
            EncodeError::InvalidTokenLimit,
        );
    }
}

#[test]
fn combined_raw_byte_cap_is_not_a_per_message_character_cap() {
    let instructions = vec![b'i'; 4096];
    let selection = vec![b's'; 4096];
    let body = encode_unverified_body(profile(), &instructions, &selection).unwrap();
    assert_eq!(
        value(&body)["messages"][1]["content"]
            .as_str()
            .unwrap()
            .len(),
        4096
    );
    let over = vec![b's'; 4097];
    expect_error(
        encode_unverified_body(profile(), &instructions, &over),
        EncodeError::InputTooLarge,
    );
    expect_error(
        encode_unverified_body(profile(), &over, &instructions),
        EncodeError::InputTooLarge,
    );
    let multibyte = "雪".repeat(2730);
    assert_eq!(multibyte.len(), 8190);
    assert!(encode_unverified_body(profile(), b"II", multibyte.as_bytes()).is_ok());
    expect_error(
        encode_unverified_body(profile(), b"III", multibyte.as_bytes()),
        EncodeError::InputTooLarge,
    );
}

#[test]
fn input_length_addition_overflow_refuses_independently() {
    assert_eq!(input_length(8191, 1), Ok(8192));
    assert_eq!(input_length(8192, 1), Err(EncodeError::InputTooLarge));
    assert_eq!(input_length(usize::MAX, 1), Err(EncodeError::InputTooLarge));
    assert_eq!(input_length(1, usize::MAX), Err(EncodeError::InputTooLarge));
}

#[test]
fn worst_escaping_and_max_profiles_stay_inside_body_ceiling() {
    let model = "m".repeat(128);
    let provider = "p".repeat(128);
    let supplied = UnverifiedOpenRouterProfile {
        model: &model,
        requested_provider: &provider,
        max_completion_tokens: 65536,
    };
    let instructions = vec![1; 4096];
    let selection = vec![2; 4096];
    let body = encode_unverified_body(supplied, &instructions, &selection).unwrap();
    assert!(body.as_bytes().len() <= 49920);
    assert!(body.as_bytes().len() <= MAX_BODY_BYTES);
    let parsed = value(&body);
    assert_eq!(
        parsed["messages"][0]["content"].as_str().unwrap().as_bytes(),
        instructions
    );
    assert_eq!(
        parsed["messages"][1]["content"].as_str().unwrap().as_bytes(),
        selection
    );
}

#[test]
fn writer_accepts_exact_cap_then_refuses_without_growth_or_partial_write() {
    let mut writer = BoundedWriter::new().unwrap();
    let capacity = writer.bytes.capacity();
    assert!(capacity >= MAX_BODY_BYTES);
    let first = vec![b'x'; MAX_BODY_BYTES - 1];
    writer.write_all(&first).unwrap();
    let error = writer.write(b"yz").expect_err("no partial last byte");
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(writer.bytes.len(), MAX_BODY_BYTES - 1);
    assert_eq!(writer.bytes.capacity(), capacity);
    writer.write_all(b"z").unwrap();
    assert_eq!(writer.bytes.len(), MAX_BODY_BYTES);
    assert_eq!(
        writer.write(b"!").unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(writer.bytes.len(), MAX_BODY_BYTES);
    assert_eq!(writer.bytes.capacity(), capacity);
    assert!(writer.exceeded);
    assert_eq!(writer.bytes[MAX_BODY_BYTES - 1], b'z');
    writer.flush().unwrap();
}

#[test]
fn writer_refuses_oversized_first_write_without_copying() {
    let mut writer = BoundedWriter::new().unwrap();
    let capacity = writer.bytes.capacity();
    let oversized = vec![b'x'; MAX_BODY_BYTES + 1];
    assert!(writer.write_all(&oversized).is_err());
    assert!(writer.bytes.is_empty());
    assert!(writer.exceeded);
    assert_eq!(writer.bytes.capacity(), capacity);
}

#[test]
fn explicit_clear_inspects_only_a_live_synthetic_allocation() {
    let mut body = encode_unverified_body(
        profile(),
        b"Synthetic instructions.",
        b"Synthetic selection.",
    )
    .unwrap();
    let before_len = body.bytes.len();
    let before_capacity = body.bytes.capacity();
    assert!(body.bytes.iter().any(|byte| *byte != 0));
    body.bytes.as_mut_slice().zeroize();
    assert_eq!(body.bytes.len(), before_len);
    assert_eq!(body.bytes.capacity(), before_capacity);
    assert!(body.bytes.iter().all(|byte| *byte == 0));
    // This does not inspect freed memory or prove crash/OS/caller cleanup.
}

#[test]
fn errors_do_not_echo_supplied_sensitive_like_data() {
    let supplied = UnverifiedOpenRouterProfile {
        model: "synthetic secret model",
        ..profile()
    };
    match encode_unverified_body(
        supplied,
        b"Synthetic private instructions.",
        b"Synthetic private text.",
    ) {
        Err(error) => {
            assert_eq!(
                error.to_string(),
                "invalid unverified model or provider slug"
            );
            assert_eq!(format!("{error:?}"), "InvalidProfile");
        }
        Ok(_) => panic!("expected static refusal"),
    }
}
