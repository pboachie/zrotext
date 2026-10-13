use serde_json::Value;
use zrotext_body_text::validate;
#[test]
fn every_shared_candidate_body_text_vector_matches() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../protocol/v1/vectors/ztse-body-text-01.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(vector["status"], "UNAPPROVED_TEST_ONLY");
    let cases = vector["textCases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let hex = case["hex"].as_str().unwrap();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let actual = validate(&bytes);
        if case["verdict"] == "accept" {
            let text = actual.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
            assert_eq!(text.as_bytes(), bytes);
            if let Some(expected) = case["text"].as_str() {
                assert_eq!(text, expected);
            }
            if let Some(length) = case["textLength"].as_u64() {
                assert_eq!(text.len() as u64, length);
            }
        } else {
            assert_eq!(
                actual.unwrap_err().to_string(),
                case["reason"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
#[test]
fn normalization_is_never_applied_and_multibyte_bounds_count_bytes() {
    for bytes in [b"e\xcc\x81".as_slice(), b"\xc3\xa9".as_slice()] {
        assert_eq!(validate(bytes).unwrap().as_bytes(), bytes);
    }
    assert!(validate(&"\u{e9}".repeat(16_384).into_bytes()).is_ok());
    assert!(validate(&"\u{e9}".repeat(16_385).into_bytes()).is_err());
}
