// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::context::decisions::Descriptor as LegacyDescriptor,
    workflow_runtime::contracts::Request as WorkflowRequest,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/workflow-action-02-proposal.json"
    ))
    .unwrap()
}
fn raw(v: &Value, member: &str) -> Vec<u8> {
    v.get("raw")
        .or_else(|| v.get("canonical"))
        .and_then(Value::as_str)
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_else(|| canonical(&v[member]))
}
fn proposal(raw: &[u8]) -> Vec<u8> {
    let mut bytes = br#"{"descriptor":"#.to_vec();
    bytes.extend(raw);
    bytes.extend(br#","request_id":"00000000-0000-0000-0000-000000000001"}"#);
    bytes
}

#[test]
fn proposed_descriptor_and_complete_request_match_independent_canonical_vectors() {
    let vectors = vectors();
    let mut count = 0;
    for group in ["positives", "binding_mutations"] {
        for vector in vectors[group].as_array().unwrap() {
            let bytes = raw(vector, "descriptor");
            let parsed = ProposedDescriptor::parse_wire(&bytes).unwrap();
            assert_eq!(parsed.canonical_wire(), bytes);
            let digest: String = parsed
                .binding_digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(digest, vector["binding_digest"].as_str().unwrap());
            if group == "binding_mutations" {
                assert_ne!(
                    digest,
                    vectors["positives"][1]["binding_digest"].as_str().unwrap()
                );
            }
            assert_eq!(
                ProposedDescriptor::parse_owner_proposal_wire(&proposal(&bytes))
                    .unwrap()
                    .canonical_wire(),
                bytes
            );
            count += 1;
        }
    }
    assert_eq!(count, 37);
    assert_ne!(
        vectors["positives"][0]["binding_digest"],
        vectors["positives"][1]["binding_digest"]
    );
}

#[test]
fn original_wire_and_nested_request_refuse_normalized_aliases_and_invalid_fields() {
    let vectors = vectors();
    let mut count = 0;
    for group in ["negative_grammar", "negative_wire"] {
        for vector in vectors[group].as_array().unwrap() {
            let bytes = raw(vector, "input");
            assert!(ProposedDescriptor::parse_wire(&bytes).is_err());
            assert!(ProposedDescriptor::parse_owner_proposal_wire(&proposal(&bytes)).is_err());
            count += 1;
        }
    }
    assert_eq!(count, 24);
    let wire = vectors["positives"][0]["canonical"].as_str().unwrap();
    for bytes in [
        format!(
            r#"{},"\u0070rofile":"workflow-action-02"}}"#,
            &wire[..wire.len() - 1]
        ),
        wire.replacen("\"profile\":", r#""\u0070rofile":"#, 1),
    ] {
        assert!(ProposedDescriptor::parse_wire(bytes.as_bytes()).is_err());
        assert!(
            ProposedDescriptor::parse_owner_proposal_wire(&proposal(bytes.as_bytes())).is_err()
        );
        count += 1;
    }
    assert_eq!(count, 26);
}

#[test]
fn shared_final_newline_string_suffixes_refuse_standalone_and_nested_wire() {
    let vectors = vectors();
    let cases = vectors["negative_string_suffix"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    assert_eq!(
        vectors["string_suffixes"],
        serde_json::json!(["\n", "\r", "\r\n", "\t", "\u{2028}", "\u{2029}"])
    );
    let mut count = 0;
    for vector in cases {
        let section = vector["field"][0].as_str().unwrap();
        let field = vector["field"][1].as_str().unwrap();
        let original = vector["input"][section][field].as_str().unwrap();
        let base = original.strip_suffix('\n').unwrap();
        for suffix in vectors["string_suffixes"].as_array().unwrap() {
            let mut input = vector["input"].clone();
            input[section][field] = Value::String(format!("{base}{}", suffix.as_str().unwrap()));
            let bytes = String::from_utf8(canonical(&input))
                .unwrap()
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
                .into_bytes();
            assert!(ProposedDescriptor::parse_wire(&bytes).is_err());
            assert!(ProposedDescriptor::parse_owner_proposal_wire(&proposal(&bytes)).is_err());
            count += 1;
        }
    }
    assert_eq!(count, 36);
}

#[test]
fn whole_request_refuses_separator_whitespace_outer_aliases_duplicates_and_cap() {
    let vectors = vectors();
    let wire = vectors["positives"][0]["canonical"].as_str().unwrap();
    let outer = String::from_utf8(proposal(wire.as_bytes())).unwrap();
    for bytes in [
        format!(" {outer}"),
        outer.replacen("\"request_id\":", r#""\u0072equest_id":"#, 1),
        outer.replacen(
            "{\"descriptor\":",
            &format!("{{\"descriptor\":{wire},\"descriptor\":"),
            1,
        ),
        outer.replacen(
            "{\"descriptor\":",
            &format!(r#"{{"\u0064escriptor":{wire},"descriptor":"#),
            1,
        ),
        outer.replacen(
            "{\"descriptor\":",
            &format!("{{\"descriptor_alias\":{wire},\"descriptor\":"),
            1,
        ),
        outer.replacen(
            "\"request_id\":",
            "\"request_id\":\"00000000-0000-0000-0000-000000000002\",\"request_id\":",
            1,
        ),
        format!("{}{outer}", " ".repeat(8193 - outer.len())),
    ] {
        assert!(ProposedDescriptor::parse_owner_proposal_wire(bytes.as_bytes()).is_err());
    }
}

#[test]
fn actual_legacy_action_and_generic_workflow_tool_consumers_reject_proposed_profile() {
    let vectors = vectors();
    for vector in vectors["positives"].as_array().unwrap() {
        let bytes = raw(vector, "descriptor");
        assert!(serde_json::from_slice::<LegacyDescriptor>(&bytes).is_err());
        let request = serde_json::json!({
            "method":"workflow.action.propose",
            "params":{
                "request_id":"00000000-0000-0000-0000-000000000001",
                "descriptor":vector["descriptor"],
            }
        });
        assert!(serde_json::from_value::<WorkflowRequest>(request).is_err());
        let legacy_action = vector["descriptor"]["action"].clone();
        assert!(serde_json::from_value::<LegacyDescriptor>(legacy_action.clone()).is_ok());
        let legacy_request = serde_json::from_value::<WorkflowRequest>(serde_json::json!({
            "method":"workflow.action.propose",
            "params":{
                "request_id":"00000000-0000-0000-0000-000000000001",
                "descriptor":legacy_action,
            }
        }))
        .unwrap();
        assert!(legacy_request.validate().is_ok());
    }
    let legacy: Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/workflow-action-01.json"
    ))
    .unwrap();
    let descriptor: LegacyDescriptor = serde_json::from_value(legacy["action"].clone()).unwrap();
    let digest: String = descriptor
        .digest()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, legacy["binding_digest"].as_str().unwrap());
}
