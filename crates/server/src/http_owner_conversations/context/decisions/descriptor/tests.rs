// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../../../protocol/v1/vectors/workflow-action-01.json"
    ))
    .unwrap()
}
#[test]
fn complete_canonical_action_matches_independent_normative_binding_vector() {
    let v = vector();
    let d: Descriptor = serde_json::from_value(v["action"].clone()).unwrap();
    assert_eq!(
        hex(&d.digest().unwrap()),
        v["binding_digest"].as_str().unwrap()
    );
    for (name, value) in v["field_edits"].as_object().unwrap() {
        let mut changed = v["action"].clone();
        changed[name] = value.clone();
        let changed: Descriptor = serde_json::from_value(changed).unwrap();
        assert_ne!(changed.digest().unwrap(), d.digest().unwrap(), "{name}");
    }
}
#[test]
fn missing_extra_boolean_unbounded_non_ascii_and_noncanonical_digest_are_rejected() {
    let v = vector();
    let base = &v["action"];
    for value in [serde_json::json!(true), serde_json::json!(1.5)] {
        let mut bad = base.clone();
        bad["revision"] = value;
        assert!(serde_json::from_value::<Descriptor>(bad).is_err());
    }
    let mut negative = base.clone();
    negative["revision"] = serde_json::json!(-1);
    assert!(
        serde_json::from_value::<Descriptor>(negative)
            .unwrap()
            .canonical()
            .is_err()
    );
    let mut bad = base.clone();
    bad["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Descriptor>(bad).is_err());
    let mut bad = base.clone();
    bad.as_object_mut().unwrap().remove("window_id");
    assert!(serde_json::from_value::<Descriptor>(bad).is_err());
    for value in ["x".repeat(129), "\u{00e9}".into(), String::new()] {
        let mut bad = base.clone();
        bad["timezone"] = serde_json::json!(value);
        assert!(
            serde_json::from_value::<Descriptor>(bad)
                .unwrap()
                .canonical()
                .is_err()
        );
    }
    assert!(decode_digest(&"AB".repeat(32)).is_err());
}
#[test]
fn any_edit_invalidates_previous_binding_and_unchanged_or_irreversible_edits_conflict() {
    use crate::http_owner_conversations::context::decisions::model::{Phase, edit};
    let base: Descriptor = serde_json::from_value(vector()["action"].clone()).unwrap();
    let mut next = base.clone();
    next.revision = 2;
    assert!(edit(&base, &next, Phase::Approved).is_err());
    next.timezone = "UTC-changed".into();
    edit(&base, &next, Phase::Approved).unwrap();
    assert_ne!(base.digest().unwrap(), next.digest().unwrap());
    for phase in [
        Phase::Dispatching,
        Phase::Unknown,
        Phase::Cancelled,
        Phase::Expired,
        Phase::Succeeded,
        Phase::Failed,
    ] {
        assert!(edit(&base, &next, phase).is_err());
    }
}
