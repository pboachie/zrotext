// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const ID: &str = "12345678-1234-1234-1234-123456789abc";
const OTHER: &str = "abcdefab-cdef-abcd-efab-cdefabcdefab";

fn body() -> String {
    format!(
        r#"{{"request_id":"{ID}","opening_id":"{ID}","capacity":1,"description":{{"context_id":"{ID}","revision":1,"digest":"{}"}},"decision_deadline_ms":"1"}}"#,
        "ab".repeat(32)
    )
}

fn valid(raw: &str) -> bool {
    serde_json::from_str::<CreateInput>(raw)
        .and_then(|input| {
            input
                .into_request()
                .map_err(|_| <serde_json::Error as de::Error>::custom("invalid request"))
        })
        .is_ok()
}

#[test]
fn create_and_nested_source_require_objects_not_positional_sequences() {
    assert!(valid(&body()));
    let source = format!(r#"["{ID}",1,"{}"]"#, "ab".repeat(32));
    let positional = format!(r#"["{ID}","{ID}",1,{source},"1"]"#);
    assert!(!valid(&positional));
    let nested = body().replace(
        &format!(r#"{{"context_id":"{ID}","revision":1,"digest":"{}"}}"#, "ab".repeat(32)),
        &source,
    );
    assert!(!valid(&nested));
    for raw in ["[]", "null", "1", "true", r#""object""#] {
        assert!(!valid(raw));
    }
    let reordered = format!(
        r#" {{ "description":{{"digest":"{}","revision":128,"context_id":"{ID}"}},"capacity":100,"opening_id":"{ID}","decision_deadline_ms":"1","request_id":"{ID}" }} "#,
        "ab".repeat(32)
    );
    assert!(valid(&reordered));
}

#[test]
fn status_requires_exactly_an_empty_object() {
    for raw in ["{}", " { } "] {
        assert!(serde_json::from_str::<StatusInput>(raw).is_ok());
    }
    for raw in ["[]", "null", "1", "true", r#"{"account_id":null}"#] {
        assert!(serde_json::from_str::<StatusInput>(raw).is_err());
    }
}

#[test]
fn streamed_members_reject_duplicates_unknown_authority_and_missing_fields() {
    let source = format!(
        r#"{{"context_id":"{ID}","revision":1,"digest":"{}"}}"#,
        "ab".repeat(32)
    );
    for (field, value) in [
        ("request_id", format!(r#""{ID}""#)),
        ("opening_id", format!(r#""{ID}""#)),
        ("capacity", "1".into()),
        ("description", source),
        ("decision_deadline_ms", r#""1""#.into()),
        ("context_id", format!(r#""{ID}""#)),
        ("revision", "1".into()),
        ("digest", format!(r#""{}""#, "ab".repeat(32))),
    ] {
        let member = format!(r#""{field}":{value}"#);
        let raw = body().replace(&member, &format!("{member},{member}"));
        assert!(!valid(&raw), "{field}");
    }
    assert!(!valid(&body().replace(
        r#""capacity":1"#,
        r#""capacity":1,"\u0063apacity":1"#,
    )));
    assert!(!valid(&body().replace(
        r#""revision":1"#,
        r#""revision":1,"\u0072evision":1"#,
    )));
    for unknown in ["account_id", "owner_id", "session_id", "permit"] {
        assert!(!valid(&body().replacen('{', &format!("{{\"{unknown}\":true,"), 1)));
        assert!(!valid(&body().replace(
            r#""revision":1"#,
            &format!(r#""revision":1,"{unknown}":true"#),
        )));
    }
    assert!(!valid(&body().replace(r#""capacity":1,"#, "")));
    assert!(!valid(&body().replace(r#""revision":1,"#, "")));
    assert!(serde_json::from_slice::<CreateInput>(&[b'{', 0xff, b'}']).is_err());
}

#[test]
fn all_uuid_assertions_reject_aliases_nil_and_nonstring_values() {
    assert!(canonical_uuid(ID).is_ok());
    let aliases = [
        ID.to_uppercase(),
        ID.replace('-', ""),
        format!("{{{ID}}}"),
        format!("urn:uuid:{ID}"),
        format!(" {ID}"),
        Uuid::nil().to_string(),
        "bad".into(),
    ];
    for alias in aliases {
        assert!(canonical_uuid(&alias).is_err());
        for field in ["request_id", "opening_id", "context_id"] {
            assert!(!valid(&body().replace(
                &format!(r#""{field}":"{ID}""#),
                &format!(r#""{field}":"{alias}""#),
            )));
        }
    }
    for field in ["request_id", "opening_id", "context_id"] {
        for value in ["null", "1", "[]", "{}", "true"] {
            assert!(!valid(&body().replace(
                &format!(r#""{field}":"{ID}""#),
                &format!(r#""{field}":{value}"#),
            )));
        }
    }
}

#[test]
fn deadline_is_a_positive_canonical_i64_string_without_loss() {
    let raw = body().replace(
        r#""decision_deadline_ms":"1""#,
        &format!(r#""decision_deadline_ms":"{}""#, i64::MAX),
    );
    let request = serde_json::from_str::<CreateInput>(&raw)
        .unwrap()
        .into_request()
        .unwrap();
    assert_eq!(request.decision_deadline_ms, i64::MAX);
    for value in [
        "", "0", "01", "+1", "-1", " 1", "1 ", "1.0", "1e0", "\u{661}",
        "9223372036854775808", "11111111111111111111",
    ] {
        assert!(!valid(&body().replace(
            r#""decision_deadline_ms":"1""#,
            &format!(r#""decision_deadline_ms":"{value}""#),
        )));
    }
    for value in ["1", "1.0", "1e0", "null", "true", "[]", "{}"] {
        assert!(!valid(&body().replace(
            r#""decision_deadline_ms":"1""#,
            &format!(r#""decision_deadline_ms":{value}"#),
        )));
    }
}

#[test]
fn capacity_and_revision_retain_integer_ranges_and_digest_validation() {
    for (field, maximum) in [("capacity", 100), ("revision", 128)] {
        for value in [1, maximum] {
            assert!(valid(&body().replace(
                &format!(r#""{field}":1"#),
                &format!(r#""{field}":{value}"#),
            )));
        }
        for value in [
            "0", "-1", "-0", "1.0", "1e0", "\"1\"", "null", "true", "9223372036854775808",
        ] {
            assert!(!valid(&body().replace(
                &format!(r#""{field}":1"#),
                &format!(r#""{field}":{value}"#),
            )));
        }
        assert!(!valid(&body().replace(
            &format!(r#""{field}":1"#),
            &format!(r#""{field}":{}"#, maximum + 1),
        )));
    }
    for digest in ["00".repeat(32), "AB".repeat(32), "ab".repeat(31)] {
        assert!(!valid(&body().replace(&"ab".repeat(32), &digest)));
    }
}

fn receipt() -> model::Receipt {
    model::Receipt {
        opening: contracts::OpeningKey {
            opening_id: canonical_uuid(ID).unwrap(),
            definition_version: i64::MAX,
            state_version: i64::MAX,
        },
        offer: None,
        allocation_id: None,
        allocation_version: None,
        phase: "open".into(),
        pending: 0,
        confirmed: 100,
    }
}

#[test]
fn create_and_status_project_closed_decimal_metadata_and_historical_acknowledgment() {
    let id = canonical_uuid(ID).unwrap();
    for applied in [true, false] {
        let result = created(
            id,
            id,
            id,
            model::Outcome {
                receipt: receipt(),
                applied,
                recorded: true,
            },
        )
        .unwrap();
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["account_id"], ID);
        assert_eq!(value["request_id"], ID);
        assert_eq!(value["outcome"]["applied"], applied);
        assert_eq!(value["outcome"]["recorded"], true);
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["outcome"].as_object().unwrap().len(), 3);
    }
    for phase in ["open", "closed", "cancelled"] {
        let mut input = receipt();
        input.phase = phase.into();
        let value = serde_json::to_value(status(id, id, input).unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        let projection = &value["receipt"];
        assert_eq!(projection.as_object().unwrap().len(), 7);
        assert_eq!(projection["opening"].as_object().unwrap().len(), 3);
        assert_eq!(projection["opening"]["opening_id"], ID);
        assert_eq!(projection["opening"]["definition_version"], i64::MAX.to_string());
        assert_eq!(projection["opening"]["state_version"], i64::MAX.to_string());
        assert_eq!(projection["pending"], "0");
        assert_eq!(projection["confirmed"], "100");
        assert_eq!(projection["phase"], phase);
        for key in ["offer", "allocation_id", "allocation_version"] {
            assert!(projection[key].is_null());
        }
    }
}

#[test]
fn impossible_library_projections_fail_unavailable_without_publishing_metadata() {
    let id = canonical_uuid(ID).unwrap();
    let other = canonical_uuid(OTHER).unwrap();
    for index in 0..12 {
        let mut input = receipt();
        match index {
            0 => input.opening.opening_id = other,
            1 => input.opening.definition_version = 0,
            2 => input.opening.state_version = -1,
            3 => input.offer = Some(contracts::OfferKey { offer_id: id, state_version: 1 }),
            4 => input.allocation_id = Some(id),
            5 => input.allocation_version = Some(1),
            6 => input.phase = "offered".into(),
            7 => input.pending = -1,
            8 => input.confirmed = -1,
            9 => input.pending = 101,
            10 => input.confirmed = i64::MAX,
            _ => input.pending = 1,
        }
        assert!(matches!(status(id, id, input), Err(ConversationError::Unavailable)));
    }
    assert!(status(Uuid::nil(), id, receipt()).is_err());
    assert!(status(id, Uuid::nil(), receipt()).is_err());
    for (account, request, recorded) in [
        (Uuid::nil(), id, true),
        (id, Uuid::nil(), true),
        (id, id, false),
    ] {
        assert!(matches!(
            created(
                account,
                request,
                id,
                model::Outcome {
                    receipt: receipt(),
                    applied: false,
                    recorded,
                },
            ),
            Err(ConversationError::Unavailable)
        ));
    }
}
