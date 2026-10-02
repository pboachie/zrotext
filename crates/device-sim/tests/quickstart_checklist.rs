// SPDX-License-Identifier: AGPL-3.0-only
//! Checks the included quickstart examples against real simulator output.
//! The separate agent_journey harness pins the modeled safety outcomes.

use serde_json::Value;
use std::process::Command;

const QUICKSTART: &str = include_str!("../../../docs/AGENT-QUICKSTART.md");

fn printed_matrix() -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_zrotext-device-sim"))
        .output()
        .expect("simulator binary starts");
    assert!(output.status.success(), "simulator exits cleanly");
    serde_json::from_slice(&output.stdout).expect("simulator prints JSON")
}

fn examples_match(document: &str, matrix: &Value) -> bool {
    let Some(scenarios) = matrix["scenarios"].as_array() else {
        return false;
    };
    let Some(journey) = scenarios
        .iter()
        .find(|scenario| scenario["scenario"] == "agent_journey")
    else {
        return false;
    };
    let Some(timeline) = journey["timeline"].as_array() else {
        return false;
    };
    let mut examples = Vec::new();
    let mut block = None::<String>;
    for line in document.lines() {
        let line = line.trim();
        if line == "```json" {
            if block.is_some() {
                return false;
            }
            block = Some(String::new());
        } else if line == "```" && block.is_some() {
            let Ok(value) = serde_json::from_str::<Value>(&block.take().unwrap()) else {
                return false;
            };
            examples.push(value);
        } else if let Some(contents) = block.as_mut() {
            contents.push_str(line);
            contents.push('\n');
        }
    }
    block.is_none() && examples.len() == 4 && timeline.get(..4) == Some(examples.as_slice())
}

fn safe_string(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'+' {
            let digits = bytes[index + 1..]
                .iter()
                .take_while(|digit| digit.is_ascii_digit())
                .count();
            if (2..=15).contains(&digits) && bytes[index + 1] != b'0' {
                return false;
            }
        }
    }
    let lower = text.to_ascii_lowercase();
    let slash = char::from(0x5c);
    let normalized = lower.replace(slash, "/");
    if normalized
        .as_bytes()
        .windows(3)
        .any(|part| part[0].is_ascii_alphabetic() && part[1] == b':' && part[2] == b'/')
    {
        return false;
    }
    for root in ["home", "users", "root", "mnt", "media"] {
        if normalized.contains(&format!("/{root}/")) {
            return false;
        }
    }
    ![
        "postgres://",
        "postgresql://",
        "mysql://",
        "redis://",
        "http://",
        "https://",
        "akia",
        "begin private key",
        "bearer ",
        "token=",
        "password=",
        "api_key",
        "delivered_by_carrier",
        "sent_message",
        "carrier_delivered",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

fn safe_value(value: &Value) -> bool {
    match value {
        Value::String(text) => safe_string(text),
        Value::Array(values) => values.iter().all(safe_value),
        Value::Object(values) => values
            .iter()
            .all(|(key, value)| safe_string(key) && safe_value(value)),
        _ => true,
    }
}

#[test]
fn documented_json_examples_match_complete_timeline_objects() {
    assert!(examples_match(QUICKSTART, &printed_matrix()));
}

#[test]
fn changed_document_ticks_and_missing_fields_are_rejected() {
    let matrix = printed_matrix();
    let tick = QUICKSTART.replacen("\"t_ms\": 1", "\"t_ms\": 99", 1);
    assert_ne!(tick, QUICKSTART);
    assert!(
        !examples_match(&tick, &matrix),
        "changed documented tick must fail"
    );
    let missing = QUICKSTART.replacen(", \"replay\": \"same_message\"", "", 1);
    assert_ne!(missing, QUICKSTART);
    assert!(
        !examples_match(&missing, &matrix),
        "missing documented field must fail"
    );
    let malformed = QUICKSTART.replacen("\"t_ms\": 1", "\"t_ms\":", 1);
    assert!(!examples_match(&malformed, &matrix));
}

#[test]
fn printed_output_stays_synthetic() {
    assert!(safe_value(&printed_matrix()));
}

#[test]
fn nested_phone_and_escaped_personal_paths_are_rejected() {
    for first in '1'..='9' {
        let phone = format!("+{first}{}", "0".repeat(10));
        assert!(!safe_value(&serde_json::json!({"nested": [phone]})));
    }
    assert!(safe_string("a+b"));
    assert!(safe_string("+0"));
    assert!(safe_string(&format!("+{}", "9".repeat(16))));
    let slash = char::from(0x5c);
    let personal = format!("C:{slash}Users{slash}fixture{slash}sample");
    assert!(!safe_value(&serde_json::json!({"nested": [personal]})));
    for root in ["home", "Users", "root", "mnt", "media"] {
        assert!(!safe_value(&serde_json::json!([format!(
            "/{root}/fixture/sample"
        )])));
    }
    for prefix in ["Bearer", "token", "password"] {
        let probe = if prefix == "Bearer" {
            format!("{prefix} fixture")
        } else {
            format!("{prefix}=fixture")
        };
        assert!(!safe_value(&serde_json::json!({"nested": [probe]})));
    }
    assert!(safe_value(
        &serde_json::json!({"recipient": "digest:fixture"})
    ));
}
