// SPDX-License-Identifier: AGPL-3.0-only
//! Capture actual process output, including dependency/background diagnostics.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::process::Command;

const CHILD: &str = "ZT_WORKFLOW_LOG_CANARY_CHILD";
const NONCE: &str = "ZT_WORKFLOW_LOG_CANARY_NONCE";
const LEAK: &str = "ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK";
const FRAME: &[u8] = b"workflow-test-receipt/";
const TEST: &str = "workflow_runtime::http::tests::log_canaries::http_success_and_refusals_keep_content_and_credentials_out_of_process_output";
const DETECTOR: &str = "workflow_runtime::http::tests::log_canaries::output_detector_detects_a_fixture_leak_without_requiring_utf8_logs";
const OUT: &str = "workflow output capture positive control";
const ERR: &str = "workflow diagnostic capture positive control";
const CONTENT: &str = "synthetic workflow rejected plaintext canary";

fn contains_secret(output: &[u8], secrets: &[String]) -> bool {
    secrets.iter().any(|secret| {
        !secret.is_empty()
            && output
                .windows(secret.len())
                .any(|part| part == secret.as_bytes())
    })
}

// One nonce-bound, bounded test-only record carries synthetic expected values.
// Every other diagnostic byte is retained, including invalid UTF-8. A logger
// cannot hide a leak by forging another frame: duplicates/foreign frames fail.
fn split_receipt(stderr: &[u8], nonce: Uuid) -> Result<(Vec<String>, Vec<u8>), &'static str> {
    if stderr.len() > 2 * 1024 * 1024 {
        return Err("oversized diagnostics");
    }
    let prefix = format!("workflow-test-receipt/{nonce}:");
    let mut secrets = None;
    let mut diagnostics = Vec::new();
    for line in stderr.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(FRAME) {
            if secrets.is_some() || !line.starts_with(prefix.as_bytes()) {
                return Err("duplicate or foreign receipt");
            }
            let payload = line.strip_suffix(b"\n").unwrap_or(line);
            let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
            let payload = &payload[prefix.len()..];
            if payload.len() > 16_384 {
                return Err("oversized receipt");
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| "invalid receipt encoding")?;
            if URL_SAFE_NO_PAD.encode(&bytes).as_bytes() != payload {
                return Err("noncanonical receipt");
            }
            let values: Vec<String> =
                serde_json::from_slice(&bytes).map_err(|_| "invalid receipt")?;
            if values.len() != 6
                || values[0] != CONTENT
                || !values[1].starts_with("ztw_")
                || values.iter().any(|v| v.is_empty() || v.len() > 8192)
            {
                return Err("invalid expected canaries");
            }
            secrets = Some(values);
        } else {
            diagnostics.extend_from_slice(line);
        }
    }
    Ok((secrets.ok_or("missing receipt")?, diagnostics))
}

fn fixture_frame(nonce: Uuid) -> Vec<u8> {
    let values = vec![
        CONTENT,
        "ztw_synthetic",
        "projection",
        "archive",
        "projection bytes",
        "archive bytes",
    ];
    format!(
        "workflow-test-receipt/{nonce}:{}\n",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&values).unwrap())
    )
    .into_bytes()
}

enum ChildTest {
    Http,
    Detector,
}
fn child_command(test: ChildTest) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(env!("CARGO_MANIFEST_DIR")).args([
        "test",
        "--locked",
        "--workspace",
        "--",
        "--exact",
        match test {
            ChildTest::Http => TEST,
            ChildTest::Detector => DETECTOR,
        },
        "--nocapture",
    ]);
    if matches!(test, ChildTest::Http) {
        command.arg("--ignored");
    }
    if let Some(toolchain) = option_env!("RUSTUP_TOOLCHAIN") {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    command
}

#[test]
fn fixed_cargo_child_selects_only_the_detector_without_holding_the_parent_build_lock() {
    let result = child_command(ChildTest::Detector).output().unwrap();
    assert!(
        result.status.success(),
        "nested Cargo failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains(&format!("test {DETECTOR} ... ok")));
    assert_eq!(output.matches("test result: ok. 1 passed").count(), 1);
    assert!(!output.contains(OUT));
}

#[test]
fn output_detector_detects_a_fixture_leak_without_requiring_utf8_logs() {
    let secret = "synthetic detector content".to_owned();
    let mut output = vec![0xff];
    output.extend(secret.as_bytes());
    assert!(contains_secret(&output, std::slice::from_ref(&secret)));
    assert!(!contains_secret(OUT.as_bytes(), &[secret]));
}

#[test]
fn receipt_preserves_diagnostic_leaks_and_rejects_forged_or_duplicate_frames() {
    let nonce = Uuid::new_v4();
    let frame = fixture_frame(nonce);
    let mut output = vec![0xff, b'\n'];
    output.extend(&frame);
    output.extend(CONTENT.as_bytes());
    let (values, diagnostics) = split_receipt(&output, nonce).unwrap();
    assert!(contains_secret(&diagnostics, &values));
    assert_eq!(diagnostics[0], 0xff);
    let mut duplicate = frame.clone();
    duplicate.extend(&frame);
    assert!(split_receipt(&duplicate, nonce).is_err());
    assert!(split_receipt(&frame, Uuid::new_v4()).is_err());
    assert!(split_receipt(b"workflow-test-receipt/invalid\n", nonce).is_err());
    assert!(split_receipt(ERR.as_bytes(), nonce).is_err());
    let oversized = format!("workflow-test-receipt/{nonce}:{}\n", "a".repeat(16_385));
    assert!(split_receipt(oversized.as_bytes(), nonce).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated HTTP log-canary schema"]
async fn http_success_and_refusals_keep_content_and_credentials_out_of_process_output() {
    if std::env::var(CHILD).as_deref() == Ok("1") {
        exercise_http().await;
        return;
    }
    for inject in ["none", "stdout", "stderr"] {
        let nonce = Uuid::new_v4();
        // Fixed command/arguments and compile-time crate directory, not a
        // runtime-selected executable or filesystem receipt path. Cargo uses
        // the operator's trusted toolchain and already-built test artifacts.
        let mut command = child_command(ChildTest::Http);
        command
            .env(CHILD, "1")
            .env(NONCE, nonce.to_string())
            .env(LEAK, inject);
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "HTTP canary child failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result
                .stdout
                .windows(OUT.len())
                .any(|v| v == OUT.as_bytes())
        );
        let (secrets, diagnostics) = split_receipt(&result.stderr, nonce).unwrap();
        assert!(diagnostics.windows(ERR.len()).any(|v| v == ERR.as_bytes()));
        assert_eq!(
            contains_secret(&result.stdout, &secrets),
            inject == "stdout",
            "the same detector must reject the stdout sensitivity leak"
        );
        assert_eq!(
            contains_secret(&diagnostics, &secrets),
            inject == "stderr",
            "the same detector must reject the stderr sensitivity leak"
        );
    }
}

async fn exercise_http() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    let projection = case.projection().await;
    case.request.content_envelope = Some(projection.clone());
    let issued = case.issue().await.unwrap();
    let archive: Vec<u8> = case
        .f
        .db
        .query_one(
            "SELECT envelope FROM workflow_context_versions WHERE context_id=$1",
            &[&case.header.context],
        )
        .await
        .unwrap()
        .get(0);
    let app = router(state(&case), true);
    let body = json!({"method":"workflow.context.content","params":{
        "request_id":Uuid::new_v4(),"context_id":case.header.context}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(body.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = json_body(response).await;
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(value["result"]["envelope_base64url"].as_str().unwrap())
            .unwrap(),
        projection
    );
    let mut refused = body.clone();
    refused["params"]["plaintext"] = json!(CONTENT);
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(refused)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({"error":{"code":"invalid_request"}})
    );
    let mut foreign = body.clone();
    foreign["params"]["context_id"] = json!(Uuid::new_v4());
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(foreign)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response).await,
        json!({"error":{"code":"forbidden"}})
    );
    crate::workflow_runtime::revoke_grant(
        &mut case.f.connect().await,
        &case.owner,
        issued.grant_id,
    )
    .await
    .unwrap();
    let response = app
        .oneshot(request(&issued.token, Some(body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await,
        json!({"error":{"code":"unauthorized"}})
    );
    let secrets = vec![
        CONTENT.to_owned(),
        issued.token.to_string(),
        URL_SAFE_NO_PAD.encode(&projection),
        URL_SAFE_NO_PAD.encode(&archive),
        format!("{:?}", projection),
        format!("{:?}", archive),
    ];
    case.f.cleanup().await;
    println!("{OUT}");
    eprintln!("{ERR}");
    let nonce = Uuid::parse_str(&std::env::var(NONCE).expect("parent nonce")).unwrap();
    eprintln!(
        "workflow-test-receipt/{nonce}:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&secrets).unwrap())
    );
    match std::env::var(LEAK).as_deref() {
        Ok("none") => {}
        Ok("stdout") => println!("{CONTENT}"),
        Ok("stderr") => eprintln!("{CONTENT}"),
        _ => panic!("invalid fixture leak mode"),
    }
}
