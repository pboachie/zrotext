// SPDX-License-Identifier: AGPL-3.0-only
//! Capture actual process output, including dependency/background diagnostics.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{fs, process::Command};

const CHILD: &str = "ZT_WORKFLOW_LOG_CANARY_CHILD";
const RECEIPT: &str = "ZT_WORKFLOW_LOG_CANARY_RECEIPT";
const LEAK: &str = "ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK";
const TEST: &str = "workflow_runtime::http::tests::log_canaries::http_success_and_refusals_keep_content_and_credentials_out_of_process_output";
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

#[test]
fn output_detector_detects_a_fixture_leak_without_requiring_utf8_logs() {
    let secret = "synthetic detector content".to_owned();
    let mut output = vec![0xff];
    output.extend(secret.as_bytes());
    assert!(contains_secret(&output, std::slice::from_ref(&secret)));
    assert!(!contains_secret(OUT.as_bytes(), &[secret]));
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated HTTP log-canary schema"]
async fn http_success_and_refusals_keep_content_and_credentials_out_of_process_output() {
    if std::env::var_os(CHILD).is_some() {
        exercise_http().await;
        return;
    }
    // Test-only receipts contain synthetic fixture values, never real credentials.
    // Each child owns its unique schema and cleans it before returning.
    let directory = std::env::temp_dir().join(format!("workflow-log-canaries-{}", Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    for inject in [false, true] {
        let receipt = directory.join(if inject {
            "injected.json"
        } else {
            "clean.json"
        });
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(CHILD, "1")
            .env(RECEIPT, &receipt)
            .env_remove(LEAK);
        if inject {
            command.env(LEAK, "1");
        }
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
        assert!(
            result
                .stderr
                .windows(ERR.len())
                .any(|v| v == ERR.as_bytes())
        );
        let secrets: Vec<String> = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert!(secrets.len() >= 5 && secrets.iter().all(|v| !v.is_empty()));
        assert_eq!(
            contains_secret(&result.stdout, &secrets),
            inject,
            "fixture-injected leak must fail the same output detector used for real requests"
        );
        assert!(!contains_secret(&result.stderr, &secrets));
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
    fs::write(
        std::env::var_os(RECEIPT).expect("parent-owned receipt"),
        serde_json::to_vec(&secrets).unwrap(),
    )
    .unwrap();
    case.f.cleanup().await;
    println!("{OUT}");
    eprintln!("{ERR}");
    if std::env::var_os(LEAK).is_some() {
        // Sensitivity control only: never add a production logger or leak hook.
        println!("{CONTENT}");
    }
}
