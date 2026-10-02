// SPDX-License-Identifier: AGPL-3.0-only
//! Capture actual process output, including dependency/background diagnostics.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

const CHILD: &str = "ZT_WORKFLOW_LOG_CANARY_CHILD";
const NONCE: &str = "ZT_WORKFLOW_LOG_CANARY_NONCE";
const LEAK: &str = "ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK";
const OUT: &str = "workflow output capture positive control";
const ERR: &str = "workflow diagnostic capture positive control";
const CONTENT: &str = "synthetic workflow rejected plaintext canary";

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated HTTP log-canary schema"]
async fn http_success_and_refusals_keep_content_and_credentials_out_of_process_output() {
    exercise_http().await;
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
    if std::env::var(CHILD).as_deref() != Ok("1") {
        return;
    }
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
