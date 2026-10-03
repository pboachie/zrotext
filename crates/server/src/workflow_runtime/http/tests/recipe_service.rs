// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::decisions::{self, model::Decision};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

async fn recipe(input: Value) -> Value {
    tokio::task::spawn_blocking(move || {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/recipes/test-service-runtime.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "recipe client refused");
        serde_json::from_slice(&output.stdout).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, Node 22+, built SDK and OpenSSL; real recipe HTTPS/router/database"]
async fn actual_recipe_https_proposes_and_only_prepares_after_independent_owner_binding() {
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[
        Operation::ContextMetadata,
        Operation::Propose,
        Operation::Status,
        Operation::Send,
    ])
    .unwrap();
    let issued = case.issue().await.unwrap();
    let mut descriptor = case.descriptor().await;
    descriptor.window_id = crate::workflow_runtime::IMMEDIATE_WINDOW_ID.into();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(state(&case), true);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut input = json!({"upstream":format!("http://{address}"),"credential":issued.token.as_str(),"descriptor":descriptor,"phase":"propose","request_id":Uuid::new_v4()});
    let proposed = recipe(input.clone()).await;
    let action: decisions::ActionState =
        serde_json::from_value(proposed["result"].clone()).unwrap();
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let approved = decisions::decide(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        action.record_version,
        action.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    input["phase"] = json!("prepare");
    input["key"] = json!(approved.key);
    input["expected_state"] = json!("waiting_owner_binding");
    input["request_id"] = json!(Uuid::new_v4());
    recipe(input.clone()).await;
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let (_, message) = case.bind_message(approved, Uuid::new_v4()).await;
    input["expected_state"] = json!("prepared");
    input["message_id"] = json!(message);
    input["request_id"] = json!(Uuid::new_v4());
    recipe(input).await;
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    server.abort();
    let _ = server.await;
    case.f.cleanup().await;
}
