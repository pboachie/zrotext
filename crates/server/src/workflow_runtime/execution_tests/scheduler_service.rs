// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

async fn driver(input: Value) -> Value {
    tokio::task::spawn_blocking(move || {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/scheduler/test-service-runtime.mjs");
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
        assert!(
            output.status.success(),
            "actual scheduler HTTPS driver refused"
        );
        serde_json::from_slice(&output.stdout).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, Node 22+, built SDK and OpenSSL; actual scheduler HTTPS/router/database"]
async fn actual_customer_scheduler_restart_resolves_lost_send_and_cancels_without_second_dispatch()
{
    let mut flow = prepared(
        &[Operation::Schedule, Operation::Send, Operation::Status],
        true,
    )
    .await;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let separator = if flow.case.f.url.contains('?') {
        '&'
    } else {
        '?'
    };
    let app = crate::workflow_runtime::http::router(
        crate::workflow_runtime::http::WorkflowHttpState {
            database_url: format!(
                "{}{separator}options=-csearch_path%3D{}",
                flow.case.f.url, flow.case.f.schema
            ),
            hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        },
        true,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let directory = std::env::temp_dir().join(format!("zrotext-scheduler-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let input = request();
    let mut fixture = json!({"upstream":format!("http://{address}"),"credential":flow.credential.as_str(),"journal":directory.join("journal.sqlite"),"phase":"enqueue","expected_state":"waiting","action_id":flow.action.key.action_id,"params":{"request_id":input.request_id,"key":flow.action.key,"policy":flow.policy,"series_id":input.series_id,"ordinal":0}});
    driver(fixture.clone()).await;
    let row = flow
        .case
        .f
        .db
        .query_one(
            "SELECT id,dispatch_id FROM workflow_schedule_occurrences WHERE action_id=$1",
            &[&flow.action.key.action_id],
        )
        .await
        .unwrap();
    let occurrence: Uuid = row.get(0);
    fixture["phase"] = json!("advance");
    let waiting = driver(fixture.clone()).await;
    assert_eq!(waiting["result"]["state"], "waiting_owner_binding");
    let (bound, message) = flow
        .case
        .bind_message(flow.action.clone(), row.get(1))
        .await;
    scheduling::retry_due(&flow, occurrence).await;
    fixture["drop_send"] = json!(true);
    fixture["expected_state"] = json!("unknown");
    let unknown = driver(fixture.clone()).await;
    let before=flow.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_integration_access WHERE operation=64),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve'),(SELECT count(*) FROM message_attempts)",&[]).await.unwrap();
    assert_eq!(before.get::<_, i64>(1), 1);
    assert_eq!(before.get::<_, i64>(2), 0);
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    fixture["drop_send"] = json!(false);
    fixture["expected_state"] = json!("prepared");
    fixture["expected_message"] = json!(message);
    let prepared = driver(fixture.clone()).await;
    assert_eq!(unknown["request_id"], prepared["request_id"]);
    assert_eq!(
        prepared["result"]["dispatch_id"],
        json!(row.get::<_, Uuid>(1))
    );
    assert_eq!(
        flow.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_integration_access WHERE operation=64",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        before.get::<_, i64>(0),
        "restart reconciliation must not invoke another Send"
    );
    fixture["phase"] = json!("cancel");
    fixture["request_id"] = json!(Uuid::new_v4());
    fixture["expected_state"] = json!("cancelled");
    driver(fixture.clone()).await;
    driver(fixture.clone()).await;
    assert_eq!(bound.key, flow.action.key);
    let row=flow.case.f.db.query_one("SELECT m.state,o.phase,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT count(*) FROM message_attempts) FROM messages m JOIN workflow_schedule_occurrences o ON(o.account_id,o.message_id)=(m.account_id,m.id) WHERE m.id=$1",&[&message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, String>(1), "failed");
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, i64>(3), 0);
    server.abort();
    let _ = server.await;
    flow.case.f.cleanup().await;
    std::fs::remove_dir_all(directory).unwrap();
}
