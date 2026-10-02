// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

fn owned_component(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("zrotext-scheduler-"))
        .and_then(|value| {
            Uuid::parse_str(value)
                .ok()
                .map(|id| id.to_string() == value)
        })
        .unwrap_or(false)
}

fn scratch_anchor(configured: &Path) -> std::io::Result<PathBuf> {
    let root = configured.canonicalize()?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    if root.starts_with(repository) || !root.is_dir() {
        return Err(std::io::Error::other("public scratch anchor refused"));
    }
    Ok(root)
}

fn create_scratch(root: &Path) -> std::io::Result<PathBuf> {
    let directory = root.join(format!("zrotext-scheduler-{}", Uuid::new_v4()));
    if !directory.starts_with(root)
        || directory.parent() != Some(root)
        || !owned_component(&directory)
    {
        return Err(std::io::Error::other("scheduler scratch refused"));
    }
    // A pre-existing entry is never adopted as owned scratch.
    std::fs::create_dir(&directory)?;
    Ok(directory)
}

fn remove_scratch(root: &Path, directory: &Path) -> std::io::Result<()> {
    if !directory.starts_with(root)
        || directory.parent() != Some(root)
        || !owned_component(directory)
    {
        return Err(std::io::Error::other("scheduler cleanup scope refused"));
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("scheduler cleanup entry refused"));
    }
    let resolved = directory.canonicalize()?;
    // Check the absolute target immediately before recursive cleanup. Private
    // parent ACLs remain required against privileged local replacement races.
    if !resolved.starts_with(root)
        || resolved.parent() != Some(root)
        || resolved != directory
        || !owned_component(&resolved)
    {
        return Err(std::io::Error::other("scheduler cleanup target refused"));
    }
    std::fs::remove_dir_all(resolved)
}

#[test]
fn scheduler_scratch_identity_refuses_other_names_and_nested_paths() {
    let root = std::env::current_dir().unwrap();
    let child = root.join(format!("zrotext-scheduler-{}", Uuid::new_v4()));
    assert!(owned_component(&child));
    assert_eq!(child.parent(), Some(root.as_path()));
    assert!(!owned_component(&root.join("zrotext-scheduler-not-a-uuid")));
    assert!(!owned_component(&root.join("other")));
    assert_ne!(
        root.join("nested")
            .join(child.file_name().unwrap())
            .parent(),
        Some(root.as_path())
    );
}

#[test]
fn scheduler_scratch_refuses_public_anchor_foreign_target_and_non_directory() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    assert!(scratch_anchor(&repository).is_err());
    let root = scratch_anchor(&std::env::temp_dir()).unwrap();
    let directory = create_scratch(&root).unwrap();
    let foreign = repository.join("Cargo.toml");
    let before = std::fs::read(&foreign).unwrap();
    assert!(remove_scratch(&root, &foreign).is_err());
    assert_eq!(std::fs::read(&foreign).unwrap(), before);
    assert!(remove_scratch(&root, &root).is_err());
    assert!(directory.is_dir());
    if !directory.starts_with(&root) || directory.parent() != Some(root.as_path()) {
        panic!("test scratch target refused");
    }
    std::fs::remove_dir(&directory).unwrap();
    if !directory.starts_with(&root) || directory.parent() != Some(root.as_path()) {
        panic!("test scratch replacement refused");
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&directory)
        .unwrap();
    assert!(remove_scratch(&root, &directory).is_err());
    assert!(directory.is_file());
    let resolved = directory.canonicalize().unwrap();
    if !resolved.starts_with(&root)
        || resolved.parent() != Some(root.as_path())
        || resolved != directory
    {
        panic!("test file cleanup refused");
    }
    std::fs::remove_file(resolved).unwrap();
}

#[cfg(unix)]
#[test]
fn scheduler_scratch_refuses_a_symlink_replacement_without_removing_its_target() {
    let root = scratch_anchor(&std::env::temp_dir()).unwrap();
    let link = create_scratch(&root).unwrap();
    let target = create_scratch(&root).unwrap();
    if !link.starts_with(&root) || link.parent() != Some(root.as_path()) {
        panic!("symlink fixture refused");
    }
    std::fs::remove_dir(&link).unwrap();
    if !link.starts_with(&root)
        || !target.starts_with(&root)
        || link.parent() != Some(root.as_path())
        || target.parent() != Some(root.as_path())
    {
        panic!("symlink fixture scope refused");
    }
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(remove_scratch(&root, &link).is_err());
    assert!(target.is_dir());
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    if !link.starts_with(&root) || link.parent() != Some(root.as_path()) {
        panic!("symlink cleanup scope refused");
    }
    std::fs::remove_file(&link).unwrap();
    remove_scratch(&root, &target).unwrap();
}

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
    // TEMP is trusted test startup configuration. Resolve its selected anchor
    // once and permit only one freshly generated child, never the anchor itself.
    let scratch_root = scratch_anchor(&std::env::temp_dir()).unwrap();
    let directory = create_scratch(&scratch_root).unwrap();
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
    remove_scratch(&scratch_root, &directory).unwrap();
}
