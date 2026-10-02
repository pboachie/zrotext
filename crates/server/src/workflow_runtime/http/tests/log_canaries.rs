// SPDX-License-Identifier: AGPL-3.0-only
//! Capture actual process output, including dependency/background diagnostics.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const CHILD: &str = "ZT_WORKFLOW_LOG_CANARY_CHILD";
const LEAK: &str = "ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK";
const TEST: &str = "workflow_runtime::http::tests::log_canaries::http_success_and_refusals_keep_content_and_credentials_out_of_process_output";
const OUT: &str = "workflow output capture positive control";
const ERR: &str = "workflow diagnostic capture positive control";
const CONTENT: &str = "synthetic workflow rejected plaintext canary";
const RECEIPT_LIMIT: u64 = 65_536;

// This root is fixed by the Cargo invocation at compilation, independently of
// the runtime executable path. No runtime environment value selects a program.
fn artifact_directory() -> PathBuf {
    let root = option_env!("CARGO_TARGET_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    root.join("debug/deps").canonicalize().unwrap()
}

fn test_binary(directory: &Path, running: &Path) -> Option<PathBuf> {
    let running = running.canonicalize().ok()?;
    for entry in fs::read_dir(directory).ok()? {
        let entry = entry.ok()?;
        if !entry.file_type().ok()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str()?;
        let stem = name
            .strip_suffix(std::env::consts::EXE_SUFFIX)
            .unwrap_or(name);
        let Some(hash) = stem.strip_prefix("zrotext_server-") else {
            continue;
        };
        if hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            // Return the trusted directory entry, never the supplied candidate.
            let allowed = directory.join(format!(
                "zrotext_server-{hash}{}",
                std::env::consts::EXE_SUFFIX
            ));
            let canonical = allowed.canonicalize().ok()?;
            if canonical.parent() == Some(directory) && canonical == running {
                return Some(allowed);
            }
        }
    }
    None
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ReceiptChannel {
    address: SocketAddr,
    capability: Uuid,
}

fn decode_receipt(bytes: &[u8], capability: Uuid) -> Result<Vec<String>, &'static str> {
    if bytes.len() as u64 > RECEIPT_LIMIT {
        return Err("receipt exceeds bound");
    }
    let (actual, secrets): (Uuid, Vec<String>) =
        serde_json::from_slice(bytes).map_err(|_| "invalid receipt")?;
    if actual != capability || secrets.len() != 6 || secrets.iter().any(String::is_empty) {
        return Err("receipt capability or shape refused");
    }
    Ok(secrets)
}

fn receive_receipt(listener: TcpListener, capability: Uuid) -> Vec<String> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                assert!(peer.ip().is_loopback());
                stream
                    .set_read_timeout(Some(Duration::from_secs(60)))
                    .unwrap();
                let mut bytes = Vec::new();
                Read::by_ref(&mut stream)
                    .take(RECEIPT_LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .unwrap();
                return decode_receipt(&bytes, capability).expect("authenticated bounded receipt");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "receipt channel timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => panic!("receipt channel refused"),
        }
    }
}

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

#[test]
fn child_program_must_be_the_running_binary_in_the_compiled_artifact_directory() {
    let directory = artifact_directory();
    let running = std::env::current_exe().unwrap();
    assert!(test_binary(&directory, &running).is_some());
    assert!(test_binary(Path::new(env!("CARGO_MANIFEST_DIR")), &running).is_none());
    assert!(test_binary(&directory, &directory.join("../untrusted.exe")).is_none());
}

#[test]
fn receipt_requires_the_parent_capability_and_a_bounded_exact_shape() {
    let capability = Uuid::new_v4();
    let secrets = vec!["synthetic receipt value".to_owned(); 6];
    let valid = serde_json::to_vec(&(capability, &secrets)).unwrap();
    assert_eq!(decode_receipt(&valid, capability).unwrap(), secrets);
    assert!(decode_receipt(&valid, Uuid::new_v4()).is_err());
    assert!(decode_receipt(b"not a receipt", capability).is_err());
    assert!(decode_receipt(&vec![0; RECEIPT_LIMIT as usize + 1], capability).is_err());
    let short = serde_json::to_vec(&(capability, &secrets[..5])).unwrap();
    assert!(decode_receipt(&short, capability).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated HTTP log-canary schema"]
async fn http_success_and_refusals_keep_content_and_credentials_out_of_process_output() {
    if std::env::var_os(CHILD).is_some() {
        let mut input = Vec::new();
        std::io::stdin().take(1025).read_to_end(&mut input).unwrap();
        assert!(input.len() <= 1024);
        let channel: ReceiptChannel = serde_json::from_slice(&input).unwrap();
        assert!(channel.address.ip().is_loopback() && channel.address.port() != 0);
        exercise_http(channel).await;
        return;
    }
    let executable = test_binary(&artifact_directory(), &std::env::current_exe().unwrap())
        .expect("running test binary must belong to the compiled Cargo artifact directory");
    for inject in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let channel = ReceiptChannel {
            address: listener.local_addr().unwrap(),
            capability: Uuid::new_v4(),
        };
        let capability = channel.capability;
        let receipt = std::thread::spawn(move || receive_receipt(listener, capability));
        let mut command = Command::new(&executable);
        command
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(CHILD, "1")
            .env_remove(LEAK)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if inject {
            command.env(LEAK, "1");
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&channel).unwrap())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "HTTP canary child failed");
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
        let secrets = receipt.join().expect("receipt receiver completed");
        assert!(secrets.len() >= 5 && secrets.iter().all(|v| !v.is_empty()));
        assert_eq!(
            contains_secret(&result.stdout, &secrets),
            inject,
            "fixture-injected leak must fail the same output detector used for real requests"
        );
        assert!(!contains_secret(&result.stderr, &secrets));
    }
}

async fn exercise_http(channel: ReceiptChannel) {
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
    let mut receipt = TcpStream::connect_timeout(&channel.address, Duration::from_secs(5)).unwrap();
    receipt
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    receipt
        .write_all(&serde_json::to_vec(&(channel.capability, secrets)).unwrap())
        .unwrap();
    drop(receipt);
    case.f.cleanup().await;
    println!("{OUT}");
    eprintln!("{ERR}");
    if std::env::var_os(LEAK).is_some() {
        // Sensitivity control only: never add a production logger or leak hook.
        println!("{CONTENT}");
    }
}
