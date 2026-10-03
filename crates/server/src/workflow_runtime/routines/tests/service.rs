// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
#[path = "scratch.rs"]
mod scratch;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

fn jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_sec1_point(false);
    json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap()),"d":URL_SAFE_NO_PAD.encode(key.to_bytes()),"ext":true})
}
async fn driver(input: Value) -> Value {
    tokio::task::spawn_blocking(move || {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/assistant/test-service-routines.mjs");
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
            "customer routine client refused: {}",
            diagnostics(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    })
    .await
    .unwrap()
}
fn diagnostics(bytes: &[u8]) -> String {
    let mut result = Vec::new();
    for line in String::from_utf8_lossy(bytes).lines().take(32) {
        if let Some(code) = line.strip_prefix("routine fixture cli_code=")
            && [
                "unavailable",
                "invalid_configuration",
                "invalid_request",
                "storage_unavailable",
                "forbidden",
                "conflict",
                "authority_unavailable",
                "unknown",
                "timeout",
                "invalid_response",
                "executor_unavailable",
                "artifact_changed",
                "invalid_invocation",
                "replay_conflict",
                "unknown_no_retry",
                "not_executable",
                "withdrawn",
                "provider_unknown",
                "invalid_output",
            ]
            .contains(&code)
        {
            result.push(format!("cli_code={code}"));
        }
        if let Some(phase) = line.strip_prefix("routine fixture phase=") {
            let mut words = phase.split_whitespace();
            let phase = words.next().unwrap_or("");
            if !["seed", "execute", "replay", "publish", "withdraw"].contains(&phase) {
                continue;
            }
            let mut fields = vec![format!("phase={phase}")];
            for word in words {
                let Some((key, value)) = word.split_once('=') else {
                    continue;
                };
                if key == "operation"
                    && ["current", "admit", "produced", "resume", "owner", "refused"]
                        .contains(&value)
                {
                    fields.push(format!("operation={value}"));
                }
                if [
                    "status",
                    "policy_remaining_ms",
                    "context_remaining_ms",
                    "elapsed_ms",
                    "timeout_ms",
                ]
                .contains(&key)
                    && let Ok(value) = value.parse::<i64>()
                {
                    fields.push(format!("{key}={value}"));
                }
            }
            result.push(fields.join(" "));
        }
        if let Some(code) = line
            .strip_prefix("routine integration fixture ")
            .and_then(|v| v.split_once(": "))
            .map(|(_, code)| code)
            && [
                "refused",
                "forbidden",
                "conflict",
                "authority_unavailable",
                "unknown",
                "timeout",
                "invalid_response",
            ]
            .contains(&code)
        {
            result.push(format!("code={code}"));
        }
    }
    result.join("; ")
}
#[test]
fn driver_diagnostics_excludes_untrusted_payload_and_names() {
    let text=diagnostics(b"example private payload\nroutine fixture phase=publish operation=owner status=403 secret=example\nroutine integration fixture example: forbidden\n");
    assert_eq!(
        text,
        "phase=publish operation=owner status=403; code=forbidden"
    );
    assert!(!text.contains("example"));
    assert_eq!(diagnostics(b"routine fixture cli_code=artifact_changed\nroutine fixture cli_code=example private payload\nroutine fixture cli_code=artifact_changed example\n"), "cli_code=artifact_changed");
}
fn input_scope(case: &Case) -> Value {
    let h = &case.header;
    json!({"kind":h.kind,"accountId":URL_SAFE_NO_PAD.encode(h.account.as_bytes()),"deviceId":URL_SAFE_NO_PAD.encode(h.device.as_bytes()),
    "lineId":URL_SAFE_NO_PAD.encode(h.line.as_bytes()),"intervalId":URL_SAFE_NO_PAD.encode(h.interval.as_bytes()),"contextId":URL_SAFE_NO_PAD.encode(h.context.as_bytes()),
    "bindingGeneration":h.binding_generation.to_string(),"revision":h.revision.to_string(),"expiresMs":h.expires_ms.to_string(),
    "trustGeneration":h.trust_generation.to_string(),"manifestVersion":h.manifest_version.to_string(),"peerDigest":URL_SAFE_NO_PAD.encode(h.peer_digest),
    "readerId":URL_SAFE_NO_PAD.encode(Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0,16],case.reader_key.verifying_key().to_sec1_point(false).as_bytes()].concat())),"manifestDigest":URL_SAFE_NO_PAD.encode(h.manifest_digest)})
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, Node 22+, built SDK and OpenSSL; actual routine HTTPS/crypto/router/database"]
async fn actual_routine_https_preserves_input_and_requires_owner_published_new_output_grant() {
    scenario(false, false).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, Node 22+, built SDK and OpenSSL; actual routine HTTPS/crypto/router/database"]
async fn original_input_owner_takeover_fences_separately_published_output_action() {
    scenario(true, false).await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual HTTPS owner-selected local process"]
async fn actual_local_process_requires_owner_pinned_installation_and_preserves_publication() {
    scenario(false, true).await;
}
async fn scenario(takeover: bool, local_process: bool) {
    let (mut case, _, mut policy, _) = prepared_with_signer(true).await;
    // This owner's bounded policy covers multiple actual TLS/database hops.
    // The default one-second pure fixture and timeout-refusal tests stay intact.
    policy.timeout_ms = 10000;
    let proxy_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("https://localhost:{proxy_port}");
    let scratch = scratch::Scratch::create().unwrap();
    let dir = &scratch.path;
    case.header.context = Uuid::new_v4();
    case.request.context = case.header.context;
    policy.context_id = case.header.context;
    policy.routine_id = Uuid::new_v4();
    policy.policy_id = Uuid::new_v4();
    policy.request_id = Uuid::new_v4();
    let mut config = json!({"phase":"seed","upstream":"http://localhost","proxy_port":proxy_port,"policy":policy,
        "request_id":Uuid::new_v4(),"publication_request_id":Uuid::new_v4(),"binding_request_id":Uuid::new_v4(),
        "artifact_path":dir.join("artifact.sqlite"),"manifest_base64url":URL_SAFE_NO_PAD.encode(&case.f.bytes),
        "root_anchor":{"accountId":URL_SAFE_NO_PAD.encode(case.f.account.as_bytes()),"generation":case.header.trust_generation.to_string(),
            "rootPoint":URL_SAFE_NO_PAD.encode(case.f.root.verifying_key().to_sec1_point(false).as_bytes()),
            "version":case.header.manifest_version.to_string(),"digest":URL_SAFE_NO_PAD.encode(case.header.manifest_digest),"anchorDigest":URL_SAFE_NO_PAD.encode([0u8;32])},
        "input_scope":input_scope(&case),"role3_private_jwk":jwk(&case.reader_key),"archive_private_jwk":jwk(&case.f.archive_key),
        "archive_reader_id":URL_SAFE_NO_PAD.encode(case.header.reader),"local_process":local_process});
    let seeded = driver(config.clone()).await;
    let archive = URL_SAFE_NO_PAD
        .decode(seeded["archive_base64url"].as_str().unwrap())
        .unwrap();
    owner::context::write(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        0,
        &archive,
    )
    .await
    .unwrap();

    case.request.content_envelope = Some(
        URL_SAFE_NO_PAD
            .decode(seeded["projection_base64url"].as_str().unwrap())
            .unwrap(),
    );
    case.request.permissions =
        Permissions::new(&[Operation::ContextMetadata, Operation::ContextContent]).unwrap();
    let input = case.issue_another().await;
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let policy_session = Uuid::new_v4();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",&[&policy_session,&case.f.account,&case.owner.user_id,&auth_hash(b"session-v1",&token),&auth_hash(b"csrf-v1",&csrf)]).await.unwrap();
    config["owner"] = json!({"cookie":format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),"csrf":csrf});
    config["input_credential"] = json!(input.token.as_str());
    let factor = case.fresh_factor().await;
    config["owner_grant"] = json!({"current_password":case.password(),"code":factor,"connector_id":case.request.connector,
        "context_id":case.header.context,"contact_id":case.request.contact,"purpose":"operational","permissions":["context_metadata","context_content","propose"],
        "signer_key_id":case.request.signer.map(|key|URL_SAFE_NO_PAD.encode(key)),"expires_at_ms":case.request.expires_ms,"content_envelope_base64url":null});
    let separator = if case.f.url.contains('?') { '&' } else { '?' };
    let database_url = format!(
        "{}{separator}options=-csearch_path%3D{}",
        case.f.url, case.f.schema
    );
    let hasher = Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let workflow = crate::workflow_runtime::http::WorkflowHttpState {
        database_url: database_url.clone(),
        hasher: hasher.clone(),
    };
    let owner = crate::http_owner_conversations::OwnerConversationsState {
        database_url: database_url.clone(),
        auth_hasher: hasher.clone(),
        canonical_origin: origin.clone(),
    };
    let auth = crate::http_auth::AuthHttpState::new(
        database_url,
        hasher,
        origin,
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_workflow_grants_enabled(true)
    .with_mfa_cipher(Arc::new(
        crate::auth::mfa::MfaCipher::new(crate::test_keys::key(89)).unwrap(),
    ));
    let app = crate::workflow_runtime::http::router(workflow.clone(), true)
        .merge(http::router(workflow, true))
        .merge(http::owner_router(owner, true))
        .nest("/v1/auth", crate::http_auth::router(auth));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    config["upstream"] = json!(format!("http://{}", listener.local_addr().unwrap()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    config["phase"] = json!("execute");
    let executed = driver(config.clone()).await;
    assert_eq!(executed["result"]["state"], "awaiting_owner_publication");
    let selected=case.f.db.query_one("SELECT policy->>'executor',policy->>'adapter_id',policy->>'artifact_digest' FROM workflow_routine_policies WHERE id=$1", &[&policy.policy_id]).await.unwrap();
    assert_eq!(
        selected.get::<_, String>(0),
        if local_process {
            "local_process"
        } else {
            "deterministic_local"
        }
    );
    if local_process {
        assert!(selected.get::<_, Option<String>>(1).is_some());
        assert_eq!(selected.get::<_, Option<String>>(2).unwrap().len(), 64);
    }
    config["phase"] = json!("replay");
    let replay = driver(config.clone()).await;
    assert_eq!(
        replay["archive_ciphertext_digest"],
        executed["archive_ciphertext_digest"]
    );
    let publishing_session = Uuid::new_v4();
    let publication_token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let publication_csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",&[&publishing_session,&case.f.account,&case.owner.user_id,&auth_hash(b"session-v1",&publication_token),&auth_hash(b"csrf-v1",&publication_csrf)]).await.unwrap();
    config["owner"] = json!({"cookie":format!("__Host-zrotext_session={publication_token}; __Host-zrotext_csrf={publication_csrf}"),"csrf":publication_csrf});
    config["phase"] = json!("publish");
    let published = driver(config.clone()).await;
    assert_eq!(published["result"]["phase"], "proposed");
    let call: Uuid = serde_json::from_value(config["request_id"].clone()).unwrap();
    let row=case.f.db.query_one("SELECT c.revision,r.generation FROM workflow_contexts c JOIN workflow_routines r ON (r.account_id,r.context_id)=(c.account_id,c.id) WHERE c.id=$1",&[&call]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT revision FROM workflow_contexts WHERE id=$1",
                &[&case.header.context]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let action=case.f.db.query_one("SELECT convert_from(descriptor,'UTF8')::jsonb->>'commitment' FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2",&[&case.f.account,&call]).await.unwrap().get::<_,String>(0);
    assert_eq!(action, "sensitive");
    let debit = case
        .f
        .db
        .query_one(
            "SELECT calls,units FROM workflow_routine_period_debits WHERE account_id=$1",
            &[&case.f.account],
        )
        .await
        .unwrap();
    assert_eq!(debit.get::<_, i64>(0), 1);
    assert_eq!(debit.get::<_, i64>(1), 5);
    assert_eq!(case.f.db.query_one("SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1 AND context_id=$2",&[&case.f.account,&case.header.context]).await.unwrap().get::<_,i64>(0),1);
    if takeover {
        decisions::takeover(
            &mut case.f.connect().await,
            &case.owner,
            Uuid::new_v4(),
            case.header.context,
        )
        .await
        .unwrap();
    }
    config["phase"] = json!("withdraw");
    assert_eq!(driver(config).await["refused"], true);
    let action_row=case.f.db.query_one("SELECT revision,binding_digest,record_version FROM workflow_actions WHERE account_id=$1 AND id=$2",&[&case.f.account,&call]).await.unwrap();
    let key = decisions::ActionKey {
        account_id: case.f.account,
        action_id: call,
        revision: action_row.get(0),
        binding_digest: action_row.get::<_, Vec<u8>>(1).try_into().unwrap(),
    };
    let refusal = decisions::decide(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        action_row.get(2),
        key,
        decisions::model::Decision::Approve,
    )
    .await;
    assert!(matches!(refusal, Err(owner::ConversationError::Forbidden)));
    assert!(case.f.db.query_one("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2",&[&case.f.account,&call]).await.unwrap().get::<_,bool>(0));
    if !takeover {
        publication_expiry_wait(&case, call, publishing_session).await;
    }
    server.abort();
    let _ = server.await;
    scratch.remove().unwrap();
    case.f.cleanup().await;
}

// Exercise the exact helper called by the final proposal permit, with a
// publishing session independent of the still-live policy creator session.
async fn publication_expiry_wait(case: &Case, call: Uuid, session: Uuid) {
    let mut blocker = case.f.connect().await;
    let mut caller = case.f.connect().await;
    let pid: i32 = caller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let deadline: i64 = case.f.db.query_one("UPDATE sessions SET expires_at=clock_timestamp()+interval '1500 milliseconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint", &[&session]).await.unwrap().get(0);
    let block = blocker.transaction().await.unwrap();
    block
        .query_one(
            "SELECT id FROM sessions WHERE id=$1 FOR UPDATE",
            &[&session],
        )
        .await
        .unwrap();
    let tx = caller.transaction().await.unwrap();
    let observer = async {
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let row = case.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'),floor(extract(epoch FROM clock_timestamp())*1000)::bigint", &[&pid]).await.unwrap();
            if row.get::<_, bool>(0) {
                assert!(
                    row.get::<_, i64>(1) < deadline,
                    "publishing session must be live before its observed lock wait"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < bound,
                "publication check did not reach the session row lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        while case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        block.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(
        output::publication_live(&tx, case.f.account, call),
        observer
    );
    assert!(matches!(result, Err(AuthError::Forbidden)));
    tx.rollback().await.unwrap();
}
