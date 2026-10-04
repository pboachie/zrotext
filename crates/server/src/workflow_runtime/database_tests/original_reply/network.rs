// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::workflow_runtime::routines::tests::service::scratch::Scratch;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::{net::Ipv4Addr, path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command};

// Node's entrypoint resolver does not accept Rust's Windows verbatim spelling.
// Only a canonical local drive path may lose that prefix; UNC/device paths
// remain unsupported rather than acquiring a different filesystem meaning.
fn node_script_path(path: &Path) -> Result<std::path::PathBuf, &'static str> {
    let raw = path.to_str().ok_or("unsupported fixture script path")?;
    if !path.is_absolute() || raw.contains("..") {
        return Err("unsupported fixture script path");
    }
    if cfg!(windows) {
        let candidate = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        let bytes = candidate.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'\\' | b'/')
        {
            return Err("unsupported fixture script path");
        }
        return Ok(candidate.into());
    }
    Ok(path.into())
}

#[test]
fn node_entrypoint_preserves_canonical_local_file_and_refuses_namespace_aliases() {
    let canonical = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/workflow_runtime/database_tests/original_reply/network.rs")
        .canonicalize()
        .unwrap();
    let normal = node_script_path(&canonical).unwrap();
    assert_eq!(normal.canonicalize().unwrap(), canonical);
    assert_eq!(node_script_path(&normal).unwrap(), normal);
    if cfg!(windows) {
        assert!(!normal.to_str().unwrap().starts_with(r"\\?\"));
        for raw in [
            r"\\?\UNC\synthetic\owned",
            r"\\.\synthetic",
            r"\\?\Volume{synthetic}\owned",
            r"\\?\synthetic",
        ] {
            assert!(node_script_path(Path::new(raw)).is_err());
        }
    }
    assert!(node_script_path(Path::new("relative-fixture")).is_err());
}

pub(super) fn jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_sec1_point(false);
    json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap()),"d":URL_SAFE_NO_PAD.encode(key.to_bytes()),"ext":true})
}
fn known_runtime_stderr(bytes: &[u8]) -> bool {
    if bytes.len() > 512 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.lines().all(|line|{
   if line=="(Use `node --trace-warnings ...` to show where the warning was created)" {return true}
   let Some(rest)=line.strip_prefix("(node:")else{return false};
   let Some((pid,warning))=rest.split_once(") ")else{return false};
   !pid.is_empty()&&pid.bytes().all(|b|b.is_ascii_digit())&&warning=="ExperimentalWarning: SQLite is an experimental feature and might change at any time"
 })
}
fn refusal_diagnostic(bytes: &[u8]) -> &'static str {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return "unavailable";
    };
    if bytes.len() > 1024 {
        return "unavailable";
    }
    for line in text.lines() {
        let Some(fields) = line.strip_prefix("original reply fixture phase=") else {
            continue;
        };
        let Some((phase, code)) = fields.split_once(";code=") else {
            return "unavailable";
        };
        if ![
            "input",
            "history",
            "scope",
            "seed_prepare",
            "transport",
            "client",
            "receiver",
            "page",
            "read",
            "consume",
            "recover",
        ]
        .contains(&phase)
        {
            return "unavailable";
        }
        return match code {
            "manifest_chain" => "manifest_chain",
            "manifest_time" => "manifest_time",
            "reader_authority" => "reader_authority",
            "signer_authority" => "signer_authority",
            "recipient_identity" => "recipient_identity",
            "recipient_order" => "recipient_order",
            _ => "unavailable",
        };
    }
    "unavailable"
}
fn refusal_stage(bytes: &[u8]) -> &'static str {
    if bytes.len() > 1024 {
        return "unavailable";
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return "unavailable";
    };
    for line in text.lines() {
        let Some(fields) = line.strip_prefix("original reply fixture phase=") else {
            continue;
        };
        let Some((phase, code)) = fields.split_once(";code=") else {
            return "unavailable";
        };
        if ![
            "unavailable",
            "manifest_chain",
            "manifest_time",
            "reader_authority",
            "signer_authority",
            "recipient_identity",
            "recipient_order",
        ]
        .contains(&code)
        {
            return "unavailable";
        }
        return match phase {
            "input" => "input",
            "history" => "history",
            "scope" => "scope",
            "seed_prepare" => "seed_prepare",
            "transport" => "transport",
            "client" => "client",
            "receiver" => "receiver",
            "page" => "page",
            "read" => "read",
            "consume" => "consume",
            "recover" => "recover",
            _ => "unavailable",
        };
    }
    "unavailable"
}
#[test]
fn subprocess_diagnostics_accept_only_known_sqlite_warning_and_refuse_secret_canary() {
    assert!(known_runtime_stderr(b""));
    assert!(known_runtime_stderr(b"(node:123) ExperimentalWarning: SQLite is an experimental feature and might change at any time\n(Use `node --trace-warnings ...` to show where the warning was created)\n"));
    assert!(!known_runtime_stderr(b"synthetic-private-canary"));
    assert!(!known_runtime_stderr(
        b"(node:123) ExperimentalWarning: synthetic-private-canary"
    ));
    assert!(!known_runtime_stderr(&[255]));
    assert_eq!(
        refusal_diagnostic(b"original reply fixture phase=seed_prepare;code=recipient_identity\n"),
        "recipient_identity"
    );
    assert_eq!(
        refusal_diagnostic(
            b"original reply fixture phase=synthetic-private-canary;code=recipient_identity\n"
        ),
        "unavailable"
    );
    assert_eq!(
        refusal_diagnostic(
            b"original reply fixture phase=seed_prepare;code=synthetic-private-canary\n"
        ),
        "unavailable"
    );
    assert_eq!(
        refusal_stage(b"original reply fixture phase=history;code=manifest_chain\n"),
        "history"
    );
    assert_eq!(
        refusal_stage(b"original reply fixture phase=history;code=synthetic-private-canary\n"),
        "unavailable"
    );
}
async fn driver(input: Value, cwd: &Path) -> Value {
    run_driver(input, cwd, Driver::OriginalReply).await
}
pub(super) enum Driver {
    OriginalReply,
    OriginalRoutine,
}
pub(super) async fn run_driver(input: Value, cwd: &Path, fixture: Driver) -> Value {
    let relative = match fixture {
        Driver::OriginalReply => "../../sdk/typescript/test/original-reply-service-driver.mjs",
        Driver::OriginalRoutine => {
            "../../sdk/typescript/test/customer-routine-original-service-driver.mjs"
        }
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .canonicalize()
        .unwrap();
    let node_script = node_script_path(&script).unwrap();
    assert_eq!(node_script.canonicalize().unwrap(), script);
    let mut command = Command::new("node");
    command.env_clear();
    for name in ["PATH", "SystemRoot", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let node_script = node_script_path(&script).unwrap();
    assert_eq!(node_script.canonicalize().unwrap(), script);
    let mut child = command
        .arg(node_script)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&input).unwrap());
    assert!(bytes.len() <= 262144);
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&bytes).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("bounded original reader driver")
        .unwrap();
    assert!(
        output.status.success(),
        "original reader driver refused: phase={} code={}",
        refusal_stage(&output.stderr),
        refusal_diagnostic(&output.stderr)
    );
    assert!(
        known_runtime_stderr(&output.stderr),
        "unexpected original reader diagnostic"
    );
    assert!(output.stdout.len() <= 524288);
    serde_json::from_slice(&output.stdout).expect("closed original reader driver response")
}
pub(super) async fn configuration(f: &OriginalCase, event: Uuid) -> Value {
    let rows=f.case.f.db.query("SELECT manifest,accepted_at_ms FROM original_reply_manifest_history WHERE account_id=$1 ORDER BY version",&[&f.case.f.account]).await.unwrap();
    let history:Vec<Value>=rows.into_iter().rev().take(1).map(|r|json!({"manifest_b64":STANDARD.encode(r.get::<_,Vec<u8>>(0)),"accepted_at_ms":r.get::<_,i64>(1).to_string()})).collect();
    json!({"phase":"seed","root_anchor":{"pin_b64":STANDARD.encode(&f.case.f.pin),"fingerprint_hex":decisions::descriptor::hex(&Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(),&f.case.f.pin].concat())),"highwater_version":u64::from_be_bytes(f.case.f.bytes[29..37].try_into().unwrap()).to_string(),"highwater_digest":decisions::descriptor::hex(&Sha256::digest(&f.case.f.bytes[..f.case.f.bytes.len()-64]))},
      "accepted_manifests":history,"scope":{"account_id":f.case.f.account,"device_id":f.case.f.device,"line_id":f.case.f.line,"interval_id":f.statement.interval,"connector_id":f.case.request.connector,"read_grant_id":f.read_grant,"reader_id":decisions::descriptor::hex(&f.statement.integration_readers[0].key_id),"peer":f.statement.peer},"event_id":event})
}
pub(super) async fn capture(f: &OriginalCase, input: &mut Value, scratch: &Scratch, event: Uuid) {
    let now: i64 = f
        .case
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    input["phone_private_jwk"] = jwk(&f.case.f.event_signer);
    input["observed_at_ms"] = json!(now.to_string());
    if input.get("local_sequence").is_none() {
        input["local_sequence"] = json!("1");
    }
    input["cek_b64"] = json!(STANDARD.encode(rand::random::<[u8; 32]>()));
    input["nonce_b64"] = json!(STANDARD.encode(rand::random::<[u8; 12]>()));
    let readers = activation::readers(&f.statement);
    input["recipients"]=json!(readers.iter().map(|r|{
      let point=if r.role==2 { f.case.f.archive_key.verifying_key().to_sec1_point(false) } else {f.case.reader_key.verifying_key().to_sec1_point(false)};
      json!({"role":r.role,"key_id":decisions::descriptor::hex(&r.key_id),"point_b64":STANDARD.encode(point.as_bytes()),"ekm_b64":STANDARD.encode(rand::random::<[u8;32]>())})
    }).collect::<Vec<_>>());
    let seeded = driver(input.clone(), &scratch.path).await;
    let envelope = STANDARD
        .decode(seeded["envelope_b64"].as_str().unwrap())
        .unwrap();
    crate::sealed_inbound::ingest::ingest_conversation(
        &mut f.case.f.connect().await,
        f.case.f.session(),
        f.case.f.line,
        1,
        &f.case.f.bytes,
        &envelope,
        activation::CaptureInterval {
            interval: f.statement.interval,
            activation_digest: f.statement.activation_digest,
        },
    )
    .await
    .unwrap();
    assert_eq!(f.case.f.db.query_one("SELECT count(*) FROM conversation_inbound_provenance WHERE account_id=$1 AND event_id=$2",&[&f.case.f.account,&event]).await.unwrap().get::<_,i64>(0),1);
}

pub(super) struct Https {
    pub(super) origin: String,
    pub(super) ca: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Https {
    pub(super) async fn start(app: axum::Router) -> Self {
        let plain = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = plain.local_addr().unwrap();
        let http = tokio::spawn(async move { axum::serve(plain, app).await.unwrap() });
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
        let cert = params.self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let tls = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                   socket=listener.accept()=>{let (socket,_)=socket.unwrap();let acceptor=acceptor.clone();children.spawn(async move{
                     if let Ok(Ok(mut tls))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await
                       && let Ok(mut plain)=tokio::net::TcpStream::connect(upstream).await {
                         let _=tokio::time::timeout(Duration::from_secs(15),tokio::io::copy_bidirectional(&mut tls,&mut plain)).await;
                     }
                   });},
                   _=children.join_next(),if !children.is_empty()=>{}
                }
            }
        });
        let encoded = STANDARD.encode(cert.der());
        let lines = encoded
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let ca = format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n");
        Self {
            origin: format!("https://{}:{port}", Ipv4Addr::LOCALHOST),
            ca,
            tasks: vec![http, tls],
        }
    }
    pub(super) async fn close(self) {
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual original reader HTTPS/SDK/PG"]
async fn original_phone_selected_ciphertext_opens_over_https_and_owner_review_survives_consumer_restart()
 {
    let mut f = OriginalCase::new().await;
    let scratch = Scratch::create().unwrap();
    let event = Uuid::new_v4();
    let mut input = configuration(&f, event).await;
    capture(&f, &mut input, &scratch, event).await;
    let issued = f.issue().await;
    let separator = if f.case.f.url.contains('?') { '&' } else { '?' };
    let state = service::http::StateData {
        database_url: format!(
            "{}{separator}options=-csearch_path%3D{}",
            f.case.f.url, f.case.f.schema
        ),
        hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    };
    let tls = Https::start(service::http::router(state, true)).await;
    input["phase"] = json!("exercise");
    input["origin"] = json!(tls.origin);
    input["ca_pem"] = json!(tls.ca);
    input["role3_private_jwk"] = jwk(&f.case.reader_key);
    input["read_credential"] = json!(issued.token.as_str());
    input["consume_request"] = json!({"active_request_id":null,"descriptor":null});
    let first = driver(input.clone(), &scratch.path).await;
    assert_eq!(first["outcome"]["disposition"], "owner_review");
    input["phase"] = json!("recover");
    let replay = driver(input, &scratch.path).await;
    assert_eq!(
        first["outcome"]["consumption_id"],
        replay["outcome"]["consumption_id"]
    );
    assert_eq!(
        f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1",
                &[&f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    tls.close().await;
    scratch.remove().unwrap();
    f.case.f.cleanup().await;
}

// The request is registered against an actually owner-approved, confirmed and
// issued source message. No phone fetch/intent/SMS operation is performed.
pub(super) async fn source_request(f: &mut OriginalCase) -> Uuid {
    let owner = f.case.owner.clone();
    source_request_with_owner(f, owner).await
}
pub(super) async fn source_request_with_owner(
    f: &mut OriginalCase,
    request_owner: auth::SessionPrincipal,
) -> Uuid {
    use crate::http_owner_conversations::context::decisions::model::Decision;
    let mut descriptor = f.case.descriptor().await;
    descriptor.window_id = crate::workflow_runtime::IMMEDIATE_WINDOW_ID.into();
    let action = decisions::register(
        &mut f.case.f.connect().await,
        &f.case.owner,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    let approved = decisions::decide(
        &mut f.case.f.connect().await,
        &f.case.owner,
        Uuid::new_v4(),
        action.record_version,
        action.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    issued_request_with_owner(f, approved, request_owner).await
}
pub(super) async fn issued_request(f: &mut OriginalCase, approved: decisions::ActionState) -> Uuid {
    let owner = f.case.owner.clone();
    issued_request_with_owner(f, approved, owner).await
}
async fn issued_request_with_owner(
    f: &mut OriginalCase,
    approved: decisions::ActionState,
    request_owner: auth::SessionPrincipal,
) -> Uuid {
    let dispatch = Uuid::new_v4();
    let (bound, message) = f.case.bind_message(approved, dispatch).await;
    let request = Uuid::new_v4();
    service::consumption::register_request(
        &mut f.case.f.connect().await,
        &request_owner,
        &service::consumption::ActiveRequest {
            request_id: request,
            action: bound.key,
            message_id: message,
            expires_at_ms: {
                let tx = f.case.f.db.transaction().await.unwrap();
                let d = decisions::store::descriptor(&tx, bound.key).await.unwrap();
                d.expires_at_ms().unwrap() - 1
            },
            maximum_turns: 1,
        },
    )
    .await
    .unwrap();
    let mut client = f.case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut permit = decisions::lock_approved(&tx, &f.case.owner, bound.key)
        .await
        .unwrap();
    permit.mark_dispatching(message, dispatch).await.unwrap();
    permit.recheck().await.unwrap();
    drop(permit);
    tx.commit().await.unwrap();
    f.case
        .f
        .db
        .batch_execute("UPDATE deployment_authority SET dispatch_enabled=TRUE")
        .await
        .unwrap();
    let session = zrotext_delivery_store::SessionRecord {
        account_id: f.case.f.account,
        device_id: f.case.f.device,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        epoch: 1,
        deployment_epoch: 1,
    };
    let ready = crate::sealed_dispatch::wire::Ready {
        grant_version: 1,
        connection_epoch: 1,
        line_id: f.case.f.line,
        binding_generation: f.case.header.binding_generation,
        reader_key_id: URL_SAFE_NO_PAD.encode(f.case.phone_reader.unwrap()),
    };
    let policy = crate::alpha_policy::AlphaPolicy::parse(
        Some("true"),
        Some(&f.case.f.account.to_string()),
        Some("+12"),
    )
    .unwrap();
    let grant =
        crate::sealed_dispatch::grant(&mut f.case.f.connect().await, &session, &ready, &policy)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(grant.message_id, message);
    request
}

// Only multi-outbound fixtures need to release the occupied device slot.
// Synthetic submission receipts use the real attempt lifecycle; they neither
// report delivery nor close the independently registered reply request.
pub(super) async fn submit_issued_request(f: &OriginalCase, request: Uuid) {
    use zrotext_delivery_store::{DeliveryStore, RadioEvent};
    use zrotext_domain::{Evidence, MessageState};

    let row = f.case.f.db.query_one(
        "SELECT fence.device_id,fence.message_id,fence.attempt_id FROM original_reply_requests request JOIN dispatch_fences fence ON (fence.account_id,fence.message_id)=(request.account_id,request.message_id) WHERE request.account_id=$1 AND request.request_id=$2 AND fence.outcome='granted'",
        &[&f.case.f.account, &request],
    ).await.unwrap();
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: f.case.f.account,
        device_id: row.get(0),
        message_id: row.get(1),
        attempt_id: row.get(2),
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0),
        segment_index: None,
        segment_count: None,
    };
    let mut delivery_client = f.case.f.connect().await;
    let mut store = DeliveryStore::new(&mut delivery_client);
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        MessageState::Submitting
    );
    let sent = RadioEvent {
        event_id: Uuid::new_v4(),
        evidence: Evidence::SentCallbackOk,
        observed_at_ms: f
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0),
        segment_index: Some(0),
        segment_count: Some(1),
        ..intent
    };
    assert_eq!(
        store.record_radio_event(sent).await.unwrap(),
        MessageState::Submitted
    );
    let retained: bool = f.case.f.db.query_one(
        "SELECT EXISTS(SELECT 1 FROM original_reply_requests WHERE account_id=$1 AND request_id=$2 AND stopped_ms IS NULL)",
        &[&f.case.f.account, &request],
    ).await.unwrap().get(0);
    assert!(retained, "submission must retain the active reply request");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual original proposal HTTPS/SDK/PG"]
async fn original_reply_unique_issued_request_proposes_once_and_restart_only_recovers_receipt() {
    let mut f = OriginalCase::new().await;
    let request = source_request(&mut f).await;
    let scratch = Scratch::create().unwrap();
    let event = Uuid::new_v4();
    let mut input = configuration(&f, event).await;
    capture(&f, &mut input, &scratch, event).await;
    let read = f.issue().await;
    f.bind_workflow_request(read.grant_id).await;
    f.case.request.permissions =
        Permissions::new(&[Operation::Propose, Operation::ContextContent]).unwrap();
    f.case.request.content_envelope = Some(f.case.projection().await);
    let output = f.case.issue_another().await;
    let mut descriptor = f.case.descriptor().await;
    // Owner-selected output cannot outlive either independently granted source
    // authority. This narrows the fixture descriptor, never the service checks.
    let deadline: i64=f.case.f.db.query_one("SELECT LEAST(g.expires_ms,r.expires_ms) FROM original_reply_grants g JOIN original_reply_requests r ON r.account_id=g.account_id WHERE g.account_id=$1 AND g.grant_id=$2 AND r.request_id=$3", &[&f.case.f.account,&read.grant_id,&request]).await.unwrap().get(0);
    descriptor.expires_at = deadline / 1000;

    let separator = if f.case.f.url.contains('?') { '&' } else { '?' };
    let state = service::http::StateData {
        database_url: format!(
            "{}{separator}options=-csearch_path%3D{}",
            f.case.f.url, f.case.f.schema
        ),
        hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    };
    let tls = Https::start(service::http::router(state, true)).await;
    input["phase"] = json!("exercise");
    input["origin"] = json!(tls.origin);
    input["ca_pem"] = json!(tls.ca);
    input["role3_private_jwk"] = jwk(&f.case.reader_key);
    input["read_credential"] = json!(read.token.as_str());
    input["output_credential"] = json!(output.token.as_str());
    input["consume_request"] = json!({"active_request_id":request,"descriptor":descriptor});
    let first = driver(input.clone(), &scratch.path).await;
    assert_eq!(first["outcome"]["disposition"], "proposal");
    assert_eq!(first["outcome"]["active_request_id"], request.to_string());
    input["phase"] = json!("recover");
    let replay = driver(input, &scratch.path).await;
    assert_eq!(first["outcome"], replay["outcome"]);
    let row=f.case.f.db.query_one("SELECT (SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1),(SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT consumed_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2)",&[&f.case.f.account,&request]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i32>(2), 1);
    let action: decisions::ActionKey =
        serde_json::from_value(first["outcome"]["action"].clone()).unwrap();
    assert!(
        f.case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&f.case.f.account, &action.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let record: i64 = f
        .case
        .f
        .db
        .query_one(
            "SELECT record_version FROM workflow_actions WHERE account_id=$1 AND id=$2",
            &[&f.case.f.account, &action.action_id],
        )
        .await
        .unwrap()
        .get(0);
    service::withdraw(&mut f.case.f.connect().await, &f.case.owner, read.grant_id)
        .await
        .unwrap();
    assert!(
        !f.case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&f.case.f.account, &action.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(matches!(
        decisions::decide(
            &mut f.case.f.connect().await,
            &f.case.owner,
            Uuid::new_v4(),
            record,
            action,
            decisions::model::Decision::Approve
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    tls.close().await;
    scratch.remove().unwrap();
    f.case.f.cleanup().await;
}
