// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    pkcs8::EncodePrivateKey,
};
use std::{
    io::Write,
    net::{Ipv4Addr, TcpListener},
    thread,
};
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() <= 255 {
        out.extend_from_slice(&[0x81, body.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn certificate() -> (Vec<u8>, Vec<u8>) {
    let key = key();
    let algorithm = seq(&[der(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])]);
    let name = seq(&[der(
        0x31,
        &seq(&[der(6, &[0x55, 4, 3]), der(0x0c, b"localhost")]),
    )]);
    let public_algorithm = seq(&[
        der(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]),
        der(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]),
    ]);
    let mut point = vec![0];
    point.extend_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
    let san = seq(&[
        der(6, &[0x55, 0x1d, 0x11]),
        der(4, &seq(&[der(0x82, b"localhost")])),
    ]);
    let constraints = seq(&[
        der(6, &[0x55, 0x1d, 0x13]),
        der(1, &[0xff]),
        der(4, &seq(&[])),
    ]);
    let tbs = seq(&[
        der(0xa0, &der(2, &[2])),
        der(2, &[1]),
        algorithm.clone(),
        name.clone(),
        seq(&[der(0x17, b"200101000000Z"), der(0x17, b"491231235959Z")]),
        name,
        seq(&[public_algorithm, der(3, &point)]),
        der(0xa3, &seq(&[san, constraints])),
    ]);
    let signature: Signature = key.sign(&tbs);
    let mut signature_bits = vec![0];
    signature_bits.extend_from_slice(signature.to_der().as_bytes());
    (
        seq(&[tbs, algorithm, der(3, &signature_bits)]),
        key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
    )
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        // Linux security fixtures use the operating system's scratch root,
        // independent of caller-selected TMPDIR/TMP/TEMP paths.
        #[cfg(target_os = "linux")]
        let root = Path::new("/tmp").canonicalize().unwrap();
        #[cfg(not(target_os = "linux"))]
        let root = std::env::temp_dir().canonicalize().unwrap();
        let root = root.to_str().unwrap();
        if root.contains("../") || root.contains("..\\") {
            panic!("canonical fixture root contains parent traversal syntax");
        }
        let path = Path::new(root).join(format!("external-authority-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&path).unwrap();
        assert!(path.canonicalize().unwrap().starts_with(root));
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_fixture_root_is_independent_of_caller_temp_paths_and_private() {
    use std::os::unix::fs::PermissionsExt;
    const CHILD: &str = "ZT_EXTERNAL_FIXTURE_ROOT_TEST";
    if std::env::var_os(CHILD).is_some() {
        let scratch = Scratch::new();
        assert!(
            scratch
                .0
                .starts_with(Path::new("/tmp").canonicalize().unwrap())
        );
        assert_eq!(
            fs::metadata(&scratch.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        return;
    }
    let scratch = Scratch::new();
    let uncreated = scratch.0.join("uncreated-temp-root");
    assert!(!uncreated.exists());
    let mut child = std::process::Command::new("/proc/self/exe")
        .args([
            "--exact",
            "failover_external::tests::linux_fixture_root_is_independent_of_caller_temp_paths_and_private",
        ])
        .env(CHILD, "1")
        .env("TMPDIR", &uncreated)
        .env("TMP", &uncreated)
        .env("TEMP", &uncreated)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "caller temp paths must not select the Linux fixture root"
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("private fixture root probe exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn signed(request: Request, reply: Reply) -> Receipt {
    let signature: Signature = key().sign(&transcript(&request, &reply).unwrap());
    Receipt {
        request,
        reply,
        signature: STANDARD.encode(signature.to_bytes()),
    }
}

/// Real TLS fixture, with a deliberately separate fsynced authority state file.
/// Synthetic host fences represent an isolated watchdog, not physical host proof.
fn server(
    mut respond: impl FnMut(Request) -> Option<Receipt> + Send + 'static,
    calls: usize,
) -> (reqwest::Url, reqwest::Certificate, thread::JoinHandle<()>) {
    let (cert, secret) = certificate();
    let trusted = reqwest::Certificate::from_der(&cert).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            secret,
        )),
    )
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for _ in 0..calls {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config.clone())).unwrap(),
                socket,
            );
            let mut bytes = Vec::new();
            let (end, length) = loop {
                let mut chunk = [0; 1024];
                let Ok(n) = stream.read(&mut chunk) else {
                    break (0, 0);
                };
                if n == 0 {
                    break (0, 0);
                }
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                    assert!(headers.contains(&format!("Bearer {}", "s".repeat(32))));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
                assert!(bytes.len() <= MAX_WIRE);
            };
            if end == 0 {
                continue;
            }
            while bytes.len() < end + length {
                let mut chunk = [0; 1024];
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let request = serde_json::from_slice(&bytes[end..end + length]).unwrap();
            if let Some(receipt) = respond(request) {
                let body = serde_json::to_vec(&receipt).unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        }
    });
    (
        format!("https://localhost:{port}/authority")
            .parse()
            .unwrap(),
        trusted,
        handle,
    )
}
fn authority(url: reqwest::Url, certificate: reqwest::Certificate) -> Authority {
    Authority {
        namespace: "fixture-deployment".into(),
        url,
        key: *key().verifying_key(),
        bearer: zeroize::Zeroizing::new("s".repeat(32)),
        client: reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .add_root_certificate(certificate)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap(),
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        timeout: Duration::from_secs(2),
        high_water: 1,
        failed: false,
    }
}
#[derive(Default, Serialize, Deserialize)]
struct Durable {
    epoch: u64,
    fence: Option<u64>,
}
fn durable(path: &Path, operation: &Operation) -> Reply {
    let mut state: Durable = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let reply = match operation {
        Operation::Fence { epoch, .. } => match state.fence {
            Some(holder) if holder == *epoch => Reply::AlreadyFenced { epoch: holder },
            Some(holder) => Reply::CompetingFence { epoch: holder },
            None => {
                state.fence = Some(*epoch);
                Reply::Fenced { epoch: *epoch }
            }
        },
        Operation::Status { .. } => state
            .fence
            .map_or(Reply::Unfenced, |epoch| Reply::Fenced { epoch }),
        Operation::ReadEpoch => Reply::Epoch { epoch: state.epoch },
        Operation::RecordEpoch { epoch } if *epoch > state.epoch => {
            state.epoch = *epoch;
            Reply::Recorded { epoch: *epoch }
        }
        Operation::RecordEpoch { .. } => Reply::RefusedEpoch { epoch: state.epoch },
    };
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&serde_json::to_vec(&state).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    reply
}

#[test]
fn lost_fence_ack_restart_replays_exact_token_without_replacing_fence() {
    let scratch = Scratch::new();
    let path = scratch.0.join("state");
    fs::write(&path, br#"{"epoch":4,"fence":null}"#).unwrap();
    let owned = path.clone();
    let (url, ca, handle) = server(
        move |request| {
            durable(&owned, &request.operation);
            None
        },
        1,
    );
    let mut adapter = SharedAuthority(Arc::new(Mutex::new(authority(url, ca))));
    let token = FenceToken::for_promotion(5);
    assert_eq!(
        adapter.fence_host("site-a", token),
        HostFenceOutcome::RefusedUnconfirmed
    );
    handle.join().unwrap();
    drop(adapter);
    let owned = path.clone();
    let (url, ca, handle) = server(
        move |request| {
            let reply = durable(&owned, &request.operation);
            Some(signed(request, reply))
        },
        3,
    );
    let mut adapter = SharedAuthority(Arc::new(Mutex::new(authority(url, ca))));
    assert_eq!(
        adapter.fence_status("site-a"),
        FenceStatus::Fenced { token }
    );
    assert_eq!(
        adapter.fence_host("site-a", token),
        HostFenceOutcome::AlreadyFenced { token }
    );
    assert_eq!(
        adapter.fence_host("site-a", FenceToken::for_promotion(6)),
        HostFenceOutcome::RefusedCompetingFence { holder: token }
    );
    handle.join().unwrap();
}

#[test]
fn independent_epoch_survives_ack_loss_and_client_authority_restart() {
    let scratch = Scratch::new();
    let path = scratch.0.join("state");
    fs::write(&path, br#"{"epoch":4,"fence":5}"#).unwrap();
    let owned = path.clone();
    let (url, ca, handle) = server(
        move |request| {
            durable(&owned, &request.operation);
            None
        },
        1,
    );
    let mut adapter = SharedAuthority(Arc::new(Mutex::new(authority(url, ca))));
    assert_eq!(
        adapter.record_promotion(5),
        AnchorRecord::RefusedUnconfirmed
    );
    handle.join().unwrap();
    drop(adapter);
    let (url, ca, handle) = server(
        move |request| {
            let reply = durable(&path, &request.operation);
            Some(signed(request, reply))
        },
        2,
    );
    let mut adapter = SharedAuthority(Arc::new(Mutex::new(authority(url, ca))));
    assert_eq!(
        adapter.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: 5 }
    );
    assert_eq!(
        adapter.record_promotion(5),
        AnchorRecord::Refused { anchored_epoch: 5 }
    );
    handle.join().unwrap();
}

#[test]
fn fresh_nonce_and_exact_operation_refuse_validly_signed_replay_or_foreign_results() {
    let (url, ca, handle) = server(
        |mut request| {
            request.nonce = Uuid::new_v4();
            Some(signed(request, Reply::Epoch { epoch: 8 }))
        },
        1,
    );
    let mut adapter = authority(url, ca);
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
    handle.join().unwrap();
    for mutate in 0..4 {
        let request = Request {
            namespace: adapter.namespace.clone(),
            nonce: Uuid::new_v4(),
            operation: Operation::Fence {
                site: "site-a".into(),
                epoch: 5,
            },
        };
        let mut receipt = signed(request.clone(), Reply::Fenced { epoch: 5 });
        match mutate {
            0 => receipt.request.namespace = "other-deployment".into(),
            1 => {
                receipt.request.operation = Operation::Status {
                    site: "site-a".into(),
                }
            }
            2 => receipt = signed(request.clone(), Reply::Fenced { epoch: 6 }),
            _ => receipt.signature = STANDARD.encode([0; 64]),
        }
        assert_eq!(adapter.verify(&request, receipt), None);
    }
}

#[test]
fn timeout_and_partition_remain_unconfirmed_without_transport_retry() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    let (url, ca, handle) = server(
        move |request| {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                thread::sleep(Duration::from_millis(2500));
            }
            Some(signed(request, Reply::Epoch { epoch: 4 }))
        },
        2,
    );
    let mut adapter = authority(url, ca);
    assert_eq!(
        adapter.call(Operation::ReadEpoch),
        Some(Reply::Epoch { epoch: 4 })
    );
    // Allow localhost's platform IPv6-to-IPv4 fallback to finish before
    // the delayed response; this checks an acknowledged request, not DNS.
    adapter.timeout = Duration::from_millis(1500);
    let start = std::time::Instant::now();
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
    assert!(start.elapsed() < Duration::from_millis(2200));
    handle.join().unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
}

#[test]
fn signed_epoch_rollback_latches_refusal_even_if_authority_recovers() {
    let (url, ca, handle) = server(
        |request| Some(signed(request, Reply::Epoch { epoch: 4 })),
        1,
    );
    let mut adapter = authority(url, ca);
    adapter.high_water = 5;
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
    handle.join().unwrap();
    assert!(adapter.failed);
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
}

#[test]
fn concurrent_promoters_observe_one_durable_fence_holder() {
    let scratch = Scratch::new();
    let path = scratch.0.join("state");
    fs::write(&path, br#"{"epoch":4,"fence":null}"#).unwrap();
    let (url, ca, handle) = server(
        move |request| {
            let reply = durable(&path, &request.operation);
            Some(signed(request, reply))
        },
        2,
    );
    let first = authority(url.clone(), ca.clone());
    let second = authority(url, ca);
    let threads: Vec<_> = [(first, 5), (second, 6)]
        .into_iter()
        .map(|(authority, epoch)| {
            thread::spawn(move || {
                let mut shared = SharedAuthority(Arc::new(Mutex::new(authority)));
                shared.fence_host("site-a", FenceToken::for_promotion(epoch))
            })
        })
        .collect();
    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, HostFenceOutcome::Fenced { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, HostFenceOutcome::RefusedCompetingFence { .. }))
            .count(),
        1
    );
    handle.join().unwrap();
}

#[test]
fn untrusted_tls_and_oversized_signed_receipts_are_not_authority() {
    let (url, ca, handle) = server(
        |request| Some(signed(request, Reply::Epoch { epoch: 4 })),
        1,
    );
    let mut adapter = authority(url, ca);
    adapter.client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    assert_eq!(adapter.call(Operation::ReadEpoch), None);
    handle.join().unwrap();
    let (url, ca, handle) = server(
        |request| {
            let mut receipt = signed(request, Reply::Epoch { epoch: 4 });
            receipt.signature = "a".repeat(MAX_WIRE + 1);
            Some(receipt)
        },
        1,
    );
    assert_eq!(authority(url, ca).call(Operation::ReadEpoch), None);
    handle.join().unwrap();
}

#[test]
fn private_configuration_refuses_missing_unknown_insecure_and_unbounded_values() {
    let scratch = Scratch::new();
    let config = scratch.0.join("config");
    let bearer = scratch.0.join("bearer");
    fs::write(&bearer, "s".repeat(32)).unwrap();
    let valid = serde_json::json!({ "namespace":"fixture-deployment", "url":"https://example.test/authority",
        "public_key_base64":STANDARD.encode(key().verifying_key().to_sec1_point(false).as_bytes()),
        "bearer_file":bearer, "timeout_ms":1000, "minimum_epoch":4 });
    for (field, value) in [
        ("url", serde_json::json!("http://example.test/authority")),
        (
            "url",
            serde_json::json!("https://example.test/authority?credential=value"),
        ),
        ("timeout_ms", serde_json::json!(5001)),
        ("minimum_epoch", serde_json::json!(0)),
        ("namespace", serde_json::json!("../foreign")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        fs::write(&config, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(Authority::load(&config).is_err());
    }
    fs::write(&config, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(Authority::load(&config).is_ok());
    fs::remove_file(&bearer).unwrap();
    assert!(Authority::load(&config).is_err());
}

#[test]
fn bounded_configuration_files_require_regular_files_and_preserve_byte_limits() {
    let scratch = Scratch::new();
    assert!(bounded_file(&scratch.0, 4).is_err());
    let file = scratch.0.join("bounded");
    fs::write(&file, b"four").unwrap();
    assert_eq!(bounded_file(&file, 4).unwrap(), b"four");
    assert!(bounded_file(&file, 3).is_err());
    fs::write(&file, []).unwrap();
    assert!(bounded_file(&file, 0).unwrap().is_empty());
    let nested = scratch.0.join("nested");
    fs::create_dir(&nested).unwrap();
    assert!(
        bounded_file(&nested.join("..").join("bounded"), 0)
            .unwrap()
            .is_empty()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_configuration_file_refuses_fifo_without_waiting_for_a_writer() {
    const CHILD_PATH: &str = "ZT_EXTERNAL_AUTHORITY_FIFO_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        assert!(bounded_file(Path::new(&path), 4).is_err());
        return;
    }
    let scratch = Scratch::new();
    let fifo = scratch.0.join("credential");
    // Only the generated fixture's exact credential path may reach mkfifo;
    // terminate options independently of its absolute parent directory.
    let owned_targets = [scratch.0.join("credential")];
    if !owned_targets.contains(&fifo) {
        panic!("FIFO target is outside the generated fixture");
    }
    assert!(
        std::process::Command::new("mkfifo")
            .arg("--")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // Linux resolves this kernel-owned link to this running test executable;
    // no caller-provided executable path or shell is used.
    let mut child = std::process::Command::new("/proc/self/exe")
        .args([
            "--exact",
            "failover_external::tests::bounded_configuration_file_refuses_fifo_without_waiting_for_a_writer",
            "--nocapture",
        ])
        .env(CHILD_PATH, &fifo)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("configuration loader waited for a FIFO writer");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
