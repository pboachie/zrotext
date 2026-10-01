// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use p256::pkcs8::EncodePrivateKey;
use std::net::{Ipv4Addr, TcpListener};
use tower::ServiceExt;
use zrotext_failover_quorum::{
    decision::{FailoverConfig, SiteFenceState},
    executor::ObservationSource,
    observe::{MemberObserver, Observation},
    store::StoreObservationSource,
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("quorum-adapters-{}", uuid::Uuid::new_v4())))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn record(member: &str, sequence: u64, at: u64) -> JournalRecord {
    JournalRecord {
        sequence,
        report: MemberReport {
            member_id: member.into(),
            observed_at_ms: at,
            writer: WriterObservation::Unreachable,
            writer_site_fence: Some(SiteFenceState {
                enabled: false,
                draining: true,
            }),
            writer_stop_confirmed: Some(true),
            standby_ready: Some(true),
            former_writer_healthy: None,
        },
    }
}
fn endpoint(member: &str) -> Endpoint {
    Endpoint {
        member: member.into(),
        url: "https://localhost/observation".parse().unwrap(),
        key: *key().verifying_key(),
        bearer: "synthetic-credential-for-test-only".into(),
    }
}

#[test]
fn signed_domain_member_and_content_are_pinned() {
    let wire = sign(
        "synthetic-quorum",
        "report",
        &record("member-a", 1, 20),
        &key(),
    )
    .unwrap();
    assert!(
        verify(
            &wire,
            "synthetic-quorum",
            "report",
            "member-a",
            key().verifying_key()
        )
        .is_ok()
    );
    for (domain, purpose, member) in [
        ("other-quorum", "report", "member-a"),
        ("synthetic-quorum", "probe", "member-a"),
        ("synthetic-quorum", "report", "member-b"),
    ] {
        assert!(verify(&wire, domain, purpose, member, key().verifying_key()).is_err());
    }
    let wrong_key = SigningKey::from_slice(&[8; 32]).unwrap();
    assert!(
        verify(
            &wire,
            "synthetic-quorum",
            "report",
            "member-a",
            wrong_key.verifying_key()
        )
        .is_err()
    );
    let mut modified = wire.clone();
    modified.journal = modified.journal.replace("stop=true", "stop=false");
    assert!(
        verify(
            &modified,
            "synthetic-quorum",
            "report",
            "member-a",
            key().verifying_key()
        )
        .is_err()
    );
}

#[test]
fn replay_checkpoint_survives_restart_reorder_and_cross_member_sequences() {
    let scratch = Scratch::new();
    let a = endpoint("member-a");
    let b = endpoint("member-b");
    let mut fence =
        ReplayFence::open(scratch.0.clone(), "synthetic-quorum", "report", &[&a, &b]).unwrap();
    let first = record("member-a", 5, 20);
    let wire = sign("synthetic-quorum", "report", &first, &key()).unwrap();
    fence.accept("member-a", &first, &wire, 20).unwrap();
    drop(fence);
    let mut fence =
        ReplayFence::open(scratch.0.clone(), "synthetic-quorum", "report", &[&a, &b]).unwrap();
    assert!(fence.accept("member-a", &first, &wire, 21).is_err());
    let older = record("member-a", 4, 21);
    let old_wire = sign("synthetic-quorum", "report", &older, &key()).unwrap();
    assert!(fence.accept("member-a", &older, &old_wire, 21).is_err());
    let other = record("member-b", 1, 21);
    let other_wire = sign("synthetic-quorum", "report", &other, &key()).unwrap();
    fence.accept("member-b", &other, &other_wire, 21).unwrap();
    let newer = record("member-a", 8, 21);
    let newer_wire = sign("synthetic-quorum", "report", &newer, &key()).unwrap();
    fence.accept("member-a", &newer, &newer_wire, 21).unwrap();
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 2);
    assert!(ReplayFence::open(scratch.0.clone(), "other-quorum", "report", &[&a, &b]).is_err());
}

#[test]
fn freshness_rejects_future_and_stale_before_advancing_replay_fence() {
    let scratch = Scratch::new();
    let endpoint = endpoint("member-a");
    let mut fence = ReplayFence::open(
        scratch.0.clone(),
        "synthetic-quorum",
        "report",
        &[&endpoint],
    )
    .unwrap();
    for (at, now, accepted) in [
        (0, 20, false),
        (20, 0, false),
        (20, 19, false),
        (20, 20 + FRESHNESS_MS + 1, false),
        (20, 20 + FRESHNESS_MS, true),
    ] {
        let report = record("member-a", 1, at);
        let wire = sign("synthetic-quorum", "report", &report, &key()).unwrap();
        assert_eq!(
            fence.accept("member-a", &report, &wire, now).is_ok(),
            accepted
        );
    }
}

#[test]
fn transport_failure_abstains_and_explicit_negative_input_never_implies_fence() {
    assert!(matches!(
        MemberObserver::new("member-a")
            .unwrap()
            .observe(abstain(), 20),
        Observation::Abstain(_)
    ));
    let mut report = record("member-a", 1, 20).report;
    report.writer_site_fence = None;
    report.writer_stop_confirmed = None;
    report.standby_ready = None;
    let Observation::Report(report) = MemberObserver::new("member-a")
        .unwrap()
        .observe(probes(report), 20)
    else {
        panic!("explicit writer result");
    };
    assert_eq!(report.writer_site_fence, None);
    assert_eq!(report.writer_stop_confirmed, None);
}

#[test]
fn committed_replay_fence_before_consensus_append_does_not_replay_after_crash() {
    let scratch = Scratch::new();
    let endpoint = endpoint("member-a");
    let mut fence = ReplayFence::open(
        scratch.0.join("replay"),
        "synthetic-quorum",
        "report",
        &[&endpoint],
    )
    .unwrap();
    let report = record("member-a", 1, 20);
    let wire = sign("synthetic-quorum", "report", &report, &key()).unwrap();
    fence.accept("member-a", &report, &wire, 20).unwrap();
    // Crash before store.record: losing the vote is safe, re-serving it is not.
    drop(fence);
    let mut fence = ReplayFence::open(
        scratch.0.join("replay"),
        "synthetic-quorum",
        "report",
        &[&endpoint],
    )
    .unwrap();
    assert!(fence.accept("member-a", &report, &wire, 21).is_err());
}

#[test]
fn corrupt_or_unwritable_replay_store_fails_closed() {
    let scratch = Scratch::new();
    let endpoint = endpoint("member-a");
    let mut fence = ReplayFence::open(
        scratch.0.clone(),
        "synthetic-quorum",
        "report",
        &[&endpoint],
    )
    .unwrap();
    fs::create_dir(scratch.0.join("member-a.pending")).unwrap();
    let report = record("member-a", 1, 20);
    let wire = sign("synthetic-quorum", "report", &report, &key()).unwrap();
    assert!(fence.accept("member-a", &report, &wire, 20).is_err());
    assert!(fence.failed);
    fs::remove_dir(scratch.0.join("member-a.pending")).unwrap();
    assert!(fence.accept("member-a", &report, &wire, 20).is_err());
    fs::write(scratch.0.join("member-a.json"), b"invalid").unwrap();
    assert!(
        ReplayFence::open(
            scratch.0.clone(),
            "synthetic-quorum",
            "report",
            &[&endpoint]
        )
        .is_err()
    );
}

#[test]
fn repeated_transport_reports_do_not_become_distinct_hysteresis_rounds() {
    let scratch = Scratch::new();
    let members = vec!["member-a".into(), "member-b".into(), "member-c".into()];
    let config = FailoverConfig::new(members.clone(), "writer", "standby").unwrap();
    let mut store = ConsensusStore::open(
        scratch.0.clone(),
        members,
        config.observation_freshness_ms(),
    )
    .unwrap();
    store.record(&record("member-a", 1, 20).report).unwrap();
    let mut source = StoreObservationSource::new(store);
    assert_eq!(source.collect(20).reports.len(), 1);
    assert!(source.collect(21).reports.is_empty());
}

#[tokio::test]
async fn report_route_requires_dedicated_bearer_and_never_serves_stale_reports() {
    let bearer = "synthetic-credential-for-test-only";
    let serving = Serving {
        token_hash: Sha256::digest(bearer.as_bytes()).into(),
        report: Arc::new(Mutex::new(Some(
            sign(
                "synthetic-quorum",
                "report",
                &record("member-a", 1, now_ms()),
                &key(),
            )
            .unwrap(),
        ))),
    };
    let app = Router::new()
        .route("/internal/failover/report", get(latest))
        .with_state(serving.clone());
    for (auth, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("Bearer wrong"), StatusCode::UNAUTHORIZED),
        (
            Some("Bearer synthetic-credential-for-test-only"),
            StatusCode::OK,
        ),
    ] {
        let mut request = Request::builder().uri("/internal/failover/report");
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = to_bytes(response.into_body(), MAX_WIRE).await.unwrap();
            let wire: Wire = serde_json::from_slice(&body).unwrap();
            verify(
                &wire,
                "synthetic-quorum",
                "report",
                "member-a",
                key().verifying_key(),
            )
            .unwrap();
        }
    }
    *serving.report.lock().unwrap() = Some(
        sign(
            "synthetic-quorum",
            "report",
            &record("member-a", 1, now_ms() - FRESHNESS_MS - 1),
            &key(),
        )
        .unwrap(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal/failover/report")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// Generate a synthetic X.509 fixture in memory; no PEM or private key is saved.
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
fn tls_server(
    body: Vec<u8>,
    status: &str,
) -> (
    reqwest::Url,
    reqwest::Certificate,
    std::thread::JoinHandle<()>,
) {
    let (cert, key) = certificate();
    let trusted = reqwest::Certificate::from_der(&cert).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
    )
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let status = status.to_string();
    let thread = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        );
        let mut request = [0; 2048];
        if stream.read(&mut request).is_err() {
            return;
        }
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    });
    (
        format!("https://localhost:{port}/observation")
            .parse()
            .unwrap(),
        trusted,
        thread,
    )
}

#[tokio::test]
async fn https_transport_validates_tls_and_bounds_body_and_auth_failure() {
    let wire = sign(
        "synthetic-quorum",
        "report",
        &record("member-a", 1, now_ms()),
        &key(),
    )
    .unwrap();
    let (url, ca, server) = tls_server(serde_json::to_vec(&wire).unwrap(), "200 OK");
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut endpoint = endpoint("member-a");
    endpoint.url = url;
    let received = fetch(&client, &endpoint).await.unwrap();
    verify(
        &received,
        "synthetic-quorum",
        "report",
        "member-a",
        key().verifying_key(),
    )
    .unwrap();
    server.join().unwrap();
    let (url, _, server) = tls_server(serde_json::to_vec(&wire).unwrap(), "200 OK");
    endpoint.url = url;
    let untrusted = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    assert!(fetch(&untrusted, &endpoint).await.is_err());
    server.join().unwrap();
    for (body, status) in [
        (vec![0; MAX_WIRE + 1], "200 OK"),
        (vec![], "401 Unauthorized"),
    ] {
        let (url, ca, server) = tls_server(body, status);
        endpoint.url = url;
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert!(fetch(&client, &endpoint).await.is_err());
        server.join().unwrap();
    }
}

#[tokio::test]
async fn configured_adapter_fetches_peers_and_probe_then_publishes_original_time() {
    let scratch = Scratch::new();
    fs::create_dir_all(&scratch.0).unwrap();
    let members = vec!["member-a".into(), "member-b".into(), "member-c".into()];
    let env = crate::failover_executor::ExecutorEnv::parse(
        Some("true"),
        Some("member-a,member-b,member-c"),
        Some("writer"),
        Some("standby"),
        Some("5000"),
        Some(scratch.0.join("store").to_str().unwrap()),
        Some("5000"),
        Some("1000"),
        Some("member-a"),
    )
    .unwrap()
    .unwrap();
    let namespace = topology_namespace(&env, "synthetic-quorum").unwrap();
    let observed_at = now_ms() - 1000;
    let probe_key = SigningKey::from_slice(&[10; 32]).unwrap();
    let b_key = SigningKey::from_slice(&[8; 32]).unwrap();
    let c_key = SigningKey::from_slice(&[9; 32]).unwrap();
    let probe_wire = sign(
        &namespace,
        "probe",
        &record("member-a", 50, observed_at),
        &probe_key,
    )
    .unwrap();
    let b_wire = sign(
        &namespace,
        "report",
        &record("member-b", 10, observed_at),
        &b_key,
    )
    .unwrap();
    let c_wire = sign(
        &namespace,
        "report",
        &record("member-c", 20, observed_at),
        &c_key,
    )
    .unwrap();
    let (probe_url, _, probe_server) =
        tls_server(serde_json::to_vec(&probe_wire).unwrap(), "200 OK");
    let (b_url, _, b_server) = tls_server(serde_json::to_vec(&b_wire).unwrap(), "200 OK");
    let (c_url, _, c_server) = tls_server(serde_json::to_vec(&c_wire).unwrap(), "200 OK");
    let signer_file = scratch.0.join("signer");
    let bearer_file = scratch.0.join("bearer");
    let ca_file = scratch.0.join("ca");
    fs::write(&signer_file, [7; 32]).unwrap();
    fs::write(&bearer_file, "synthetic-credential-for-test-only").unwrap();
    fs::write(
        &ca_file,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(certificate().0)
        ),
    )
    .unwrap();
    let entry = |member: &str, url: reqwest::Url, key: &SigningKey| serde_json::json!({"member_id":member,"url":url.as_str(),"public_key_base64":STANDARD.encode(key.verifying_key().to_sec1_bytes()),"bearer_file":bearer_file});
    let config = serde_json::json!({"namespace":"synthetic-quorum","signing_key_file":signer_file,"serving_bearer_file":bearer_file,"probe":entry("member-a",probe_url,&probe_key),"peers":[entry("member-b",b_url,&b_key),entry("member-c",c_url,&c_key)],"ca_certificate_file":ca_file});
    let config_file = scratch.0.join("adapter.json");
    // No quorum member's report key may also attest this member's probe facts.
    // Otherwise a peer can produce its own vote and induce a second local vote.
    for reused in [key(), b_key.clone(), c_key.clone()] {
        let mut reused_key = config.clone();
        reused_key["probe"]["public_key_base64"] =
            serde_json::json!(STANDARD.encode(reused.verifying_key().to_sec1_bytes()));
        fs::write(&config_file, serde_json::to_vec(&reused_key).unwrap()).unwrap();
        assert!(Adapters::load(&config_file, &env).is_err());
    }
    fs::write(&config_file, serde_json::to_vec(&config).unwrap()).unwrap();
    let adapters = Adapters::load(&config_file, &env).unwrap();
    let app = adapters.router();
    let store = Arc::new(Mutex::new(
        ConsensusStore::open(scratch.0.join("store"), members, FRESHNESS_MS).unwrap(),
    ));
    let handle = store.clone();
    std::thread::spawn(move || {
        let (mut source, mut sink) = adapters.into_ports(handle);
        let probe = source.probe();
        let Observation::Report(report) = MemberObserver::new("member-a")
            .unwrap()
            .observe(probe, now_ms())
        else {
            panic!("verified input must report");
        };
        sink.submit(&report).unwrap();
    })
    .join()
    .unwrap();
    probe_server.join().unwrap();
    b_server.join().unwrap();
    c_server.join().unwrap();
    assert_eq!(store.lock().unwrap().round(now_ms()).reports.len(), 3);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal/failover/report")
                .header(
                    header::AUTHORIZATION,
                    "Bearer synthetic-credential-for-test-only",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let wire: Wire =
        serde_json::from_slice(&to_bytes(response.into_body(), MAX_WIRE).await.unwrap()).unwrap();
    let local = verify(
        &wire,
        &namespace,
        "report",
        "member-a",
        key().verifying_key(),
    )
    .unwrap();
    assert_eq!(local.report.observed_at_ms, observed_at);
    assert_eq!(local.sequence, 1);
}

#[tokio::test]
async fn dead_transport_has_a_deadline_and_cannot_assert_negative_evidence() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((_socket, _)) => {
                    std::thread::sleep(Duration::from_millis(300));
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("synthetic listener failed: {error}"),
            }
        }
    });
    let mut endpoint = endpoint("member-a");
    endpoint.url = format!("https://localhost:{port}/observation")
        .parse()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    assert!(fetch(&client, &endpoint).await.is_err());
    assert!(start.elapsed() < Duration::from_millis(250));
    server.join().unwrap();
    assert!(matches!(
        MemberObserver::new("member-a")
            .unwrap()
            .observe(abstain(), now_ms()),
        Observation::Abstain(_)
    ));
}

#[test]
fn endpoint_configuration_rejects_plaintext_redirect_credentials_and_unsafe_member() {
    for (url, member) in [
        ("http://localhost/observation", "member-a"),
        ("https://user@localhost/observation", "member-a"),
        ("https://localhost/observation?query=value", "member-a"),
        ("https://localhost/observation#fragment", "member-a"),
        ("https://localhost/observation", "../member-a"),
    ] {
        assert!(
            Endpoint::load(EndpointConfig {
                member_id: member.into(),
                url: url.into(),
                public_key_base64: STANDARD.encode(key().verifying_key().to_sec1_bytes()),
                bearer_file: PathBuf::from("unused")
            })
            .is_err()
        );
    }
}

#[test]
fn published_unsigned_vector_matches_canonical_journal_and_signed_domains() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/quorum-observation-01.json"
    ))
    .unwrap();
    let journal = vector["journal"].as_str().unwrap();
    let record = JournalRecord::decode(journal).unwrap();
    assert_eq!(record.encode().unwrap(), journal);
    assert_eq!(record.sequence, vector["sequence"].as_u64().unwrap());
    assert_eq!(
        record.report.observed_at_ms,
        vector["observed_at_ms"].as_u64().unwrap()
    );
    assert_eq!(
        record.report.member_id,
        vector["member_id"].as_str().unwrap()
    );
    let wire = sign(
        vector["namespace"].as_str().unwrap(),
        vector["purpose"].as_str().unwrap(),
        &record,
        &key(),
    )
    .unwrap();
    assert_eq!(
        verify(
            &wire,
            vector["namespace"].as_str().unwrap(),
            "report",
            "member-a",
            key().verifying_key()
        )
        .unwrap(),
        record
    );
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/quorum-observation.schema.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::to_value(&wire)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        schema["required"].as_array().unwrap().len()
    );
    let mut extra = serde_json::to_value(&wire).unwrap();
    extra["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Wire>(extra).is_err());
}

#[test]
fn sequence_exhaustion_and_timestamp_regression_never_advance_receipt() {
    let scratch = Scratch::new();
    let endpoint = endpoint("member-a");
    let mut fence = ReplayFence::open(
        scratch.0.clone(),
        "synthetic-quorum",
        "report",
        &[&endpoint],
    )
    .unwrap();
    let first = record("member-a", 1, 20);
    let wire = sign("synthetic-quorum", "report", &first, &key()).unwrap();
    fence.accept("member-a", &first, &wire, 20).unwrap();
    let regression = record("member-a", 2, 19);
    let wire = sign("synthetic-quorum", "report", &regression, &key()).unwrap();
    assert!(fence.accept("member-a", &regression, &wire, 20).is_err());
    let exhausted = record("member-a", u64::MAX, 20);
    let wire = sign("synthetic-quorum", "report", &exhausted, &key()).unwrap();
    assert!(
        verify(
            &wire,
            "synthetic-quorum",
            "report",
            "member-a",
            key().verifying_key()
        )
        .is_err()
    );
}

#[test]
fn topology_binding_changes_with_writer_sites_membership_and_deployment() {
    let scratch = Scratch::new();
    let env = |writer, roster| {
        crate::failover_executor::ExecutorEnv::parse(
            Some("true"),
            Some(roster),
            Some(writer),
            Some("standby"),
            Some("5000"),
            Some(scratch.0.to_str().unwrap()),
            Some("5000"),
            Some("1000"),
            Some("member-a"),
        )
        .unwrap()
        .unwrap()
    };
    let original = env("writer", "member-a,member-b,member-c");
    let domain = topology_namespace(&original, "synthetic-quorum").unwrap();
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/quorum-observation-01.json"
    ))
    .unwrap();
    assert_eq!(domain, vector["namespace"].as_str().unwrap());
    assert_ne!(
        domain,
        topology_namespace(
            &env("different-writer", "member-a,member-b,member-c"),
            "synthetic-quorum"
        )
        .unwrap()
    );
    assert_ne!(
        domain,
        topology_namespace(
            &env("writer", "member-a,member-b,member-d"),
            "synthetic-quorum"
        )
        .unwrap()
    );
    assert_ne!(
        domain,
        topology_namespace(&original, "other-quorum").unwrap()
    );
    assert_eq!(
        domain,
        topology_namespace(
            &env("writer", "member-c,member-b,member-a"),
            "synthetic-quorum"
        )
        .unwrap()
    );
}
