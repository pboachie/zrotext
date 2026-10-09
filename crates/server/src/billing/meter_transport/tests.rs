// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePrivateKey,
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener},
};
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
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
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

fn request() -> MeterRequest {
    MeterRequest {
        identifier: "zt_usage_fixture_one".into(),
        idempotency_key: "zt_usage_fixture_one".into(),
        event_name: "gateway_submit".into(),
        customer_id: "cus_fixture".into(),
        timestamp: 1700000000,
        units: 1,
        api_version: "2025-07-30.basil",
    }
}
fn ack() -> Value {
    serde_json::json!({"object":"billing.meter_event","identifier":"zt_usage_fixture_one","event_name":"gateway_submit","timestamp":1700000000,"livemode":false,"payload":{"stripe_customer_id":"cus_fixture","value":"1"}})
}

#[test]
fn ambiguous_acknowledgement_fields_cannot_hide_an_earlier_conflict() {
    let original = serde_json::to_string(&ack()).unwrap();
    for (field, conflict) in [
        ("object", "\"other\""),
        ("identifier", "\"foreign\""),
        ("event_name", "\"foreign\""),
        ("livemode", "true"),
        ("timestamp", "1"),
        ("payload", "{}"),
    ] {
        let repeated = format!("{{\"{field}\":{conflict},{}", &original[1..]);
        assert_eq!(
            acknowledgement(repeated.as_bytes(), &request()),
            MeterResponse::InvalidResponse,
            "repeated {field} must not become an acknowledgement"
        );
    }
    for (field, conflict) in [("stripe_customer_id", "foreign"), ("value", "2")] {
        let repeated = original.replace(
            "\"payload\":{",
            &format!("\"payload\":{{\"{field}\":\"{conflict}\","),
        );
        assert_eq!(
            acknowledgement(repeated.as_bytes(), &request()),
            MeterResponse::InvalidResponse,
            "repeated payload {field} must not become an acknowledgement"
        );
    }
}

#[test]
fn acknowledgement_allows_provider_metadata_but_not_truncated_or_wrong_types() {
    let mut valid = ack();
    valid["created"] = serde_json::json!(1700000001);
    valid["payload"]["additional_metadata"] = serde_json::json!("synthetic");
    assert!(matches!(
        acknowledgement(&serde_json::to_vec(&valid).unwrap(), &request()),
        MeterResponse::Acknowledged { .. }
    ));
    assert_eq!(acknowledgement(b"{", &request()), MeterResponse::Unknown);
    assert_eq!(
        acknowledgement(br#"["billing.meter_event","zt_usage_fixture_one","gateway_submit",false,1700000000,{"stripe_customer_id":"cus_fixture","value":"1"}]"#, &request()),
        MeterResponse::InvalidResponse
    );
    let mut array_payload = ack();
    array_payload["payload"] = serde_json::json!(["cus_fixture", "1"]);
    assert_eq!(
        acknowledgement(&serde_json::to_vec(&array_payload).unwrap(), &request()),
        MeterResponse::InvalidResponse
    );
    for field in [
        "object",
        "identifier",
        "event_name",
        "livemode",
        "timestamp",
        "payload",
    ] {
        let mut invalid = ack();
        invalid[field] = Value::Null;
        assert_eq!(
            acknowledgement(&serde_json::to_vec(&invalid).unwrap(), &request()),
            MeterResponse::InvalidResponse
        );
    }
}

#[tokio::test]
async fn repeated_live_mode_over_actual_tls_is_not_acknowledged() {
    let valid = serde_json::to_string(&ack()).unwrap();
    let repeated = format!("{{\"livemode\":true,{}", &valid[1..]);
    let (transport, listener) = fixture(repeated.into_bytes(), "200 OK", "", Duration::ZERO);
    assert_eq!(
        transport.submit(request()).await,
        MeterResponse::InvalidResponse
    );
    assert!(!listener.join().unwrap().is_empty());
}
fn fixture(
    body: Vec<u8>,
    status: &str,
    extra: &str,
    delay: Duration,
) -> (StripeTestMeterTransport, std::thread::JoinHandle<Vec<u8>>) {
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
    let status = status.to_owned();
    let extra = extra.to_owned();
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(3);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => return Vec::new(),
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
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        );
        let mut bytes = Vec::new();
        let mut buf = [0; 2048];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return bytes,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            };
            if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let text = String::from_utf8_lossy(&bytes[..pos]);
                let len = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|s| s.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= pos + 4 + len {
                    break;
                }
            }
        }
        std::thread::sleep(delay);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        bytes
    });
    let mut transport =
        StripeTestMeterTransport::new(format!("{}{}", "rk_test_", "synthetic_transport_only"))
            .unwrap();
    transport.endpoint = format!("https://localhost:{port}/v1/billing/meter_events")
        .parse()
        .unwrap();
    transport.http = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .add_root_certificate(trusted)
        .resolve(
            "localhost",
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        )
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    (transport, handle)
}
#[tokio::test]
async fn exact_test_ack_echoes_original_wire_idempotency_and_customer() {
    let (t, h) = fixture(
        serde_json::to_vec(&ack()).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    let result = t.submit(request()).await;
    let wire = h.join().unwrap();
    assert_eq!(
        result,
        MeterResponse::Acknowledged {
            identifier: request().identifier,
            livemode: false
        }
    );
    let bytes = wire;
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("POST /v1/billing/meter_events"));
    assert!(
        text.to_ascii_lowercase()
            .contains("idempotency-key: zt_usage_fixture_one")
    );
    assert!(text.contains("2025-07-30.basil"));
    assert!(text.contains("payload%5Bstripe_customer_id%5D=cus_fixture"));
    assert!(text.contains("timestamp=1700000000"));
}
#[tokio::test]
async fn hundred_character_identifier_preserves_exact_tls_ack_and_idempotency() {
    let mut submitted = request();
    submitted.identifier = "a".repeat(100);
    submitted.idempotency_key = submitted.identifier.clone();
    let mut acknowledged = ack();
    acknowledged["identifier"] = Value::String(submitted.identifier.clone());
    let (transport, listener) = fixture(
        serde_json::to_vec(&acknowledged).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    assert_eq!(
        transport.submit(submitted.clone()).await,
        MeterResponse::Acknowledged {
            identifier: submitted.identifier.clone(),
            livemode: false,
        }
    );
    let wire = String::from_utf8(listener.join().unwrap()).unwrap();
    assert!(
        wire.to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}\r\n", submitted.identifier))
    );
    assert!(wire.contains(&format!("identifier={}&", submitted.identifier)));
}

#[tokio::test]
async fn hundred_one_character_identifier_is_refused_before_network() {
    let mut submitted = request();
    submitted.identifier = "a".repeat(101);
    submitted.idempotency_key = submitted.identifier.clone();
    let mut acknowledged = ack();
    acknowledged["identifier"] = Value::String(submitted.identifier.clone());
    let (transport, listener) = fixture(
        serde_json::to_vec(&acknowledged).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    let result = transport.submit(submitted).await;
    let wire = listener.join().unwrap();
    assert_eq!(result, MeterResponse::InvalidResponse);
    assert!(
        wire.is_empty(),
        "unsupported identifier reached the TLS listener"
    );
}

#[tokio::test]
async fn foreign_or_live_ack_is_never_accepted_as_test_usage() {
    for field in [
        "identifier",
        "event_name",
        "timestamp",
        "livemode",
        "payload",
    ] {
        let mut v = ack();
        v[field] = serde_json::Value::Null;
        let (t, h) = fixture(
            serde_json::to_vec(&v).unwrap(),
            "200 OK",
            "",
            Duration::ZERO,
        );
        assert_eq!(t.submit(request()).await, MeterResponse::InvalidResponse);
        h.join().unwrap();
    }
}
#[tokio::test]
async fn explicit_http_refusals_preserve_bounded_retry_and_never_follow_redirect() {
    for (status, code) in [
        ("429 Too Many Requests", 429),
        ("503 Service Unavailable", 503),
        ("400 Bad Request", 400),
        ("302 Found", 302),
    ] {
        let (t, h) = fixture(
            vec![],
            status,
            "Retry-After: 999999\r\nLocation: https://redirect.invalid/\r\n",
            Duration::ZERO,
        );
        assert_eq!(
            t.submit(request()).await,
            MeterResponse::Http {
                status: code,
                retry_after_seconds: 600
            }
        );
        h.join().unwrap();
    }
}
#[tokio::test]
async fn response_loss_timeout_and_oversize_remain_unknown_without_transport_resend() {
    for (body, delay) in [
        (vec![], Duration::ZERO),
        (vec![0; MAX_BODY + 1], Duration::ZERO),
        (
            serde_json::to_vec(&ack()).unwrap(),
            Duration::from_millis(1200),
        ),
    ] {
        let (t, h) = fixture(body, "200 OK", "", delay);
        assert_eq!(t.submit(request()).await, MeterResponse::Unknown);
        h.join().unwrap();
    }
}
#[test]
fn configuration_refuses_live_credentials_and_alternate_units() {
    assert!(StripeTestMeterTransport::new("sk_live_synthetic_only".into()).is_err());
    assert!(StripeTestMeterTransport::new("rk_test_synthetic_only\n".into()).is_err());
}

#[tokio::test]
async fn untrusted_tls_cannot_record_acknowledgement_or_receive_meter_payload() {
    let (mut t, h) = fixture(
        serde_json::to_vec(&ack()).unwrap(),
        "200 OK",
        "",
        Duration::ZERO,
    );
    t.http = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .resolve(
            "localhost",
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, t.endpoint.port().unwrap())),
        )
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    assert_eq!(t.submit(request()).await, MeterResponse::Unknown);
    assert!(h.join().unwrap().is_empty());
}
#[test]
fn independent_forwarding_gate_requires_explicit_test_billing_and_write_credential() {
    assert!(
        StripeTestMeterTransport::configured(false, false, None)
            .unwrap()
            .is_none()
    );
    assert!(StripeTestMeterTransport::configured(true, false, None).is_err());
    assert!(StripeTestMeterTransport::configured(true, true, None).is_err());
    assert!(
        StripeTestMeterTransport::configured(true, true, Some("sk_live_synthetic_only".into()))
            .is_err()
    );
    assert!(
        StripeTestMeterTransport::configured(
            true,
            true,
            Some(format!("{}{}", "rk_test_", "synthetic_write_only"))
        )
        .unwrap()
        .is_some()
    );
}

mod worker;
