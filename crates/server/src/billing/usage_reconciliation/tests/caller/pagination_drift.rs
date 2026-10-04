// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

// Route-aware TLS fixture: the old reader is allowed to finish successfully
// without the second page read, so the refusal assertion is a real negative control.
async fn changing_page(
    start: i64,
    end: i64,
) -> (
    TestUsageReconciler,
    tokio::task::JoinHandle<usize>,
    tokio::sync::oneshot::Sender<()>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let trusted = reqwest::Certificate::from_der(cert.cert.der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut page_reads = 0;
        loop {
            let socket = tokio::select! {
                _ = &mut stopped => break,
                socket = listener.accept() => socket.unwrap().0,
            };
            let mut stream = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(socket))
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            let mut bytes = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && request.len() + n <= 8192);
                request.extend_from_slice(&bytes[..n]);
            }
            let text = std::str::from_utf8(&request).unwrap();
            assert!(
                text.to_ascii_lowercase()
                    .contains("stripe-version: 2025-07-30.basil")
            );
            let target = text.lines().next().unwrap().split(' ').nth(1).unwrap();
            let path = target.split('?').next().unwrap();
            let value = match path {
                "/v1/billing/meters/mtr_Synthetic" => meter(),
                "/v1/billing/meters/mtr_Synthetic/event_summaries" => {
                    let mut v = summary(1);
                    v["data"][0]["start_time"] = json!(start);
                    v["data"][0]["end_time"] = json!(end);
                    v
                }
                "/v1/invoices/in_Synthetic" => {
                    let mut v = line("il_Fixed", 1);
                    v["pricing"]["price_details"]["price"] = json!("price_Fixed");
                    invoice(vec![v], true)
                }
                "/v1/invoices/in_Synthetic/lines" => {
                    page_reads += 1;
                    assert!(target.contains("starting_after=il_Fixed"));
                    let mut v = line("il_Synthetic", if page_reads == 1 { 1 } else { 2 });
                    v["period"] = json!({"start":start,"end":end});
                    v["parent"]["subscription_item_details"]["subscription_item"] =
                        json!("si_Synthetic");
                    json!({"object":"list","has_more":false,"data":[v]})
                }
                "/v1/prices/price_Fixed" => {
                    let mut v = price();
                    v["id"] = json!("price_Fixed");
                    v["recurring"]["meter"] = json!("mtr_Unrelated");
                    v
                }
                "/v1/prices/price_Synthetic" => price(),
                _ => panic!("unexpected synthetic route"),
            };
            let body = serde_json::to_vec(&value).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            let _ = stream.shutdown().await;
        }
        page_reads
    });
    let http = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .add_root_certificate(trusted)
        .resolve("localhost", address)
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    (
        TestUsageReconciler {
            http,
            key: zeroize::Zeroizing::new(format!("{}{}", "rk_test_", "synthetic_read_only")),
            base: format!("https://localhost:{}/", address.port())
                .parse()
                .unwrap(),
        },
        task,
        stop,
    )
}

#[tokio::test]
async fn later_invoice_page_drift_refuses_unchanged_first_page_and_aggregate() {
    let s = scope();
    let (worker, server, stop) = changing_page(s.start, s.end).await;
    let outcome = worker.observe(&s).await;
    stop.send(()).unwrap();
    let pages = server.await.unwrap();
    assert!(outcome.is_err());
    assert_eq!(pages, 2);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; later invoice page drift cannot commit evidence"]
async fn changed_later_invoice_page_cannot_append_observation() {
    let mut f = database::invoice_fixture().await;
    database::seed(
        &f.db,
        f.account,
        f.device,
        "cus_Synthetic",
        "mtr_Synthetic",
        true,
    )
    .await;
    let before = database::authority_snapshot(&f.db, f.account).await;
    let s = scope();
    let (worker, server, stop) = changing_page(s.start, s.end).await;
    let outcome = worker
        .reconcile_period(&mut f.db, f.account, 1, "2024-01-01", Uuid::new_v4())
        .await;
    stop.send(()).unwrap();
    let pages = server.await.unwrap();
    assert!(outcome.is_err());
    assert_eq!(pages, 2);
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM billing_usage_reconciliations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(database::authority_snapshot(&f.db, f.account).await, before);
    f.cleanup().await;
}
