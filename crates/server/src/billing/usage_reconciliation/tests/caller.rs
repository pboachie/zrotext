// SPDX-License-Identifier: AGPL-3.0-only
use super::super::*;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
mod invoice_binding;
mod pagination_drift;

struct Reply {
    path: &'static str,
    body: Vec<u8>,
    status: u16,
    location: Option<&'static str>,
}
fn reply(path: &'static str, value: Value) -> Reply {
    Reply {
        path,
        body: serde_json::to_vec(&value).unwrap(),
        status: 200,
        location: None,
    }
}
fn scope() -> Scope {
    Scope {
        account: Uuid::new_v4(),
        policy: 1,
        period: "2024-01-01".into(),
        customer: "cus_Synthetic".into(),
        meter: "mtr_Synthetic".into(),
        event_name: "gateway_submit".into(),
        start: 1704067200,
        end: 1706745600,
        invoice: Some("in_Synthetic".into()),
        subscription: Some("sub_Synthetic".into()),
        invoice_binding: None,
    }
}
fn meter() -> Value {
    json!({"object":"billing.meter","id":"mtr_Synthetic","livemode":false,"event_name":"gateway_submit","status":"active",
    "default_aggregation":{"formula":"sum"},"customer_mapping":{"type":"by_id","event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}})
}
fn summary(n: i64) -> Value {
    json!({"object":"list","has_more":false,"data":[{"id":"mtrusg_Synthetic","object":"billing.meter_event_summary","livemode":false,
    "meter":"mtr_Synthetic","start_time":1704067200,"end_time":1706745600,"aggregated_value":n}]})
}
fn price() -> Value {
    json!({"id":"price_Synthetic","object":"price","livemode":false,"billing_scheme":"per_unit","transform_quantity":null,"tiers_mode":null,
    "recurring":{"meter":"mtr_Synthetic","usage_type":"metered"}})
}
fn line(id: &str, quantity: i64) -> Value {
    json!({"id":id,"object":"line_item","livemode":false,"quantity":quantity,
    "pricing":{"price_details":{"price":"price_Synthetic"}},"parent":{"type":"subscription_item_details","subscription_item_details":{"subscription":"sub_Synthetic","proration":false}},
    "period":{"start":1704067200,"end":1706745600}})
}
fn invoice(lines: Vec<Value>, more: bool) -> Value {
    json!({"id":"in_Synthetic","object":"invoice","livemode":false,"customer":"cus_Synthetic","status":"paid",
    "parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_Synthetic"}},"lines":{"object":"list","has_more":more,"data":lines}})
}
async fn tls(replies: Vec<Reply>) -> (TestUsageReconciler, tokio::task::JoinHandle<Vec<String>>) {
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
    let task = tokio::spawn(async move {
        let mut paths = Vec::new();
        let probe_redirect = replies.iter().any(|r| r.location.is_some());
        for response in replies {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let handshake = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(socket))
                .await
                .unwrap();
            let Ok(mut stream) = handshake else {
                break;
            };
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && request.len() + n <= 8192);
                request.extend_from_slice(&buf[..n]);
            }
            let text = std::str::from_utf8(&request).unwrap();
            let start = text.lines().next().unwrap();
            let parts: Vec<_> = start.split(' ').collect();
            assert_eq!(parts[0], "GET");
            assert!(parts[1].starts_with(response.path));
            let lower = text.to_ascii_lowercase();
            assert!(lower.contains("stripe-version: 2025-07-30.basil"));
            assert!(lower.contains("authorization: bearer "));
            assert!(!lower.contains("idempotency-key:"));
            paths.push(parts[1].to_owned());
            let headers = format!(
                "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status,
                response.body.len()
            );
            let headers = if let Some(location) = response.location {
                headers.replace(
                    "Connection: close",
                    &format!("Location: {location}\r\nConnection: close"),
                )
            } else {
                headers
            };
            stream.write_all(headers.as_bytes()).await.unwrap();
            if let Err(error) = stream.write_all(&response.body).await {
                assert!(
                    response.body.len() > 65536
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        )
                );
            }
            let _ = stream.shutdown().await;
        }
        if probe_redirect
            && let Ok(Ok((socket, _))) =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
        {
            let mut stream = acceptor.accept(socket).await.unwrap();
            let mut bytes = [0; 8192];
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(n > 0);
            paths.push("redirect_followed".into());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await;
        }
        paths
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
    )
}
fn observation(invoice: Value, n: i64) -> Vec<Reply> {
    vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(n),
        ),
        reply("/v1/invoices/in_Synthetic", invoice.clone()),
        reply("/v1/prices/price_Synthetic", price()),
        reply("/v1/invoices/in_Synthetic", invoice),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(n),
        ),
    ]
}

#[tokio::test]
async fn actual_verified_https_reads_exact_customer_period_invoice_and_meter_without_writes() {
    let (worker, server) = tls(observation(
        invoice(vec![line("il_Synthetic", 3)], false),
        3,
    ))
    .await;
    assert_eq!(worker.observe(&scope()).await.unwrap(), (3, Some(3)));
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 6);
    let url = Url::parse(&format!("https://fixture.invalid{}", paths[1])).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(query.get("customer").unwrap(), "cus_Synthetic");
    assert_eq!(query.get("start_time").unwrap(), "1704067200");
    assert_eq!(query.get("end_time").unwrap(), "1706745600");
    assert!(!query.contains_key("value_grouping_window"));
}

#[tokio::test]
async fn incomplete_invoice_and_changed_aggregate_refuse_observation() {
    let (worker, server) = tls(vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(3),
        ),
        reply("/v1/invoices/in_Synthetic", invoice(vec![], true)),
    ])
    .await;
    assert!(worker.observe(&scope()).await.is_err());
    assert_eq!(server.await.unwrap().len(), 3);
    let mut replies = observation(invoice(vec![line("il_Synthetic", 3)], false), 3);
    replies[5] = reply(
        "/v1/billing/meters/mtr_Synthetic/event_summaries",
        summary(4),
    );
    let (worker, server) = tls(replies).await;
    assert!(worker.observe(&scope()).await.is_err());
    assert_eq!(server.await.unwrap().len(), 6);
}

#[tokio::test]
async fn provider_redirect_and_oversized_response_are_refused_without_another_request() {
    for (status, body) in [(302, b"{}".to_vec()), (200, vec![b' '; 65537])] {
        let (worker, server) = tls(vec![Reply {
            path: "/v1/billing/meters/mtr_Synthetic",
            status,
            body,
            location: (status == 302).then_some("/redirect_target"),
        }])
        .await;
        assert!(worker.observe(&scope()).await.is_err());
        assert_eq!(server.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn complete_multiple_invoice_pages_select_usage_and_cache_unrelated_prices() {
    let mut fixed1 = line("il_First", 3);
    fixed1["pricing"]["price_details"]["price"] = json!("price_Fixed");
    let mut fixed2 = fixed1.clone();
    fixed2["id"] = json!("il_FixedSecond");
    let first = invoice(vec![fixed1, fixed2], true);
    let mut fixed_price = price();
    fixed_price["id"] = json!("price_Fixed");
    fixed_price["recurring"]["meter"] = json!("mtr_Unrelated");
    let replies = vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(3),
        ),
        reply("/v1/invoices/in_Synthetic", first.clone()),
        reply(
            "/v1/invoices/in_Synthetic/lines",
            json!({"object":"list","has_more":false,"data":[line("il_Selected",3)]}),
        ),
        reply("/v1/prices/price_Fixed", fixed_price),
        reply("/v1/prices/price_Synthetic", price()),
        reply("/v1/invoices/in_Synthetic", first),
        reply(
            "/v1/invoices/in_Synthetic/lines",
            json!({"object":"list","has_more":false,"data":[line("il_Selected",3)]}),
        ),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(3),
        ),
    ];
    let (worker, server) = tls(replies).await;
    assert_eq!(worker.observe(&scope()).await.unwrap(), (3, Some(3)));
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 9);
    let query = Url::parse(&format!("https://fixture.invalid{}", paths[3])).unwrap();
    assert!(
        query
            .query_pairs()
            .any(|(k, v)| k == "starting_after" && v == "il_FixedSecond")
    );
    assert_eq!(
        paths
            .iter()
            .filter(|p| p.as_str() == "/v1/prices/price_Fixed")
            .count(),
        1
    );
}

#[tokio::test]
async fn duplicate_invoice_page_and_ninth_price_refuse_partial_observation() {
    let first = invoice(vec![line("il_First", 3)], true);
    let (worker, server) = tls(vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(3),
        ),
        reply("/v1/invoices/in_Synthetic", first),
        reply(
            "/v1/invoices/in_Synthetic/lines",
            json!({"object":"list","has_more":false,"data":[line("il_First",3)]}),
        ),
    ])
    .await;
    assert!(worker.observe(&scope()).await.is_err());
    assert_eq!(server.await.unwrap().len(), 4);
    let lines: Vec<_> = (0..9)
        .map(|n| {
            let mut l = line(&format!("il_Synthetic{n}"), 1);
            l["pricing"]["price_details"]["price"] = json!(format!("price_Synthetic{n}"));
            l
        })
        .collect();
    let mut replies = vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            summary(3),
        ),
        reply("/v1/invoices/in_Synthetic", invoice(lines, false)),
    ];
    for n in 0..8 {
        let mut p = price();
        p["id"] = json!(format!("price_Synthetic{n}"));
        p["recurring"]["meter"] = json!("mtr_Unrelated");
        replies.push(reply("/v1/prices/price_Synthetic", p));
    }
    let (worker, server) = tls(replies).await;
    assert!(worker.observe(&scope()).await.is_err());
    assert_eq!(server.await.unwrap().len(), 11);
}

#[tokio::test]
async fn invalid_ca_or_hostname_refuses_before_any_bearer_http_bytes() {
    for wrong_host in [false, true] {
        let (mut worker, server) =
            tls(vec![reply("/v1/billing/meters/mtr_Synthetic", meter())]).await;
        if wrong_host {
            worker.base.set_host(Some("127.0.0.1")).unwrap();
        } else {
            worker.http = Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
        }
        assert!(worker.observe(&scope()).await.is_err());
        assert!(server.await.unwrap().is_empty());
    }
}

mod database;
