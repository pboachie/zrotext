// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{collections::VecDeque, net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Fixture {
    replies: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
}
async fn handler(State(f): State<Fixture>, request: Request) -> Response {
    f.calls.lock().await.push((
        request.uri().path().to_string(),
        request
            .headers()
            .get("stripe-version")
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    ));
    let (status, value) = f.replies.lock().await.pop_front().unwrap();
    (status, axum::Json(value)).into_response()
}
async fn server(
    replies: Vec<(StatusCode, Value)>,
) -> (String, Fixture, tokio::task::JoinHandle<()>) {
    let f = Fixture {
        replies: Arc::new(Mutex::new(replies.into())),
        calls: Arc::default(),
    };
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().fallback(handler).with_state(f.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (base, f, task)
}
fn values() -> (Value, Value) {
    (
        json!({"id":"sub_transportfixture","object":"subscription","livemode":false,
        "customer":"cus_transportfixture","status":"active","latest_invoice":"in_transportfixture",
        "cancel_at":null,"cancel_at_period_end":false,"items":{"object":"list","has_more":false,"data":[{
            "id":"si_transportfixture","quantity":1,"price":{"id":"price_transportfixture"},
            "current_period_start":1000,"current_period_end":2000}]}}),
        json!({"id":"in_transportfixture","object":"invoice","livemode":false,"customer":"cus_transportfixture",
         "status":"paid","billing_reason":"subscription_cycle","parent":{"type":"subscription_details",
             "subscription_details":{"subscription":"sub_transportfixture"}},"lines":{"object":"list","has_more":false,"data":[{
                 "id":"il_transportfixture","parent":{"type":"subscription_item_details","subscription_item_details":{
                     "subscription_item":"si_transportfixture","proration":false}},"period":{"start":1000,"end":2000},
                 "pricing":{"price_details":{"price":"price_transportfixture"}}}]}}),
    )
}
fn http() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap()
}
fn key() -> String {
    format!("rk_test_{}", uuid::Uuid::new_v4().simple())
}

#[tokio::test]
async fn both_current_reads_use_the_existing_api_pin_and_exact_object_paths() {
    let (sub, invoice) = values();
    let (base, f, task) = server(vec![
        (StatusCode::OK, sub.clone()),
        (StatusCode::OK, invoice.clone()),
        (StatusCode::OK, sub),
        (StatusCode::OK, invoice),
    ])
    .await;
    let proof = fetch(&http(), &key(), &base, "sub_transportfixture")
        .await
        .unwrap();
    assert!(proof.observation.can_establish_period());
    let calls = f.calls.lock().await;
    assert_eq!(
        calls.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec![
            "/v1/subscriptions/sub_transportfixture",
            "/v1/invoices/in_transportfixture",
            "/v1/subscriptions/sub_transportfixture",
            "/v1/invoices/in_transportfixture"
        ]
    );
    assert!(
        calls
            .iter()
            .all(|(_, version)| version == STRIPE_API_VERSION)
    );
    task.abort();
}

#[tokio::test]
async fn invoice_missing_or_changed_between_reads_never_becomes_subscription_deletion_or_paid_authority()
 {
    let (sub, invoice) = values();
    let (base, _, task) = server(vec![
        (StatusCode::OK, sub.clone()),
        (StatusCode::NOT_FOUND, json!({})),
    ])
    .await;
    assert!(matches!(
        fetch(&http(), &key(), &base, "sub_transportfixture").await,
        Err(BillingError::Provider(
            worker::ProviderFailure::InvalidResponse
        ))
    ));
    task.abort();
    let mut changed = invoice.clone();
    changed["status"] = json!("open");
    let (base, _, task) = server(vec![
        (StatusCode::OK, sub.clone()),
        (StatusCode::OK, invoice),
        (StatusCode::OK, sub),
        (StatusCode::OK, changed),
    ])
    .await;
    assert!(matches!(
        fetch(&http(), &key(), &base, "sub_transportfixture").await,
        Err(BillingError::Provider(
            worker::ProviderFailure::InvalidResponse
        ))
    ));
    task.abort();
}
