// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::TokenHasher,
    http_auth::{DisabledVerificationDispatcher, RegistrationPolicy},
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

fn price() -> Value {
    serde_json::json!({"object":"price","id":"price_fixture","livemode":false,"active":true,"type":"recurring","billing_scheme":"per_unit","currency":"usd","unit_amount":1700,"recurring":{"interval":"month","interval_count":1,"usage_type":"licensed"}})
}

#[test]
fn verified_catalog_rejects_live_wrong_price_and_ambiguous_terms() {
    let q = super::super::TestQuotaPlan {
        price_id: "price_fixture".into(),
        outbound_limit: 123,
        device_limit: Some(2),
    };
    let catalog = parse_catalog(&price(), "price_fixture", Some(&q)).unwrap();
    let v = serde_json::to_value(&catalog).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"schema_version":1,"mode":"test","currency":"usd","unit_amount":1700,"interval":"month","interval_count":1,"outbound_limit":123,"device_cap":2})
    );
    for (key, value) in [
        ("livemode", true.into()),
        ("active", false.into()),
        ("id", "price_other".into()),
        ("unit_amount", Value::Null),
        ("unit_amount", (-1).into()),
        ("currency", "USd".into()),
        ("billing_scheme", "tiered".into()),
    ] {
        let mut changed = price();
        changed[key] = value;
        assert!(
            parse_catalog(&changed, "price_fixture", Some(&q)).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("interval", "unknown".into()),
        ("interval_count", 0.into()),
        ("usage_type", "metered".into()),
    ] {
        let mut changed = price();
        changed["recurring"][key] = value;
        assert!(parse_catalog(&changed, "price_fixture", Some(&q)).is_err());
    }
    let mut bad = q;
    bad.price_id = "price_other".into();
    assert!(parse_catalog(&price(), "price_fixture", Some(&bad)).is_err());
}

#[tokio::test]
async fn only_bounded_validated_provider_test_price_becomes_served_plan() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = Router::new().route("/v1/prices/price_fixture", get(|| async { Json(price()) }));
    let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
    let auth = AuthHttpState::new(
        "postgres://unused".into(),
        Arc::new(TokenHasher::new(vec![1; 32]).unwrap()),
        "https://test.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    assert!(
        SessionState::new(
            auth.clone(),
            "rk_live_fixture123456".into(),
            "price_fixture".into()
        )
        .is_err()
    );
    let mut state =
        SessionState::new(auth, "rk_test_fixture123456".into(), "price_fixture".into()).unwrap();
    assert!(state.verified_catalog().is_none());
    let unavailable = router(state.clone())
        .oneshot(Request::builder().uri("/plan").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    state.stripe = Arc::new(StripeClient {
        http: HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        secret_key: "rk_test_fixture123456".into(),
        api_base: format!("http://{address}"),
    });
    let verified = state.verify_catalog(None).await.unwrap();
    let available = crate::billing::availability::router(
        crate::billing::availability::State::for_test_sessions(
            &RegistrationPolicy::Open,
            true,
            verified.verified_catalog().unwrap(),
        ),
    );
    let response = available
        .oneshot(
            Request::builder()
                .uri("/availability")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 2048).await.unwrap()).unwrap();
    assert_eq!(body["billing"], "test");
    assert_eq!(body["checkout_available"], true);
    assert_eq!(body["plan_catalog_available"], true);
    let response = router(verified)
        .oneshot(Request::builder().uri("/plan").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 2048).await.unwrap()).unwrap();
    assert_eq!(body["mode"], "test");
    assert_eq!(body["unit_amount"], 1700);
    assert!(body["outbound_limit"].is_null());
    server.abort();
}
