// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn malformed_or_ambient_authority_fetch_is_closed_before_storage() {
    let state = FetchState03::new(
        "postgresql://fetch-refusal.invalid/db".into(),
        "synthetic".into(),
        1,
        "https://gateway.invalid".into(),
        Arc::new(TokenHasher::new(crate::test_keys::key(17)).unwrap()),
    )
    .unwrap();
    let app = routes(state);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/sealed-profile03-contract-01.json"
    ))
    .unwrap();
    let packet = serde_json::json!({"grant":vector["grant"]["frame"],"signature_der":vector["grant"]["signatureDerBase64url"]});
    // The independent vector is valid syntax; each changed request must refuse
    // before opening the deliberately unavailable database.
    assert!(Fetch03::parse(&serde_json::to_vec(&packet).unwrap()).is_ok());
    let raw = serde_json::to_string(&packet).unwrap();
    for (body, extra) in [
        ("{}".to_owned(), None),
        (" ".repeat(4097), None),
        (format!("{{\"grant\":null,{}", &raw[1..]), None),
        (format!("[{}]", raw), None),
        (raw.clone(), Some(("authorization", "Bearer synthetic"))),
        (raw.clone(), Some(("cookie", "synthetic=1"))),
        (raw.clone(), Some(("origin", "https://gateway.invalid"))),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/sealed/dispatch/envelope03")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((name, value)) = extra {
            request = request.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"error":"invalid_request"})
        );
    }
}
