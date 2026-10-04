// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn read_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "__Host-zrotext_session=synthetic-session; __Host-zrotext_csrf=synthetic-csrf",
        ),
    );
    h.insert("x-zrotext-csrf", HeaderValue::from_static("synthetic-csrf"));
    h
}
#[test]
fn operations_keep_closed_original_identity_and_query() {
    let id = Uuid::from_u128(17);
    let path = format!("{PREFIX}/{id}");
    assert!(
        matches!(operation(&Method::GET,&path,Some("generation=1")),Ok(Operation::Status(g,1)) if g==id)
    );
    for query in [
        None,
        Some("generation=01"),
        Some("generation=1&generation=1"),
        Some("generation=0"),
    ] {
        assert!(operation(&Method::GET, &path, query).is_err());
    }
    assert!(operation(&Method::POST, &format!("{PREFIX}/intents"), Some("x=1")).is_err());
    assert!(operation(&Method::POST, &format!("{PREFIX}/{id}/complete/x"), None).is_err());
    assert!(
        operation(
            &Method::POST,
            &format!("{PREFIX}/00000000-0000-0000-0000-000000000000/cancel"),
            None
        )
        .is_err()
    );
}
#[test]
fn cookie_only_content_read_and_bearer_or_ambiguous_framing_refuse() {
    let mut h = read_headers();
    assert!(headers(&h, false).is_ok());
    h.remove("x-zrotext-csrf");
    assert!(headers(&h, false).is_err());
    h = read_headers();
    h.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer synthetic"),
    );
    assert!(headers(&h, false).is_err());
    h = read_headers();
    h.append(header::COOKIE, HeaderValue::from_static("other=synthetic"));
    assert!(headers(&h, false).is_err());
    h = read_headers();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("01"));
    assert!(headers(&h, false).is_err());
    h = read_headers();
    h.insert(
        header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    assert!(headers(&h, false).is_err());
}
#[test]
fn post_requires_original_json_origin_and_csrf_before_body() {
    let mut h = read_headers();
    assert!(headers(&h, true).is_err());
    h.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://owner.invalid"),
    );
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(headers(&h, true).is_ok());
    h.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(headers(&h, true).is_err());
}

fn app(f: &crate::contact_reader_issuer::tests::Owner) -> Router {
    router(OwnerContactIssuanceState {
        database_url: f.url(),
        auth_hasher: f.hasher.clone(),
        mfa_cipher: f.cipher.clone(),
        canonical_origin: crate::contact_reader_issuer::tests::ORIGIN.into(),
    })
}
fn request(
    f: &crate::contact_reader_issuer::tests::Owner,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> axum::http::Request<Body> {
    let mut r = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::COOKIE,
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                f.credentials.token, f.credentials.csrf_token
            ),
        )
        .header("x-zrotext-csrf", &f.credentials.csrf_token);
    if method == "POST" {
        r = r
            .header(header::ORIGIN, crate::contact_reader_issuer::tests::ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
    }
    r.body(Body::from(body)).unwrap()
}
#[tokio::test]
async fn no_store_methods_and_missing_auth_refuse_without_a_database() {
    use tower::ServiceExt;
    for (method, status) in [
        ("HEAD", StatusCode::METHOD_NOT_ALLOWED),
        ("OPTIONS", StatusCode::METHOD_NOT_ALLOWED),
        ("GET", StatusCode::UNAUTHORIZED),
    ] {
        let path = format!("{PREFIX}/{}?generation=1", Uuid::from_u128(7));
        let state = OwnerContactIssuanceState {
            database_url: "not a database url".into(),
            auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(96)).unwrap()),
            mfa_cipher: Arc::new(MfaCipher::new(crate::test_keys::key(97)).unwrap()),
            canonical_origin: crate::contact_reader_issuer::tests::ORIGIN.into(),
        };
        let response = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine Cookie/CSRF owner/MFA, synthetic extant admission"]
async fn real_router_allocates_unsigned_then_verifies_whole_root_signature_and_factor() {
    use crate::contact_reader_issuer::{
        model::{MAX_RESPONSE, ResultView},
        tests::Owner,
    };
    use tower::ServiceExt;
    let f = Owner::new(true, true).await;
    let input = f.input().await;
    let response = app(&f)
        .oneshot(request(
            &f,
            "POST",
            &format!("{PREFIX}/intents"),
            serde_json::to_vec(&input).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let raw = to_bytes(response.into_body(), MAX_RESPONSE).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let id = Uuid::parse_str(v["authorization"].as_str().unwrap()).unwrap();
    let generation = v["generation"].as_str().unwrap().parse().unwrap();
    let value = crate::contact_reader_issuer::lifecycle::status(
        &mut f.schema.connect().await,
        &f.principal,
        id,
        generation,
    )
    .await
    .unwrap();
    let p = match value {
        ResultView::Pending(p) => *p,
        _ => panic!("expected pending"),
    };
    let body = serde_json::json!({"generation":p.generation,"create_request":p.create_request,"creation_expected_revision":p.creation_expected_revision,"unsigned_digest":p.unsigned_digest,"signed_statement":model::Packed::<314,817>(f.signed(&p)),"code":f.recovery[0]});
    let response = app(&f)
        .oneshot(request(
            &f,
            "POST",
            &format!("{PREFIX}/{id}/complete"),
            serde_json::to_vec(&body).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let raw = to_bytes(response.into_body(), MAX_RESPONSE).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["kind"], "historical_completed");
    assert!(v.get("code").is_none());
    assert_eq!(v["current"]["phase"], "active");
    assert_eq!(AccountSlot::in_flight(f.principal.tenant.account_id()), 0);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real maintained invitation and observer session"]
async fn genuine_observer_and_owner_cookie_without_current_csrf_cannot_read_or_mutate() {
    use crate::{
        auth,
        contact_reader_issuer::tests::{ORIGIN, Owner},
    };
    use tower::ServiceExt;
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let email = format!("issuer-observer-{}@example.test", Uuid::new_v4());
    let mut db = f.schema.connect().await;
    let invitation = auth::seats::create_invitation_with_proof(
        &mut db,
        Some(&f.cipher),
        &f.hasher,
        &f.principal,
        "synthetic issuer password",
        Some(&f.recovery[1]),
        &email,
    )
    .await
    .unwrap();
    let accepted = auth::seats::accept_invitation(
        &mut db,
        &f.hasher,
        &invitation.token,
        "synthetic observer password",
    )
    .await
    .unwrap();
    assert!(
        auth::verify_email_with_password(
            &mut db,
            &f.hasher,
            &accepted.verification_token,
            "synthetic observer password"
        )
        .await
        .unwrap()
    );
    let credentials = auth::login(&db, &f.hasher, &email, "synthetic observer password")
        .await
        .unwrap();
    for(method,path,body)in [("GET",format!("{PREFIX}/{}?generation={}",p.authorization.0,p.generation.0),Vec::new()),("POST",format!("{PREFIX}/withdraw"),serde_json::to_vec(&serde_json::json!({"expected_revision":"1","expected_authorization":p.authorization,"expected_generation":p.generation,"expected_digest":p.unsigned_digest})).unwrap())]{
        let mut r=request(&f,method,&path,body);r.headers_mut().insert(header::COOKIE,HeaderValue::from_str(&format!("__Host-zrotext_session={}; __Host-zrotext_csrf={}",credentials.token,credentials.csrf_token)).unwrap());r.headers_mut().insert("x-zrotext-csrf",HeaderValue::from_str(&credentials.csrf_token).unwrap());
        let response=app(&f).oneshot(r).await.unwrap();assert_eq!(response.status(),StatusCode::UNAUTHORIZED);assert_eq!(response.headers()[header::CACHE_CONTROL],"no-store");
    }
    let mut r = request(
        &f,
        "GET",
        &format!(
            "{PREFIX}/{}?generation={}",
            p.authorization.0, p.generation.0
        ),
        Vec::new(),
    );
    r.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        app(&f).oneshot(r).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(crate::sealed_root_enrollment::canonical_origin(ORIGIN));
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual selected export router and unchanged enrolled erasure refusal"]
async fn selected_export_bypasses_private_families_preserves_csrf_and_enrolled_erasure_blocker() {
    use crate::contact_reader_issuer::tests::{ORIGIN, Owner};
    use tower::ServiceExt;
    let f = Owner::new(true, true).await;
    let state = crate::http_owner_export::OwnerExportState {
        database_url: f.url(),
        auth_hasher: f.hasher.clone(),
        canonical_origin: ORIGIN.into(),
        contacts_vault: None,
    };
    // These private-family tables need not be available for the public selector.
    // The real shared fixture deliberately omits later workflow tables.
    let response = crate::http_owner_export::router(state.clone())
        .oneshot(request(
            &f,
            "GET",
            "/v1/owner/export?contact_reader_only=state",
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let raw = to_bytes(response.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 2);
    assert_eq!(v["kind"], "contact_reader_state");
    assert_eq!(v["state"]["current"]["phase"], "empty");
    for query in [
        "contact_reader_only=other",
        "contact_reader_only=state&before=00000000-0000-0000-0000-000000000001",
        "contact_reader_only=state&contact_reader_pending_after=1:00000000-0000-0000-0000-000000000001",
        "contact_reader_only=state&contact_reader_only=state",
    ] {
        assert_eq!(
            crate::http_owner_export::router(state.clone())
                .oneshot(request(
                    &f,
                    "GET",
                    &format!("/v1/owner/export?{query}"),
                    Vec::new()
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut r = request(
        &f,
        "GET",
        "/v1/owner/export?contact_reader_only=state",
        Vec::new(),
    );
    r.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        crate::http_owner_export::router(state)
            .oneshot(r)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let erasure = crate::http_owner_erasure::OwnerErasureState {
        database_url: f.url(),
        auth_hasher: f.hasher.clone(),
        canonical_origin: ORIGIN.into(),
        mfa_cipher: Some(f.cipher.clone()),
    };
    let body = serde_json::to_vec(
        &serde_json::json!({"current_password":"synthetic issuer password","code":f.recovery[2]}),
    )
    .unwrap();
    let response = crate::http_owner_erasure::router(erasure)
        .oneshot(request(&f, "POST", "/v1/owner/erasure", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_state WHERE account_id=$1",
                &[&f.principal.tenant.account_id()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.schema.cleanup().await;
}
