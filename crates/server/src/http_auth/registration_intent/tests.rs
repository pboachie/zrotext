// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{TokenHasher, registration_intent::tests::Fixture};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

const ORIGIN: &str = "https://example.test";

fn proof(credentials: &Credentials) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{}={}; {}={}",
            intent::INTENT_COOKIE,
            credentials.token.as_str(),
            intent::CSRF_COOKIE,
            credentials.csrf.as_str()
        ))
        .unwrap(),
    );
    headers.insert(
        intent::CSRF_HEADER,
        HeaderValue::from_str(&credentials.csrf).unwrap(),
    );
    headers
}

fn post(path: &str, credentials: &Credentials, body: serde_json::Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.headers_mut().extend(proof(credentials));
    request
}

#[test]
fn exact_origin_and_unique_independent_cookie_header_proof_are_required() {
    let credentials = Credentials::random();
    let headers = proof(&credentials);
    assert!(header_proof(&headers, ORIGIN).is_ok());
    for change in [0, 1, 2, 3, 4, 5] {
        let mut invalid = headers.clone();
        match change {
            0 => {
                invalid.remove(header::ORIGIN);
            }
            1 => {
                invalid.insert(
                    header::ORIGIN,
                    HeaderValue::from_static("https://other.example.test"),
                );
            }
            2 => {
                invalid.remove(intent::CSRF_HEADER);
            }
            3 => {
                invalid.insert(
                    intent::CSRF_HEADER,
                    HeaderValue::from_static("different-proof"),
                );
            }
            4 => {
                invalid.append(
                    header::COOKIE,
                    HeaderValue::from_str(&format!(
                        "{}={}",
                        intent::INTENT_COOKIE,
                        credentials.token.as_str()
                    ))
                    .unwrap(),
                );
            }
            _ => {
                invalid.append(header::ORIGIN, HeaderValue::from_static(ORIGIN));
            }
        }
        assert!(header_proof(&invalid, ORIGIN).is_err());
    }
    let mut duplicate = headers;
    duplicate.append(
        intent::CSRF_HEADER,
        HeaderValue::from_str(&credentials.csrf).unwrap(),
    );
    assert!(header_proof(&duplicate, ORIGIN).is_err());
}

#[tokio::test]
async fn invalid_header_proof_rejects_an_unread_body_without_database_access() {
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(180)).unwrap()),
        ORIGIN.to_owned(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = super::super::router(state);
    for path in ["/registration-intent/verify", "/registration-intent/resend"] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::convert::Infallible>,
            >()))
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.clone().oneshot(request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
}

#[test]
fn intent_dtos_do_not_accept_passwords_email_or_caller_authority() {
    assert!(serde_json::from_value::<VerifyBody>(serde_json::json!({"token":"synthetic"})).is_ok());
    for body in [
        serde_json::json!({"token":"synthetic","password":"synthetic"}),
        serde_json::json!({"token":"synthetic","account_id":"synthetic"}),
        serde_json::json!({"email":"owner@example.test"}),
    ] {
        assert!(serde_json::from_value::<VerifyBody>(body).is_err());
    }
    assert!(serde_json::from_value::<ResendBody>(serde_json::json!({})).is_ok());
    assert!(
        serde_json::from_value::<ResendBody>(serde_json::json!({"email":"owner@example.test"}))
            .is_err()
    );
}

struct NoNetworkMail;
impl super::super::VerificationDispatcher for NoNetworkMail {
    fn ready(&self) -> bool {
        true
    }
    fn dispatch<'a>(
        &'a self,
        _email: &'a str,
        _token: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), super::super::DispatchFailure>> + Send + 'a,
        >,
    > {
        Box::pin(async { Err(super::super::DispatchFailure::Connect) })
    }
}

fn app(f: &Fixture) -> axum::Router {
    super::super::router(
        AuthHttpState::new(
            f.dsn.clone(),
            Arc::new(TokenHasher::new(crate::test_keys::key(180)).unwrap()),
            ORIGIN.to_owned(),
            Arc::new(NoNetworkMail),
        )
        .unwrap()
        .with_registration_policy(super::super::RegistrationPolicy::Open),
    )
}

fn registration_request(email: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/register")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"email":email,"password":crate::test_keys::password(180)})
                .to_string(),
        ))
        .unwrap()
}

fn response_credentials(response: &Response) -> Credentials {
    let get = |name: &str| {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                value
                    .to_str()
                    .ok()?
                    .split(';')
                    .next()?
                    .strip_prefix(&format!("{name}="))
                    .map(str::to_owned)
            })
            .unwrap()
    };
    Credentials {
        token: Zeroizing::new(get(intent::INTENT_COOKIE)),
        csrf: Zeroizing::new(get(intent::CSRF_COOKIE)),
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn actual_register_cookies_bind_code_only_verification_without_auth_cookie_writes() {
    let f = Fixture::new().await;
    let app = app(&f);
    let response = app
        .clone()
        .oneshot(registration_request("owner@example.test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
    let original = response_credentials(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    let id: uuid::Uuid =
        f.db.query_one("SELECT id FROM email_verifications", &[])
            .await
            .unwrap()
            .get(0);
    let code = f.verification_token(id);
    let foreign = app
        .clone()
        .oneshot(post(
            "/registration-intent/verify",
            &Credentials::random(),
            serde_json::json!({"token":code}),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
    assert!(!foreign.headers().contains_key(header::SET_COOKIE));
    let verified = app
        .clone()
        .oneshot(post(
            "/registration-intent/verify",
            &original,
            serde_json::json!({"token":code}),
        ))
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::NO_CONTENT);
    assert!(
        !verified.headers().contains_key(header::SET_COOKIE),
        "no late auth, CSRF or intent-cookie replacement"
    );
    let replay = app
        .oneshot(post(
            "/registration-intent/verify",
            &original,
            serde_json::json!({"token":code}),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn opaque_declines_collisions_and_resends_have_equal_empty_results_and_independent_cookies() {
    let f = Fixture::new().await;
    let app = app(&f);
    let created = app
        .clone()
        .oneshot(registration_request("owner@example.test"))
        .await
        .unwrap();
    let original = response_credentials(&created);
    let collision = app
        .clone()
        .oneshot(registration_request("owner@example.test"))
        .await
        .unwrap();
    let decoy = response_credentials(&collision);
    assert_ne!(original.token.as_str(), decoy.token.as_str());
    assert_ne!(original.csrf.as_str(), decoy.csrf.as_str());
    let closed = super::super::router(
        AuthHttpState::new(
            "postgres://unused".to_owned(),
            Arc::new(TokenHasher::new(crate::test_keys::key(180)).unwrap()),
            ORIGIN.to_owned(),
            Arc::new(NoNetworkMail),
        )
        .unwrap(),
    );
    let declined = closed
        .oneshot(registration_request("owner@example.test"))
        .await
        .unwrap();
    for response in [created, collision, declined] {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }
    for credentials in [&original, &decoy, &Credentials::random()] {
        let response = app
            .clone()
            .oneshot(post(
                "/registration-intent/resend",
                credentials,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert!(
            to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn an_existing_other_account_session_is_preserved_and_refuses_intent_consumption() {
    let mut f = Fixture::new().await;
    let (other, _) = f.signup().await;
    auth::verify_email_with_password(
        &mut f.db,
        &f.hasher,
        &other.verification_token,
        &crate::test_keys::password(180),
    )
    .await
    .unwrap();
    let email: String =
        f.db.query_one("SELECT email FROM users WHERE id=$1", &[&other.user_id])
            .await
            .unwrap()
            .get(0);
    let session = auth::login(&f.db, &f.hasher, &email, &crate::test_keys::password(180))
        .await
        .unwrap();
    let (target, credentials) = f.signup().await;
    let mut request = post(
        "/registration-intent/verify",
        &credentials,
        serde_json::json!({"token":target.verification_token}),
    );
    request.headers_mut().append(
        header::COOKIE,
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={}", session.token)).unwrap(),
    );
    let response = app(&f).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        auth::authenticate_session(&f.db, &f.hasher, &session.token)
            .await
            .unwrap()
            .tenant
            .account_id(),
        other.account_id
    );
    assert!(
        !f.db
            .query_one(
                "SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1",
                &[&target.user_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.cleanup().await;
}
