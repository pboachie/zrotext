use super::*;
use axum::{body::Body, http::Request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Mutex;
use tower::ServiceExt;

struct CaptureVerification(Mutex<Option<String>>);

impl VerificationDispatcher for CaptureVerification {
    fn ready(&self) -> bool {
        true
    }

    fn password_reset_ready(&self) -> bool {
        true
    }

    fn dispatch<'a>(
        &'a self,
        _email: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>> {
        *self.0.lock().unwrap() = Some(token.to_owned());
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn password_change_response_clears_both_cookies() {
    let response = cleared_session_response().unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().any(
        |cookie| cookie.starts_with("__Host-zrotext_session=;") && cookie.contains("Max-Age=0")
    ));
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-zrotext_csrf=;")
                && cookie.contains("Max-Age=0"))
    );
}

fn json_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::ORIGIN, "https://zrotext.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn invite_post(uri: &str, body: serde_json::Value, token: &str) -> Request<Body> {
    let mut request = json_post(uri, body);
    request.headers_mut().insert(
        "x-zrotext-registration-token",
        HeaderValue::from_str(token).unwrap(),
    );
    request
}

fn owner_post(uri: &str, body: serde_json::Value, cookies: &str, csrf: &str) -> Request<Body> {
    let mut request = json_post(uri, body);
    request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(cookies).unwrap());
    request
        .headers_mut()
        .insert(CSRF_HEADER, HeaderValue::from_str(csrf).unwrap());
    request
}

#[tokio::test]
async fn mfa_enrollment_is_off_by_default() {
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(state);
    for (path, body) in [
        ("/mfa/enroll", serde_json::json!({"password":"unused"})),
        ("/mfa/confirm", serde_json::json!({"code":"000000"})),
    ] {
        let response = app.clone().oneshot(json_post(path, body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

fn key_list_request(cookie_header: Option<&str>, csrf: Option<&str>, uri: &str) -> Request<Body> {
    let mut request = Request::builder().uri(uri);
    if let Some(cookies) = cookie_header {
        request = request.header(header::COOKIE, cookies);
    }
    if let Some(csrf) = csrf {
        request = request.header(CSRF_HEADER, csrf);
    }
    request.body(Body::empty()).unwrap()
}

#[test]
fn registration_policy_defaults_closed_and_matches_exact_addresses_or_domains() {
    let token = STANDARD.encode([7u8; 32]);
    let mut headers = HeaderMap::new();
    assert!(
        RegistrationPolicy::parse(None, None, None, None)
            .unwrap()
            .admitted_email(&headers, "owner@example.test")
            .unwrap()
            .is_none()
    );
    let allowlist = RegistrationPolicy::parse(
        Some("allowlist"),
        Some("OWNER@Example.Test"),
        Some("Team.Example.Test"),
        Some(&token),
    )
    .unwrap();
    assert!(
        allowlist
            .admitted_email(&headers, "owner@example.test")
            .unwrap()
            .is_none()
    );
    headers.insert(
        "x-zrotext-registration-token",
        HeaderValue::from_static("wrong"),
    );
    assert!(
        allowlist
            .admitted_email(&headers, "owner@example.test")
            .unwrap()
            .is_none()
    );
    headers.insert(
        "x-zrotext-registration-token",
        HeaderValue::from_str(&token).unwrap(),
    );
    assert!(
        allowlist
            .admitted_email(&headers, "owner@example.test")
            .unwrap()
            .is_none()
    );
    let owner_invite = allowlist.issue_invite("OWNER@EXAMPLE.TEST").unwrap();
    headers.insert(
        "x-zrotext-registration-token",
        HeaderValue::from_str(&owner_invite).unwrap(),
    );
    assert_eq!(
        allowlist
            .admitted_email(&headers, "owner@example.test")
            .unwrap()
            .as_deref(),
        Some("owner@example.test")
    );
    assert!(
        allowlist
            .admitted_email(&headers, "another@team.example.test")
            .unwrap()
            .is_none()
    );
    let domain_invite = allowlist.issue_invite("another@team.example.test").unwrap();
    headers.insert(
        "x-zrotext-registration-token",
        HeaderValue::from_str(&domain_invite).unwrap(),
    );
    assert_eq!(
        allowlist
            .admitted_email(&headers, "another@team.example.test")
            .unwrap()
            .as_deref(),
        Some("another@team.example.test")
    );
    assert!(allowlist.issue_invite("someone@example.test").is_err());
    assert!(allowlist.admits("owner@example.test"));
    assert!(allowlist.admits("another@team.example.test"));
    assert!(!allowlist.admits("owner@evil.example.test"));
    assert!(!allowlist.admits("another@sub.team.example.test"));
    assert!(!allowlist.admits("another@example.test"));
    assert!(
        RegistrationPolicy::parse(Some("open"), None, None, None)
            .unwrap()
            .admits("another@example.test")
    );
    for (mode, emails, domains, key) in [
        (Some("allowlist"), None, None, Some(token.as_str())),
        (Some("allowlist"), Some("owner@example.test"), None, None),
        (Some("closed"), Some("owner@example.test"), None, None),
        (Some("closed"), None, None, Some(token.as_str())),
        (Some("open"), None, Some("example.test"), None),
        (
            Some("allowlist"),
            Some("owner@example.test,"),
            None,
            Some(token.as_str()),
        ),
        (
            Some("allowlist"),
            None,
            Some("example.test,evil..test"),
            Some(token.as_str()),
        ),
        (
            Some("allowlist"),
            None,
            Some("example.test@evil.test"),
            Some(token.as_str()),
        ),
        (
            Some("allowlist"),
            Some("owner@example.test"),
            None,
            Some("short"),
        ),
        (Some("OPEN"), None, None, None),
    ] {
        assert!(RegistrationPolicy::parse(mode, emails, domains, key).is_err());
    }
}

#[test]
fn canonical_origin_and_cookie_parsing_are_strict() {
    assert!(valid_canonical_origin("https://zrotext.example"));
    assert!(valid_canonical_origin("https://app.example.com:8443"));
    assert!(valid_canonical_origin("https://xn--bcher-kva.example"));
    assert!(valid_canonical_origin("https://[::1]"));
    assert!(!valid_canonical_origin("http://zrotext.example"));
    assert!(!valid_canonical_origin("https://zrotext.example/"));
    assert!(!valid_canonical_origin("https://zrotext.example/path"));
    assert!(!valid_canonical_origin("https://a@zrotext.example"));
    for (input, expected) in [
        ("https://App.Example.com", "https://app.example.com"),
        ("https://app.example.com:443", "https://app.example.com"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
    ] {
        assert!(!valid_canonical_origin(input));
        let error = AuthHttpState::new(
            "postgres://unused".to_owned(),
            Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
            input.to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .err()
        .unwrap();
        assert!(error.contains(&format!("use {expected}")));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("other=1; __Host-zrotext_session=zts_abc"),
    );
    assert_eq!(cookie(&headers, SESSION_COOKIE), Some("zts_abc"));
    assert_eq!(cookie(&headers, CSRF_COOKIE), None);
}

struct FailingVerification;

impl VerificationDispatcher for FailingVerification {
    fn ready(&self) -> bool {
        true
    }

    fn dispatch<'a>(
        &'a self,
        _email: &'a str,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>> {
        Box::pin(async { Err(DispatchFailure::Rejected) })
    }
}

#[tokio::test]
async fn repeated_delivery_failures_produce_one_content_free_warning() {
    let dispatcher = FailingVerification;
    let mut gate = VerificationWarningGate::default();
    let now = Instant::now();
    let mut warnings = Vec::new();
    for _ in 0..2 {
        let category = dispatcher
            .dispatch("owner@example.test", "ztv_secret-token")
            .await
            .unwrap_err();
        warnings.extend(gate.on_failure(category, now));
    }
    assert_eq!(
        warnings,
        ["verification mail delivery failed (category=rejected)"]
    );
    assert!(!warnings[0].contains("owner@example.test"));
    assert!(!warnings[0].contains("ztv_"));
    assert!(
        gate.on_failure(DispatchFailure::Rejected, now + Duration::from_secs(300))
            .is_some()
    );
}

#[tokio::test]
async fn failed_mail_worker_reports_each_attempt_and_final_dead_letter() {
    let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
        return;
    };
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("mail_failure_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let database_url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(44)).unwrap());
    let test_password = Uuid::new_v4().to_string();
    auth::register(&mut client, &hasher, "owner@example.test", &test_password)
        .await
        .unwrap();
    let state = AuthHttpState::new(
        database_url,
        hasher,
        "https://zrotext.example".to_owned(),
        Arc::new(FailingVerification),
    )
    .unwrap();
    let mut gate = VerificationWarningGate::default();
    let now = Instant::now();
    let mut warnings = Vec::new();
    for attempt in 1..=6 {
        let outcome = dispatch_one_verification_report(&state).await.unwrap();
        assert_eq!(
            outcome,
            VerificationDispatchOutcome::Failed {
                category: DispatchFailure::Rejected,
                dead_lettered: attempt == 6,
            }
        );
        if let VerificationDispatchOutcome::Failed { category, .. } = outcome {
            warnings.extend(gate.on_failure(category, now));
        }
        if attempt < 6 {
            client
                .execute(
                    "UPDATE verification_mail_outbox SET next_attempt_at=now()-interval '1 second'",
                    &[],
                )
                .await
                .unwrap();
        }
    }
    assert_eq!(
        warnings,
        ["verification mail delivery failed (category=rejected)"]
    );
    let row = client
        .query_one(
            "SELECT attempt_count, dead_at IS NOT NULL FROM verification_mail_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i32>(0), 6);
    assert!(row.get::<_, bool>(1));
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[test]
fn unauthenticated_writes_require_exact_origin() {
    let mut headers = HeaderMap::new();
    assert!(require_origin(&headers, "https://zrotext.example").is_err());
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    assert!(require_origin(&headers, "https://zrotext.example").is_err());
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://zrotext.example"),
    );
    assert!(require_origin(&headers, "https://zrotext.example").is_ok());
}

#[test]
fn smtp_configuration_preserves_sender_identity_without_connecting() {
    let sender = SmtpVerificationDispatcher::new(
        "smtp.example.test",
        465,
        "user".to_owned(),
        "test-only-password".to_owned(),
        "notice@example.test",
        Some("ZROtext"),
        Some("support@example.test"),
    )
    .unwrap();
    assert_eq!(sender.from.name.as_deref(), Some("ZROtext"));
    assert_eq!(
        sender.reply_to.unwrap().email.to_string(),
        "support@example.test"
    );
    assert!(
        SmtpVerificationDispatcher::new(
            "smtp.example.test",
            587,
            "user".to_owned(),
            "test-only-password".to_owned(),
            "notice@example.test",
            Some("bad\nname"),
            None,
        )
        .is_err()
    );
}

#[test]
fn verification_mail_names_the_shipped_form_without_a_code_url() {
    let body = verification_email_body("synthetic-code");
    assert!(body.contains("/owner/account#verify"));
    assert!(body.contains("synthetic-code"));
    assert!(!body.contains("?token="));
}

#[tokio::test]
async fn registration_fails_closed_without_delivery_and_never_returns_token() {
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_registration_policy(RegistrationPolicy::Open);
    let request = Request::builder()
        .method("POST")
        .uri("/register")
        .header(header::ORIGIN, "https://zrotext.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"email":"owner@example.test","password":"correct horse 123"}"#,
        ))
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("ztv_"));
}

#[tokio::test]
async fn allowlist_without_address_bound_invite_never_reaches_database() {
    let master = STANDARD.encode([3u8; 32]);
    let policy = RegistrationPolicy::parse(
        Some("allowlist"),
        Some("owner@example.test"),
        None,
        Some(&master),
    )
    .unwrap();
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap()
    .with_registration_policy(policy);
    let app = router(state);
    for request in [
        json_post(
            "/register",
            serde_json::json!({"email":"owner@example.test","password":"short"}),
        ),
        invite_post(
            "/register",
            serde_json::json!({"email":"not-an-email","password":"short"}),
            &STANDARD.encode([4u8; 32]),
        ),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    }
}

#[tokio::test]
async fn login_rejects_cross_origin_before_password_work() {
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"email":"owner@example.test","password":"correct horse 123"}"#,
        ))
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn verified_password_reset_survives_anonymous_request_and_confirm_exhaustion() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_reset_budget_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    for index in 0..120 {
        assert!(
            abuse_limits::consume(
                &db,
                &hasher,
                Limit::PasswordResetRequest,
                Some(&format!("unknown-{index}@example.test")),
            )
            .await
            .unwrap()
        );
    }
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap();
    let app = router(state);
    for email in ["unknown-final@example.test", "owner@example.test"] {
        let response = app
            .clone()
            .oneshot(json_post(
                "/password/reset/request",
                serde_json::json!({"email":email}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM password_reset_mail_outbox WHERE canceled_at IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let reset = account::claim_reset_mail(&mut db, &hasher)
        .await
        .unwrap()
        .unwrap();
    for index in 0..120 {
        assert!(
            abuse_limits::consume(
                &db,
                &hasher,
                Limit::PasswordResetConfirm,
                Some(&format!("unknown-confirm-{index}")),
            )
            .await
            .unwrap()
        );
    }
    let invalid = format!("ztr_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let new_password = Uuid::new_v4().to_string();
    let invalid_response = app
        .clone()
        .oneshot(json_post(
            "/password/reset/confirm",
            serde_json::json!({"token":invalid,"new_password":new_password}),
        ))
        .await
        .unwrap();
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    let valid_response = app
        .clone()
        .oneshot(json_post(
            "/password/reset/confirm",
            serde_json::json!({"token":reset.token,"new_password":new_password}),
        ))
        .await
        .unwrap();
    assert_eq!(valid_response.status(), StatusCode::NO_CONTENT);
    let replay = app
        .clone()
        .oneshot(json_post(
            "/password/reset/confirm",
            serde_json::json!({"token":reset.token,"new_password":new_password}),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &new_password)
            .await
            .is_ok()
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_http_account_lifecycle_enforces_csrf_and_revocation() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_auth_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (test_client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/002_auth.sql"
        ))
        .await
        .unwrap();
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/005_verification_outbox.sql"
        ))
        .await
        .unwrap();
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"
        ))
        .await
        .unwrap();
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/013_owner_mfa.sql"
        ))
        .await
        .unwrap();
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
        ))
        .await
        .unwrap();
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"
        ))
        .await
        .unwrap();
    let capture = Arc::new(CaptureVerification(Mutex::new(None)));
    let state = AuthHttpState::new(
        url,
        Arc::new(TokenHasher::new(crate::test_keys::key(42)).unwrap()),
        "https://zrotext.example".to_owned(),
        capture.clone(),
    )
    .unwrap();
    let denied = router(state.clone());
    assert_eq!(
        denied
            .oneshot(json_post(
                "/register",
                serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    let master_key = STANDARD.encode([9u8; 32]);
    let policy = RegistrationPolicy::parse(
        Some("allowlist"),
        Some("OWNER@EXAMPLE.TEST,SECOND@EXAMPLE.TEST"),
        None,
        Some(&master_key),
    )
    .unwrap();
    let invite = policy.issue_invite("owner@example.test").unwrap();
    let state = state.with_registration_policy(policy);
    let app = router(state.clone());
    assert_eq!(
        app.clone()
            .oneshot(json_post(
                "/register",
                serde_json::json!({"email":"owner@example.test","password":"short"}),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        app.clone()
            .oneshot(invite_post(
                "/register",
                serde_json::json!({"email":"not-an-email","password":"short"}),
                &STANDARD.encode([8u8; 32]),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        app.clone()
            .oneshot(invite_post(
                "/register",
                serde_json::json!({"email":"stranger@example.test","password":"correct horse 123"}),
                &invite,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        app.clone()
            .oneshot(invite_post(
                "/register",
                serde_json::json!({"email":"second@example.test","password":"correct horse 123"}),
                &invite,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        test_client
            .query_one("SELECT count(*) FROM users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        test_client
            .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let response = app
        .clone()
        .oneshot(invite_post(
            "/register",
            serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
            &invite,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        test_client
            .query_one("SELECT count(*) FROM accounts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        test_client
            .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    for (email, password) in [
        ("unknown@example.test", "correct horse 123"),
        ("owner@example.test", "wrong password"),
        ("owner@example.test", "correct horse 123"),
    ] {
        let response = app
            .clone()
            .oneshot(json_post(
                "/resend-verification",
                serde_json::json!({"email":email,"password":password}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    assert!(dispatch_one_verification(&state).await.unwrap());
    let token = capture.0.lock().unwrap().take().unwrap();
    let response = app
        .clone()
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":token}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Closing registration after verification leaves the owner able to
    // authenticate and use the same account.
    let closed_app = router(
        state
            .clone()
            .with_registration_policy(RegistrationPolicy::Closed),
    );
    let response = closed_app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 3);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    let cookie_header = cookies.join("; ");
    let csrf = cookies[1].split_once('=').unwrap().1;
    let session_request = Request::builder()
        .uri("/session")
        .header(header::COOKIE, &cookie_header)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(session_request).await.unwrap().status(),
        StatusCode::OK
    );
    let second = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":"correct horse 123"}),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
    let second_cookie = second
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ");
    let copied_cookie_only = owner_post(
        "/sessions/revoke-others",
        serde_json::json!({}),
        &cookie_header,
        csrf,
    );
    assert_eq!(
        app.clone()
            .oneshot(copied_cookie_only)
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let wrong_password = Uuid::new_v4().to_string();
    let stolen_request = owner_post(
        "/sessions/revoke-others",
        serde_json::json!({"current_password":wrong_password}),
        &cookie_header,
        csrf,
    );
    assert_eq!(
        app.clone().oneshot(stolen_request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let second_session = || {
        Request::builder()
            .uri("/session")
            .header(header::COOKIE, &second_cookie)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(second_session())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let proven_request = owner_post(
        "/sessions/revoke-others",
        serde_json::json!({"current_password":"correct horse 123"}),
        &cookie_header,
        csrf,
    );
    assert_eq!(
        app.clone().oneshot(proven_request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(second_session())
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let body = serde_json::json!({"scopes":["messages:read"],"lifetime_days":30});
    let mut request = json_post("/api-keys", body.clone());
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie_header).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut request = json_post("/api-keys", body);
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie_header).unwrap(),
    );
    request
        .headers_mut()
        .insert(CSRF_HEADER, HeaderValue::from_str(csrf).unwrap());
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let key: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let key_id = key["id"].as_str().unwrap();
    assert!(key["token"].as_str().unwrap().starts_with("ztk_"));
    let response = app
        .clone()
        .oneshot(key_list_request(None, None, "/api-keys"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response = app
        .clone()
        .oneshot(key_list_request(Some(&cookie_header), None, "/api-keys"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some("wrong"),
            "/api-keys",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            "/api-keys",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let listed = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&listed).contains("ztk_"));
    assert!(!String::from_utf8_lossy(&listed).contains("token_hash"));
    let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["id"], key["id"]);
    assert_eq!(listed["keys"][0]["status"], "active");
    assert_eq!(
        listed["keys"][0]["scopes"],
        serde_json::json!(["messages:read"])
    );
    assert!(listed["keys"][0].get("token").is_none());
    test_client
        .execute(
            "UPDATE api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
            &[&Uuid::parse_str(key_id).unwrap()],
        )
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            "/api-keys",
        ))
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed["keys"][0]["status"], "expired");
    let (mut outsider, connection) = tokio_postgres::connect(&state.database_url, NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let foreign_password = Uuid::new_v4().to_string();
    let foreign = auth::register(
        &mut outsider,
        &state.hasher,
        "foreign@example.test",
        &foreign_password,
    )
    .await
    .unwrap();
    auth::verify_email(&mut outsider, &state.hasher, &foreign.verification_token)
        .await
        .unwrap();
    let foreign_session = auth::login(
        &outsider,
        &state.hasher,
        "foreign@example.test",
        &foreign_password,
    )
    .await
    .unwrap();
    let foreign_owner =
        auth::authenticate_session(&outsider, &state.hasher, &foreign_session.token)
            .await
            .unwrap();
    let foreign_key = auth::create_api_key(
        &mut outsider,
        &state.hasher,
        &foreign_owner,
        &[Scope::MessagesRead],
        None,
        Some(30),
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            "/api-keys",
        ))
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_ne!(listed["keys"][0]["id"], foreign_key.id.to_string());
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            &format!("/api-keys?before={}", foreign_key.id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/api-keys/{key_id}"))
        .header(header::ORIGIN, "https://zrotext.example")
        .header(header::COOKIE, &cookie_header)
        .header(CSRF_HEADER, csrf)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            "/api-keys",
        ))
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed["keys"][0]["status"], "revoked");
    let owner = auth::authenticate_session(
        &test_client,
        &state.hasher,
        cookies[0].split_once('=').unwrap().1,
    )
    .await
    .unwrap();
    for i in 0..52u8 {
        let test_hash = rand::random::<[u8; 32]>();
        test_client
                .execute(
                    "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,$6)",
                    &[
                        &Uuid::new_v4(),
                        &owner.tenant.account_id(),
                        &owner.user_id,
                        &format!("paging{i:06}"),
                        &&test_hash[..],
                        &vec!["messages:read".to_owned()],
                    ],
                )
                .await
                .unwrap();
    }
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            "/api-keys",
        ))
        .await
        .unwrap();
    let first: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first["keys"].as_array().unwrap().len(), 50);
    let cursor = first["next_cursor"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(key_list_request(
            Some(&cookie_header),
            Some(csrf),
            &format!("/api-keys?before={cursor}"),
        ))
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second["keys"].as_array().unwrap().len(), 3);
    assert_eq!(second["next_cursor"], serde_json::Value::Null);
    assert!(!first["keys"].as_array().unwrap().iter().any(|key| {
        second["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|other| other["id"] == key["id"])
    }));
    let request = Request::builder()
        .method("POST")
        .uri("/logout")
        .header(header::ORIGIN, "https://zrotext.example")
        .header(header::COOKIE, &cookie_header)
        .header(CSRF_HEADER, csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let request = Request::builder()
        .uri("/session")
        .header(header::COOKIE, &cookie_header)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // The stolen-cookie regression above signs in a second browser.
    for _ in 0..10 {
        assert!(
            auth::abuse_limits::consume(
                &test_client,
                &state.hasher,
                Limit::Login,
                Some("owner@example.test"),
            )
            .await
            .unwrap()
        );
    }
    let response = router(state)
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"OWNER@example.test","password":"correct horse 123"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn api_key_issuance_budget_survives_concurrency_revocation_and_new_sessions() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("key_budget_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(vec![42; 32]).unwrap());
    let password = format!("synthetic-{}", Uuid::new_v4());
    let mut sessions = Vec::new();
    for email in ["owner@example.test", "other@example.test"] {
        let signup = auth::register(&mut client, &hasher, email, &password)
            .await
            .unwrap();
        auth::verify_email(&mut client, &hasher, &signup.verification_token)
            .await
            .unwrap();
        sessions.push(
            auth::login(&client, &hasher, email, &password)
                .await
                .unwrap(),
        );
    }
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let apps = [router(state.clone()), router(state)];
    let request_for = |session: &auth::SessionCredentials| {
        owner_post(
            "/api-keys",
            serde_json::json!({"scopes":["messages:read"]}),
            &format!(
                "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                session.token, session.csrf_token
            ),
            &session.csrf_token,
        )
    };
    let mut tasks = Vec::new();
    for index in 0..32 {
        let app = apps[index % 2].clone();
        let request = request_for(&sessions[0]);
        tasks.push(tokio::spawn(async move {
            app.oneshot(request).await.unwrap().status()
        }));
    }
    let mut created = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            status => panic!("unexpected status {status}"),
        }
    }
    assert_eq!(created, 20);
    let count: i64 = client
        .query_one("SELECT count(*) FROM api_keys", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 20);
    client
        .execute("UPDATE api_keys SET revoked_at=now()", &[])
        .await
        .unwrap();
    let fresh = auth::login(&client, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert_eq!(
        apps[0]
            .clone()
            .oneshot(request_for(&fresh))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        apps[1]
            .clone()
            .oneshot(request_for(&sessions[1]))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    // Cleanup must retain a daily subject budget beyond the generic two-minute window.
    client
        .execute(
            "UPDATE auth_abuse_counters SET updated_at=now()-interval '3 minutes'",
            &[],
        )
        .await
        .unwrap();
    abuse_limits::prune(&client).await.unwrap();
    assert_eq!(
        apps[0]
            .clone()
            .oneshot(request_for(&fresh))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    client
        .batch_execute(
            "DROP FUNCTION auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)",
        )
        .await
        .unwrap();
    assert_eq!(
        apps[1]
            .clone()
            .oneshot(request_for(&sessions[1]))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_http_expired_pending_signup_is_replaced_with_uniform_responses() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_pending_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let capture = Arc::new(CaptureVerification(Mutex::new(None)));
    let state = AuthHttpState::new(
        url,
        Arc::new(TokenHasher::new(crate::test_keys::key(43)).unwrap()),
        "https://zrotext.example".to_owned(),
        capture.clone(),
    )
    .unwrap()
    .with_registration_policy(RegistrationPolicy::Open);
    let app = router(state.clone());
    let register = |password: &'static str| {
        app.clone().oneshot(json_post(
            "/register",
            serde_json::json!({"email":"held@example.test","password":password}),
        ))
    };
    // First registrant never verifies; its code is mailed to the address.
    assert_eq!(
        register("first registrant 1").await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert!(dispatch_one_verification(&state).await.unwrap());
    let stale_token = capture.0.lock().unwrap().take().unwrap();
    // A second attempt inside the window looks identical and mails nothing.
    assert_eq!(
        register("address owner 123").await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert!(!dispatch_one_verification(&state).await.unwrap());
    client
        .execute(
            "UPDATE users SET created_at=now()-interval '25 hours' WHERE email='held@example.test'",
            &[],
        )
        .await
        .unwrap();
    // After the window the same request replaces the stale record.
    assert_eq!(
        register("address owner 123").await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert!(dispatch_one_verification(&state).await.unwrap());
    let token = capture.0.lock().unwrap().take().unwrap();
    assert_ne!(token, stale_token);
    let verify = |token: String| {
        app.clone().oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":token}),
        ))
    };
    assert_eq!(
        verify(stale_token).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        verify(token).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let login = |password: &'static str| {
        app.clone().oneshot(json_post(
            "/login",
            serde_json::json!({"email":"held@example.test","password":password}),
        ))
    };
    assert_eq!(
        login("first registrant 1").await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login("address owner 123").await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn valid_verification_survives_anonymous_invalid_code_exhaustion() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_verify_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let test_password = Uuid::new_v4().to_string();
    let signup = auth::register(
        &mut client,
        &hasher,
        "verify-cap@example.test",
        &test_password,
    )
    .await
    .unwrap();
    let state = AuthHttpState::new(
        url.clone(),
        hasher,
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let a = router(state.clone());
    let b = router(state.clone());
    for _ in 0..120 {
        let response = a
            .clone()
            .oneshot(json_post(
                "/verify-email",
                serde_json::json!({"token":"invalid"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut wrong_code = signup.verification_token.clone();
    let last = wrong_code.pop().unwrap();
    wrong_code.push(if last == 'A' { 'Q' } else { 'A' });
    assert!(
        !auth::verification_token_is_live(&client, &state.hasher, &wrong_code)
            .await
            .unwrap()
    );
    let invalid = b
        .clone()
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":wrong_code}),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut wrong_origin = json_post(
        "/verify-email",
        serde_json::json!({"token":signup.verification_token}),
    );
    wrong_origin.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    assert_eq!(
        b.clone().oneshot(wrong_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let valid = b
        .clone()
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":signup.verification_token}),
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::NO_CONTENT);
    let replay = a
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":signup.verification_token}),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::TOO_MANY_REQUESTS);
    let row = client
        .query_one(
            "SELECT u.email_verified_at IS NOT NULL,
                        (SELECT count(*) FROM email_verifications v
                         WHERE v.user_id=u.id AND v.used_at IS NOT NULL)
                 FROM users u WHERE u.id=$1",
            &[&signup.user_id],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, i64>(1), 1);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_sign_in_survives_anonymous_login_budget_exhaustion() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_login_budget_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let signup = auth::register(&mut client, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut client, &hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    let other = auth::register(&mut client, &hasher, "other@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut client, &hasher, &other.verification_token)
            .await
            .unwrap()
    );
    let state = AuthHttpState::new(
        url.clone(),
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(state);
    let login = |email: &str, cookie: Option<&str>| {
        let mut request = json_post(
            "/login",
            serde_json::json!({"email":email,"password":password.as_str()}),
        );
        if let Some(cookie) = cookie {
            request
                .headers_mut()
                .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        }
        request
    };
    let set_cookies = |response: &Response| {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    // An ordinary sign-in remembers this browser.
    let response = app
        .clone()
        .oneshot(login("owner@example.test", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 3);
    let known = cookies[2].clone();
    assert!(known.starts_with("__Host-zrotext_login_client=ztl_"));
    assert!(!known.contains("owner"));

    // One anonymous source targets the owner's address, then sprays
    // made-up addresses until the shared route budget is exhausted too.
    for _ in 1..12 {
        assert!(
            abuse_limits::consume(&client, &hasher, Limit::Login, Some("owner@example.test"))
                .await
                .unwrap()
        );
    }
    for index in 12..237 {
        assert!(
            abuse_limits::consume(
                &client,
                &hasher,
                Limit::Login,
                Some(&format!("junk-{index}@example.test")),
            )
            .await
            .unwrap()
        );
    }
    for index in 237..240 {
        let response = app
            .clone()
            .oneshot(login(&format!("junk-{index}@example.test"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // Under a busy parallel suite the 60-second route window may roll
    // while the password workers run. Top it up so the rescue assertion
    // still exercises an exhausted anonymous ceiling.
    for index in 0..240 {
        if !abuse_limits::consume(
            &client,
            &hasher,
            Limit::Login,
            Some(&format!("topup-{index}@example.test")),
        )
        .await
        .unwrap()
        {
            break;
        }
    }
    assert!(
        !abuse_limits::consume(
            &client,
            &hasher,
            Limit::Login,
            Some("topup-final@example.test"),
        )
        .await
        .unwrap()
    );
    let junk = app
        .clone()
        .oneshot(login("junk-final@example.test", None))
        .await
        .unwrap();
    assert_eq!(junk.status(), StatusCode::TOO_MANY_REQUESTS);
    // Without its login-client token, the owner looks like everyone else.
    let response = app
        .clone()
        .oneshot(login("owner@example.test", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // A forged tag, or a token presented for another address, is ignored.
    let (id, _) = known.split_once('.').unwrap();
    let forged = format!("{id}.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
    let response = app
        .clone()
        .oneshot(login("owner@example.test", Some(&forged)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = app
        .clone()
        .oneshot(login("other@example.test", Some(&known)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // The remembered browser still signs in and keeps its token.
    let response = app
        .clone()
        .oneshot(login(" OWNER@example.test ", Some(&known)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with("__Host-zrotext_session=zts_"));
    // The remembered browser's own budget is bounded like any address.
    let (_, value) = known.split_once('=').unwrap();
    let own = auth::login_client_subject(&hasher, value, "owner@example.test").unwrap();
    for _ in 1..12 {
        assert!(
            abuse_limits::consume_verified(&client, &hasher, Limit::Login, &own)
                .await
                .unwrap()
        );
    }
    let response = app
        .clone()
        .oneshot(login("owner@example.test", Some(&known)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Second-factor completion: junk challenge tokens exhaust the route,
    // but a live challenge still reaches factor verification.
    client
        .execute(
            "UPDATE users SET mfa_enabled=true WHERE id=$1",
            &[&signup.user_id],
        )
        .await
        .unwrap();
    let challenge = mfa::begin_login_challenge(
        &client,
        &hasher,
        signup.account_id,
        signup.user_id,
        &password,
    )
    .await
    .unwrap();
    for index in 0..300 {
        abuse_limits::consume(
            &client,
            &hasher,
            Limit::MfaChallenge,
            Some(&format!("junk-{index}")),
        )
        .await
        .unwrap();
    }
    let mfa_login = |token: &str| {
        json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":token,"code":"000000"}),
        )
    };
    let junk_token = format!("ztm_{}", URL_SAFE_NO_PAD.encode([7u8; 32]));
    assert_eq!(
        app.clone()
            .oneshot(mfa_login(&junk_token))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.oneshot(mfa_login(&challenge)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_http_mfa_never_sets_session_before_factor_and_limits_replay() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_mfa_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let wrong_password = Uuid::new_v4().to_string();
    let signup = auth::register(&mut client, &hasher, "mfa@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut client, &hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    let key = rand::random::<[u8; 32]>().to_vec();
    let state = AuthHttpState::new(
        url.clone(),
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_mfa_cipher(Arc::new(MfaCipher::new(key).unwrap()))
    .with_mfa_enrollment_enabled();
    let app = router(state);
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 3);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    let cookie_header = cookies.join("; ");
    let csrf = cookies[1].split_once('=').unwrap().1;
    let response = app
        .clone()
        .oneshot(json_post(
            "/mfa/enroll",
            serde_json::json!({"password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/enroll",
            serde_json::json!({"password":wrong_password.as_str()}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/enroll",
            serde_json::json!({"password":password.as_str()}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let secret = totp_rs::Secret::try_from_base32(body["secret_base32"].as_str().unwrap()).unwrap();
    let code = totp_rs::Builder::new()
        .with_secret(secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/confirm",
            serde_json::json!({"code":code}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let recovery = body["recovery_codes"][0].as_str().unwrap();
    let recovery_next = body["recovery_codes"][1].as_str().unwrap().to_owned();
    let recovery_disable = body["recovery_codes"][2].as_str().unwrap().to_owned();
    let status_request = Request::builder()
        .method("GET")
        .uri("/mfa")
        .header(header::COOKIE, &cookie_header)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(status_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge = body["challenge_token"].as_str().unwrap();
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            &[&signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let response = app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":challenge,"code":recovery}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        3
    );
    let response = app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":challenge,"code":recovery}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            &[&signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let second_challenge = body["challenge_token"].as_str().unwrap();
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(json_post(
                "/login/mfa",
                serde_json::json!({"challenge_token":second_challenge,"code":"invalid"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":second_challenge,"code":recovery_next}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let fresh_challenge = body["challenge_token"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":fresh_challenge,"code":recovery_next}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/disable",
            serde_json::json!({"password":password.as_str(),"code":recovery_disable}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    client
            .execute(
                "UPDATE owner_mfa SET failed_window_started_at=now()-interval '16 minutes' WHERE account_id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap();
    let no_key_app = router(
        AuthHttpState::new(
            url,
            hasher,
            "https://zrotext.example".to_owned(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap(),
    );
    let response = no_key_app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge = body["challenge_token"].as_str().unwrap();
    let response = no_key_app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":challenge,"code":recovery_next}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 3);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    let cookie_header = cookies.join("; ");
    let csrf = cookies[1].split_once('=').unwrap().1;
    let response = no_key_app
        .clone()
        .oneshot(owner_post(
            "/mfa/disable",
            serde_json::json!({"password":password.as_str(),"code":"zrc_AAAAAAAAAAAAAAAAAAAAAA"}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let failures: i32 = client
        .query_one(
            "SELECT failed_attempts FROM owner_mfa WHERE account_id=$1",
            &[&signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failures, 1);
    let response = no_key_app
        .clone()
        .oneshot(owner_post(
            "/mfa/disable",
            serde_json::json!({"password":password.as_str(),"code":recovery_disable}),
            &cookie_header,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = no_key_app
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"mfa@example.test","password":password.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
