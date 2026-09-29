use super::*;
use axum::{body::Body, extract::ConnectInfo, http::Request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{net::SocketAddr, sync::Mutex};
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

/// The raw value of one `Set-Cookie` pair in a response, without attributes.
fn set_cookie_value(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
}

/// A reset request with optional trusted-browser cookie, transport peer, and
/// forwarded header. Returns the full response for byte-parity checks.
fn reset_request(
    email: &str,
    trusted_cookie: Option<&str>,
    peer: Option<SocketAddr>,
    forwarded_for: Option<&str>,
) -> Request<Body> {
    let mut request = json_post(
        "/password/reset/request",
        serde_json::json!({"email": email}),
    );
    if let Some(cookie) = trusted_cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
    }
    if let Some(forwarded) = forwarded_for {
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_str(forwarded).unwrap());
    }
    if let Some(peer) = peer {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    request
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

#[tokio::test]
async fn api_key_route_authenticates_before_parsing_the_body() {
    // Since the preauth change on main, owner mutation routes authenticate
    // (and admit through the account slot) before the body is read, so an
    // unusable database answers 503 regardless of the body. The bodies differ
    // only in the required password, proving neither is parsed first; the
    // missing- and wrong-password 400s are covered against a live database by
    // postgres_http_account_lifecycle_enforces_csrf_and_revocation.
    let state = AuthHttpState::new(
        "not a database url".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(state);
    let cookies = format!("{SESSION_COOKIE}=zts_fixture; {CSRF_COOKIE}=ztc_fixture");
    for body in [
        serde_json::json!({"scopes":["messages:read"],"lifetime_days":30}),
        serde_json::json!({
            "scopes":["messages:read"],"lifetime_days":30,
            "current_password":"synthetic-password",
        }),
    ] {
        let response = app
            .clone()
            .oneshot(owner_post("/api-keys", body, &cookies, "ztc_fixture"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[test]
fn revoke_others_keeps_api_keys_unless_the_body_opts_in() {
    let body: RevokeOtherSessionsBody =
        serde_json::from_value(serde_json::json!({"current_password":"synthetic"})).unwrap();
    assert!(!body.revoke_api_keys);
    let body: RevokeOtherSessionsBody = serde_json::from_value(serde_json::json!({
        "current_password":"synthetic","revoke_api_keys":true,
    }))
    .unwrap();
    assert!(body.revoke_api_keys);
    assert!(
        serde_json::from_value::<RevokeOtherSessionsBody>(serde_json::json!({
            "current_password":"synthetic","revoke_api_keys":"no",
        }))
        .is_err()
    );
}

#[test]
fn api_key_lifetime_body_maps_omitted_null_and_days() {
    // The required step-up password is a parse-level constraint too: a body
    // without it never deserializes, so the route cannot reach the proof with
    // a missing password.
    assert!(
        serde_json::from_value::<CreateKeyBody>(serde_json::json!({
            "scopes":["messages:read"],"lifetime_days":30,
        }))
        .is_err()
    );
    let body: CreateKeyBody = serde_json::from_value(
        serde_json::json!({"scopes":["messages:read"],"current_password":"x"}),
    )
    .unwrap();
    assert_eq!(body.lifetime_days, crate::auth::ApiKeyLifetime::Unspecified);
    let body: CreateKeyBody = serde_json::from_value(serde_json::json!({
        "scopes":["messages:read"],"lifetime_days":null,"current_password":"x",
    }))
    .unwrap();
    assert_eq!(body.lifetime_days, crate::auth::ApiKeyLifetime::Never);
    let body: CreateKeyBody = serde_json::from_value(serde_json::json!({
        "scopes":["messages:read"],"lifetime_days":30,"current_password":"x",
    }))
    .unwrap();
    assert_eq!(body.lifetime_days, crate::auth::ApiKeyLifetime::Days(30));
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

/// Reproduces the invite token format that shipped before expiring invites,
/// from `invite_digest` in `crates/server/src/http_auth/mod.rs` at commit
/// e13264c ("Integrate owner enrollment, account setup and mail diagnostics
/// (#189)", 2026-09-24): a bare `STANDARD`-encoded HMAC-SHA256 over the
/// `zrotext-registration-invite-v1\0` domain separator and the normalized
/// email. Exactly 32 bytes, no expiry field. An authentic v1 token like this
/// must stop admitting under the v2 format, since a leaked one would
/// otherwise admit its address forever.
fn legacy_v1_invite_token(key: &[u8; 32], normalized_email: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"zrotext-registration-invite-v1\0");
    mac.update(normalized_email.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

#[test]
fn invite_tokens_carry_a_signed_expiry_and_denials_stay_uniform() {
    // The enrollment key rides the random per-process test master, like every
    // other fixture secret, so no reusable key bytes appear in source.
    let enrollment_key: [u8; 32] = crate::test_keys::key(91).try_into().unwrap();
    let master = STANDARD.encode(enrollment_key);
    let allowlist = RegistrationPolicy::parse(
        Some("allowlist"),
        Some("owner@example.test,second@example.test"),
        None,
        Some(&master),
    )
    .unwrap();
    // Issuance and admission share one pinned instant, so every assertion is
    // exact rather than leaving slack for wall-clock scheduling.
    let now = 2_000_000_000u64;
    let admitted = |token: &str, email: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-zrotext-registration-token",
            HeaderValue::from_str(token).unwrap(),
        );
        allowlist.admitted_email_at(&headers, email, now).unwrap()
    };

    // Default issuance signs an expiry exactly seven days out.
    let invite = allowlist
        .issue_invite_with_lifetime_at("owner@example.test", INVITE_MAX_LIFETIME, now)
        .unwrap();
    let decoded = STANDARD.decode(&invite).unwrap();
    assert_eq!(decoded.len(), INVITE_TOKEN_LEN);
    assert_eq!(
        u64::from_be_bytes(decoded[..8].try_into().unwrap()),
        now + INVITE_MAX_LIFETIME.as_secs()
    );

    // A requested shorter lifetime lands exactly in the signed expiry.
    let short = allowlist
        .issue_invite_with_lifetime_at("owner@example.test", Duration::from_secs(3600), now)
        .unwrap();
    let short_bytes = STANDARD.decode(&short).unwrap();
    assert_eq!(
        u64::from_be_bytes(short_bytes[..8].try_into().unwrap()),
        now + 3600
    );

    // The lifetime stays bounded: sub-second, zero, and over-cap requests are
    // refused; whole-second lifetimes up to the cap are accepted. A 500ms
    // lifetime would otherwise truncate to zero seconds of life and silently
    // mint an already-expired token.
    assert!(
        allowlist
            .issue_invite_with_lifetime_at("owner@example.test", Duration::from_millis(500), now)
            .is_err()
    );
    assert!(
        allowlist
            .issue_invite_with_lifetime_at("owner@example.test", Duration::ZERO, now)
            .is_err()
    );
    assert!(
        allowlist
            .issue_invite_with_lifetime_at(
                "owner@example.test",
                INVITE_MAX_LIFETIME + Duration::from_secs(1),
                now
            )
            .is_err()
    );
    assert!(
        allowlist
            .issue_invite_with_lifetime_at("owner@example.test", INVITE_MAX_LIFETIME, now)
            .is_ok()
    );

    // An unexpired invite still admits exactly its bound address, never
    // another allowlisted one.
    assert_eq!(
        admitted(&short, "owner@example.test").as_deref(),
        Some("owner@example.test")
    );
    assert_eq!(admitted(&short, "second@example.test"), None);

    // An expired invite, and one expiring exactly now, are denied.
    let expired = invite_token(&enrollment_key, "owner@example.test", now - 1);
    assert_eq!(admitted(&expired, "owner@example.test"), None);
    let boundary = invite_token(&enrollment_key, "owner@example.test", now);
    assert_eq!(admitted(&boundary, "owner@example.test"), None);

    // Admission holds the same lifetime cap as issuance: a correctly signed
    // expiry further out than seven days is denied even though only the
    // master key could have minted it, while the cap boundary still admits.
    let overreaching = invite_token(
        &enrollment_key,
        "owner@example.test",
        now + INVITE_MAX_LIFETIME.as_secs() + 1,
    );
    assert_eq!(admitted(&overreaching, "owner@example.test"), None);
    let capped = invite_token(
        &enrollment_key,
        "owner@example.test",
        now + INVITE_MAX_LIFETIME.as_secs(),
    );
    assert_eq!(
        admitted(&capped, "owner@example.test").as_deref(),
        Some("owner@example.test")
    );

    // Stretching the expiry without the master key breaks the tag.
    let mut stretched = short_bytes.clone();
    stretched[..8].copy_from_slice(&(now + 24 * 60 * 60).to_be_bytes());
    assert_eq!(
        admitted(&STANDARD.encode(stretched), "owner@example.test"),
        None
    );

    // A flipped tag byte is denied.
    let mut flipped = short_bytes;
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        admitted(&STANDARD.encode(flipped), "owner@example.test"),
        None
    );

    // An authentic pre-expiry v1 digest (the legacy_v1_invite_token
    // construction above, 32 bytes with no expiry field) is denied.
    let legacy = legacy_v1_invite_token(&enrollment_key, "owner@example.test");
    assert_eq!(STANDARD.decode(&legacy).unwrap().len(), 32);
    assert_eq!(admitted(&legacy, "owner@example.test"), None);

    // A v2 token whose signed expiry is the Unix epoch is well-formed but
    // never live. This is a v2 token with expiry zero, distinct from the
    // legacy v1 format above.
    let zero_expiry = invite_token(&enrollment_key, "owner@example.test", 0);
    assert_eq!(
        STANDARD.decode(&zero_expiry).unwrap().len(),
        INVITE_TOKEN_LEN
    );
    assert_eq!(admitted(&zero_expiry, "owner@example.test"), None);
}

#[tokio::test]
async fn expired_or_forged_invites_share_the_denial_no_op_without_database_access() {
    let enrollment_key: [u8; 32] = crate::test_keys::key(92).try_into().unwrap();
    let master = STANDARD.encode(enrollment_key);
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
    // The request path reads the wall clock itself, so fixtures are anchored
    // to the instant captured before the requests run: the expired token can
    // only grow more expired and the valid one keeps a full hour of signed
    // life, whatever instant admission ends up observing.
    let before = unix_now_secs().unwrap();
    let expired = invite_token(
        &enrollment_key,
        "owner@example.test",
        before.saturating_sub(1),
    );
    let valid = invite_token(&enrollment_key, "owner@example.test", before + 3600);
    let mut stretched = STANDARD.decode(&valid).unwrap();
    stretched[..8].copy_from_slice(&(before + 24 * 60 * 60).to_be_bytes());
    let legacy = legacy_v1_invite_token(&enrollment_key, "owner@example.test");
    // The database URL is unusable on purpose: a request that passed admission
    // would fail to connect and answer 503 instead of the 202 no-op.
    let app = router(state);
    for token in [
        expired.as_str(),
        STANDARD.encode(stretched).as_str(),
        legacy.as_str(),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(invite_post(
                    "/register",
                    serde_json::json!({
                        "email":"owner@example.test",
                        "password":crate::test_keys::password(1)
                    }),
                    token,
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
                    "UPDATE verification_mail_outbox SET next_attempt_at=now()-interval '1 minute'",
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
        crate::test_keys::password(3),
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
            crate::test_keys::password(3),
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
    // Recipients who never signed up must learn that the code is not theirs
    // to use, and registrants must learn that the code alone is not enough.
    assert!(body.contains("If you did not sign up for ZROtext, ignore this message."));
    assert!(body.contains("password"));
}

#[tokio::test]
async fn verification_without_password_is_malformed_and_never_reaches_database() {
    let state = AuthHttpState::new(
        "postgres://unused".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(state);
    // A code alone is a malformed body: the JSON extractor rejects it before
    // the (unusable) database is contacted, so no connection failure shows.
    for body in [
        serde_json::json!({"token":"ztv_synthetic-code"}),
        serde_json::json!({"token":"ztv_synthetic-code","password":null}),
        serde_json::json!({"password":crate::test_keys::password(1)}),
    ] {
        let response = app
            .clone()
            .oneshot(json_post("/verify-email", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    // A complete body is the first request that needs the database.
    let response = app
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":"ztv_synthetic-code","password":crate::test_keys::password(1)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
            serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}).to_string(),
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
async fn owner_routes_reject_missing_session_cookie_before_database() {
    // An unparsable URL fails any connection attempt with 503, so a 401 here
    // proves the handler never asked the pool for a connection.
    let state = AuthHttpState::new(
        "not a database url".to_owned(),
        Arc::new(TokenHasher::new(crate::test_keys::key(7)).unwrap()),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(state);
    let key = format!("/api-keys/{}", Uuid::new_v4());
    for (method, uri) in [
        ("GET", "/session"),
        ("GET", "/sessions"),
        ("GET", "/mfa"),
        ("GET", "/api-keys"),
        ("DELETE", key.as_str()),
        ("POST", "/logout"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ORIGIN, "https://zrotext.example")
            .header(header::COOKIE, "unrelated=1")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
    // With a session cookie the handler does need the database.
    let request = Request::builder()
        .uri("/session")
        .header(header::COOKIE, format!("{SESSION_COOKIE}=zts_fixture"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
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
            serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}).to_string(),
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
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
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
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

#[test]
fn verified_reset_subject_is_distinct_and_rolls_with_the_code_throttle() {
    let email = "owner@example.test";
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let subject = verified_reset_subject(email, start);
    assert_ne!(subject, email);
    assert!(subject.starts_with("owner@example.test\0verified\0"));
    assert_eq!(
        verified_reset_subject(
            email,
            start + VERIFIED_RESET_WINDOW - Duration::from_secs(1)
        ),
        subject
    );
    assert_ne!(
        verified_reset_subject(email, start + VERIFIED_RESET_WINDOW),
        subject
    );
    assert_ne!(verified_reset_subject("other@example.test", start), subject);
}

#[test]
fn trusted_reset_subjects_are_distinct_from_every_other_lane() {
    let email = "owner@example.test";
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let window = trusted_reset_window_subject(email, start);
    let daily = trusted_reset_daily_subject(email);
    // The trusted window subject rolls with the same throttle cadence.
    assert_eq!(
        trusted_reset_window_subject(
            email,
            start + VERIFIED_RESET_WINDOW - Duration::from_secs(1)
        ),
        window
    );
    assert_ne!(
        trusted_reset_window_subject(email, start + VERIFIED_RESET_WINDOW),
        window
    );
    // It shares no subject with the verified lane, the anonymous counter, or
    // the trusted lane's own daily cap.
    assert_ne!(window, verified_reset_subject(email, start));
    assert_ne!(window, email);
    assert_ne!(window, daily);
    assert_ne!(daily, email);
    assert_ne!(daily, verified_reset_subject(email, start));
    assert_ne!(trusted_reset_daily_subject("other@example.test"), daily);
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn stranger_spending_address_budget_does_not_block_owner_password_reset() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_reset_address_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
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
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap();
    let app = router(state);
    let request = |email: &str| {
        json_post(
            "/password/reset/request",
            serde_json::json!({"email":email}),
        )
    };
    async fn queued(db: &Client) -> i64 {
        db.query_one(
            "SELECT count(*) FROM password_reset_mail_outbox WHERE canceled_at IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0)
    }
    async fn issued(db: &Client) -> i64 {
        db.query_one("SELECT count(*) FROM password_resets", &[])
            .await
            .unwrap()
            .get(0)
    }
    // A stranger naming the owner's address spends the anonymous per-address
    // budget (3 per day). The first request issues a code; the inner throttle
    // makes the rest no-ops.
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(request("owner@example.test"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    assert_eq!(queued(&db).await, 1);
    assert_eq!(issued(&db).await, 1);
    // The owner's next request inside the throttle window stays a no-op with
    // the same 202: the address budget is spent and the code is recent.
    let response = app
        .clone()
        .oneshot(request("owner@example.test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(issued(&db).await, 1);
    // Once the throttle window has passed, the owner still gets a fresh code
    // although the anonymous per-address budget stays spent for a day.
    db.execute(
        "UPDATE password_resets SET created_at=created_at-interval '16 minutes'",
        &[],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(request("owner@example.test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(issued(&db).await, 2);
    assert_eq!(queued(&db).await, 1);
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let reset = account::claim_reset_mail(&mut db, &hasher)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reset.email, "owner@example.test");
    // The verified lane keeps the code cadence: further requests in the same
    // throttle window issue nothing.
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(request("owner@example.test"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    assert_eq!(issued(&db).await, 2);
    // Unknown addresses get the same 202 before and after their budget is
    // spent, and never queue anything.
    for _ in 0..4 {
        let response = app
            .clone()
            .oneshot(request("nobody@example.test"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    assert_eq!(issued(&db).await, 2);
    assert_eq!(queued(&db).await, 1);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// The fixed owner row the recording budgets answer with: a trusted-browser
/// cookie minted for exactly this row is valid, and any other is not.
const RECORDING_OWNER_USER: Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000101");
const RECORDING_OWNER_ACCOUNT: Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000102");
const RECORDING_OWNER_EPOCH: i64 = 0;
const RECORDING_OWNER_PASSWORD: &str = "recording-owner-password-hash";

/// Records which budget statements an admission runs, answering from fixed
/// outcomes. `anonymous` answers both anonymous charges, and `window` and
/// `daily` answer both lanes; the recorded name carries the lane each
/// subject belonged to.
struct RecordingResetBudgets {
    anonymous: bool,
    live: bool,
    window: bool,
    daily: bool,
    calls: Mutex<Vec<&'static str>>,
}

impl RecordingResetBudgets {
    fn record(&self, call: &'static str, answer: bool) -> Result<bool, tokio_postgres::Error> {
        self.calls.lock().unwrap().push(call);
        Ok(answer)
    }
}

/// Which lane a charge or read subject belonged to, from its subject string.
fn recorded_lane(subject: &str) -> &'static str {
    if subject.contains("\0trusted") {
        "trusted"
    } else {
        "verified"
    }
}

impl ResetBudgets for RecordingResetBudgets {
    async fn charge_anonymous(&self, _: &str) -> Result<bool, tokio_postgres::Error> {
        self.record("charge_anonymous", self.anonymous)
    }
    async fn owner_row(&self, _: &str) -> Result<Option<OwnerResetRow>, tokio_postgres::Error> {
        let _ = self.record("owner_row", self.live);
        Ok(self.live.then(|| OwnerResetRow {
            user_id: RECORDING_OWNER_USER,
            account_id: RECORDING_OWNER_ACCOUNT,
            trusted_browser_epoch: RECORDING_OWNER_EPOCH,
            password_hash: RECORDING_OWNER_PASSWORD.to_owned(),
        }))
    }
    async fn charge_window(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        self.record(
            match recorded_lane(subject) {
                "trusted" => "charge_window:trusted",
                _ => "charge_window:verified",
            },
            self.window,
        )
    }
    async fn charge_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        self.record(
            match recorded_lane(subject) {
                "trusted" => "charge_daily:trusted",
                _ => "charge_daily:verified",
            },
            self.daily,
        )
    }
    async fn read_daily(&self, subject: &str) -> Result<bool, tokio_postgres::Error> {
        self.record(
            match recorded_lane(subject) {
                "trusted" => "read_daily:trusted",
                _ => "read_daily:verified",
            },
            self.daily,
        )
    }
}

#[tokio::test]
async fn reset_admission_runs_the_same_statement_count_for_known_and_unknown_addresses() {
    let hasher = TokenHasher::new(crate::test_keys::key(204)).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let trusted_cookie = auth::trusted_browser_cookie(
        &hasher,
        RECORDING_OWNER_USER,
        RECORDING_OWNER_ACCOUNT,
        RECORDING_OWNER_EPOCH,
        RECORDING_OWNER_PASSWORD,
        now - Duration::from_secs(60),
    )
    .split_once('=')
    .unwrap()
    .1
    .split(';')
    .next()
    .unwrap()
    .to_owned();
    // (anonymous, live, window, daily) -> expected admission and calls.
    type Case = ((bool, bool, bool, bool), bool, &'static [&'static str]);
    let verified: [Case; 7] = [
        // The anonymous budget admits before any probe, known or not, with
        // or without trusted evidence.
        ((true, true, true, true), true, &["charge_anonymous"]),
        ((true, false, true, true), true, &["charge_anonymous"]),
        // Unknown address, anonymous budget spent. A presented cookie changes
        // nothing: there is no owner row to validate it against.
        (
            (false, false, true, true),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_anonymous",
                "read_daily:verified",
            ],
        ),
        // Verified owner admitted through the window and the daily cap.
        (
            (false, true, true, true),
            true,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:verified",
                "charge_daily:verified",
            ],
        ),
        // Verified owner over the daily cap: refused.
        (
            (false, true, true, false),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:verified",
                "charge_daily:verified",
            ],
        ),
        // Verified owner refused by the window: the daily cap is only read.
        (
            (false, true, false, true),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:verified",
                "read_daily:verified",
            ],
        ),
        (
            (false, true, false, false),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:verified",
                "read_daily:verified",
            ],
        ),
    ];
    for ((anonymous, live, window, daily), admitted, calls) in verified {
        let budgets = RecordingResetBudgets {
            anonymous,
            live,
            window,
            daily,
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            admit_reset_request_with(
                &budgets,
                &hasher,
                "owner@example.test",
                now,
                ResetTrust {
                    trusted_browser: None,
                    trusted_network: false,
                },
            )
            .await
            .unwrap(),
            admitted,
            "{anonymous} {live} {window} {daily}"
        );
        assert_eq!(budgets.calls.lock().unwrap().as_slice(), calls);
    }
    // Trusted evidence, from a valid cookie and from a trusted network, runs
    // the same statements against the trusted lane's own subjects instead.
    let trusted: [Case; 3] = [
        (
            (false, true, true, true),
            true,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:trusted",
                "charge_daily:trusted",
            ],
        ),
        (
            (false, true, true, false),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:trusted",
                "charge_daily:trusted",
            ],
        ),
        (
            (false, true, false, true),
            false,
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:trusted",
                "read_daily:trusted",
            ],
        ),
    ];
    for (cookie, network) in [
        (Some(trusted_cookie.as_str()), false),
        (None, true),
        (Some(trusted_cookie.as_str()), true),
    ] {
        for ((anonymous, live, window, daily), admitted, calls) in trusted {
            let budgets = RecordingResetBudgets {
                anonymous,
                live,
                window,
                daily,
                calls: Mutex::new(Vec::new()),
            };
            let trust = ResetTrust {
                trusted_browser: cookie,
                trusted_network: network,
            };
            assert_eq!(
                admit_reset_request_with(&budgets, &hasher, "owner@example.test", now, trust)
                    .await
                    .unwrap(),
                admitted,
                "{anonymous} {live} {window} {daily} cookie={} network={network}",
                cookie.is_some()
            );
            assert_eq!(budgets.calls.lock().unwrap().as_slice(), calls);
        }
    }
    // A forged or malformed cookie falls back to the normal lanes: the same
    // statements as no cookie at all.
    for forged in [
        String::new(),
        "ztb_forged.1800000000.forgedtag".to_owned(),
        trusted_cookie.replace('0', "1"),
        format!("{trusted_cookie}.extra"),
    ] {
        let budgets = RecordingResetBudgets {
            anonymous: false,
            live: true,
            window: false,
            daily: false,
            calls: Mutex::new(Vec::new()),
        };
        let trust = ResetTrust {
            trusted_browser: Some(&forged),
            trusted_network: false,
        };
        assert!(
            !admit_reset_request_with(&budgets, &hasher, "owner@example.test", now, trust)
                .await
                .unwrap()
        );
        assert_eq!(
            budgets.calls.lock().unwrap().as_slice(),
            &[
                "charge_anonymous",
                "owner_row",
                "charge_window:verified",
                "read_daily:verified",
            ]
        );
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn verified_reset_lane_refuses_the_thirteenth_code_of_a_day_per_address() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_reset_daily_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    for email in ["capped@example.test", "other@example.test"] {
        let owner = auth::register(&mut db, &hasher, email, &Uuid::new_v4().to_string())
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut db, &hasher, &owner.verification_token)
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
    // Each request returns the same 202; admission is observable only as an
    // issued code once the 15-minute code throttle is aged out. The whole
    // response (status, headers and body) is returned for parity checks.
    let request = |email: &'static str| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(json_post(
                    "/password/reset/request",
                    serde_json::json!({"email":email}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let (parts, body) = response.into_parts();
            let body = axum::body::to_bytes(body, 16 * 1024).await.unwrap();
            (parts.status, format!("{:?}", parts.headers), body)
        }
    };
    async fn daily_rows(db: &Client) -> i64 {
        db.query_one(
            "SELECT count(*) FROM auth_abuse_counters WHERE scope='password_reset_verified_daily'",
            &[],
        )
        .await
        .unwrap()
        .get(0)
    }
    async fn issued(db: &Client, email: &str) -> i64 {
        db.query_one(
            "SELECT count(*) FROM password_resets r JOIN users u ON u.id=r.user_id WHERE u.email=$1",
            &[&email],
        )
        .await
        .unwrap()
        .get(0)
    }
    async fn age_codes(db: &Client) {
        db.execute(
            "UPDATE password_resets SET created_at=created_at-interval '16 minutes'",
            &[],
        )
        .await
        .unwrap();
    }
    // Spend the anonymous per-address budget (the first request issues a
    // code), then take one code through the verified lane.
    for _ in 0..3 {
        request("capped@example.test").await;
    }
    assert_eq!(issued(&db, "capped@example.test").await, 1);
    age_codes(&db).await;
    request("capped@example.test").await;
    assert_eq!(issued(&db, "capped@example.test").await, 2);
    // Record ten more verified admissions today, as if spread over earlier
    // throttle windows, so the lane has spent 11 of its 12 daily codes. Only
    // this address has used the verified lane so far, so the daily scope holds
    // exactly its per-address row and the scope's route-ceiling row (whose
    // ceiling of 1,200 per minute is far from reached at 11).
    let updated = db
        .execute(
            "UPDATE auth_abuse_counters SET attempts=11 \
             WHERE scope='password_reset_verified_daily' AND attempts=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(updated, 2);
    // The twelfth verified code of the day is still issued.
    age_codes(&db).await;
    request("capped@example.test").await;
    assert_eq!(issued(&db, "capped@example.test").await, 3);
    // The thirteenth is refused with the same 202 although the code throttle
    // and the window subject would both allow it.
    age_codes(&db).await;
    let capped = request("capped@example.test").await;
    assert_eq!(issued(&db, "capped@example.test").await, 3);
    // An unknown address gets a byte-identical response, whether its own
    // anonymous budget is fresh or spent, and it never charges (or creates) a
    // daily verified-lane counter: it only reads that budget.
    let rows = daily_rows(&db).await;
    for _ in 0..5 {
        assert_eq!(request("nobody@example.test").await, capped);
    }
    assert_eq!(daily_rows(&db).await, rows);
    assert_eq!(issued(&db, "capped@example.test").await, 3);
    // An unrelated owner address is unaffected, on both lanes.
    for _ in 0..3 {
        request("other@example.test").await;
    }
    assert_eq!(issued(&db, "other@example.test").await, 1);
    age_codes(&db).await;
    request("other@example.test").await;
    assert_eq!(issued(&db, "other@example.test").await, 2);
    assert_eq!(issued(&db, "capped@example.test").await, 3);
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
            "../../../../deploy/compose/migrations/048_observer_memberships.sql"
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
    test_client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
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
                serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}),
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
                serde_json::json!({"email":"stranger@example.test","password":crate::test_keys::password(1)}),
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
                serde_json::json!({"email":"second@example.test","password":crate::test_keys::password(1)}),
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
            serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}),
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
    // Label 3 was never registered for this account; label 1 is the owner's.
    for (email, password) in [
        ("unknown@example.test", crate::test_keys::password(4)),
        ("owner@example.test", crate::test_keys::password(3)),
        ("owner@example.test", crate::test_keys::password(1)),
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
            serde_json::json!({"token":token,"password":crate::test_keys::password(1)}),
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
            serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}),
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
    assert_eq!(cookies.len(), 4);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    assert!(cookies[3].starts_with("__Host-zrotext_trusted_browser=ztb_"));
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
            serde_json::json!({"email":"owner@example.test","password":crate::test_keys::password(1)}),
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
        StatusCode::BAD_REQUEST
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
        serde_json::json!({"current_password":crate::test_keys::password(1)}),
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
    let body = serde_json::json!({
        "scopes":["messages:read"],"lifetime_days":30,
        "current_password":crate::test_keys::password(1),
    });
    let mut request = json_post("/api-keys", body.clone());
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie_header).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    // A live cookie and CSRF token without the password (the stolen-cookie
    // case) or with a guessed password mint nothing.
    for proof in [
        serde_json::json!({"scopes":["messages:read"],"lifetime_days":30}),
        serde_json::json!({
            "scopes":["messages:read"],"lifetime_days":30,
            "current_password":wrong_password,
        }),
    ] {
        let response = app
            .clone()
            .oneshot(owner_post("/api-keys", proof, &cookie_header, csrf))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
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
        auth::ApiKeyLifetime::Days(30),
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
            serde_json::json!({"email":"OWNER@example.test","password":crate::test_keys::password(1)}),
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
            serde_json::json!({"scopes":["messages:read"],"current_password":password}),
            &format!(
                "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                session.token, session.csrf_token
            ),
            &session.csrf_token,
        )
    };
    // Rounds of exactly the per-account in-flight cap: every request in a
    // round is admitted by the cap, so each 429 here comes from the database
    // budget racing across two router instances.
    let mut created = 0;
    for round in 0..32 / crate::http_auth::preauth::ACCOUNT_IN_FLIGHT {
        let mut tasks = Vec::new();
        for index in 0..crate::http_auth::preauth::ACCOUNT_IN_FLIGHT {
            let app = apps[(round + index) % 2].clone();
            let request = request_for(&sessions[0]);
            tasks.push(tokio::spawn(async move {
                app.oneshot(request).await.unwrap().status()
            }));
        }
        for task in tasks {
            match task.await.unwrap() {
                StatusCode::CREATED => created += 1,
                StatusCode::TOO_MANY_REQUESTS => {}
                status => panic!("unexpected status {status}"),
            }
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
    let verify = |token: String, password: &'static str| {
        app.clone().oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":token,"password":password}),
        ))
    };
    assert_eq!(
        verify(stale_token, "first registrant 1")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        verify(token, "address owner 123").await.unwrap().status(),
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
async fn postgres_http_verification_needs_registrant_password_and_collision_cancels_code() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_verify_pw_test_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let capture = Arc::new(CaptureVerification(Mutex::new(None)));
    let state = AuthHttpState::new(
        url,
        Arc::new(TokenHasher::new(crate::test_keys::key(44)).unwrap()),
        "https://zrotext.example".to_owned(),
        capture.clone(),
    )
    .unwrap()
    .with_registration_policy(RegistrationPolicy::Open);
    let app = router(state.clone());
    let register = |email: &'static str, password: &'static str| {
        app.clone().oneshot(json_post(
            "/register",
            serde_json::json!({"email":email,"password":password}),
        ))
    };
    let verify = |token: String, password: &'static str| {
        app.clone().oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":token,"password":password}),
        ))
    };
    let login = |email: &'static str, password: &'static str| {
        app.clone().oneshot(json_post(
            "/login",
            serde_json::json!({"email":email,"password":password}),
        ))
    };
    // A stranger registers the address owner's email with a foreign password;
    // the code lands in the address owner's mailbox.
    assert_eq!(
        register("claimed@example.test", "stranger password 1")
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert!(dispatch_one_verification(&state).await.unwrap());
    let foreign_code = capture.0.lock().unwrap().take().unwrap();
    assert_eq!(
        login("claimed@example.test", "stranger password 1")
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    // Pasting the code with any password other than the registrant's fails
    // exactly like an unknown code, and the code stays unconsumed.
    assert_eq!(
        verify(foreign_code.clone(), "address owner 123")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        verify("ztv_not-a-real-code".to_owned(), "stranger password 1")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        auth::verification_token_is_live(&client, &state.hasher, &foreign_code)
            .await
            .unwrap()
    );
    // The address owner's own sign-up collides with the pending record. The
    // response stays generic and mails nothing, but the foreign code and its
    // queued mail are canceled, so not even the registrant can use it now.
    assert_eq!(
        register("claimed@example.test", "address owner 123")
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert!(!dispatch_one_verification(&state).await.unwrap());
    assert!(
        !auth::verification_token_is_live(&client, &state.hasher, &foreign_code)
            .await
            .unwrap()
    );
    assert_eq!(
        verify(foreign_code.clone(), "stranger password 1")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM email_verifications WHERE used_at IS NULL),
                    (SELECT count(*) FROM verification_mail_outbox WHERE canceled_at IS NULL),
                    (SELECT count(*) FROM users WHERE email_verified_at IS NOT NULL)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    // The stranger never observes the 403 -> 204 transition.
    assert_eq!(
        login("claimed@example.test", "stranger password 1")
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    // A genuine registrant still verifies with the code and the password it
    // chose, and only with that password.
    assert_eq!(
        register("owner@example.test", "genuine owner 123")
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert!(dispatch_one_verification(&state).await.unwrap());
    let code = capture.0.lock().unwrap().take().unwrap();
    assert_eq!(
        verify(code.clone(), "genuine owner 124")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        verify(code.clone(), "genuine owner 123")
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        verify(code, "genuine owner 123").await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        login("owner@example.test", "genuine owner 123")
            .await
            .unwrap()
            .status(),
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
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
                serde_json::json!({"token":"invalid","password":test_password}),
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
            serde_json::json!({"token":wrong_code,"password":test_password}),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut wrong_origin = json_post(
        "/verify-email",
        serde_json::json!({"token":signup.verification_token,"password":test_password}),
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
            serde_json::json!({"token":signup.verification_token,"password":test_password}),
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::NO_CONTENT);
    let replay = a
        .oneshot(json_post(
            "/verify-email",
            serde_json::json!({"token":signup.verification_token,"password":test_password}),
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
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
    assert_eq!(cookies.len(), 4);
    let known = cookies[2].clone();
    assert!(known.starts_with("__Host-zrotext_login_client=ztl_"));
    assert!(!known.contains("owner"));
    assert!(cookies[3].starts_with("__Host-zrotext_trusted_browser=ztb_"));

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
    assert_eq!(cookies.len(), 3);
    assert!(cookies[0].starts_with("__Host-zrotext_session=zts_"));
    assert!(cookies[2].starts_with("__Host-zrotext_trusted_browser=ztb_"));
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
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
    assert_eq!(cookies.len(), 4);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    assert!(cookies[3].starts_with("__Host-zrotext_trusted_browser=ztb_"));
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
        4
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
    // Exhausted sign-in factors do not spend the signed-in owner's step-up
    // budget: a wrong code is checked (401), not refused (429).
    let response = app
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
            hasher.clone(),
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
    assert_eq!(cookies.len(), 4);
    assert!(cookies[2].starts_with("__Host-zrotext_login_client=ztl_"));
    assert!(cookies[3].starts_with("__Host-zrotext_trusted_browser=ztb_"));
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
    let failures = abuse_limits::failures_in_window(
        &client,
        &hasher,
        Limit::MfaStepUp,
        &signup.user_id.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(failures, 2);
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

fn hash_permit_state() -> AuthHttpState {
    AuthHttpState::new(
        "postgresql://127.0.0.1:1/unused".into(),
        Arc::new(TokenHasher::new(vec![42; 32]).unwrap()),
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn concurrent_password_work_waits_for_a_permit_instead_of_refusing() {
    let state = Arc::new(hash_permit_state());
    let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Three sign-ins arrive together; each stubbed hash takes 300 ms and the
    // process runs two at a time. The third must queue, not get a 429.
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let (state, running, peak) = (state.clone(), running.clone(), peak.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = state.hash_permit().await?;
            let now = running.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            running.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, AuthHttpError>(())
        }));
    }
    for task in tasks {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(state.hash_limit.available_permits(), 2);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn saturated_password_work_returns_503_with_retry_after() {
    let state = hash_permit_state();
    let held = state
        .hash_limit
        .clone()
        .acquire_many_owned(2)
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let error = state.hash_permit().await.unwrap_err();
    assert!(matches!(error, AuthHttpError::Busy));
    assert!(started.elapsed() >= HASH_PERMIT_WAIT);
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], br#"{"code":"unavailable"}"#);
    // A permit released within the wait is taken rather than refused.
    let waiter = tokio::spawn({
        let state = state.clone();
        async move { state.hash_permit().await.map(drop) }
    });
    tokio::time::sleep(HASH_PERMIT_WAIT / 2).await;
    drop(held);
    assert!(waiter.await.unwrap().is_ok());
    // Real throttles and other 503s keep their existing responses.
    let throttled = AuthHttpError::TooManyRequests.into_response();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers().get(header::RETRY_AFTER).is_none());
    let unavailable = AuthHttpError::Unavailable.into_response();
    assert!(unavailable.headers().get(header::RETRY_AFTER).is_none());
    // A closed gate fails closed as busy.
    state.hash_limit.close();
    assert!(matches!(
        state.hash_permit().await,
        Err(AuthHttpError::Busy)
    ));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn saturated_hash_waiters_are_refused_fast_without_pinning_more_connections() {
    let state = hash_permit_state();
    // Both hash permits stay held, so every caller queues for the full wait.
    let held = state
        .hash_limit
        .clone()
        .acquire_many_owned(HASH_PERMITS as u32)
        .await
        .unwrap();
    // Fill every waiter slot. Each task stands for a budget-admitted request
    // that holds one request-pool connection while it queues.
    let mut waiters = Vec::new();
    for _ in 0..HASH_WAIT_SLOTS {
        let state = state.clone();
        waiters.push(tokio::spawn(
            async move { state.hash_permit().await.map(drop) },
        ));
    }
    // Let every queued task register before the next caller tries.
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(state.hash_wait_limit.available_permits(), 0);
    let started = tokio::time::Instant::now();
    let error = state.hash_permit().await.unwrap_err();
    // The refusal is immediate: without a waiter cap this call would idle a
    // request-pool connection for the whole HASH_PERMIT_WAIT first.
    assert!(matches!(error, AuthHttpError::Busy));
    assert!(started.elapsed() < HASH_PERMIT_WAIT);
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    // Waiter slots recycle: each queued request times out and releases its
    // slot, so later requests can queue again and then hash normally.
    for waiter in waiters {
        assert!(matches!(waiter.await.unwrap(), Err(AuthHttpError::Busy)));
    }
    assert_eq!(state.hash_wait_limit.available_permits(), HASH_WAIT_SLOTS);
    drop(held);
    assert!(state.hash_permit().await.is_ok());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_hash_waiter_frees_its_queue_slot_for_the_next_request() {
    let state = hash_permit_state();
    let held = state
        .hash_limit
        .clone()
        .acquire_many_owned(HASH_PERMITS as u32)
        .await
        .unwrap();
    // Every waiter slot is taken by requests queued on the held permits.
    // Each holds its hash permit for a while, like a real Argon2 operation.
    let mut waiters = Vec::new();
    for _ in 0..HASH_WAIT_SLOTS {
        let state = state.clone();
        waiters.push(tokio::spawn(async move {
            let _permit = state.hash_permit().await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok::<_, AuthHttpError>(())
        }));
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(state.hash_wait_limit.available_permits(), 0);
    // The permits free mid-wait: the first queued waiters take them and stop
    // occupying waiter slots, so a late request can still queue and succeed
    // rather than being refused fast.
    drop(held);
    // Paused time cannot advance until the woken waiters run, so the freed
    // waiter slots are visible to the late request below.
    tokio::time::sleep(Duration::from_millis(1)).await;
    let late = tokio::spawn({
        let state = state.clone();
        async move { state.hash_permit().await.map(drop) }
    });
    assert!(late.await.unwrap().is_ok());
    for waiter in waiters {
        assert!(waiter.await.unwrap().is_ok());
    }
    // Both gates return to full: no waiter slot or hash permit leaked.
    assert_eq!(state.hash_limit.available_permits(), HASH_PERMITS);
    assert_eq!(state.hash_wait_limit.available_permits(), HASH_WAIT_SLOTS);
    assert!(state.hash_permit().await.is_ok());
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn concurrent_logins_queue_for_password_work_and_saturation_is_503() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("http_login_permit_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let owners = ["one@example.test", "two@example.test", "three@example.test"];
    for email in owners {
        let signup = auth::register(&mut client, &hasher, email, &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut client, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
    }
    let mut state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    // Unoptimized test builds hash slowly; this test is about queueing, not
    // about how long a hash takes.
    state.hash_permit_wait = Duration::from_secs(120);
    let gate = state.hash_limit.clone();
    let app = router(state.clone());
    let login = |email: &str| {
        json_post(
            "/login",
            serde_json::json!({"email":email,"password":password.as_str()}),
        )
    };
    let mut tasks = Vec::new();
    for email in owners {
        tasks.push(tokio::spawn(app.clone().oneshot(login(email))));
    }
    for task in tasks {
        assert_eq!(
            task.await.unwrap().unwrap().status(),
            StatusCode::NO_CONTENT
        );
    }
    // With every permit held past the wait, the owner is told the server is
    // busy, not that their budget is spent.
    state.hash_permit_wait = Duration::from_millis(50);
    let busy_app = router(state);
    let held = gate.acquire_many_owned(2).await.unwrap();
    let response = busy_app.oneshot(login(owners[0])).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    drop(held);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Schema, migrations, and connection URL shared by the trusted-lane
/// PostgreSQL tests.
async fn trusted_lane_database(
    base_url: &str,
    schema: &str,
) -> (tokio_postgres::Client, tokio_postgres::Client, String) {
    let (setup, connection) = tokio_postgres::connect(base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
        include_str!("../../../../deploy/compose/migrations/054_stateless_device_challenges.sql"),
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    (setup, db, url)
}

/// Issue one reset request against `app` and return the full response after
/// asserting the uniform 202.
async fn send_reset(
    app: &Router,
    email: &str,
    trusted_cookie: Option<&str>,
    peer: Option<SocketAddr>,
    forwarded_for: Option<&str>,
) -> (StatusCode, String, axum::body::Bytes) {
    let response = app
        .clone()
        .oneshot(reset_request(email, trusted_cookie, peer, forwarded_for))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 16 * 1024).await.unwrap();
    (parts.status, format!("{:?}", parts.headers), body)
}

async fn trusted_lane_issued(db: &Client, email: &str) -> i64 {
    db.query_one(
        "SELECT count(*) FROM password_resets r JOIN users u ON u.id=r.user_id WHERE u.email=$1",
        &[&email],
    )
    .await
    .unwrap()
    .get(0)
}

async fn trusted_lane_age_codes(db: &Client) {
    db.execute(
        "UPDATE password_resets SET created_at=created_at-interval '16 minutes'",
        &[],
    )
    .await
    .unwrap();
}

/// Spend the verified reset lane's full daily cap for every address exercised
/// so far, as if earlier throttle windows had admitted eleven more requests
/// after the one already charged: the subject row reaches its 12-per-day cap,
/// so further verified-lane requests are refused. The route row shares the
/// scope and stays far under its ceiling.
async fn trusted_lane_exhaust_verified_daily(db: &Client) {
    let updated = db
        .execute(
            "UPDATE auth_abuse_counters SET attempts=12 \
             WHERE scope='password_reset_verified_daily' AND attempts=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(updated, 2);
}

async fn trusted_lane_daily_rows(db: &Client) -> i64 {
    db.query_one(
        "SELECT count(*) FROM auth_abuse_counters WHERE scope='password_reset_verified_daily'",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

/// Spend both public reset lanes for `email`'s owner: the anonymous
/// per-address cap (three requests issue one code), one verified-lane code
/// once the code throttle has passed, then the verified lane's daily cap.
/// Leaves two issued codes, and checks as a control that a cookieless
/// request with aged codes issues nothing more, so any later code must come
/// through the trusted lane.
async fn trusted_lane_close_public_lanes(app: &Router, db: &Client, email: &str) {
    for _ in 0..3 {
        send_reset(app, email, None, None, None).await;
    }
    assert_eq!(trusted_lane_issued(db, email).await, 1);
    trusted_lane_age_codes(db).await;
    send_reset(app, email, None, None, None).await;
    assert_eq!(trusted_lane_issued(db, email).await, 2);
    trusted_lane_exhaust_verified_daily(db).await;
    trusted_lane_age_codes(db).await;
    send_reset(app, email, None, None, None).await;
    assert_eq!(
        trusted_lane_issued(db, email).await,
        2,
        "control: with aged codes the public lanes must refuse"
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn trusted_browser_cookie_grants_reset_codes_beyond_the_public_lanes() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_cookie_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
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
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap();
    let app = router(state);
    // A successful sign-in marks the browser as trusted.
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":password}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let trusted = set_cookie_value(&response, auth::TRUSTED_BROWSER_COOKIE).unwrap();
    let cookie_header = format!("{}={trusted}", auth::TRUSTED_BROWSER_COOKIE);
    // A stranger naming the address spends the anonymous per-address budget.
    for _ in 0..3 {
        send_reset(&app, "owner@example.test", None, None, None).await;
    }
    assert_eq!(trusted_lane_issued(&db, "owner@example.test").await, 1);
    // The verified lane admits one more code once the throttle window passes.
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "owner@example.test", None, None, None).await;
    assert_eq!(trusted_lane_issued(&db, "owner@example.test").await, 2);
    trusted_lane_exhaust_verified_daily(&db).await;
    trusted_lane_age_codes(&db).await;
    let capped = send_reset(&app, "owner@example.test", None, None, None).await;
    assert_eq!(trusted_lane_issued(&db, "owner@example.test").await, 2);
    // The same exhausted public lanes still admit the browser that signed in:
    // the trusted lane charges its own subjects and issues a fresh code.
    let rows_before = trusted_lane_daily_rows(&db).await;
    trusted_lane_age_codes(&db).await;
    let trusted_response =
        send_reset(&app, "owner@example.test", Some(&cookie_header), None, None).await;
    assert_eq!(trusted_response.0, capped.0);
    assert_eq!(trusted_lane_issued(&db, "owner@example.test").await, 3);
    assert_eq!(trusted_lane_daily_rows(&db).await, rows_before + 1);
    // The trusted lane keeps the code cadence and the uniform 202: further
    // requests inside the throttle window issue nothing, and an unknown
    // address carrying the same cookie gets the same response and issues
    // nothing.
    send_reset(&app, "owner@example.test", Some(&cookie_header), None, None).await;
    assert_eq!(trusted_lane_issued(&db, "owner@example.test").await, 3);
    trusted_lane_age_codes(&db).await;
    let unknown = send_reset(
        &app,
        "nobody@example.test",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(unknown.0, trusted_response.0);
    assert_eq!(trusted_lane_issued(&db, "nobody@example.test").await, 0);
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn forged_or_foreign_trusted_evidence_gets_no_extra_budget() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_forged_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    for email in ["target@example.test", "other@example.test"] {
        let owner = auth::register(&mut db, &hasher, email, &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut db, &hasher, &owner.verification_token)
                .await
                .unwrap()
        );
    }
    let networks = TrustedNetworks::parse(Some("198.51.100.0/24"), Some("203.0.113.0/24")).unwrap();
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap()
    .with_reset_trusted_networks(networks);
    let app = router(state);
    let login = |app: Router, email: String| {
        let request = json_post(
            "/login",
            serde_json::json!({"email": email, "password": password}),
        );
        async move {
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            set_cookie_value(&response, auth::TRUSTED_BROWSER_COOKIE).unwrap()
        }
    };
    let own = login(app.clone(), "target@example.test".to_owned()).await;
    let foreign = login(app.clone(), "other@example.test".to_owned()).await;
    let cookie_header = |value: &str| format!("{}={value}", auth::TRUSTED_BROWSER_COOKIE);
    let own_header = cookie_header(&own);
    let foreign_header = cookie_header(&foreign);
    // Tamper a fully significant tag character: the final base64 character
    // carries ignored padding bits, so flipping it can decode identically.
    let forged_header = cookie_header(&{
        let (prefix, tag) = own.rsplit_once('.').unwrap();
        let flipped = if tag.as_bytes()[0] == b'A' { "B" } else { "A" };
        format!("{prefix}.{flipped}{}", &tag[1..])
    });
    // Exhaust the public lanes for the target address.
    for _ in 0..3 {
        send_reset(&app, "target@example.test", None, None, None).await;
    }
    assert_eq!(trusted_lane_issued(&db, "target@example.test").await, 1);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "target@example.test", None, None, None).await;
    assert_eq!(trusted_lane_issued(&db, "target@example.test").await, 2);
    trusted_lane_exhaust_verified_daily(&db).await;
    let refused = send_reset(&app, "target@example.test", None, None, None).await;
    // A tampered tag, another owner's cookie, a spoofed forwarded header from
    // a caller with no peer information, and a spoofed header from an
    // untrusted peer all fall back to the exhausted public lanes: same 202,
    // no code, and no trusted-lane counter rows.
    let rows_before = trusted_lane_daily_rows(&db).await;
    trusted_lane_age_codes(&db).await;
    for (cookie, peer, forwarded) in [
        (Some(forged_header.clone()), None, None),
        (Some(foreign_header.clone()), None, None),
        (None, None, Some("198.51.100.9")),
        (
            None,
            Some("192.0.2.8:443".parse().unwrap()),
            Some("198.51.100.9"),
        ),
        (Some("garbage".to_owned()), None, None),
    ] {
        let response = send_reset(
            &app,
            "target@example.test",
            cookie.as_deref(),
            peer,
            forwarded,
        )
        .await;
        assert_eq!(response.0, refused.0);
        assert_eq!(response.1, refused.1);
        assert_eq!(response.2, refused.2);
    }
    assert_eq!(trusted_lane_issued(&db, "target@example.test").await, 2);
    assert_eq!(trusted_lane_daily_rows(&db).await, rows_before);
    // The valid cookie still crosses the exhausted lanes, proving the
    // refusals above came from the evidence being rejected.
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "target@example.test", Some(&own_header), None, None).await;
    assert_eq!(trusted_lane_issued(&db, "target@example.test").await, 3);
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn password_change_and_erasure_invalidate_trusted_browser_cookies() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_revoke_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
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
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap();
    let app = router(state);
    async fn issued(db: &Client) -> i64 {
        db.query_one("SELECT count(*) FROM password_resets", &[])
            .await
            .unwrap()
            .get(0)
    }
    // Sign in: the browser becomes trusted and holds session cookies.
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":password}),
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
    let trusted = set_cookie_value(&response, auth::TRUSTED_BROWSER_COOKIE).unwrap();
    let trusted_header = format!("{}={trusted}", auth::TRUSTED_BROWSER_COOKIE);
    let cookie_header = cookies.join("; ");
    let csrf = cookies
        .iter()
        .find_map(|cookie| {
            cookie
                .strip_prefix("__Host-zrotext_csrf=")
                .map(str::to_owned)
        })
        .unwrap();
    // Exhaust the public lanes, then confirm the trusted lane still issues.
    for _ in 0..3 {
        send_reset(&app, "owner@example.test", None, None, None).await;
    }
    assert_eq!(issued(&db).await, 1);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "owner@example.test", None, None, None).await;
    assert_eq!(issued(&db).await, 2);
    trusted_lane_exhaust_verified_daily(&db).await;
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        Some(&trusted_header),
        None,
        None,
    )
    .await;
    assert_eq!(issued(&db).await, 3);
    // A password change revokes every session and every trusted browser.
    let new_password = Uuid::new_v4().to_string();
    let response = app
        .clone()
        .oneshot(owner_post(
            "/password",
            serde_json::json!({
                "current_password": password,
                "new_password": new_password,
            }),
            &cookie_header,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        Some(&trusted_header),
        None,
        None,
    )
    .await;
    assert_eq!(issued(&db).await, 3);
    // Erasing the account removes the user row the cookie binds to, and its
    // membership, sessions and reset history cascade away with it; the
    // request falls back to the spent anonymous lane with the same 202 and
    // must not queue anything for the erased address.
    db.execute("DELETE FROM users", &[]).await.unwrap();
    assert_eq!(issued(&db).await, 0);
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        Some(&trusted_header),
        None,
        None,
    )
    .await;
    assert_eq!(issued(&db).await, 0);
    // A fresh sign-in with the new password mints fresh trust, and the
    // trusted lane still has budget left for the address.
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &new_password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let response = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":new_password}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let fresh = set_cookie_value(&response, auth::TRUSTED_BROWSER_COOKIE).unwrap();
    assert_ne!(fresh, trusted);
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        Some(&format!("{}={fresh}", auth::TRUSTED_BROWSER_COOKIE)),
        None,
        None,
    )
    .await;
    // The erasure also cascaded the reset history away, so this is the first
    // code of the re-registered owner.
    assert_eq!(issued(&db).await, 1);
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn trusted_network_reset_requests_survive_exhausted_public_lanes() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_network_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
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
    let networks = TrustedNetworks::parse(Some("198.51.100.0/24"), Some("203.0.113.0/24")).unwrap();
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap()
    .with_reset_trusted_networks(networks);
    let app = router(state);
    async fn issued(db: &Client) -> i64 {
        db.query_one("SELECT count(*) FROM password_resets", &[])
            .await
            .unwrap()
            .get(0)
    }
    // Exhaust the public lanes from unconfigured addresses.
    for _ in 0..3 {
        send_reset(
            &app,
            "owner@example.test",
            None,
            Some("192.0.2.10:443".parse().unwrap()),
            None,
        )
        .await;
    }
    assert_eq!(issued(&db).await, 1);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "owner@example.test", None, None, None).await;
    assert_eq!(issued(&db).await, 2);
    trusted_lane_exhaust_verified_daily(&db).await;
    let refused = send_reset(&app, "owner@example.test", None, None, None).await;
    // A request whose socket peer is inside a trusted network is admitted
    // through the trusted lane with the same 202.
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        None,
        Some("198.51.100.7:443".parse().unwrap()),
        None,
    )
    .await;
    assert_eq!(issued(&db).await, 3);
    // A trusted proxy may vouch for the client it forwarded.
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        None,
        Some("203.0.113.5:443".parse().unwrap()),
        Some("198.51.100.9"),
    )
    .await;
    assert_eq!(issued(&db).await, 4);
    // An untrusted peer cannot spoof its way in with the header, and a
    // trusted proxy does not vouch for an outside client.
    trusted_lane_age_codes(&db).await;
    for (email, peer, forwarded) in [
        (
            "owner@example.test",
            Some("192.0.2.8:443".parse().unwrap()),
            Some("198.51.100.9"),
        ),
        (
            "owner@example.test",
            Some("203.0.113.5:443".parse().unwrap()),
            Some("192.0.2.8"),
        ),
    ] {
        let response = send_reset(&app, email, None, peer, forwarded).await;
        assert_eq!(response.0, refused.0);
    }
    // An unknown address from a trusted network still issues nothing.
    trusted_lane_age_codes(&db).await;
    let response = send_reset(
        &app,
        "nobody@example.test",
        None,
        Some("198.51.100.7:443".parse().unwrap()),
        None,
    )
    .await;
    assert_eq!(response.0, refused.0);
    assert_eq!(issued(&db).await, 4);
    // The unknown trusted-network request spent only its own anonymous
    // budget; the real owner's trusted lane is untouched and still admits.
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        None,
        Some("198.51.100.7:443".parse().unwrap()),
        None,
    )
    .await;
    assert_eq!(issued(&db).await, 5);
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[test]
fn forwarded_for_chain_joins_every_header_line_in_arrival_order() {
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        "x-forwarded-for",
        axum::http::HeaderValue::from_str("198.51.100.9").unwrap(),
    );
    headers.append(
        "x-forwarded-for",
        axum::http::HeaderValue::from_str("192.0.2.8, 203.0.113.4").unwrap(),
    );
    // Some proxies append a new header line instead of extending the first;
    // every line must be read, in order, or the client-controlled first line
    // would be the only one believed.
    assert_eq!(
        super::forwarded_for_chain(&headers).as_deref(),
        Some("198.51.100.9,192.0.2.8,203.0.113.4")
    );
    assert_eq!(
        super::forwarded_for_chain(&axum::http::HeaderMap::new()),
        None
    );
}

/// Proxies inside `RESET_TRUSTED_CIDRS` (one private range for both), where
/// resolving a collapsed chain to the proxy's own address would grant trust.
fn overlapping_trusted_networks() -> TrustedNetworks {
    TrustedNetworks::parse(
        Some("198.51.100.0/24"),
        Some("198.51.100.5/32,198.51.100.6/32"),
    )
    .unwrap()
}

fn forwarded_headers(lines: &[&[u8]]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append("x-forwarded-for", HeaderValue::from_bytes(line).unwrap());
    }
    headers
}

#[test]
fn a_collapsed_forwarded_chain_never_trusts_the_proxy_itself() {
    let networks = overlapping_trusted_networks();
    let proxy: Option<SocketAddr> = Some("198.51.100.5:443".parse().unwrap());
    let trusted = |headers: &HeaderMap| {
        networks.reset_trusted_client(proxy, super::forwarded_for_chain(headers).as_deref())
    };
    // Control: a definite client inside the trusted range is trusted.
    assert!(trusted(&forwarded_headers(&[b"198.51.100.9"])));
    // A client-supplied line holding an obs-text byte, merged by an
    // appending proxy with the real client, is unreadable as a whole. It must
    // not be dropped: the chain would collapse and the proxy become the
    // client.
    assert!(!trusted(&forwarded_headers(&[b"x\x80y, 192.0.2.8"])));
    assert!(!trusted(&forwarded_headers(&[b"\xff"])));
    // An unreadable line to the right of the client poisons the chain. One
    // to its left is client-injected content the right-to-left walk never
    // reaches, like any other spoofed left entry, so the definite client the
    // proxy appended still decides.
    assert!(!trusted(&forwarded_headers(&[b"198.51.100.9", b"\x80"])));
    assert!(!trusted(&forwarded_headers(&[
        b"198.51.100.9",
        b"\x80",
        b"198.51.100.6"
    ])));
    assert!(trusted(&forwarded_headers(&[b"\x80", b"198.51.100.9"])));
    assert!(!trusted(&forwarded_headers(&[b"\x80", b"192.0.2.8"])));
    // Empty headers and empty entries resolve to no client.
    assert!(!trusted(&forwarded_headers(&[b""])));
    assert!(!trusted(&forwarded_headers(&[b" , "])));
    assert!(!trusted(&forwarded_headers(&[b"", b""])));
    assert!(!trusted(&forwarded_headers(&[b"198.51.100.9", b""])));
    // No header at all from a trusted proxy names no client either.
    assert!(!trusted(&HeaderMap::new()));
    // A chain of only trusted proxies names no client.
    assert!(!trusted(&forwarded_headers(&[
        b"198.51.100.6",
        b"198.51.100.5"
    ])));
    // A spoofed trusted left-most line cannot hide the real client.
    assert!(!trusted(&forwarded_headers(&[
        b"198.51.100.9",
        b"192.0.2.8"
    ])));
    // Malformed entries fail closed.
    assert!(!trusted(&forwarded_headers(&[
        b"198.51.100.9, 198.51.100.6:51234"
    ])));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn collapsed_forwarded_chains_from_a_trusted_proxy_get_no_trusted_lane() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_collapse_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
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
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap()
    .with_reset_trusted_networks(overlapping_trusted_networks());
    let app = router(state);
    async fn issued(db: &Client) -> i64 {
        db.query_one("SELECT count(*) FROM password_resets", &[])
            .await
            .unwrap()
            .get(0)
    }
    let proxy: SocketAddr = "198.51.100.5:443".parse().unwrap();
    let outside: SocketAddr = "192.0.2.10:443".parse().unwrap();
    // Exhaust the public lanes from an outside address.
    for _ in 0..3 {
        send_reset(&app, "owner@example.test", None, Some(outside), None).await;
    }
    assert_eq!(issued(&db).await, 1);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "owner@example.test", None, Some(outside), None).await;
    assert_eq!(issued(&db).await, 2);
    trusted_lane_exhaust_verified_daily(&db).await;
    // Every collapsed or unusable chain through the proxy is refused like any
    // outside request, with codes aged so that an admission would issue.
    let lines: [&[&[u8]]; 7] = [
        &[],
        &[b""],
        &[b" , "],
        &[b"x\x80y, 192.0.2.8"],
        &[b"198.51.100.6, 198.51.100.5"],
        &[b"198.51.100.9, 192.0.2.8"],
        &[b"198.51.100.9", b"\x80"],
    ];
    for chain in lines {
        trusted_lane_age_codes(&db).await;
        let mut request = reset_request("owner@example.test", None, Some(proxy), None);
        for line in chain {
            request
                .headers_mut()
                .append("x-forwarded-for", HeaderValue::from_bytes(line).unwrap());
        }
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            issued(&db).await,
            2,
            "chain {chain:?} from the proxy must not reach the trusted lane"
        );
    }
    // Control: the same proxy vouching for a definite client inside the
    // trusted range is admitted through the trusted lane.
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        None,
        Some(proxy),
        Some("198.51.100.9, 198.51.100.6"),
    )
    .await;
    assert_eq!(issued(&db).await, 3);
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn revoking_other_sessions_invalidates_other_browsers_trusted_cookies() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!(
        "http_reset_trusted_revokeothers_{}",
        Uuid::new_v4().simple()
    );
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(216)).unwrap());
    let password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap();
    let app = router(state);
    async fn issued(db: &tokio_postgres::Client) -> i64 {
        db.query_one("SELECT count(*) FROM password_resets", &[])
            .await
            .unwrap()
            .get(0)
    }
    fn cookie_pair(response: &Response) -> (String, String) {
        let joined = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>()
            .join("; ");
        let csrf = joined
            .split("; ")
            .find_map(|c| c.strip_prefix("__Host-zrotext_csrf=").map(str::to_owned))
            .unwrap();
        (joined, csrf)
    }
    fn trusted_cookie(response: &Response) -> String {
        format!(
            "{}={}",
            auth::TRUSTED_BROWSER_COOKIE,
            set_cookie_value(response, auth::TRUSTED_BROWSER_COOKIE).unwrap()
        )
    }
    // Two browsers sign in; both sessions live and both browsers trusted.
    let first = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":password}),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    let (first_cookies, first_csrf) = cookie_pair(&first);
    let first_trusted = trusted_cookie(&first);
    let second = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":password}),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
    let second_trusted = trusted_cookie(&second);

    // Close both public lanes before any trusted cookie is used, so that from
    // here on a request can only be admitted through the trusted lane.
    trusted_lane_close_public_lanes(&app, &db, "owner@example.test").await;
    assert_eq!(issued(&db).await, 2);
    // Browser B's trusted cookie spends the trusted lane before revocation.
    // Codes are aged before every trusted send: inside the 15-minute code
    // throttle nothing is issued whatever lane admits, which would make the
    // assertions below vacuous.
    trusted_lane_age_codes(&db).await;
    send_reset(
        &app,
        "owner@example.test",
        Some(&second_trusted),
        None,
        None,
    )
    .await;
    assert_eq!(
        issued(&db).await,
        3,
        "browser B's trusted cookie must spend the trusted lane"
    );

    // The owner revokes every other session from browser A: the trust epoch
    // bumps, so every browser's pre-revocation trusted cookie must stop
    // working, including browser B's.
    let response = app
        .clone()
        .oneshot(owner_post(
            "/sessions/revoke-others",
            serde_json::json!({"current_password": password}),
            &first_cookies,
            &first_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let epoch: i64 = db
        .query_one(
            "SELECT trusted_browser_epoch FROM users WHERE email='owner@example.test'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(epoch, 1, "revoke-others must bump the trust epoch");

    // Both pre-revocation cookies, including the revoking browser's own, are
    // rejected on the reset path even with aged codes.
    for stale in [&second_trusted, &first_trusted] {
        trusted_lane_age_codes(&db).await;
        send_reset(&app, "owner@example.test", Some(stale), None, None).await;
        assert_eq!(
            issued(&db).await,
            3,
            "a trusted cookie issued before revoke-others must be rejected"
        );
    }
    // A sign-in after the revocation mints a fresh cookie under the new
    // epoch, and the reset path accepts it.
    let third = app
        .clone()
        .oneshot(json_post(
            "/login",
            serde_json::json!({"email":"owner@example.test","password":password}),
        ))
        .await
        .unwrap();
    assert_eq!(third.status(), StatusCode::NO_CONTENT);
    let fresh_trusted = trusted_cookie(&third);
    assert_ne!(fresh_trusted, first_trusted);
    assert_ne!(fresh_trusted, second_trusted);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, "owner@example.test", Some(&fresh_trusted), None, None).await;
    assert_eq!(
        issued(&db).await,
        4,
        "a trusted cookie issued after revoke-others must be accepted"
    );
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mfa_changes_invalidate_earlier_trusted_cookies_on_the_reset_path() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("http_reset_trusted_mfa_{}", Uuid::new_v4().simple());
    let (setup, mut db, url) = trusted_lane_database(&base_url, &schema).await;
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let email = "owner@example.test";
    let owner = auth::register(&mut db, &hasher, email, &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let state = AuthHttpState::new(
        url,
        hasher.clone(),
        "https://zrotext.example".to_owned(),
        Arc::new(CaptureVerification(Mutex::new(None))),
    )
    .unwrap()
    .with_mfa_cipher(Arc::new(
        MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap(),
    ))
    .with_mfa_enrollment_enabled();
    let app = router(state);
    async fn json_body(response: Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    async fn epoch(db: &Client) -> i64 {
        db.query_one("SELECT trusted_browser_epoch FROM users", &[])
            .await
            .unwrap()
            .get(0)
    }
    fn trusted_cookie(response: &Response) -> String {
        format!(
            "{}={}",
            auth::TRUSTED_BROWSER_COOKIE,
            set_cookie_value(response, auth::TRUSTED_BROWSER_COOKIE).unwrap()
        )
    }
    let login = || {
        json_post(
            "/login",
            serde_json::json!({"email":email,"password":password.as_str()}),
        )
    };
    // Browser A signs in and is trusted; its session enrolls MFA later.
    let response = app.clone().oneshot(login()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let before_mfa = trusted_cookie(&response);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    let session_cookies = cookies.join("; ");
    let csrf = cookies
        .iter()
        .find_map(|c| c.strip_prefix("__Host-zrotext_csrf=").map(str::to_owned))
        .unwrap();

    trusted_lane_close_public_lanes(&app, &db, email).await;
    // Control: before any MFA change the cookie spends the trusted lane.
    trusted_lane_age_codes(&db).await;
    send_reset(&app, email, Some(&before_mfa), None, None).await;
    assert_eq!(trusted_lane_issued(&db, email).await, 3);

    // Confirming MFA enrollment bumps the trust epoch.
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/enroll",
            serde_json::json!({"password":password.as_str()}),
            &session_cookies,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
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
            &session_cookies,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let recovery_login = body["recovery_codes"][0].as_str().unwrap().to_owned();
    let recovery_disable = body["recovery_codes"][1].as_str().unwrap().to_owned();
    assert_eq!(epoch(&db).await, 1);
    // The cookie issued before the MFA change is rejected on the reset path.
    trusted_lane_age_codes(&db).await;
    send_reset(&app, email, Some(&before_mfa), None, None).await;
    assert_eq!(
        trusted_lane_issued(&db, email).await,
        3,
        "a trusted cookie issued before MFA enrollment must be rejected"
    );
    // A fresh sign-in through the MFA step mints a cookie that is accepted.
    let response = app.clone().oneshot(login()).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let challenge = json_body(response).await["challenge_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(json_post(
            "/login/mfa",
            serde_json::json!({"challenge_token":challenge,"code":recovery_login}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let after_enroll = trusted_cookie(&response);
    assert_ne!(after_enroll, before_mfa);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, email, Some(&after_enroll), None, None).await;
    assert_eq!(
        trusted_lane_issued(&db, email).await,
        4,
        "a trusted cookie issued after MFA enrollment must be accepted"
    );

    // Disabling MFA bumps the epoch again.
    let response = app
        .clone()
        .oneshot(owner_post(
            "/mfa/disable",
            serde_json::json!({"password":password.as_str(),"code":recovery_disable}),
            &session_cookies,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(epoch(&db).await, 2);
    for stale in [&after_enroll, &before_mfa] {
        trusted_lane_age_codes(&db).await;
        send_reset(&app, email, Some(stale), None, None).await;
        assert_eq!(
            trusted_lane_issued(&db, email).await,
            4,
            "a trusted cookie issued before MFA was disabled must be rejected"
        );
    }
    let response = app.clone().oneshot(login()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let after_disable = trusted_cookie(&response);
    trusted_lane_age_codes(&db).await;
    send_reset(&app, email, Some(&after_disable), None, None).await;
    assert_eq!(
        trusted_lane_issued(&db, email).await,
        5,
        "a trusted cookie issued after MFA was disabled must be accepted"
    );
    setup
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

// Pooling is compiled only off-Windows (founder decision, issue #485), so the
// reuse proof runs on the deployment platform: several mails through one
// dispatcher must share fewer SMTP connections than mails.
#[cfg(not(windows))]
#[tokio::test]
async fn pooled_smtp_sessions_are_reused_across_mails() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = std::sync::Arc::new(AtomicUsize::new(0));
    // Minimal plain-SMTP stub: 220 greeting, 250 for everything but DATA
    // (354 then collect until ".") and QUIT (221).
    let counted = connections.clone();
    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                writer.write_all(b"220 stub ready\r\n").await.unwrap();
                while let Ok(Some(line)) = lines.next_line().await {
                    let upper = line.to_ascii_uppercase();
                    if upper.starts_with("QUIT") {
                        writer.write_all(b"221 bye\r\n").await.unwrap();
                        return;
                    }
                    if upper.starts_with("DATA") {
                        writer.write_all(b"354 go\r\n").await.unwrap();
                        while let Ok(Some(body)) = lines.next_line().await {
                            if body == "." {
                                break;
                            }
                        }
                        writer.write_all(b"250 queued\r\n").await.unwrap();
                        continue;
                    }
                    writer.write_all(b"250 ok\r\n").await.unwrap();
                }
            });
        }
    });
    // A plain (non-TLS) transport carrying exactly the production pool
    // configuration; the stub cannot speak TLS, and the point under test is
    // the pooling, not the encryption.
    use lettre::{AsyncTransport, Tokio1Executor};
    let transport =
        lettre::AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(address.ip().to_string())
            .port(address.port())
            .pool_config(super::smtp_pool_config())
            .build();
    let mails = 5;
    for i in 0..mails {
        let message = lettre::Message::builder()
            .from(format!("sender{i}@example.test").parse().unwrap())
            .to("recipient@example.test".parse().unwrap())
            .body(format!("message {i}"))
            .unwrap();
        transport
            .send(message)
            .await
            .unwrap_or_else(|error| panic!("mail {i} must be accepted by the stub: {error}"));
    }
    let opened = connections.load(Ordering::SeqCst);
    assert!(
        opened < mails,
        "{mails} mails opened {opened} connections; sessions must be pooled"
    );
    server.abort();
}
