// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{self, SessionCredentials, TokenHasher};
use crate::http_auth::{DispatchFailure, VerificationDispatcher};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
use std::{future::Future, pin::Pin};
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;

struct NoMail;
impl VerificationDispatcher for NoMail {
    fn ready(&self) -> bool {
        false
    }
    fn dispatch<'a>(
        &'a self,
        _email: &'a str,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchFailure>> + Send + 'a>> {
        Box::pin(async { Err(DispatchFailure::Connect) })
    }
}

const MIGRATIONS: [&str; 11] = [
    include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
    include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
    include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
    include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
    include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
    include_str!("../../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
    include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    include_str!("../../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
    include_str!("../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
    include_str!("../../../../../deploy/compose/migrations/073_collaboration_drafts.sql"),
];
struct Fixture {
    db: Client,
    schema: String,
    url: String,
    state: AuthHttpState,
    owner: SessionCredentials,
    other: SessionCredentials,
    member: SessionCredentials,
    owner_id: Uuid,
    member_id: Uuid,
    account: Uuid,
    password: String,
}
impl Fixture {
    async fn new() -> Self {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("collaboration_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in MIGRATIONS {
            db.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(61)).unwrap());
        let password = crate::test_keys::password(61);
        let first = auth::register(&mut db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        auth::verify_email(&mut db, &hasher, &first.verification_token)
            .await
            .unwrap();
        let owner = auth::login(&db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &owner.token)
            .await
            .unwrap();
        let invite = auth::seats::create_invitation_with_proof(
            &mut db,
            None,
            &hasher,
            &principal,
            &password,
            None,
            "member@example.test",
        )
        .await
        .unwrap();
        let accepted = auth::seats::accept_invitation(&mut db, &hasher, &invite.token, &password)
            .await
            .unwrap();
        auth::verify_email_with_password(&mut db, &hasher, &accepted.verification_token, &password)
            .await
            .unwrap();
        let member = auth::login(&db, &hasher, "member@example.test", &password)
            .await
            .unwrap();
        let foreign = auth::register(&mut db, &hasher, "other@example.test", &password)
            .await
            .unwrap();
        auth::verify_email(&mut db, &hasher, &foreign.verification_token)
            .await
            .unwrap();
        let other = auth::login(&db, &hasher, "other@example.test", &password)
            .await
            .unwrap();
        let state =
            AuthHttpState::new(url.clone(), hasher, "https://example.test".into(), Arc::new(NoMail))
                .unwrap()
                .with_collaboration_drafts_enabled();
        Self {
            db,
            schema,
            url,
            state,
            owner,
            member,
            other,
            owner_id: first.user_id,
            member_id: accepted.user_id,
            account: first.account_id,
            password,
        }
    }
    fn app(&self) -> Router {
        Router::new()
            .nest("/v1/auth", crate::http_auth::router(self.state.clone()))
            .nest(
                "/v1/observer",
                crate::http_observer::router(crate::http_observer::ObserverState {
                    database_url: self.url.clone(),
                    auth_hasher: self.state.hasher.clone(),
                }),
            )
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        who: Option<&SessionCredentials>,
        body: Value,
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, "https://example.test")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(who) = who {
            request = request
                .header(
                    header::COOKIE,
                    format!(
                        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                        who.token, who.csrf_token
                    ),
                )
                .header("x-zrotext-csrf", &who.csrf_token);
        }
        self.app()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    async fn grant(&self, user: Uuid) -> Uuid {
        let response=self.request(Method::POST,"/v1/auth/collaboration/grants",Some(&self.owner),json!({"user_id":user,"role":"encrypted_drafter","confirm_widening":true,"current_password":self.password})).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        data(response).await["grant_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
    async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}
async fn data(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}
fn artifact(id: Uuid) -> Value {
    json!({"draft_id":id,"ciphertext_base64":STANDARD.encode(vec![73_u8;32])})
}

#[test]
fn opaque_bytes_require_canonical_encoding_and_exact_size_bounds() {
    for size in [28, 32, 8192] {
        assert_eq!(
            drafts::decode_ciphertext(&STANDARD.encode(vec![0_u8; size]))
                .unwrap()
                .len(),
            size
        );
    }
    for size in [0, 27, 8193] {
        assert!(drafts::decode_ciphertext(&STANDARD.encode(vec![0_u8; size])).is_err());
    }
    for encoded in ["not base64", " YQ==", "YQ==\n"] {
        assert!(drafts::decode_ciphertext(encoded).is_err());
    }
}

#[tokio::test]
async fn collaboration_routes_are_unmounted_by_default() {
    let state = AuthHttpState::new(
        "unavailable".into(),
        Arc::new(TokenHasher::new(crate::test_keys::key(61)).unwrap()),
        "https://example.test".into(),
        Arc::new(NoMail),
    )
    .unwrap();
    let app = Router::new().nest("/v1/auth", crate::http_auth::router(state));
    for (method, path) in [
        (Method::GET, "grants"),
        (Method::POST, "grants"),
        (
            Method::DELETE,
            "grants/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        (Method::GET, "drafts"),
        (Method::POST, "drafts"),
        (Method::GET, "drafts/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        (
            Method::DELETE,
            "drafts/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        (Method::GET, "export"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/v1/auth/collaboration/{path}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn every_collaboration_route_enforces_selected_authority_and_own_account_author() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    let item = format!("/v1/auth/collaboration/drafts/{id}");
    let grant_body = json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password});
    for (method, path, body) in [
        (Method::GET, "/v1/auth/collaboration/grants", json!(null)),
        (
            Method::POST,
            "/v1/auth/collaboration/grants",
            grant_body.clone(),
        ),
        (
            Method::DELETE,
            "/v1/auth/collaboration/grants/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            json!(null),
        ),
        (Method::GET, "/v1/auth/collaboration/drafts", json!(null)),
        (Method::POST, "/v1/auth/collaboration/drafts", artifact(id)),
        (Method::GET, item.as_str(), json!(null)),
        (Method::DELETE, item.as_str(), json!(null)),
        (Method::GET, "/v1/auth/collaboration/export", json!(null)),
    ] {
        assert_eq!(
            f.request(method.clone(), path, None, body.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let member = f
            .request(method.clone(), path, Some(&f.member), body.clone())
            .await;
        assert_eq!(
            member.status(),
            if path.contains("/drafts") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        if path.contains("/drafts") {
            assert_eq!(
                f.request(method, path, Some(&f.owner), body).await.status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    let grant = f.grant(f.member_id).await;
    let created = f
        .request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            artifact(id),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            artifact(id)
        )
        .await
        .status(),
        StatusCode::OK
    );
    let mut changed = artifact(id);
    changed["ciphertext_base64"] = json!(STANDARD.encode(vec![74_u8; 32]));
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            changed
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let list = data(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            json!(null),
        )
        .await,
    )
    .await;
    assert_eq!(list["drafts"].as_array().unwrap().len(), 1);
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.other), json!(null))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    f.grant(f.owner_id).await;
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.owner), json!(null))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(Method::DELETE, &item, Some(&f.owner), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::OK
    );
    let foreign = auth::authenticate_session(&f.db, &f.state.hasher, &f.other.token)
        .await
        .unwrap();
    let foreign_grant=f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.other),json!({"user_id":foreign.user_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password})).await;
    assert_eq!(foreign_grant.status(), StatusCode::CREATED);
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.other), json!(null))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(Method::DELETE, &item, Some(&f.other), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let foreign_export = data(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/export",
            Some(&f.other),
            json!(null),
        )
        .await,
    )
    .await;
    assert!(foreign_export["drafts"].as_array().unwrap().is_empty());
    assert_eq!(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/grants",
            Some(&f.owner),
            json!(null)
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/export",
            Some(&f.owner),
            json!(null)
        )
        .await
        .status(),
        StatusCode::OK
    );
    for path in [
        "/v1/auth/api-keys",
        "/v1/auth/seats/invitations",
        "/v1/auth/sms-line-owner-keys/challenge",
    ] {
        assert_eq!(
            f.request(Method::POST, path, Some(&f.member), json!({}))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.request(Method::DELETE, &item, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(Method::DELETE, &item, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(Method::GET, &item, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            artifact(id)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let revoke = format!("/v1/auth/collaboration/grants/{grant}");
    assert_eq!(
        f.request(Method::DELETE, &revoke, Some(&f.other), json!(null))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(Method::DELETE, &revoke, Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.request(Method::DELETE, &revoke, Some(&f.owner), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(Method::DELETE, &revoke, Some(&f.owner), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            json!(null)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn grant_widening_requires_confirmation_proof_and_never_accepts_api_key_authority() {
    let mut f = Fixture::new().await;
    for body in [
        json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":false,"current_password":f.password}),
        json!({"user_id":f.member_id,"role":"owner","confirm_widening":true,"current_password":f.password}),
        json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password,"send":true}),
    ] {
        assert_eq!(
            f.request(
                Method::POST,
                "/v1/auth/collaboration/grants",
                Some(&f.owner),
                body
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let wrong=f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.owner),json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":crate::test_keys::password(62)})).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let foreign = auth::authenticate_session(&f.db, &f.state.hasher, &f.other.token)
        .await
        .unwrap();
    assert_eq!(f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.owner),json!({"user_id":foreign.user_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password})).await.status(),StatusCode::FORBIDDEN);
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    let key = auth::create_api_key(
        &mut f.db,
        &f.state.hasher,
        &owner,
        &[auth::Scope::MessagesSend],
        None,
        auth::ApiKeyLifetime::Days(30),
    )
    .await
    .unwrap();
    for (method, path) in [
        (Method::GET, "/v1/auth/collaboration/grants"),
        (Method::POST, "/v1/auth/collaboration/grants"),
        (Method::GET, "/v1/auth/collaboration/drafts"),
        (Method::POST, "/v1/auth/collaboration/drafts"),
        (Method::GET, "/v1/auth/collaboration/export"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", key.token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(artifact(Uuid::new_v4()).to_string()))
            .unwrap();
        assert_eq!(
            f.app().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM collaboration_draft_grants", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let cipher = auth::mfa::MfaCipher::new(crate::test_keys::key(62)).unwrap();
    let pending = auth::mfa::begin_enrollment(&mut f.db, &cipher, &owner, &f.password)
        .await
        .unwrap();
    let totp = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(&pending.secret_base32).unwrap())
        .build()
        .unwrap();
    let recovery = auth::mfa::confirm_enrollment(
        &mut f.db,
        &cipher,
        &f.state.hasher,
        &owner,
        &totp.generate_current().to_string(),
    )
    .await
    .unwrap();
    f.state = f.state.clone().with_mfa_cipher(Arc::new(cipher));
    assert_eq!(f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.owner),json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password})).await.status(),StatusCode::UNAUTHORIZED);
    let granted=f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.owner),json!({"user_id":f.member_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password,"code":recovery.codes[0]})).await;
    assert_eq!(granted.status(), StatusCode::CREATED);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mixed_observer_drafter_role_adds_only_drafting_and_each_half_revokes_independently() {
    let mut f = Fixture::new().await;
    let draft = json!({"draft_id":Uuid::new_v4(),"ciphertext_base64":STANDARD.encode(vec![7_u8;32])});
    // Before any drafting grant: the observer seat reads status, cannot draft
    // and holds no owner authority.
    assert_eq!(
        f.request(Method::GET, "/v1/observer/devices", Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.request(Method::POST, "/v1/auth/collaboration/drafts", Some(&f.member), draft.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(Method::GET, "/v1/auth/collaboration/grants", Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // The drafting grant adds drafting only: status reads continue, owner
    // authority is not inherited.
    let grant = f.grant(f.member_id).await;
    assert_eq!(
        f.request(Method::POST, "/v1/auth/collaboration/drafts", Some(&f.member), draft.clone())
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        f.request(Method::GET, "/v1/observer/devices", Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.request(Method::GET, "/v1/auth/collaboration/grants", Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Revoking only the grant keeps the observer seat fully alive.
    assert_eq!(
        f.request(Method::DELETE, &format!("/v1/auth/collaboration/grants/{grant}"), Some(&f.owner), json!(null))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(Method::POST, "/v1/auth/collaboration/drafts", Some(&f.member), draft.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(Method::GET, "/v1/observer/devices", Some(&f.member), json!(null))
            .await
            .status(),
        StatusCode::OK
    );
    // Removing the observer seat ends the whole membership: the session can
    // neither read status nor draft, and the introduced grants and ciphertext
    // are scrubbed.
    f.grant(f.member_id).await;
    assert_eq!(
        f.request(Method::POST, "/v1/auth/collaboration/drafts", Some(&f.member), draft.clone())
            .await
            .status(),
        StatusCode::CREATED
    );
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    auth::seats::remove_observer(&mut f.db, &owner, f.member_id)
        .await
        .unwrap();
    for path in ["/v1/observer/devices", "/v1/auth/collaboration/drafts"] {
        let dead = f.request(Method::GET, path, Some(&f.member), json!(null)).await;
        assert_eq!(dead.status(), StatusCode::UNAUTHORIZED, "stale membership read {path}");
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM collaboration_draft_grants", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM collaboration_drafts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}
