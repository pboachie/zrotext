// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{self, Role, TokenHasher};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct Fixture {
    db: Client,
    setup: Client,
    schema: String,
    url: String,
    hasher: Arc<TokenHasher>,
    principal: SessionPrincipal,
    token: String,
    password: String,
}
impl Fixture {
    async fn new() -> Self {
        let base =
            std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable database required");
        let (setup, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("session_clock_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        auth::test_schema::apply(&db).await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(37)).unwrap());
        let password = Uuid::new_v4().to_string();
        let signup = auth::register(&mut db, &hasher, "clock@example.test", &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let credentials = auth::login(&db, &hasher, "clock@example.test", &password)
            .await
            .unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        Self {
            db,
            setup,
            schema,
            url,
            hasher,
            principal,
            token: credentials.token,
            password,
        }
    }
    async fn finish(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
    async fn utc(&self) -> i64 {
        self.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable session clock schema"]
async fn session_response_has_current_database_time_and_never_caches_authority() {
    let f = Fixture::new().await;
    let state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = crate::http_auth::router(state);
    let before = f.utc().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/session")
                .header("cookie", format!("__Host-zrotext_session={}", f.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 5);
    assert_eq!(
        body["account_id"],
        f.principal.tenant.account_id().to_string()
    );
    assert_eq!(body["user_id"], f.principal.user_id.to_string());
    let decimal = body["server_now_ms"].as_str().unwrap();
    let utc = decimal.parse::<i64>().unwrap();
    assert!(utc > 0 && decimal == utc.to_string());
    assert!(utc >= before && utc <= f.utc().await);
    assert_eq!(body["session_id"], f.principal.session_id.to_string());
    assert_eq!(body["role"], "owner");
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&f.principal.session_id],
    )
    .await
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/session")
                .header("cookie", format!("__Host-zrotext_session={}", f.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("server_now_ms"));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable session clock schema"]
async fn session_time_requires_live_cookie_and_does_not_refresh_expired_idle_authority() {
    let f = Fixture::new().await;
    let state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = crate::http_auth::router(state);
    for request in [
        Request::builder(),
        Request::builder().header("authorization", format!("Bearer {}", f.token)),
        Request::builder().header("cookie", "__Host-zrotext_session=invalid"),
    ] {
        let response = app
            .clone()
            .oneshot(request.uri("/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("server_now_ms"));
    }
    for change in [
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second'",
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour', \
         last_used_at=clock_timestamp()-interval '73 hours'",
        "UPDATE sessions SET last_used_at=NULL, \
         created_at=clock_timestamp()-interval '73 hours'",
    ] {
        f.db.batch_execute(change).await.unwrap();
        let before: String =
            f.db.query_one(
                "SELECT COALESCE(last_used_at,created_at)::text FROM sessions WHERE id=$1",
                &[&f.principal.session_id],
            )
            .await
            .unwrap()
            .get(0);
        assert!(matches!(
            sample(&f.db, &f.principal).await,
            Err(AuthError::Unauthorized)
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/session")
                    .header("cookie", format!("__Host-zrotext_session={}", f.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{change}");
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("server_now_ms"));
        let after: String =
            f.db.query_one(
                "SELECT COALESCE(last_used_at,created_at)::text FROM sessions WHERE id=$1",
                &[&f.principal.session_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after, "expired authority was refreshed: {change}");
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable session clock schema"]
async fn clock_sample_rechecks_expiry_revocation_identity_and_membership_after_authentication() {
    let mut f = Fixture::new().await;
    assert!(sample(&f.db, &f.principal).await.is_ok());
    let session = f.principal.session_id;
    f.principal.session_id = Uuid::new_v4();
    assert!(matches!(
        sample(&f.db, &f.principal).await,
        Err(AuthError::Unauthorized)
    ));
    f.principal.session_id = session;
    let user = f.principal.user_id;
    f.principal.user_id = Uuid::new_v4();
    assert!(matches!(
        sample(&f.db, &f.principal).await,
        Err(AuthError::Unauthorized)
    ));
    f.principal.user_id = user;
    let account = f.principal.tenant.account_id();
    f.principal.tenant = auth::Tenant {
        account_id: Uuid::new_v4(),
    };
    assert!(matches!(
        sample(&f.db, &f.principal).await,
        Err(AuthError::Unauthorized)
    ));
    f.principal.tenant = auth::Tenant {
        account_id: account,
    };
    f.principal.role = Role::Observer;
    assert!(matches!(
        sample(&f.db, &f.principal).await,
        Err(AuthError::Unauthorized)
    ));
    f.principal.role = Role::Owner;
    for (change, restore) in [
        (
            "UPDATE sessions SET revoked_at=clock_timestamp()",
            "UPDATE sessions SET revoked_at=NULL",
        ),
        (
            "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second'",
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 day'",
        ),
        (
            "UPDATE sessions SET last_used_at=clock_timestamp()-interval '73 hours'",
            "UPDATE sessions SET last_used_at=clock_timestamp()",
        ),
        (
            "UPDATE accounts SET disabled_at=clock_timestamp()",
            "UPDATE accounts SET disabled_at=NULL",
        ),
        (
            "UPDATE users SET email_verified_at=NULL",
            "UPDATE users SET email_verified_at=clock_timestamp()",
        ),
        (
            "UPDATE sessions SET csrf_hash=decode(repeat('01',32),'hex')",
            "UPDATE sessions SET csrf_hash=$1",
        ),
    ] {
        f.db.batch_execute(change).await.unwrap();
        assert!(
            matches!(
                sample(&f.db, &f.principal).await,
                Err(AuthError::Unauthorized)
            ),
            "{change}"
        );
        if restore.contains("$1") {
            f.db.execute(restore, &[&&f.principal.csrf_hash[..]])
                .await
                .unwrap();
        } else {
            f.db.batch_execute(restore).await.unwrap();
        }
        assert!(sample(&f.db, &f.principal).await.is_ok(), "{restore}");
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer session clock schema"]
async fn observer_clock_preserves_role_and_rejects_revoked_membership() {
    let f = Fixture::new().await;
    let observer = Uuid::new_v4();
    f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'observer@example.test',password_hash,clock_timestamp() FROM users WHERE id=$2",&[&observer,&f.principal.user_id]).await.unwrap();
    f.db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
        &[&f.principal.tenant.account_id(), &observer],
    )
    .await
    .unwrap();
    let credentials = auth::login(&f.db, &f.hasher, "observer@example.test", &f.password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert_eq!(principal.role, Role::Observer);
    assert!(sample(&f.db, &principal).await.is_ok());
    let state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    let response = crate::http_auth::router(state)
        .oneshot(
            Request::builder()
                .uri("/session")
                .header(
                    "cookie",
                    format!("__Host-zrotext_session={}", credentials.token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["role"], "observer");
    assert_eq!(body["session_id"], principal.session_id.to_string());
    assert!(
        body["server_now_ms"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > 0
    );
    f.db.execute(
        "UPDATE memberships SET revoked_at=clock_timestamp() WHERE user_id=$1",
        &[&observer],
    )
    .await
    .unwrap();
    assert!(matches!(
        sample(&f.db, &principal).await,
        Err(AuthError::Unauthorized)
    ));
    f.finish().await;
}
