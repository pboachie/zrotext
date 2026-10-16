// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit test-only real HTTP composition for the browser/Android handoff.
//! No enrollment, phone key or owner decision is pre-created by this fixture.

use super::*;
use crate::{
    auth::{self, login, register, verify_email},
    http_auth::{self, AuthHttpState, DisabledVerificationDispatcher},
};
use serde_json::json;
use std::io::Write;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Notify};

const ORIGIN: &str = "https://localhost:8443";

struct Fixture {
    db: Mutex<Option<Client>>,
    account: Uuid,
    token: String,
    done: Arc<Notify>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Snapshot,
    Finish,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    version: u8,
    operation: Operation,
}

async fn control(
    State(f): State<Arc<Fixture>>,
    headers: HeaderMap,
    ApiJson(command): ApiJson<Command>,
) -> Response {
    let values = headers.get_all("x-zrotext-fixture-token");
    let supplied = headers
        .get("x-zrotext-fixture-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if command.version != 1
        || values.iter().count() != 1
        || !bool::from(supplied.as_bytes().ct_eq(f.token.as_bytes()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let guard = f.db.lock().await;
    let Some(db) = guard.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match command.operation {
        Operation::Snapshot => {
            let row = db.query_one(
                "SELECT (SELECT count(*) FROM devices WHERE account_id=$1), \
                 (SELECT count(*) FROM device_keys WHERE account_id=$1 AND revoked_at IS NULL), \
                 (SELECT count(*) FROM pairing_requests WHERE account_id=$1 AND approved_at IS NOT NULL)",
                &[&f.account],
            ).await.unwrap();
            Json(
                json!({"version":1,"synthetic":true,"devices":row.get::<_,i64>(0),
                "active_keys":row.get::<_,i64>(1),"approved_pairings":row.get::<_,i64>(2)}),
            )
            .into_response()
        }
        Operation::Finish => {
            f.done.notify_one();
            Json(json!({"version":1,"synthetic":true,"finished":true})).into_response()
        }
    }
}

/// The external consumer owns a localhost-only TLS frontend and an isolated
/// Android test device. Readiness includes synthetic cookies and must remain
/// in private fixture output. This test has no provider, socket or SMS worker.
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL, selected HTTPS localhost frontend and explicit browser/Android fixture consumer"]
async fn ordinary_pairing_browser_android_fixture() {
    let root_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("select an isolated disposable PostgreSQL fixture");
    let (mut db, connection) = tokio_postgres::connect(&root_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("pairing_browser_android_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    // Use the complete frozen predecessor train; never the smaller enrollment
    // unit fixture's selected migration subset.
    auth::test_schema::apply(&db).await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(1)).unwrap());
    let enrollment_hasher = Arc::new(EnrollmentHasher::new(crate::test_keys::key(2)).unwrap());
    let password = crate::test_keys::password(3);
    let signup = register(&mut db, &hasher, "pairing-owner@example.test", &password)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let signed_in = login(&db, &hasher, "pairing-owner@example.test", &password)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&root_url).unwrap();
    assert!(!scoped.query_pairs().any(|(key, _)| key == "options"));
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let auth = AuthHttpState::new(
        scoped.to_string(),
        hasher.clone(),
        ORIGIN.to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = Router::new()
        .nest("/v1/auth", http_auth::router(auth.clone()))
        .nest("/v1/account", http_auth::setup::router(auth))
        .nest(
            "/v1/enrollment",
            router(EnrollmentHttpState::new(
                scoped.to_string(),
                hasher,
                enrollment_hasher,
                ORIGIN.to_owned(),
            )),
        )
        .merge(crate::owner_ui::router());
    let token: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let done = Arc::new(Notify::new());
    let fixture = Arc::new(Fixture {
        db: Mutex::new(Some(db)),
        account: signup.account_id,
        token: token.clone(),
        done: done.clone(),
    });
    let app = app.merge(
        Router::new()
            .route("/__fixture/pairing-setup", post(control))
            .layer(DefaultBodyLimit::max(1024))
            .with_state(fixture.clone()),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { done.notified().await })
            .await
            .unwrap();
    });
    println!(
        "ZT_PAIRING_SETUP_READY {}",
        json!({"version":1,"synthetic":true,"port":port,"origin":ORIGIN,"controlToken":token,
            "accountId":signup.account_id,"cookies":[
                {"name":"__Host-zrotext_session","value":signed_in.token},
                {"name":"__Host-zrotext_csrf","value":signed_in.csrf_token}]}),
    );
    std::io::stdout().flush().unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(600), &mut server).await;
    if result.is_err() {
        server.abort();
        let _ = server.await;
    }
    let db = fixture
        .db
        .lock()
        .await
        .take()
        .expect("fixture owns its database");
    assert!(schema.starts_with("pairing_browser_android_"));
    db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    result
        .expect("browser/Android consumer did not finish")
        .expect("fixture server failed");
}

#[test]
fn fixture_control_accepts_no_key_approval_or_identity_input() {
    assert!(serde_json::from_str::<Command>(r#"{"version":1,"operation":"snapshot"}"#).is_ok());
    for invalid in [
        r#"{"version":1,"operation":"approve"}"#,
        r#"{"version":1,"operation":"snapshot","device_id":"synthetic"}"#,
        r#"{"version":1,"operation":"finish","token":"synthetic"}"#,
    ] {
        assert!(serde_json::from_str::<Command>(invalid).is_err());
    }
}
