// SPDX-License-Identifier: AGPL-3.0-only
//! Owner routes authenticate from headers before their body is read, so a body
//! trickle without a live session cannot hold owner/API admission permits.
use super::*;
use crate::{
    auth::{self, SessionCredentials, TokenHasher},
    http_auth::{
        self, AuthHttpState, CSRF_COOKIE, DisabledVerificationDispatcher, SESSION_COOKIE,
        preauth::{ACCOUNT_IN_FLIGHT, AccountSlot},
    },
};
use axum::routing::get;
use tokio::sync::mpsc;
use tokio_postgres::NoTls;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://zrotext.example";
/// Far below the 10 s body deadline: a rejection this fast was not waiting for the body.
const PROMPT: Duration = Duration::from_secs(2);

/// A body that sends `first` and then stays open until `sender` is dropped or
/// sends more, like a client trickling one byte at a time.
fn trickle(first: &'static [u8]) -> (Body, mpsc::UnboundedSender<Bytes>) {
    let (sender, receiver) = mpsc::unbounded_channel::<Bytes>();
    sender.send(Bytes::from_static(first)).unwrap();
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|chunk| (Ok::<_, std::io::Error>(chunk), receiver))
    });
    (Body::from_stream(stream), sender)
}

fn owner_request(uri: &str, body: Body, session: Option<(&str, &str)>) -> Request {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some((token, csrf)) = session {
        builder = builder
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE}={token}; {CSRF_COOKIE}={csrf}"),
            )
            .header("x-zrotext-csrf", csrf);
    }
    builder.body(body).unwrap()
}

fn get_request(uri: &str) -> Request {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

struct Fixture {
    app: Router,
    session: SessionCredentials,
    account_id: Uuid,
}

async fn fixture(default_permits: usize) -> Fixture {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("preauth_{}", Uuid::new_v4().simple());
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
    let hasher = Arc::new(TokenHasher::new(vec![42; 32]).unwrap());
    let password = format!("synthetic-{}", Uuid::new_v4());
    let email = format!("preauth-{}@example.test", Uuid::new_v4().simple());
    let signup = auth::register(&mut client, &hasher, &email, &password)
        .await
        .unwrap();
    auth::verify_email(&mut client, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let session = auth::login(&client, &hasher, &email, &password)
        .await
        .unwrap();
    let account_id = auth::authenticate_session(&client, &hasher, &session.token)
        .await
        .unwrap()
        .tenant
        .account_id();
    let state = AuthHttpState::new(
        url,
        hasher,
        ORIGIN.to_owned(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = protect_with(
        Router::new()
            .nest("/v1/auth", http_auth::router(state))
            .route("/readyz", get(|| async { StatusCode::OK })),
        Limits {
            provider: 1,
            device: 1,
            anonymous: 1,
            probe: 1,
            default: default_permits,
            body_deadline: BODY_DEADLINE,
            handler_deadline: HANDLER_DEADLINE,
        },
    );
    Fixture {
        app,
        session,
        account_id,
    }
}

async fn status_within(app: &Router, request: Request, limit: Duration) -> StatusCode {
    tokio::time::timeout(limit, app.clone().oneshot(request))
        .await
        .expect("answered before the body deadline")
        .unwrap()
        .status()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn credential_less_and_forged_session_trickles_get_prompt_rejections_and_free_permits() {
    let f = fixture(2).await;
    let mut open_bodies = Vec::new();
    // Many more trickles than owner/API permits, one after another: each must be
    // rejected from its headers and give its permit back at once, or the third
    // would already see 503. Bodies stay open for the whole test.
    for _ in 0..16 {
        let (body, sender) = trickle(b"{");
        open_bodies.push(sender);
        assert_eq!(
            status_within(
                &f.app,
                owner_request("/v1/auth/password", body, None),
                PROMPT
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
    }
    // A syntactically valid but unknown session fails the pooled lookup before
    // the body, with the same 401.
    for _ in 0..16 {
        let (body, sender) = trickle(b"{");
        open_bodies.push(sender);
        let forged = owner_request(
            "/v1/auth/api-keys",
            body,
            Some((
                "zts_notarealsessiontokenvalue",
                "ztc_notarealcsrftokenvalue",
            )),
        );
        assert_eq!(
            status_within(&f.app, forged, PROMPT).await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Probes and a real owner request are still admitted while those bodies
    // remain open.
    assert_eq!(
        status_within(&f.app, get_request("/readyz"), PROMPT).await,
        StatusCode::OK
    );
    let real = owner_request(
        "/v1/auth/api-keys",
        Body::from(serde_json::json!({"scopes":["messages:read"]}).to_string()),
        Some((&f.session.token, &f.session.csrf_token)),
    );
    assert_eq!(
        status_within(&f.app, real, PROMPT).await,
        StatusCode::CREATED
    );
    assert_eq!(AccountSlot::in_flight(f.account_id), 0);
    drop(open_bodies);
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn one_account_cannot_hold_more_than_its_in_flight_cap() {
    let f = fixture(ACCOUNT_IN_FLIGHT + 4).await;
    let session = (f.session.token.as_str(), f.session.csrf_token.as_str());
    // Authenticated requests whose bodies trickle: each holds a slot and a
    // permit, but no pooled database client, while its body is outstanding.
    let mut held = Vec::new();
    for _ in 0..ACCOUNT_IN_FLIGHT {
        let (body, sender) = trickle(b"{\"scopes\":");
        let request = owner_request("/v1/auth/api-keys", body, Some(session));
        let app = f.app.clone();
        held.push((
            sender,
            tokio::spawn(async move { app.oneshot(request).await }),
        ));
    }
    let deadline = tokio::time::Instant::now() + PROMPT;
    while AccountSlot::in_flight(f.account_id) < ACCOUNT_IN_FLIGHT {
        assert!(tokio::time::Instant::now() < deadline, "slots never taken");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The next one from the same account is refused from its headers.
    let (body, _extra) = trickle(b"{");
    assert_eq!(
        status_within(
            &f.app,
            owner_request("/v1/auth/api-keys", body, Some(session)),
            PROMPT
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Owner/API permits are not exhausted, so probes still pass.
    assert_eq!(
        status_within(&f.app, get_request("/readyz"), PROMPT).await,
        StatusCode::OK
    );
    // Finishing one held body releases its slot for the next request.
    let (sender, task) = held.remove(0);
    sender
        .send(Bytes::from_static(b"[\"messages:read\"]}"))
        .unwrap();
    drop(sender);
    let finished = tokio::time::timeout(PROMPT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(finished.status(), StatusCode::CREATED);
    let complete = owner_request(
        "/v1/auth/api-keys",
        Body::from(serde_json::json!({"scopes":["messages:read"]}).to_string()),
        Some(session),
    );
    assert_eq!(
        status_within(&f.app, complete, PROMPT).await,
        StatusCode::CREATED
    );
    drop(held);
}

#[tokio::test]
async fn probes_are_admitted_while_owner_and_api_permits_are_exhausted() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let app = protect_with(
        Router::new()
            .route(
                "/v1/owner/slow",
                axum::routing::post({
                    let entered = entered.clone();
                    let release = release.clone();
                    move || async move {
                        entered.notify_one();
                        release.notified().await;
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .route("/readyz", get(|| async { StatusCode::OK }))
            .route("/healthz", get(|| async { StatusCode::OK }))
            .route("/about/version", get(|| async { StatusCode::OK })),
        Limits {
            provider: 1,
            device: 1,
            anonymous: 1,
            probe: 1,
            default: 1,
            body_deadline: BODY_DEADLINE,
            handler_deadline: HANDLER_DEADLINE,
        },
    );
    let held = tokio::spawn(
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/owner/slow")
                .body(Body::empty())
                .unwrap(),
        ),
    );
    entered.notified().await;
    let busy = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/owner/slow")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    for uri in ["/readyz", "/healthz", "/about/version"] {
        assert_eq!(
            app.clone()
                .oneshot(get_request(uri))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "{uri}"
        );
    }
    release.notify_one();
    assert_eq!(
        held.await.unwrap().unwrap().status(),
        StatusCode::NO_CONTENT
    );
}
