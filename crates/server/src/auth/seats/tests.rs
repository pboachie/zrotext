// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::abuse_limits::{self, Lane, Limit};
use crate::auth::{self, Role, login, mfa, register, verify_email};
use std::sync::Arc;
use tokio_postgres::NoTls;
use totp_rs::{Builder, Secret};

/// The auth-side schema every seat test needs, applied in order.
const AUTH_MIGRATIONS: [&str; 10] = [
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
];

/// Extra migrations for the observer device-status read, which shares the
/// enrollment status query and its tables.
const DEVICE_MIGRATIONS: [&str; 5] = [
    include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
    include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
    include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
    include_str!("../../../../../deploy/compose/migrations/041_device_preconditions.sql"),
    include_str!("../../../../../deploy/compose/migrations/047_device_network_service.sql"),
];

struct Fixture {
    db: Client,
    setup: Client,
    schema: String,
    url: String,
    hasher: Arc<TokenHasher>,
    owner: SessionPrincipal,
    owner_credentials: auth::SessionCredentials,
    password: String,
}

impl Fixture {
    async fn new(with_devices: bool) -> Self {
        let base =
            std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable database required");
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("observer_seats_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        // 002 creates accounts and users, which the enrollment-side device
        // migrations reference; everything else follows it.
        db.batch_execute(AUTH_MIGRATIONS[0]).await.unwrap();
        if with_devices {
            for migration in DEVICE_MIGRATIONS {
                db.batch_execute(migration).await.unwrap();
            }
        }
        for migration in &AUTH_MIGRATIONS[1..] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(42)).unwrap());
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let owner_credentials = login(&db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        let owner = auth::authenticate_session(&db, &hasher, &owner_credentials.token)
            .await
            .unwrap();
        assert_eq!(owner.role, Role::Owner);
        Self {
            db,
            setup,
            schema,
            url,
            hasher,
            owner,
            owner_credentials,
            password,
        }
    }

    /// A second, independent owner with its own account for tenant isolation.
    async fn other_owner(&mut self, email: &str) -> SessionPrincipal {
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut self.db, &self.hasher, email, &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut self.db, &self.hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let credentials = login(&self.db, &self.hasher, email, &password)
            .await
            .unwrap();
        auth::authenticate_session(&self.db, &self.hasher, &credentials.token)
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// Accept an invitation and verify the address with the chosen password,
/// returning the live observer session credentials.
async fn accept_and_verify(
    db: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    password: &str,
    email: &str,
) -> auth::SessionCredentials {
    accept_invitation(db, hasher, token, password)
        .await
        .unwrap();
    let mail = crate::auth::claim_verification_mail(db, hasher)
        .await
        .unwrap()
        .expect("acceptance queues a verification code");
    assert_eq!(mail.email, email);
    assert!(
        crate::auth::verify_email_with_password(db, hasher, &mail.token, password)
            .await
            .unwrap()
    );
    login(db, hasher, email, password).await.unwrap()
}

/// Invitation creation without the step-up proof, for tests of the caps and
/// address semantics, which are independent of it. Production code can only
/// reach `create_invitation_in` through `create_invitation_with_proof`; the
/// proof itself is covered by `invitation_creation_requires_owner_step_up`
/// and the HTTP tests below.
async fn create_invitation(
    db: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    email: &str,
) -> Result<IssuedInvitation, AuthError> {
    let email = normalize_email(email)?;
    let tx = db.transaction().await?;
    let issued = create_invitation_in(&tx, hasher, principal, &email).await?;
    tx.commit().await?;
    Ok(issued)
}

/// Spent attempts of the per-account `SeatInvite` budget.
async fn seat_invite_attempts(f: &Fixture) -> i32 {
    let hash = abuse_limits::subject_hash(
        &f.hasher,
        Limit::SeatInvite,
        &f.owner.tenant.account_id().to_string(),
        Lane::Anonymous,
    )
    .unwrap();
    f.db.query_opt(
        "SELECT attempts FROM auth_abuse_counters WHERE scope='seat_invite' AND subject_hash=$1",
        &[&&hash[..]],
    )
    .await
    .unwrap()
    .map_or(0, |row| row.get(0))
}

async fn count_rows(db: &Client, sql: &str, account: Uuid) -> i64 {
    db.query_one(sql, &[&account]).await.unwrap().get(0)
}

async fn step_up_failures(f: &Fixture) -> i32 {
    abuse_limits::failures_in_window(
        &f.db,
        &f.hasher,
        Limit::MfaStepUp,
        &f.owner.user_id.to_string(),
    )
    .await
    .unwrap()
}

fn totp_now(secret_base32: &str) -> String {
    Builder::new()
        .with_secret(Secret::try_from_base32(secret_base32).unwrap())
        .build()
        .unwrap()
        .generate_current()
        .to_string()
}

fn seat_app(f: &Fixture, mfa_key: Option<[u8; 32]>) -> axum::Router {
    let mut state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    // Password hashing queues behind a process-wide two-worker gate that every
    // parallel test in this binary shares; the production two-second wait can
    // expire under that contention and answer 503, which is what made the
    // browser-flow test flaky in parallel runs.
    state.hash_permit_wait = std::time::Duration::from_secs(120);
    if let Some(key) = mfa_key {
        state = state.with_mfa_cipher(Arc::new(mfa::MfaCipher::new(key.to_vec()).unwrap()));
    }
    axum::Router::new().nest("/auth", crate::http_auth::router(state))
}

/// One owner-cookie request against the seat routes, returning the status and
/// the JSON body (`Null` when the body is not JSON).
async fn owner_call(
    app: &axum::Router,
    f: &Fixture,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::{body::Body, body::to_bytes, http::Request};
    use tower::ServiceExt;
    let cookie = format!(
        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
        f.owner_credentials.token, f.owner_credentials.csrf_token
    );
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", "https://example.test")
        .header("cookie", cookie)
        .header("x-zrotext-csrf", &f.owner_credentials.csrf_token);
    let body = if body.is_null() {
        String::new()
    } else {
        builder = builder.header("content-type", "application/json");
        body.to_string()
    };
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn invite_over_http(
    app: &axum::Router,
    f: &Fixture,
    email: &str,
    password: &str,
    code: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    owner_call(
        app,
        f,
        "POST",
        "/auth/seats/invitations",
        serde_json::json!({"email":email,"current_password":password,"code":code}),
    )
    .await
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitation_acceptance_verification_and_sign_in_flow() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    assert!(issued.token.starts_with("zti_"));
    assert_eq!(issued.email, "observer@example.test");
    // Only the HMAC of the token is stored, never the token itself.
    let stored: Vec<u8> =
        f.db.query_one(
            "SELECT token_hash FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        stored,
        f.hasher.digest(b"seat-invitation-v1", &issued.token)
    );

    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert!(page.seats.is_empty());
    assert_eq!(page.invitations.len(), 1);
    assert_eq!(page.invitations[0].id, issued.id);
    assert!(page.invitations[0].accepted_at_ms.is_none());

    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert_eq!(observer.role, Role::Observer);
    assert_eq!(observer.tenant.account_id(), f.owner.tenant.account_id());

    // The owner sees the seat as active and the invitation as accepted.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert_eq!(page.seats[0].email, "observer@example.test");
    assert!(page.seats[0].email_verified);
    assert!(page.seats[0].revoked_at_ms.is_none());
    assert!(page.invitations[0].accepted_at_ms.is_some());
    assert_eq!(page.invitations[0].accepted_user_id, page.seats[0].user_id);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn the_session_lookup_maps_every_column_for_an_owner_and_an_observer() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    // Each principal field is compared with the database row it must come
    // from, so a shifted column offset in the typed lookup cannot pass.
    for (email, principal, session, role) in [
        (
            "owner@example.test",
            &f.owner,
            &f.owner_credentials,
            Role::Owner,
        ),
        (
            "observer@example.test",
            &observer,
            &credentials,
            Role::Observer,
        ),
    ] {
        let row = f
            .db
            .query_one(
                "SELECT u.id,m.account_id,m.role FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.email=$1",
                &[&email],
            )
            .await
            .unwrap();
        assert_eq!(principal.user_id, row.get::<_, Uuid>(0));
        assert_eq!(principal.tenant.account_id(), row.get::<_, Uuid>(1));
        assert_eq!(principal.session_id, session.id);
        assert_eq!(principal.role, role);
        assert_eq!(role == Role::Owner, row.get::<_, String>(2) == "owner");
        // The CSRF column is read from the right position too.
        principal
            .require_csrf_token(&f.hasher, &session.csrf_token, &session.csrf_token)
            .unwrap();
    }
    assert_ne!(f.owner.user_id, observer.user_id);
    assert_eq!(f.owner.tenant.account_id(), observer.tenant.account_id());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitations_are_single_use_cancellable_and_expiry_bound() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "first@example.test")
        .await
        .unwrap();
    // Replay after acceptance: the second accept runs the same password work
    // and fails with the same error as an unknown token.
    accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password)
        .await
        .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));

    // Cancellation kills a live invitation permanently.
    let canceled = create_invitation(&mut f.db, &f.hasher, &f.owner, "second@example.test")
        .await
        .unwrap();
    assert!(
        cancel_invitation(&mut f.db, &f.owner, canceled.id)
            .await
            .unwrap()
    );
    assert!(
        !cancel_invitation(&mut f.db, &f.owner, canceled.id)
            .await
            .unwrap()
    );
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &canceled.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));

    // Expiry is evaluated by the server clock at acceptance time.
    let expired = create_invitation(&mut f.db, &f.hasher, &f.owner, "third@example.test")
        .await
        .unwrap();
    f.db.execute(
        "UPDATE seat_invitations SET expires_at=now()-interval '1 second' WHERE id=$1",
        &[&expired.id],
    )
    .await
    .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &expired.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, &expired.token)
            .await
            .unwrap()
    );

    // Malformed tokens never reach the database probe.
    for malformed in ["", "zti_", "ztv_short", "zti_not-base64!"] {
        assert!(matches!(
            accept_invitation(&mut f.db, &f.hasher, malformed, &f.password).await,
            Err(AuthError::InvalidInput)
        ));
    }
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, "zti_not-base64!")
            .await
            .unwrap()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn conflicting_existing_user_is_rejected_untouched() {
    let mut f = Fixture::new(false).await;
    // Inviting a registered address succeeds for the owner like any other; the
    // conflict is discovered only by the token holder, and acceptance never
    // touches the existing user.
    let taken = create_invitation(&mut f.db, &f.hasher, &f.owner, "owner@example.test")
        .await
        .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &taken.token, &f.password).await,
        Err(AuthError::Conflict)
    ));
    assert_eq!(
        count_rows(
            &f.db,
            "SELECT count(*) FROM memberships WHERE account_id=$1 AND role='owner' AND revoked_at IS NULL",
            f.owner.tenant.account_id()
        )
        .await,
        1
    );
    assert!(
        login(&f.db, &f.hasher, "owner@example.test", &f.password)
            .await
            .is_ok()
    );

    // A user that appears after issuance blocks acceptance without being
    // modified: its password, membership, and the invitation all stay intact.
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let other_password = format!("synthetic-{}", Uuid::new_v4());
    let signup = register(
        &mut f.db,
        &f.hasher,
        "observer@example.test",
        &other_password,
    )
    .await
    .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::Conflict)
    ));
    let row = f
        .db
        .query_one(
            "SELECT u.email_verified_at,m.role,m.revoked_at FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1",
            &[&signup.user_id],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<std::time::SystemTime>>(0).is_none());
    assert_eq!(row.get::<_, String>(1), "owner");
    assert!(row.get::<_, Option<std::time::SystemTime>>(2).is_none());
    // The invitation was not consumed by the refusal.
    let accepted: Option<std::time::SystemTime> =
        f.db.query_one(
            "SELECT accepted_at FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(accepted.is_none());
    // The pre-existing account is intact: its owner verifies and signs in
    // with its own password, entirely unaffected by the invitation.
    assert!(
        verify_email(&mut f.db, &f.hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    assert!(
        login(&f.db, &f.hasher, "observer@example.test", &other_password)
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_removal_revokes_every_credential_and_never_resurrects() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    let observer_id = observer.user_id;
    // A stray reset code the seat could have used is dead after removal.
    let reset = crate::auth::random_token("ztr_");
    let reset_hash = f.hasher.digest(b"password-reset-v1", &reset);
    f.db
        .execute(
            "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')",
            &[
                &Uuid::new_v4(),
                &f.owner.tenant.account_id(),
                &observer_id,
                &&reset_hash[..],
            ],
        )
        .await
        .unwrap();

    // An API key of the seat, inserted directly because observers cannot mint
    // one through any route.
    let key_token = crate::auth::random_token("ztk_");
    let key_prefix: String = key_token.chars().skip(4).take(12).collect();
    let key_hash = f.hasher.digest(b"api-key-v1", &key_token);
    f.db.execute(
        "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,ARRAY['devices:read'])",
        &[
            &Uuid::new_v4(),
            &f.owner.tenant.account_id(),
            &observer_id,
            &key_prefix,
            &&key_hash[..],
        ],
    )
    .await
    .unwrap();

    // The owner cannot be removed through this path, and an unknown seat id
    // is not found. The owner's user and membership are untouched by both.
    assert!(
        remove_observer(&mut f.db, &f.owner, f.owner.user_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        remove_observer(&mut f.db, &f.owner, Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.role='owner' AND m.revoked_at IS NULL",
            &[&f.owner.user_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let removal = remove_observer(&mut f.db, &f.owner, observer_id)
        .await
        .unwrap()
        .expect("the seat is removed");
    assert!(removal.address_freed);

    // Every credential of the seat is dead: session, login, reset code, key.
    assert!(matches!(
        auth::authenticate_session(&f.db, &f.hasher, &credentials.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        login(&f.db, &f.hasher, "observer@example.test", &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        !crate::auth::account::reset_token_is_live(&f.db, &f.hasher, &reset)
            .await
            .unwrap()
    );
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key_token)
            .await
            .is_err()
    );
    // The old identity is gone entirely, not merely revoked.
    for table in [
        "users WHERE id",
        "memberships WHERE user_id",
        "sessions WHERE user_id",
        "api_keys WHERE created_by_user_id",
        "password_resets WHERE user_id",
    ] {
        assert_eq!(
            f.db.query_one(&format!("SELECT count(*) FROM {table}=$1"), &[&observer_id])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0,
            "{table}"
        );
    }
    // Second removal is a no-op and the owner is unaffected.
    assert!(
        remove_observer(&mut f.db, &f.owner, observer_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth::authenticate_session(&f.db, &f.hasher, &f.owner_credentials.token)
            .await
            .is_ok()
    );

    // No request path restores the seat: there is no row left to update.
    assert_eq!(
        f.db.execute(
            "UPDATE memberships SET revoked_at=NULL WHERE user_id=$1",
            &[&observer_id]
        )
        .await
        .unwrap(),
        0
    );
    // Re-accepting the consumed invitation cannot recreate the seat either.
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    // The owner's list keeps a removed tombstone, sourced from the invitation.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert!(page.seats[0].revoked_at_ms.is_some());
    assert!(page.seats[0].user_id.is_none());
    assert!(page.seats[0].address_free);
    assert_eq!(page.seats[0].email, "observer@example.test");
    assert!(page.invitations.is_empty());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn concurrent_accepts_and_cancel_race_have_one_winner() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let token_a = issued.token.clone();
    let token_b = issued.token.clone();
    let hasher = f.hasher.clone();
    let password = f.password.clone();
    let url = f.url.clone();
    let first = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        accept_invitation(&mut client, &hasher, &token_a, &password).await
    });
    let second = {
        let url = f.url.clone();
        let hasher = f.hasher.clone();
        let password = f.password.clone();
        tokio::spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            accept_invitation(&mut client, &hasher, &token_b, &password).await
        })
    };
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one concurrent acceptance wins"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AuthError::InvalidCredentials)))
            .count(),
        1
    );

    // A cancel racing an acceptance can only lose once the row is claimed.
    let racing = create_invitation(&mut f.db, &f.hasher, &f.owner, "racer@example.test")
        .await
        .unwrap();
    let cancel_url = f.url.clone();
    let cancel_owner = f.owner.clone();
    let cancel_id = racing.id;
    let cancel = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&cancel_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        cancel_invitation(&mut client, &cancel_owner, cancel_id).await
    });
    let acceptance = accept_invitation(&mut f.db, &f.hasher, &racing.token, &f.password).await;
    let canceled = cancel.await.unwrap().unwrap();
    match (acceptance.is_ok(), canceled) {
        // The acceptance won the row lock; the cancel then found it consumed.
        (true, false) => {}
        // The cancel won; the acceptance then failed the liveness recheck.
        (false, true) => assert!(matches!(acceptance, Err(AuthError::InvalidCredentials))),
        outcome => panic!("unexpected race outcome: {outcome:?}"),
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_management_is_tenant_scoped() {
    let mut f = Fixture::new(false).await;
    let other = f.other_owner("other-owner@example.test").await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    // Another account's owner sees none of this account's seats or
    // invitations and can neither cancel nor remove them.
    let stranger_page = list_seats(&f.db, &other).await.unwrap();
    assert!(stranger_page.seats.is_empty());
    assert!(stranger_page.invitations.is_empty());
    assert!(
        !cancel_invitation(&mut f.db, &other, issued.id)
            .await
            .unwrap()
    );
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert!(
        remove_observer(&mut f.db, &other, observer.user_id)
            .await
            .unwrap()
            .is_none()
    );
    // The observer itself cannot manage seats, not even its own.
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &observer, "another@example.test").await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        list_seats(&f.db, &observer).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        remove_observer(&mut f.db, &observer, observer.user_id).await,
        Err(AuthError::Unauthorized)
    ));
    // Another account may invite the same address at the same time: one
    // account's open invitation never blocks or reveals itself to another.
    let shared = create_invitation(&mut f.db, &f.hasher, &f.owner, "shared@example.test")
        .await
        .unwrap();
    let theirs = create_invitation(&mut f.db, &f.hasher, &other, "shared@example.test")
        .await
        .unwrap();
    assert_ne!(shared.id, theirs.id);
    assert_ne!(shared.token, theirs.token);
    // Cancelling is scoped per account: the owner's cancel leaves the other
    // account's invitation for the same address live.
    assert!(
        cancel_invitation(&mut f.db, &f.owner, shared.id)
            .await
            .unwrap()
    );
    assert!(
        !cancel_invitation(&mut f.db, &f.owner, theirs.id)
            .await
            .unwrap()
    );
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, &shared.token)
            .await
            .unwrap()
    );
    assert!(
        invitation_token_is_live(&f.db, &f.hasher, &theirs.token)
            .await
            .unwrap()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_and_invitation_budgets_are_bounded() {
    // The caps are pinned to their documented value of ten rather than to the
    // constants, so raising either constant fails this test.
    assert_eq!((MAX_OPEN_INVITATIONS, MAX_ACTIVE_OBSERVERS), (10, 10));
    let mut f = Fixture::new(false).await;
    for index in 0..10 {
        create_invitation(
            &mut f.db,
            &f.hasher,
            &f.owner,
            &format!("observer-{index}@example.test"),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "overflow@example.test").await,
        Err(AuthError::Conflict)
    ));
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.invitations.len() as i64, 10);
    // Canceling one opens exactly one slot again.
    let victim = page.invitations.last().unwrap().id;
    assert!(
        cancel_invitation(&mut f.db, &f.owner, victim)
            .await
            .unwrap()
    );
    let overflow = create_invitation(&mut f.db, &f.hasher, &f.owner, "overflow@example.test")
        .await
        .unwrap();
    // An expired invitation no longer counts against the open cap.
    f.db.execute(
        "UPDATE seat_invitations SET expires_at=now()-interval '1 second' WHERE id=$1",
        &[&overflow.id],
    )
    .await
    .unwrap();
    let stale = create_invitation(&mut f.db, &f.hasher, &f.owner, "stale@example.test")
        .await
        .unwrap();

    // The live-observer seat cap also bounds invitation creation.
    for index in 0..10 {
        let user_id = Uuid::new_v4();
        f.db
            .execute(
                "INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,$2,password_hash,now() FROM users WHERE id=$3",
                &[&user_id, &format!("bulk-{index}@example.test"), &f.owner.user_id],
            )
            .await
            .unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&f.owner.tenant.account_id(), &user_id],
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "seat-overflow@example.test").await,
        Err(AuthError::Conflict)
    ));
    // Removing one seat frees the seat cap again.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    let victim = page.seats.last().unwrap().user_id.unwrap();
    assert!(
        remove_observer(&mut f.db, &f.owner, victim)
            .await
            .unwrap()
            .is_some()
    );
    // Freeing an invitation slot as well lets the creation through: both the
    // live-seat and open-invitation caps must be below their bounds.
    assert!(
        cancel_invitation(&mut f.db, &f.owner, stale.id)
            .await
            .unwrap()
    );
    assert!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "seat-overflow@example.test")
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn expired_unverified_observers_are_pending_user_pruning() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let acceptance = accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password)
        .await
        .unwrap();
    // A fresh unverified observer is never pruned.
    assert_eq!(prune_expired_pending_observers(&mut f.db).await.unwrap(), 0);
    f.db.execute(
        "UPDATE users SET created_at=now()-interval '2 days' WHERE id=$1",
        &[&acceptance.user_id],
    )
    .await
    .unwrap();
    assert_eq!(prune_expired_pending_observers(&mut f.db).await.unwrap(), 1);
    // The user, membership, and invitation link are gone; the invitation row
    // keeps only its audit columns and the address is free again.
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM memberships", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let row =
        f.db.query_one(
            "SELECT accepted_at,accepted_user_id FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<std::time::SystemTime>>(0).is_some());
    assert!(row.get::<_, Option<Uuid>>(1).is_none());
    assert!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn a_fresh_observer_principal_never_passes_an_owner_precheck() {
    let mut f = Fixture::new(true).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    // `authenticate_session` hands each principal a single-use shortcut in
    // place of one unlocked recheck. Each owner precheck below therefore gets
    // its own freshly authenticated observer, so a missing role check would
    // wave it through on that shortcut.
    let fresh = || async {
        auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
            .await
            .unwrap()
    };
    let observer = fresh().await;
    assert_eq!(observer.role, Role::Observer);
    assert!(matches!(
        auth::list_api_keys(&f.db, &observer, None).await,
        Err(AuthError::Unauthorized)
    ));
    let observer = fresh().await;
    assert!(matches!(
        auth::revoke_api_key(&f.db, &observer, Uuid::new_v4()).await,
        Err(AuthError::Unauthorized)
    ));
    let observer = fresh().await;
    assert!(matches!(
        crate::enrollment::pairing_view(&f.db, &observer, Uuid::new_v4()).await,
        Err(crate::enrollment::EnrollmentError::Unauthorized)
    ));
    // The member checks stay open to the same observer, on the shortcut and
    // on the recheck alike.
    let observer = fresh().await;
    assert!(auth::account::list_sessions(&f.db, &observer).await.is_ok());
    assert!(auth::account::list_sessions(&f.db, &observer).await.is_ok());
    let observer = fresh().await;
    assert!(
        crate::enrollment::list_account_devices(&f.db, &observer, None)
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitation_creation_requires_owner_step_up() {
    let mut f = Fixture::new(false).await;
    let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let account = f.owner.tenant.account_id();
    let rows = "SELECT count(*) FROM seat_invitations WHERE account_id=$1";

    // A wrong password mints nothing.
    assert!(matches!(
        create_invitation_with_proof(
            &mut f.db,
            Some(&cipher),
            &f.hasher,
            &f.owner,
            &format!("wrong-{}", Uuid::new_v4()),
            None,
            "observer@example.test",
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert_eq!(count_rows(&f.db, rows, account).await, 0);

    // The current password is enough while MFA is off.
    let issued = create_invitation_with_proof(
        &mut f.db,
        Some(&cipher),
        &f.hasher,
        &f.owner,
        &f.password,
        None,
        "observer@example.test",
    )
    .await
    .unwrap();
    assert!(issued.token.starts_with("zti_"));
    assert_eq!(count_rows(&f.db, rows, account).await, 1);

    // Once MFA is enabled the password alone stops working.
    let pending = mfa::begin_enrollment(&mut f.db, &cipher, &f.owner, &f.password)
        .await
        .unwrap();
    let recovery = mfa::confirm_enrollment(
        &mut f.db,
        &cipher,
        &f.hasher,
        &f.owner,
        &totp_now(&pending.secret_base32),
    )
    .await
    .unwrap();
    assert!(matches!(
        create_invitation_with_proof(
            &mut f.db,
            Some(&cipher),
            &f.hasher,
            &f.owner,
            &f.password,
            None,
            "second@example.test",
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    // A wrong password is refused before any code is considered and does not
    // spend the MFA budget; a wrong code does.
    assert!(matches!(
        create_invitation_with_proof(
            &mut f.db,
            Some(&cipher),
            &f.hasher,
            &f.owner,
            &format!("wrong-{}", Uuid::new_v4()),
            Some(&recovery.codes[0]),
            "second@example.test",
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert_eq!(step_up_failures(&f).await, 0);
    for expected in 1..=5 {
        assert!(matches!(
            create_invitation_with_proof(
                &mut f.db,
                Some(&cipher),
                &f.hasher,
                &f.owner,
                &f.password,
                Some("000000"),
                "second@example.test",
            )
            .await,
            Err(AuthError::InvalidCredentials)
        ));
        assert_eq!(step_up_failures(&f).await, expected);
    }
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    // The exhausted failure budget refuses even a valid recovery code.
    assert!(matches!(
        create_invitation_with_proof(
            &mut f.db,
            Some(&cipher),
            &f.hasher,
            &f.owner,
            &f.password,
            Some(&recovery.codes[0]),
            "second@example.test",
        )
        .await,
        Err(AuthError::RateLimited)
    ));
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    // After the window lapses a valid code mints.
    f.db.execute(
        "UPDATE auth_abuse_counters SET window_started_at=now()-interval '16 minutes' WHERE scope='mfa_step_up'",
        &[],
    )
    .await
    .unwrap();
    create_invitation_with_proof(
        &mut f.db,
        Some(&cipher),
        &f.hasher,
        &f.owner,
        &f.password,
        Some(&recovery.codes[0]),
        "second@example.test",
    )
    .await
    .unwrap();
    assert_eq!(count_rows(&f.db, rows, account).await, 2);
    // An observer session never passes, whatever proof it carries.
    let other_password = f.password.clone();
    let observer_invite = create_invitation(&mut f.db, &f.hasher, &f.owner, "third@example.test")
        .await
        .unwrap();
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &observer_invite.token,
        &other_password,
        "third@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert!(matches!(
        create_invitation_with_proof(
            &mut f.db,
            Some(&cipher),
            &f.hasher,
            &observer,
            &other_password,
            None,
            "fourth@example.test",
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn conflicts_surface_only_to_the_token_holder_at_accept() {
    let mut f = Fixture::new(false).await;
    let other = f.other_owner("other-owner@example.test").await;
    let account = f.owner.tenant.account_id();

    // Two accounts invite one unregistered address; both succeed.
    let mine = create_invitation(&mut f.db, &f.hasher, &f.owner, "shared@example.test")
        .await
        .unwrap();
    let theirs = create_invitation(&mut f.db, &f.hasher, &other, "shared@example.test")
        .await
        .unwrap();
    // The first token holder to accept wins the address.
    let winner_password = format!("synthetic-{}", Uuid::new_v4());
    let acceptance = accept_invitation(&mut f.db, &f.hasher, &theirs.token, &winner_password)
        .await
        .unwrap();
    // The other token holder alone learns of the conflict, and nothing about
    // the winner changes: same password, membership, and account.
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &mine.token, &f.password).await,
        Err(AuthError::Conflict)
    ));
    let row = f
        .db
        .query_one(
            "SELECT m.account_id,m.role,m.revoked_at IS NULL FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1",
            &[&acceptance.user_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Uuid>(0), other.tenant.account_id());
    assert_eq!(row.get::<_, String>(1), "observer");
    assert!(row.get::<_, bool>(2));
    assert!(
        crate::auth::verify_email_with_password(
            &mut f.db,
            &f.hasher,
            &acceptance.verification_token,
            &winner_password,
        )
        .await
        .unwrap()
    );
    assert!(
        login(&f.db, &f.hasher, "shared@example.test", &winner_password)
            .await
            .is_ok()
    );
    // The refused invitation was not consumed, and still counts as an open
    // invitation the inviting owner can list and cancel.
    assert_eq!(
        count_rows(
            &f.db,
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND accepted_at IS NULL AND canceled_at IS NULL",
            account
        )
        .await,
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn reinviting_an_address_replaces_the_earlier_invitation() {
    let mut f = Fixture::new(false).await;
    let account = f.owner.tenant.account_id();
    let open = "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND accepted_at IS NULL AND canceled_at IS NULL";

    // Re-inviting a live invitation retires the first token.
    let first = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let second = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    assert_ne!(first.token, second.token);
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, &first.token)
            .await
            .unwrap()
    );
    assert!(
        invitation_token_is_live(&f.db, &f.hasher, &second.token)
            .await
            .unwrap()
    );
    assert_eq!(count_rows(&f.db, open, account).await, 1);

    // An expired open invitation never blocks the address: inviting again
    // needs no manual cancel and leaves exactly one open row.
    f.db.execute(
        "UPDATE seat_invitations SET expires_at=now()-interval '1 second' WHERE id=$1",
        &[&second.id],
    )
    .await
    .unwrap();
    let third = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    assert!(
        invitation_token_is_live(&f.db, &f.hasher, &third.token)
            .await
            .unwrap()
    );
    let stale_canceled: bool =
        f.db.query_one(
            "SELECT canceled_at IS NOT NULL FROM seat_invitations WHERE id=$1",
            &[&second.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(stale_canceled);
    assert_eq!(count_rows(&f.db, open, account).await, 1);

    // The database itself keeps the uniqueness per account and address.
    let duplicate = f
        .db
        .execute(
            "INSERT INTO seat_invitations(id,account_id,email,token_hash,expires_at) VALUES($1,$2,'observer@example.test',$3,now()+interval '1 day')",
            &[&Uuid::new_v4(), &account, &vec![7u8; 32]],
        )
        .await
        .unwrap_err();
    assert_eq!(
        duplicate.code(),
        Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    );

    // At the open cap a re-invite of an already invited address nets zero and
    // succeeds, while a new address is still refused.
    for index in 0..MAX_OPEN_INVITATIONS - 1 {
        create_invitation(
            &mut f.db,
            &f.hasher,
            &f.owner,
            &format!("observer-{index}@example.test"),
        )
        .await
        .unwrap();
    }
    assert_eq!(count_rows(&f.db, open, account).await, MAX_OPEN_INVITATIONS);
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "overflow@example.test").await,
        Err(AuthError::Conflict)
    ));
    create_invitation(&mut f.db, &f.hasher, &f.owner, "observer-0@example.test")
        .await
        .unwrap();
    assert_eq!(count_rows(&f.db, open, account).await, MAX_OPEN_INVITATIONS);
    // A refused request rolls the replacement back: the earlier token lives.
    let survivor = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer-1@example.test")
        .await
        .unwrap();
    assert!(
        invitation_token_is_live(&f.db, &f.hasher, &survivor.token)
            .await
            .unwrap()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitation_route_demands_password_and_mfa_and_charges_budgets() {
    use axum::http::StatusCode;

    let mut f = Fixture::new(false).await;
    let key = rand::random::<[u8; 32]>();
    let cipher = mfa::MfaCipher::new(key.to_vec()).unwrap();
    let app = seat_app(&f, Some(key));
    let account = f.owner.tenant.account_id();
    let rows = "SELECT count(*) FROM seat_invitations WHERE account_id=$1";

    // A session cookie and CSRF alone, with no proof in the body, mint nothing.
    let (status, _) = owner_call(
        &app,
        &f,
        "POST",
        "/auth/seats/invitations",
        serde_json::json!({"email":"observer@example.test"}),
    )
    .await;
    assert!(status.is_client_error() && status != StatusCode::CREATED);
    assert_eq!(count_rows(&f.db, rows, account).await, 0);

    // A wrong password answers exactly as API-key creation does, mints
    // nothing, and spends the per-account SeatInvite budget, which is charged
    // before the password is hashed and so also bounds guesses on this route.
    let before = seat_invite_attempts(&f).await;
    let (status, _) = invite_over_http(
        &app,
        &f,
        "observer@example.test",
        &format!("wrong-{}", Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(count_rows(&f.db, rows, account).await, 0);
    assert_eq!(seat_invite_attempts(&f).await, before + 1);

    // The right password mints and is charged the same single attempt.
    let (status, body) =
        invite_over_http(&app, &f, "observer@example.test", &f.password, None).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["token"].as_str().unwrap().starts_with("zti_"));
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    assert_eq!(seat_invite_attempts(&f).await, before + 2);

    // An exhausted SeatInvite budget refuses even the correct password.
    f.db.execute(
        "UPDATE auth_abuse_counters SET attempts=30 WHERE scope='seat_invite' AND attempts<30",
        &[],
    )
    .await
    .unwrap();
    let (status, _) = invite_over_http(&app, &f, "budget@example.test", &f.password, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    f.db.execute(
        "DELETE FROM auth_abuse_counters WHERE scope='seat_invite'",
        &[],
    )
    .await
    .unwrap();

    // With MFA enabled the password alone is refused with the same status.
    let pending = mfa::begin_enrollment(&mut f.db, &cipher, &f.owner, &f.password)
        .await
        .unwrap();
    let recovery = mfa::confirm_enrollment(
        &mut f.db,
        &cipher,
        &f.hasher,
        &f.owner,
        &totp_now(&pending.secret_base32),
    )
    .await
    .unwrap();
    let (status, _) = invite_over_http(&app, &f, "second@example.test", &f.password, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(step_up_failures(&f).await, 0);
    // A wrong code answers the same, and spends the MFA step-up failure
    // budget on top of the SeatInvite attempt.
    let (status, _) =
        invite_over_http(&app, &f, "second@example.test", &f.password, Some("000000")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(step_up_failures(&f).await, 1);
    assert_eq!(seat_invite_attempts(&f).await, 2);
    assert_eq!(count_rows(&f.db, rows, account).await, 1);
    // A valid recovery code mints.
    let (status, _) = invite_over_http(
        &app,
        &f,
        "second@example.test",
        &f.password,
        Some(&recovery.codes[0]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(count_rows(&f.db, rows, account).await, 2);
    // Cancel is a narrowing action: session and CSRF stay sufficient.
    let listed =
        f.db.query_one(
            "SELECT id FROM seat_invitations WHERE email='second@example.test'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0);
    let (status, _) = owner_call(
        &app,
        &f,
        "DELETE",
        &format!("/auth/seats/invitations/{listed}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn inviting_owner_cannot_tell_registered_unknown_and_elsewhere_invited_addresses_apart() {
    use axum::http::StatusCode;

    let mut f = Fixture::new(false).await;
    let app = seat_app(&f, None);
    let account = f.owner.tenant.account_id();
    let other = f.other_owner("registered@example.test").await;
    // The third case: an address another account already holds an open
    // invitation for.
    let elsewhere = create_invitation(&mut f.db, &f.hasher, &other, "elsewhere@example.test")
        .await
        .unwrap();
    // The fourth case: an address that used to be an observer of another
    // account, whose removal deleted the old user.
    let former_invite = create_invitation(&mut f.db, &f.hasher, &other, "former@example.test")
        .await
        .unwrap();
    let former_credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &former_invite.token,
        &f.password,
        "former@example.test",
    )
    .await;
    let former = auth::authenticate_session(&f.db, &f.hasher, &former_credentials.token)
        .await
        .unwrap();
    assert!(
        remove_observer(&mut f.db, &other, former.user_id)
            .await
            .unwrap()
            .unwrap()
            .address_freed
    );
    let cases = [
        "registered@example.test",
        "elsewhere@example.test",
        "unknown@example.test",
        "former@example.test",
    ];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut shapes = Vec::new();
    for (index, address) in cases.iter().enumerate() {
        let attempts_before = seat_invite_attempts(&f).await;
        let (status, body) = invite_over_http(&app, &f, address, &f.password, None).await;
        // Same status, and a real single-use token in every case.
        assert_eq!(status, StatusCode::CREATED, "{address}");
        let object = body.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["email", "expires_at_ms", "id", "token"], "{address}");
        assert_eq!(body["email"], *address);
        let token = body["token"].as_str().unwrap();
        assert!(token.starts_with("zti_"));
        assert!(
            invitation_token_is_live(&f.db, &f.hasher, token)
                .await
                .unwrap(),
            "{address}"
        );
        let expires = body["expires_at_ms"].as_i64().unwrap();
        let week_ms = i64::from(INVITATION_DAYS) * 86_400_000;
        assert!((expires - now_ms - week_ms).abs() < 120_000, "{address}");
        // The same budget effect, and one more open slot, every time.
        assert_eq!(
            seat_invite_attempts(&f).await,
            attempts_before + 1,
            "{address}"
        );
        assert_eq!(
            count_rows(
                &f.db,
                "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at>now()",
                account
            )
            .await,
            index as i64 + 1
        );
        shapes.push(serde_json::json!({
            "status": status.as_u16(),
            "keys": keys,
            "token_len": token.len(),
        }));
    }
    assert_eq!(shapes[0], shapes[1]);
    assert_eq!(shapes[1], shapes[2]);
    assert_eq!(shapes[2], shapes[3]);

    // The owner's list shows each invitation identically, as open.
    let (status, listed) =
        owner_call(&app, &f, "GET", "/auth/seats", serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let invitations = listed["invitations"].as_array().unwrap();
    assert_eq!(invitations.len(), cases.len());
    for invitation in invitations {
        assert_eq!(invitation["status"], "open");
        assert!(invitation["accepted_at_ms"].is_null());
        assert!(invitation["canceled_at_ms"].is_null());
        assert!(invitation["accepted_user_id"].is_null());
    }
    // The other account's invitation is untouched by all of it.
    assert!(
        invitation_token_is_live(&f.db, &f.hasher, &elsewhere.token)
            .await
            .unwrap()
    );
    assert_eq!(
        count_rows(
            &f.db,
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND accepted_at IS NULL AND canceled_at IS NULL",
            other.tenant.account_id()
        )
        .await,
        1
    );
    // The open-invitation cap counts all four kinds alike.
    for index in cases.len() as i64..MAX_OPEN_INVITATIONS {
        let (status, _) = invite_over_http(
            &app,
            &f,
            &format!("filler-{index}@example.test"),
            &f.password,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) = invite_over_http(&app, &f, "overflow@example.test", &f.password, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn concurrent_accepts_of_one_address_by_two_accounts_have_one_winner() {
    let mut f = Fixture::new(false).await;
    let other = f.other_owner("other-owner@example.test").await;
    let mine = create_invitation(&mut f.db, &f.hasher, &f.owner, "shared@example.test")
        .await
        .unwrap();
    let theirs = create_invitation(&mut f.db, &f.hasher, &other, "shared@example.test")
        .await
        .unwrap();
    let mut accepts = Vec::new();
    for token in [mine.token.clone(), theirs.token.clone()] {
        let url = f.url.clone();
        let hasher = f.hasher.clone();
        let password = format!("synthetic-{}", Uuid::new_v4());
        accepts.push(tokio::spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            accept_invitation(&mut client, &hasher, &token, &password).await
        }));
    }
    let mut outcomes = Vec::new();
    for accept in accepts {
        outcomes.push(accept.await.unwrap());
    }
    // Exactly one token holder gets the address; the other sees a conflict,
    // never a server error, and their invitation is left unconsumed.
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AuthError::Conflict)))
            .count(),
        1,
        "{:?}",
        outcomes
            .iter()
            .map(|r| r.as_ref().err())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM users WHERE email='shared@example.test'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM seat_invitations WHERE email='shared@example.test' AND accepted_at IS NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn removal_frees_the_address_for_a_fresh_seat_and_for_registration() {
    let mut f = Fixture::new(false).await;
    let account = f.owner.tenant.account_id();
    let email = "observer@example.test";
    let first = create_invitation(&mut f.db, &f.hasher, &f.owner, email)
        .await
        .unwrap();
    let old_password = format!("synthetic-{}", Uuid::new_v4());
    let old_credentials =
        accept_and_verify(&mut f.db, &f.hasher, &first.token, &old_password, email).await;
    let old = auth::authenticate_session(&f.db, &f.hasher, &old_credentials.token)
        .await
        .unwrap();
    let key_token = crate::auth::random_token("ztk_");
    let key_prefix: String = key_token.chars().skip(4).take(12).collect();
    let key_hash = f.hasher.digest(b"api-key-v1", &key_token);
    f.db.execute(
        "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,ARRAY['devices:read'])",
        &[&Uuid::new_v4(), &account, &old.user_id, &key_prefix, &&key_hash[..]],
    )
    .await
    .unwrap();
    assert!(
        remove_observer(&mut f.db, &f.owner, old.user_id)
            .await
            .unwrap()
            .unwrap()
            .address_freed
    );

    // The removed person's password, session, and key are dead, and the old
    // user id is gone.
    assert!(matches!(
        login(&f.db, &f.hasher, email, &old_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(matches!(
        auth::authenticate_session(&f.db, &f.hasher, &old_credentials.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key_token)
            .await
            .is_err()
    );
    assert_eq!(
        count_rows(&f.db, "SELECT count(*) FROM users WHERE id=$1", old.user_id).await,
        0
    );

    // The tombstone is listed but holds no seat and no invitation slot: with
    // one seat short of the cap the owner can still invite and the invitation
    // is accepted.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert_eq!(page.seats[0].email, email);
    assert!(page.seats[0].revoked_at_ms.is_some());
    assert!(page.seats[0].address_free);
    for index in 0..MAX_ACTIVE_OBSERVERS - 1 {
        let user_id = Uuid::new_v4();
        f.db
            .execute(
                "INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,$2,password_hash,now() FROM users WHERE id=$3",
                &[&user_id, &format!("bulk-{index}@example.test"), &f.owner.user_id],
            )
            .await
            .unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&account, &user_id],
        )
        .await
        .unwrap();
    }
    let again = create_invitation(&mut f.db, &f.hasher, &f.owner, email)
        .await
        .unwrap();
    // Accepting creates a brand-new user with a new password.
    let new_password = format!("synthetic-{}", Uuid::new_v4());
    let new_credentials =
        accept_and_verify(&mut f.db, &f.hasher, &again.token, &new_password, email).await;
    let fresh = auth::authenticate_session(&f.db, &f.hasher, &new_credentials.token)
        .await
        .unwrap();
    assert_ne!(fresh.user_id, old.user_id);
    assert_eq!(fresh.role, Role::Observer);
    assert!(matches!(
        login(&f.db, &f.hasher, email, &old_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    // The seat cap is now full, so it counts live seats only, not tombstones.
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "seat-overflow@example.test").await,
        Err(AuthError::Conflict)
    ));

    // Removing the fresh seat frees the address for the person to register
    // their own owner account.
    assert!(
        remove_observer(&mut f.db, &f.owner, fresh.user_id)
            .await
            .unwrap()
            .unwrap()
            .address_freed
    );
    let own_password = format!("synthetic-{}", Uuid::new_v4());
    let signup = register(&mut f.db, &f.hasher, email, &own_password)
        .await
        .unwrap();
    assert!(
        verify_email(&mut f.db, &f.hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    let own = login(&f.db, &f.hasher, email, &own_password).await.unwrap();
    let own = auth::authenticate_session(&f.db, &f.hasher, &own.token)
        .await
        .unwrap();
    assert_eq!(own.role, Role::Owner);
    assert_ne!(own.tenant.account_id(), account);
    f.finish().await;
}

/// A row that restricts deleting the observer's membership: a pairing request
/// the observer "created". Observers cannot pair, so this is unreachable
/// through the routes; it stands in for any restricting reference.
async fn restrict_observer_deletion(f: &Fixture, user_id: Uuid) {
    f.db.execute(
        "INSERT INTO pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,expires_at) VALUES($1,$2,$3,$4,'synthetic',now()+interval '1 hour')",
        &[
            &Uuid::new_v4(),
            &f.owner.tenant.account_id(),
            &user_id,
            &vec![9u8; 32],
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn removal_is_never_blocked_and_reports_an_address_that_stays_occupied() {
    let mut f = Fixture::new(true).await;
    let email = "observer@example.test";
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, email)
        .await
        .unwrap();
    let credentials =
        accept_and_verify(&mut f.db, &f.hasher, &issued.token, &f.password, email).await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    restrict_observer_deletion(&f, observer.user_id).await;

    // The database refuses the user delete, and removal still succeeds.
    let removal = remove_observer(&mut f.db, &f.owner, observer.user_id)
        .await
        .unwrap()
        .expect("removal is never blocked");
    assert!(!removal.address_freed);
    // Every revocation committed: session, login, membership, sessions.
    assert!(matches!(
        auth::authenticate_session(&f.db, &f.hasher, &credentials.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        login(&f.db, &f.hasher, email, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    let membership_revoked: bool =
        f.db.query_one(
            "SELECT revoked_at IS NOT NULL FROM memberships WHERE user_id=$1",
            &[&observer.user_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(membership_revoked);
    assert_eq!(
        count_rows(
            &f.db,
            "SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND user_id IN (SELECT user_id FROM memberships WHERE account_id=$1 AND role='observer')",
            f.owner.tenant.account_id()
        )
        .await,
        0
    );
    // The user row survives, so the address stays occupied, and the owner's
    // list says so.
    assert_eq!(
        count_rows(
            &f.db,
            "SELECT count(*) FROM users WHERE id=$1",
            observer.user_id
        )
        .await,
        1
    );
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert!(page.seats[0].revoked_at_ms.is_some());
    assert!(!page.seats[0].address_free);
    assert_eq!(page.seats[0].user_id, Some(observer.user_id));
    // A new invitation is issued as usual but its token holder is refused at
    // acceptance, without touching the surviving user.
    let again = create_invitation(&mut f.db, &f.hasher, &f.owner, email)
        .await
        .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &again.token, &f.password).await,
        Err(AuthError::Conflict)
    ));
    // The revocation is still irreversible, and removing again is a no-op.
    assert!(
        f.db.execute(
            "UPDATE memberships SET revoked_at=NULL WHERE user_id=$1",
            &[&observer.user_id]
        )
        .await
        .is_err()
    );
    assert!(
        remove_observer(&mut f.db, &f.owner, observer.user_id)
            .await
            .unwrap()
            .is_none()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn removal_response_and_list_state_whether_the_address_is_free() {
    use axum::http::StatusCode;

    let mut f = Fixture::new(true).await;
    let app = seat_app(&f, None);
    let mut ids = Vec::new();
    for email in ["free@example.test", "occupied@example.test"] {
        let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, email)
            .await
            .unwrap();
        let credentials =
            accept_and_verify(&mut f.db, &f.hasher, &issued.token, &f.password, email).await;
        let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
            .await
            .unwrap();
        ids.push(observer.user_id);
    }
    restrict_observer_deletion(&f, ids[1]).await;

    let (status, listed) =
        owner_call(&app, &f, "GET", "/auth/seats", serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    for seat in listed["seats"].as_array().unwrap() {
        assert_eq!(seat["status"], "active");
        assert_eq!(seat["address_free"], false);
    }
    for (id, expected_free) in [(ids[0], true), (ids[1], false)] {
        let (status, body) = owner_call(
            &app,
            &f,
            "DELETE",
            &format!("/auth/seats/{id}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "removed");
        assert_eq!(body["address_free"], expected_free);
    }
    let (_, listed) = owner_call(&app, &f, "GET", "/auth/seats", serde_json::Value::Null).await;
    let seats = listed["seats"].as_array().unwrap();
    assert_eq!(seats.len(), 2);
    for seat in seats {
        assert_eq!(seat["status"], "removed");
        let free = seat["email"] == "free@example.test";
        assert_eq!(seat["address_free"], free, "{}", seat["email"]);
        assert_eq!(seat["user_id"].is_null(), free);
    }
    // An unknown seat is still a plain not-found.
    let (status, _) = owner_call(
        &app,
        &f,
        "DELETE",
        &format!("/auth/seats/{}", Uuid::new_v4()),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    f.finish().await;
}

/// The complete owner and invitee browser flow over the real HTTP routes:
/// invite, list, accept, verify, sign in, read device status, and remove.
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn observer_seat_browser_flow_over_http() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    let mut f = Fixture::new(true).await;
    let mut state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    // See `seat_app`: the process-wide hashing gate makes the production
    // two-second permit wait flaky when tests run in parallel.
    state.hash_permit_wait = std::time::Duration::from_secs(120);
    let app = axum::Router::new()
        .nest("/auth", crate::http_auth::router(state))
        .nest(
            "/observer",
            crate::http_observer::router(crate::http_observer::ObserverState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
            }),
        );
    let owner_cookie = format!(
        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
        f.owner_credentials.token, f.owner_credentials.csrf_token
    );

    let request = |method: &str, path: &str, cookie: &str, csrf: Option<&str>, body: String| {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", "https://example.test")
            .header("cookie", cookie);
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(csrf) = csrf {
            builder = builder.header("x-zrotext-csrf", csrf);
        }
        builder.body(Body::from(body)).unwrap()
    };

    // The owner invites an observer and receives the token exactly once.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/invitations",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            serde_json::json!({"email":"observer@example.test","current_password":f.password})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let issued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitation_token = issued["token"].as_str().unwrap().to_owned();
    let invitation_id: Uuid = issued["id"].as_str().unwrap().parse().unwrap();
    assert!(invitation_token.starts_with("zti_"));

    // The owner lists the outstanding invitation.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["invitations"].as_array().unwrap().len(), 1);
    assert_eq!(seats["invitations"][0]["status"], "open");

    // The invitee accepts with a fresh password; no cookies are needed.
    let observer_password = format!("synthetic-{}", Uuid::new_v4());
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/accept",
            "",
            None,
            serde_json::json!({"token":invitation_token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // A replay of the same token is rejected.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/accept",
            "",
            None,
            serde_json::json!({"token":invitation_token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The invitee verifies independently with the queued code and password.
    let mail = crate::auth::claim_verification_mail(&mut f.db, &f.hasher)
        .await
        .unwrap()
        .expect("acceptance queued a verification code");
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/verify-email",
            "",
            None,
            serde_json::json!({"token":mail.token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The verified invitee signs in and receives session cookies.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/login",
            "",
            None,
            serde_json::json!({"email":"observer@example.test","password":observer_password})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut observer_session = String::new();
    let mut observer_csrf = String::new();
    for value in response.headers().get_all(header::SET_COOKIE) {
        let cookie = value.to_str().unwrap();
        if cookie.starts_with("__Host-zrotext_session=") {
            observer_session = cookie.split(';').next().unwrap().to_owned();
        } else if cookie.starts_with("__Host-zrotext_csrf=") {
            observer_csrf = cookie.split(';').next().unwrap().to_owned();
        }
    }
    let observer_cookie = format!("{observer_session}; {observer_csrf}");
    let observer_csrf_value = observer_csrf
        .split_once('=')
        .expect("csrf cookie")
        .1
        .to_owned();

    // The observer reads its own session metadata and the device status.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/session",
            &observer_cookie,
            None,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["role"], "observer");
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/observer/devices",
            &observer_cookie,
            Some(&observer_csrf_value),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(devices["devices"].as_array().unwrap().is_empty());

    // Seat management stays owner-only, including for a signed-in observer.
    for (method, path) in [
        ("GET", "/auth/seats"),
        ("POST", "/auth/seats/invitations"),
        (
            "DELETE",
            format!("/auth/seats/invitations/{invitation_id}").as_str(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                method,
                path,
                &observer_cookie,
                Some(&observer_csrf_value),
                serde_json::json!({"email":"intruder@example.test"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }

    // The owner sees the active seat and removes it.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["seats"].as_array().unwrap().len(), 1);
    assert_eq!(seats["seats"][0]["status"], "active");
    let observer_user_id: Uuid = seats["seats"][0]["user_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/auth/seats/{observer_user_id}"),
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let removed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["address_free"], true);

    // The removed seat is dead: no sign-in, and the old session is revoked.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/login",
            "",
            None,
            serde_json::json!({"email":"observer@example.test","password":observer_password})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/observer/devices",
            &observer_cookie,
            Some(&observer_csrf_value),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The owner still manages the account after the removal.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["seats"][0]["status"], "removed");
    assert_eq!(seats["seats"][0]["address_free"], true);
    assert!(seats["seats"][0]["user_id"].is_null());
    f.finish().await;
}
