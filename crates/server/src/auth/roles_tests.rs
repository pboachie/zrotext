// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    db: Client,
    setup: Client,
    schema: String,
    url: String,
    hasher: Arc<TokenHasher>,
    owner: SessionPrincipal,
    observer: SessionPrincipal,
    observer_credentials: SessionCredentials,
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
        let schema = format!("owner_roles_{}", Uuid::new_v4().simple());
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
        super::test_schema::apply(&db).await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(37)).unwrap());
        let password = Uuid::new_v4().to_string();
        let signup = register(&mut db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let credentials = login(&db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        let owner = authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let observer_id = Uuid::new_v4();
        db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'observer@example.test',password_hash,now() FROM users WHERE id=$2", &[&observer_id, &owner.user_id]).await.unwrap();
        db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&owner.tenant.account_id(), &observer_id],
        )
        .await
        .unwrap();
        let observer_credentials = SessionCredentials {
            id: Uuid::new_v4(),
            token: random_token("zts_"),
            csrf_token: random_token("ztc_"),
        };
        let hash = hasher.digest(b"session-v1", &observer_credentials.token);
        let csrf_hash = hasher.digest(b"csrf-v1", &observer_credentials.csrf_token);
        db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')", &[&observer_credentials.id, &owner.tenant.account_id(), &observer_id, &&hash[..], &&csrf_hash[..]]).await.unwrap();
        let observer = SessionPrincipal {
            tenant: Tenant {
                account_id: owner.tenant.account_id(),
            },
            user_id: observer_id,
            session_id: observer_credentials.id,
            role: Role::Observer,
            csrf_hash,
            verification: FreshVerification::spent(),
        };
        Self {
            db,
            setup,
            schema,
            url,
            hasher,
            owner,
            observer,
            observer_credentials,
            password,
        }
    }

    async fn finish(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable role schema"]
async fn membership_roles_preserve_one_owner_and_irreversible_observer_identity() {
    let f = Fixture::new().await;
    let third = Uuid::new_v4();
    f.db.execute("INSERT INTO users(id,email,password_hash) SELECT $1,'another@example.test',password_hash FROM users WHERE id=$2", &[&third, &f.owner.user_id]).await.unwrap();
    for role in ["owner", "admin"] {
        assert!(
            f.db.execute(
                "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,$3)",
                &[&f.owner.tenant.account_id(), &third, &role]
            )
            .await
            .is_err()
        );
    }
    f.db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
        &[&f.owner.tenant.account_id(), &third],
    )
    .await
    .unwrap();
    for statement in [
        "UPDATE memberships SET role='observer' WHERE role='owner'",
        "UPDATE memberships SET role='owner' WHERE role='observer'",
        "UPDATE memberships SET revoked_at=now() WHERE role='owner'",
        "UPDATE memberships SET created_at=created_at+interval '1 second' WHERE role='observer'",
    ] {
        assert!(f.db.batch_execute(statement).await.is_err(), "{statement}");
    }
    f.db.execute(
        "UPDATE memberships SET revoked_at=now() WHERE user_id=$1",
        &[&f.observer.user_id],
    )
    .await
    .unwrap();
    assert!(
        f.db.execute(
            "UPDATE memberships SET revoked_at=NULL WHERE user_id=$1",
            &[&f.observer.user_id]
        )
        .await
        .is_err()
    );
    let other_account = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&other_account])
        .await
        .unwrap();
    assert!(
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&other_account, &third]
        )
        .await
        .is_err()
    );
    assert!(
        f.db.execute(
            "UPDATE memberships SET account_id=$1 WHERE user_id=$2",
            &[&other_account, &third]
        )
        .await
        .is_err()
    );
    // Account deletion still cascades through both roles; the trigger must not
    // turn an observer tombstone into an account-retention dependency.
    f.db.execute(
        "DELETE FROM accounts WHERE id=$1",
        &[&f.owner.tenant.account_id()],
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM memberships", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable role schema"]
async fn observers_authenticate_but_cannot_use_owner_authority_helpers() {
    let mut f = Fixture::new().await;
    // A live observer session authenticates and reports the observer role...
    let observer_principal = authenticate_session(&f.db, &f.hasher, &f.observer_credentials.token)
        .await
        .unwrap();
    assert_eq!(observer_principal.role, Role::Observer);
    assert_eq!(
        observer_principal.tenant.account_id(),
        f.owner.tenant.account_id()
    );
    // ...and the observer signs in with its own password like the owner does.
    let observer_session = login(&f.db, &f.hasher, "observer@example.test", &f.password)
        .await
        .unwrap();
    assert!(
        authenticate_session(&f.db, &f.hasher, &observer_session.token)
            .await
            .is_ok()
    );
    let owner_key = create_api_key(
        &mut f.db,
        &f.hasher,
        &f.owner,
        &[Scope::DevicesRead],
        None,
        ApiKeyLifetime::Unspecified,
    )
    .await
    .unwrap();
    assert!(
        authenticate_api_key(&f.db, &f.hasher, &owner_key.token)
            .await
            .is_ok()
    );
    assert!(
        create_api_key(
            &mut f.db,
            &f.hasher,
            &f.observer,
            &[Scope::DevicesRead],
            None,
            ApiKeyLifetime::Unspecified
        )
        .await
        .is_err()
    );
    assert!(list_api_keys(&f.db, &f.observer, None).await.is_err());
    assert!(
        revoke_api_key(&f.db, &f.observer, owner_key.id)
            .await
            .is_err()
    );
    // Self-service revocation is scoped to the caller's own sessions: the
    // owner's session is not the observer's to revoke.
    assert!(
        !revoke_session(&f.db, &f.observer, f.owner.session_id)
            .await
            .unwrap()
    );
    assert!(account::list_sessions(&f.db, &f.observer).await.is_ok());
    assert!(
        account::revoke_other_sessions(
            &mut f.db,
            None,
            &f.hasher,
            &f.observer,
            &f.password,
            None,
            true
        )
        .await
        .is_ok()
    );
    let rotated = Uuid::new_v4().to_string();
    assert!(
        account::change_password(
            &mut f.db,
            None,
            &f.hasher,
            &f.observer,
            &f.password,
            &rotated,
            None
        )
        .await
        .is_ok()
    );
    // The rotated password signs the observer in; the old one no longer does.
    assert!(
        login(&f.db, &f.hasher, "observer@example.test", &rotated)
            .await
            .is_ok()
    );
    assert!(matches!(
        login(&f.db, &f.hasher, "observer@example.test", &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(mfa::status(&f.db, &f.observer).await.is_err());
    let enrollment_hasher =
        crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(38)).unwrap();
    assert!(matches!(
        crate::enrollment::create_pairing(
            &f.db,
            &enrollment_hasher,
            &f.observer,
            "Synthetic gateway"
        )
        .await,
        Err(crate::enrollment::EnrollmentError::Unauthorized)
    ));
    // Even an externally inserted, correctly hashed scoped key is not a grant
    // to turn an observer into an API principal.
    let token = random_token("ztk_");
    let prefix = token.chars().skip(4).take(12).collect::<String>();
    let hash = f.hasher.digest(b"api-key-v1", &token);
    f.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,ARRAY['devices:read'])", &[&Uuid::new_v4(), &f.owner.tenant.account_id(), &f.observer.user_id, &prefix, &&hash[..]]).await.unwrap();
    assert!(matches!(
        authenticate_api_key(&f.db, &f.hasher, &token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        authenticate_api_key(&f.db, &f.hasher, &owner_key.token)
            .await
            .is_ok()
    );
    assert_eq!(
        list_api_keys(&f.db, &f.owner, None)
            .await
            .unwrap()
            .keys
            .len(),
        2
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable role schema"]
async fn observer_identity_is_not_reclaimed_by_owner_registration_or_recovery() {
    let mut f = Fixture::new().await;
    account::request_password_reset(&mut f.db, &f.hasher, "observer@example.test")
        .await
        .unwrap();
    assert!(
        !account::operator_reset_password(
            &mut f.db,
            "observer@example.test",
            &Uuid::new_v4().to_string()
        )
        .await
        .unwrap()
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM password_resets WHERE user_id=$1",
            &[&f.observer.user_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    f.db.execute(
        "UPDATE users SET email_verified_at=NULL,created_at=now()-interval '2 days' WHERE id=$1",
        &[&f.observer.user_id],
    )
    .await
    .unwrap();
    assert_eq!(prune_expired_pending_owners(&mut f.db).await.unwrap(), 0);
    assert!(
        register(&mut f.db, &f.hasher, "observer@example.test", &f.password)
            .await
            .is_err()
    );
    assert!(
        !request_verification_resend(&mut f.db, &f.hasher, "observer@example.test", &f.password)
            .await
            .unwrap()
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM accounts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.db.query_one(
            "SELECT role FROM memberships WHERE user_id=$1",
            &[&f.observer.user_id]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "observer"
    );
    assert!(
        login(&f.db, &f.hasher, "owner@example.test", &f.password)
            .await
            .is_ok()
    );
    // Once the pending window has fully elapsed, the unverified observer is
    // pending-user pruning: its rows cascade away and the address is free for
    // a later sign-up or a fresh invitation. Verified seats are never pruned.
    assert_eq!(
        seats::prune_expired_pending_observers(&mut f.db)
            .await
            .unwrap(),
        1
    );
    assert!(
        register(&mut f.db, &f.hasher, "observer@example.test", &f.password)
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable role schema"]
async fn observer_resets_and_mfa_challenges_do_not_admit_but_verification_does() {
    let mut f = Fixture::new().await;
    let reset = random_token("ztr_");
    let reset_hash = f.hasher.digest(b"password-reset-v1", &reset);
    f.db.execute("INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')", &[&Uuid::new_v4(), &f.owner.tenant.account_id(), &f.observer.user_id, &&reset_hash[..]]).await.unwrap();
    assert!(
        !account::reset_token_is_live(&f.db, &f.hasher, &reset)
            .await
            .unwrap()
    );
    assert!(matches!(
        account::confirm_password_reset(&mut f.db, &f.hasher, &reset, &Uuid::new_v4().to_string())
            .await,
        Err(AuthError::Unauthorized)
    ));
    f.db.execute(
        "UPDATE users SET mfa_enabled=true WHERE id=$1",
        &[&f.observer.user_id],
    )
    .await
    .unwrap();
    assert!(
        mfa::begin_login_challenge(
            &f.db,
            &f.hasher,
            f.owner.tenant.account_id(),
            f.observer.user_id,
            &f.password
        )
        .await
        .is_err()
    );
    let challenge = random_token("ztm_");
    let hash = f.hasher.digest(b"mfa-login-challenge-v1", &challenge);
    f.db.execute("INSERT INTO owner_mfa_login_challenges(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '5 minutes')", &[&Uuid::new_v4(), &f.owner.tenant.account_id(), &f.observer.user_id, &&hash[..]]).await.unwrap();
    assert!(matches!(
        mfa::complete_login(&mut f.db, None, &f.hasher, &challenge, "000000").await,
        Err(AuthError::Unauthorized)
    ));
    // An observer carrying stray MFA material cannot sign in at all.
    assert!(matches!(
        login(&f.db, &f.hasher, "observer@example.test", &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    f.db.execute(
        "UPDATE users SET mfa_enabled=false,email_verified_at=NULL WHERE id=$1",
        &[&f.observer.user_id],
    )
    .await
    .unwrap();
    let id = Uuid::new_v4();
    let token = verification_token_for_id(&f.hasher, id);
    let hash = f.hasher.digest(b"email-verification-v1", &token);
    f.db.execute("INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')", &[&id, &f.owner.tenant.account_id(), &f.observer.user_id, &&hash[..]]).await.unwrap();
    f.db.execute(
        "INSERT INTO verification_mail_outbox(verification_id) VALUES($1)",
        &[&id],
    )
    .await
    .unwrap();
    assert!(
        verification_token_is_live(&f.db, &f.hasher, &token)
            .await
            .unwrap()
    );
    // Observers verify their own address with their own password-bound code.
    assert!(verify_email(&mut f.db, &f.hasher, &token).await.unwrap());
    // Consumption canceled the queued mail, so nothing is left to claim.
    assert!(
        claim_verification_mail(&mut f.db, &f.hasher)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM sessions WHERE user_id=$1",
            &[&f.observer.user_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert!(
        login(&f.db, &f.hasher, "observer@example.test", &f.password)
            .await
            .is_ok()
    );
    assert!(
        login(&f.db, &f.hasher, "owner@example.test", &f.password)
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable role schema"]
async fn observer_http_requests_fail_closed_on_existing_owner_routes() {
    let f = Fixture::new().await;
    let cipher = Arc::new(mfa::MfaCipher::new(crate::test_keys::key(39)).unwrap());
    let state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_mfa_cipher(cipher)
    .with_mfa_enrollment_enabled()
    .with_sms_line_activation_enabled();
    let app = axum::Router::new()
        .nest("/auth", crate::http_auth::router(state.clone()))
        .nest(
            "/billing",
            crate::billing::owner::status_router(state.clone()).merge(
                crate::billing::sessions::router(
                    crate::billing::sessions::SessionState::new(
                        state,
                        format!("sk_test_{}", Uuid::new_v4().simple()),
                        "price_synthetic".into(),
                    )
                    .unwrap(),
                ),
            ),
        )
        .merge(crate::http_owner_messages::router(
            crate::http_owner_messages::OwnerMessagesState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
                canonical_origin: "https://example.test".into(),
            },
        ))
        .merge(crate::http_owner_review::router(
            crate::http_owner_review::OwnerReviewState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
                canonical_origin: "https://example.test".into(),
            },
        ))
        .merge(crate::http_webhooks::router(
            crate::http_webhooks::WebhookHttpState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
                canonical_origin: "https://example.test".into(),
                vault: Arc::new(
                    crate::webhook_worker::WebhookSecretVault::new(
                        1,
                        zeroize::Zeroizing::new(crate::test_keys::key(40)),
                    )
                    .unwrap(),
                ),
            },
        ))
        .nest(
            "/enrollment",
            crate::http_enrollment::router(crate::http_enrollment::EnrollmentHttpState::new(
                f.url.clone(),
                f.hasher.clone(),
                Arc::new(
                    crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(38)).unwrap(),
                ),
                "https://example.test".into(),
            )),
        )
        .merge(crate::http_owner_export::router(
            crate::http_owner_export::OwnerExportState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
                canonical_origin: "https://example.test".into(),
                contacts_vault: None,
            },
        ));
    let id = Uuid::new_v4();
    use p256::elliptic_curve::Generate;
    let signing_key = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
    let signing_point = base64::engine::general_purpose::STANDARD
        .encode(signing_key.verifying_key().to_sec1_point(false).as_bytes());
    let password_body = serde_json::json!({"current_password":f.password,"password":f.password,"new_password":Uuid::new_v4().to_string(),"code":"000000","scopes":["devices:read"],"display_name":"Synthetic gateway"}).to_string();
    for (method, path) in [
        ("GET", "/auth/api-keys".to_owned()),
        ("GET", "/auth/mfa".to_owned()),
        ("POST", "/auth/api-keys".to_owned()),
        ("POST", "/auth/mfa/enroll".to_owned()),
        ("POST", "/auth/mfa/confirm".to_owned()),
        ("POST", "/auth/mfa/disable".to_owned()),
        ("DELETE", format!("/auth/api-keys/{id}")),
        ("GET", "/enrollment/devices".to_owned()),
        ("POST", "/enrollment/pairings".to_owned()),
        ("GET", format!("/enrollment/pairings/{id}")),
        ("POST", format!("/enrollment/pairings/{id}/cancel")),
        ("POST", format!("/enrollment/pairings/{id}/approve")),
        ("DELETE", format!("/enrollment/devices/{id}")),
        ("GET", "/v1/owner/export".to_owned()),
        ("GET", "/v1/owner/messages".to_owned()),
        ("GET", "/v1/owner/opt-out-review".to_owned()),
        ("GET", "/v1/owner/opt-out-holds".to_owned()),
        ("GET", "/billing/status".to_owned()),
        ("GET", "/v1/webhooks".to_owned()),
        ("GET", format!("/v1/inbound/messages/{id}/events")),
        ("GET", format!("/v1/webhooks/{id}/deliveries")),
        ("POST", format!("/v1/webhooks/{id}/enable")),
        ("POST", format!("/v1/webhooks/{id}/disable")),
        ("POST", format!("/v1/webhooks/{id}/rotate")),
        ("POST", format!("/v1/webhooks/{id}/deliveries/{id}/replay")),
        ("POST", "/v1/webhooks".to_owned()),
        ("POST", "/v1/owner/opt-out-holds".to_owned()),
        ("POST", "/v1/owner/opt-out-review/decisions".to_owned()),
        ("GET", "/auth/sms-line-owner-keys".to_owned()),
        (
            "DELETE",
            format!(
                "/auth/sms-line-owner-keys/{}",
                URL_SAFE_NO_PAD.encode([1_u8; 32])
            ),
        ),
        ("POST", "/auth/sms-line-owner-keys/challenge".to_owned()),
        ("POST", "/auth/sms-line-owner-keys".to_owned()),
        ("POST", "/billing/checkout".to_owned()),
        ("POST", "/billing/portal".to_owned()),
        ("GET", "/auth/sms-lines".to_owned()),
        ("POST", format!("/auth/sms-lines/{id}/activations")),
        ("GET", format!("/auth/sms-lines/{id}/activations/{id}")),
        (
            "POST",
            format!("/auth/sms-lines/{id}/activations/{id}/approve"),
        ),
        // Seat management is owner authority: listing, inviting, canceling,
        // and removing all refuse an observer session.
        ("GET", "/auth/seats".to_owned()),
        ("POST", "/auth/seats/invitations".to_owned()),
        ("DELETE", format!("/auth/seats/invitations/{id}")),
        ("DELETE", format!("/auth/seats/{id}")),
    ] {
        let body = if path == "/enrollment/pairings" {
            serde_json::json!({"display_name":"Synthetic gateway"}).to_string()
        } else if path.starts_with("/enrollment/") && path.ends_with("/approve") {
            serde_json::json!({"comparison_code":"123456","key_fingerprint":"ab".repeat(32)})
                .to_string()
        } else if path == "/v1/webhooks" {
            serde_json::json!({"callback_url":"https://example.test/hook"}).to_string()
        } else if path == "/v1/owner/opt-out-holds" {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            serde_json::json!({"recipient_e164":"+15551234567","channel":"email","reason":"opt_out","reported_at_ms":now}).to_string()
        } else if path.ends_with("/decisions") {
            serde_json::json!({"review_event_id":id,"decision":"not_opt_out"}).to_string()
        } else if path == "/auth/sms-line-owner-keys/challenge" {
            serde_json::json!({"signing_key_sec1_b64":signing_point}).to_string()
        } else if path == "/auth/sms-line-owner-keys" {
            serde_json::json!({"challenge_id":id,"nonce_b64":base64::engine::general_purpose::STANDARD.encode([0_u8;32]),"signature_der_b64":base64::engine::general_purpose::STANDARD.encode([0_u8;8]),"mfa_code":"000000"}).to_string()
        } else if path.starts_with("/auth/sms-line-owner-keys/") {
            serde_json::json!({"mfa_code":"000000"}).to_string()
        } else if path.starts_with("/auth/sms-lines/") && path.ends_with("/activations") {
            serde_json::json!({"device_id":id}).to_string()
        } else if path.starts_with("/auth/sms-lines/") && path.ends_with("/approve") {
            serde_json::json!({"owner_signature_der_b64":base64::engine::general_purpose::STANDARD.encode([0_u8; 8])}).to_string()
        } else if path.starts_with("/billing/") {
            String::new()
        } else if path == "/auth/seats/invitations" {
            serde_json::json!({"email":"invitee@example.test"}).to_string()
        } else {
            password_body.clone()
        };
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .header("origin", "https://example.test")
            .header("content-type", "application/json")
            .header(
                "cookie",
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    f.observer_credentials.token, f.observer_credentials.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &f.observer_credentials.csrf_token)
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
    f.finish().await;
}
