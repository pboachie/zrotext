
use super::*;

#[tokio::test]
async fn postgres_operator_bootstrap_creates_one_verified_owner_under_concurrency() {
    let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
        return;
    };
    let (setup, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("bootstrap_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut first, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (mut second, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
    ] {
        first.batch_execute(sql).await.unwrap();
    }
    let first_password = Uuid::new_v4().to_string();
    let second_password = Uuid::new_v4().to_string();
    let third_password = Uuid::new_v4().to_string();
    let (a, b) = tokio::join!(
        bootstrap_owner(&mut first, "first@example.test", &first_password),
        bootstrap_owner(&mut second, "second@example.test", &second_password),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a, b);
    assert!(
        !bootstrap_owner(&mut first, "third@example.test", &third_password)
            .await
            .unwrap()
    );
    for table in ["accounts", "users", "memberships"] {
        let count: i64 = first
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "{table}");
    }
    assert_eq!(
        first
            .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
    );
    assert!(
        first
            .query_one("SELECT email_verified_at IS NOT NULL FROM users", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let (email, password) = if a {
        ("first@example.test", first_password.as_str())
    } else {
        ("second@example.test", second_password.as_str())
    };
    let hasher = TokenHasher::new(crate::test_keys::key(37)).unwrap();
    assert!(login(&first, &hasher, email, password).await.is_ok());
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

// Tokio's default test runtime stays on one thread; separate tests cannot
// satisfy this counter through concurrent password checks. Capture its Arc
// before offloading so the blocking worker increments the originating test.
thread_local! {
    pub(super) static PASSWORD_VERIFICATIONS: std::sync::Arc<std::sync::atomic::AtomicUsize> = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
}

#[test]
fn tenant_context_rejects_cross_account_ids() {
    let owner = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    let tenant = Tenant { account_id: owner };
    assert!(tenant.require_account(owner).is_ok());
    assert!(matches!(
        tenant.require_account(foreign),
        Err(AuthError::Forbidden)
    ));
}

#[test]
fn api_scopes_and_device_restriction_fail_closed() {
    let permitted = Uuid::new_v4();
    let key = ApiPrincipal {
        tenant: Tenant {
            account_id: Uuid::new_v4(),
        },
        key_id: Uuid::new_v4(),
        scopes: vec![Scope::MessagesSend],
        bound_device_id: Some(permitted),
    };
    assert!(key.require(Scope::MessagesSend, Some(permitted)).is_ok());
    assert!(key.require(Scope::MessagesRead, Some(permitted)).is_err());
    assert!(
        key.require(Scope::MessagesSend, Some(Uuid::new_v4()))
            .is_err()
    );
    assert!(key.require(Scope::MessagesSend, None).is_err());
}

#[test]
fn token_domains_are_separate_and_csrf_needs_origin() {
    let hasher = TokenHasher::new(crate::test_keys::key(7)).unwrap();
    let token = random_token("ztc_");
    let principal = SessionPrincipal {
        tenant: Tenant {
            account_id: Uuid::new_v4(),
        },
        user_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        csrf_hash: hasher.digest(b"csrf-v1", &token),
    };
    assert_ne!(
        hasher.digest(b"csrf-v1", &token),
        hasher.digest(b"session-v1", &token)
    );
    assert!(
        principal
            .require_csrf(
                &hasher,
                "https://example.test",
                "https://example.test",
                &token,
                &token
            )
            .is_ok()
    );
    assert!(
        principal
            .require_csrf(
                &hasher,
                "https://evil.test",
                "https://example.test",
                &token,
                &token
            )
            .is_err()
    );
    assert!(
        principal
            .require_csrf(
                &hasher,
                "https://example.test",
                "https://example.test",
                &token,
                "wrong"
            )
            .is_err()
    );
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_tenant_revocation_and_scope_contract() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("auth_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/002_auth.sql"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/005_verification_outbox.sql"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/013_owner_mfa.sql"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
        ))
        .await
        .unwrap();
    let hasher = TokenHasher::new(crate::test_keys::key(11)).unwrap();
    let a_password = Uuid::new_v4().to_string();
    let b_password = Uuid::new_v4().to_string();
    let a = register(&mut client, &hasher, "A@example.test", &a_password)
        .await
        .unwrap();
    let b = register(&mut client, &hasher, "b@example.test", &b_password)
        .await
        .unwrap();
    for _ in 0..2 {
        let password = Uuid::new_v4().to_string();
        let before =
            PASSWORD_VERIFICATIONS.with(|count| count.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(
            login(&client, &hasher, "unknown@example.test", &password).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert_eq!(
            PASSWORD_VERIFICATIONS.with(|count| count.load(std::sync::atomic::Ordering::SeqCst)),
            before + 1
        );
    }
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(matches!(
        login(&client, &hasher, "a@example.test", &a_password).await,
        Err(AuthError::EmailNotVerified)
    ));
    assert!(
        verify_email(&mut client, &hasher, &a.verification_token)
            .await
            .unwrap()
    );
    assert!(
        !verify_email(&mut client, &hasher, &a.verification_token)
            .await
            .unwrap()
    );
    assert!(
        verify_email(&mut client, &hasher, &b.verification_token)
            .await
            .unwrap()
    );
    let sa = login(&client, &hasher, "a@example.test", &a_password)
        .await
        .unwrap();
    let sb = login(&client, &hasher, "b@example.test", &b_password)
        .await
        .unwrap();
    let pa = authenticate_session(&client, &hasher, &sa.token)
        .await
        .unwrap();
    let pb = authenticate_session(&client, &hasher, &sb.token)
        .await
        .unwrap();
    assert!(pa.tenant.require_account(b.account_id).is_err());
    assert!(!revoke_session(&client, &pb, sa.id).await.unwrap());
    let bound_device = Uuid::new_v4();
    let key = create_api_key(
        &mut client,
        &hasher,
        &pa,
        &[Scope::MessagesSend],
        Some(bound_device),
        Some(30),
    )
    .await
    .unwrap();
    let api = authenticate_api_key(&client, &hasher, &key.token)
        .await
        .unwrap();
    assert_eq!(api.tenant.account_id(), a.account_id);
    assert!(api.require(Scope::MessagesSend, Some(bound_device)).is_ok());
    assert!(
        api.require(Scope::MessagesSend, Some(Uuid::new_v4()))
            .is_err()
    );
    assert!(api.require(Scope::MessagesRead, None).is_err());
    assert!(!revoke_api_key(&client, &pb, key.id).await.unwrap());
    assert!(revoke_session(&client, &pa, sa.id).await.unwrap());
    assert!(matches!(
        authenticate_session(&client, &hasher, &sa.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        create_api_key(&mut client, &hasher, &pa, &[Scope::BillingRead], None, None).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(revoke_api_key(&client, &pa, key.id).await.unwrap());
    assert!(matches!(
        authenticate_api_key(&client, &hasher, &key.token).await,
        Err(AuthError::Unauthorized)
    ));
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

fn is_unique_violation(result: &Result<Signup, AuthError>) -> bool {
    matches!(result, Err(AuthError::Database(error))
            if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION))
}

async fn pending_signup_schema(base_url: &str, schema: &str) -> (Client, Client, String) {
    let (setup, connection) = tokio_postgres::connect(base_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    (setup, client, url)
}

/// Moves an owner's sign-up past the pending window. Its codes are left
/// live on purpose: the window, not only the code expiry, must bind.
async fn age_signup(client: &Client, user_id: Uuid) {
    client
        .execute(
            "UPDATE users SET created_at=now()-interval '25 hours' WHERE id=$1",
            &[&user_id],
        )
        .await
        .unwrap();
}

async fn count(client: &Client, sql: &str, id: Uuid) -> i64 {
    client.query_one(sql, &[&id]).await.unwrap().get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_expired_unverified_signup_releases_its_email() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("pending_signup_test_{}", Uuid::new_v4().simple());
    let (setup, mut client, _) = pending_signup_schema(&base_url, &schema).await;
    let hasher = TokenHasher::new(crate::test_keys::key(13)).unwrap();
    let first_password = Uuid::new_v4().to_string();
    let owner_password = Uuid::new_v4().to_string();

    // A third party registers the address first and never verifies it.
    let first = register(
        &mut client,
        &hasher,
        "claimed@example.test",
        &first_password,
    )
    .await
    .unwrap();
    // Within the pending window the address stays reserved.
    assert!(is_unique_violation(
        &register(
            &mut client,
            &hasher,
            "Claimed@example.test",
            &owner_password
        )
        .await
    ));
    // State tied to the pending record must disappear with it.
    client
            .execute(
                "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$4,now()+interval '1 day')",
                &[&Uuid::new_v4(), &first.account_id, &first.user_id, &&[7u8; 32][..]],
            )
            .await
            .unwrap();

    age_signup(&client, first.user_id).await;
    // After the window the stale record can neither be verified, nor
    // mailed, nor resent, even though its code row has not yet expired.
    assert!(
        !verification_token_is_live(&client, &hasher, &first.verification_token)
            .await
            .unwrap()
    );
    assert!(
        claim_verification_mail(&mut client, &hasher)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !request_verification_resend(
            &mut client,
            &hasher,
            "claimed@example.test",
            &first_password
        )
        .await
        .unwrap()
    );

    // The real owner can now sign up; the stale record is replaced.
    let owner = register(
        &mut client,
        &hasher,
        "claimed@example.test",
        &owner_password,
    )
    .await
    .unwrap();
    assert_ne!(owner.account_id, first.account_id);
    for sql in [
        "SELECT count(*) FROM users WHERE id=$1",
        "SELECT count(*) FROM memberships WHERE user_id=$1",
        "SELECT count(*) FROM email_verifications WHERE user_id=$1",
        "SELECT count(*) FROM sessions WHERE user_id=$1",
    ] {
        assert_eq!(count(&client, sql, first.user_id).await, 0, "{sql}");
    }
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM accounts WHERE id=$1",
            first.account_id
        )
        .await,
        0
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM verification_mail_outbox", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // The stale code is dead; only the new owner's code verifies.
    assert!(
        !verify_email(&mut client, &hasher, &first.verification_token)
            .await
            .unwrap()
    );
    let mail = claim_verification_mail(&mut client, &hasher)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mail.token, owner.verification_token);
    assert!(
        verify_email(&mut client, &hasher, &mail.token)
            .await
            .unwrap()
    );
    assert!(matches!(
        login(&client, &hasher, "claimed@example.test", &first_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    let session = login(&client, &hasher, "claimed@example.test", &owner_password)
        .await
        .unwrap();

    // A verified owner is never replaced, however old the sign-up.
    age_signup(&client, owner.user_id).await;
    assert!(is_unique_violation(
        &register(
            &mut client,
            &hasher,
            "claimed@example.test",
            &first_password
        )
        .await
    ));
    assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 0);
    let principal = authenticate_session(&client, &hasher, &session.token)
        .await
        .unwrap();
    assert_eq!(principal.tenant.account_id(), owner.account_id);
    assert!(
        login(&client, &hasher, "claimed@example.test", &owner_password)
            .await
            .is_ok()
    );

    // An operator-disabled pending account is left for the operator.
    let disabled = register(
        &mut client,
        &hasher,
        "disabled@example.test",
        &first_password,
    )
    .await
    .unwrap();
    age_signup(&client, disabled.user_id).await;
    client
        .execute(
            "UPDATE accounts SET disabled_at=now() WHERE id=$1",
            &[&disabled.account_id],
        )
        .await
        .unwrap();
    assert!(is_unique_violation(
        &register(
            &mut client,
            &hasher,
            "disabled@example.test",
            &owner_password
        )
        .await
    ));
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_concurrent_signups_replace_a_stale_record_once() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("pending_race_test_{}", Uuid::new_v4().simple());
    let (setup, mut client, url) = pending_signup_schema(&base_url, &schema).await;
    let hasher = TokenHasher::new(crate::test_keys::key(17)).unwrap();
    let stale = register(
        &mut client,
        &hasher,
        "race@example.test",
        &Uuid::new_v4().to_string(),
    )
    .await
    .unwrap();
    age_signup(&client, stale.user_id).await;
    let (mut a, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (mut b, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let a_password = Uuid::new_v4().to_string();
    let b_password = Uuid::new_v4().to_string();
    let (ra, rb) = tokio::join!(
        register(&mut a, &hasher, "race@example.test", &a_password),
        register(&mut b, &hasher, "race@example.test", &b_password),
    );
    let winners = [&ra, &rb].iter().filter(|result| result.is_ok()).count();
    assert_eq!(winners, 1);
    assert!(is_unique_violation(&ra) || is_unique_violation(&rb));
    let row = client
            .query_one(
                "SELECT count(*),(SELECT count(*) FROM accounts),(SELECT count(*) FROM email_verifications) FROM users",
                &[],
            )
            .await
            .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert!(
        !verify_email(&mut client, &hasher, &stale.verification_token)
            .await
            .unwrap()
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_prune_removes_only_expired_unverified_owners() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let schema = format!("pending_prune_test_{}", Uuid::new_v4().simple());
    let (setup, mut client, _) = pending_signup_schema(&base_url, &schema).await;
    let hasher = TokenHasher::new(crate::test_keys::key(19)).unwrap();
    let password = Uuid::new_v4().to_string();
    let stale = register(&mut client, &hasher, "stale@example.test", &password)
        .await
        .unwrap();
    let fresh = register(&mut client, &hasher, "fresh@example.test", &password)
        .await
        .unwrap();
    let verified = register(&mut client, &hasher, "verified@example.test", &password)
        .await
        .unwrap();
    assert!(
        verify_email(&mut client, &hasher, &verified.verification_token)
            .await
            .unwrap()
    );
    age_signup(&client, stale.user_id).await;
    age_signup(&client, verified.user_id).await;
    assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 1);
    assert_eq!(prune_expired_pending_owners(&mut client).await.unwrap(), 0);
    let users = "SELECT count(*) FROM users WHERE id=$1";
    assert_eq!(count(&client, users, stale.user_id).await, 0);
    assert_eq!(count(&client, users, fresh.user_id).await, 1);
    assert_eq!(count(&client, users, verified.user_id).await, 1);
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM accounts WHERE id=$1",
            stale.account_id
        )
        .await,
        0
    );
    assert!(
        !verify_email(&mut client, &hasher, &stale.verification_token)
            .await
            .unwrap()
    );
    assert!(
        verify_email(&mut client, &hasher, &fresh.verification_token)
            .await
            .unwrap()
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
