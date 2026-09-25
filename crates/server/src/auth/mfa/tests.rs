
use super::*;
use crate::auth::{self, TokenHasher};
use tokio_postgres::NoTls;

#[test]
fn encrypted_secret_is_bound_to_owner_identity() {
    let mut key = vec![0u8; 32];
    rng().fill_bytes(&mut key);
    let cipher = MfaCipher::new(key).unwrap();
    let account = Uuid::new_v4();
    let user = Uuid::new_v4();
    let mut secret = [0u8; 20];
    rng().fill_bytes(&mut secret);
    let (nonce, ciphertext) = cipher.seal(account, user, &secret).unwrap();
    assert!(cipher.open(account, user, &nonce, &ciphertext).is_ok());
    assert!(
        cipher
            .open(Uuid::new_v4(), user, &nonce, &ciphertext)
            .is_err()
    );
    assert!(
        cipher
            .open(account, Uuid::new_v4(), &nonce, &ciphertext)
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_enrollment_challenge_replay_recovery_and_disable() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("mfa_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let cipher = MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let password_a = Uuid::new_v4().to_string();
    let password_b = Uuid::new_v4().to_string();
    let wrong_password = Uuid::new_v4().to_string();
    let a = auth::register(&mut client, &hasher, "a@example.test", &password_a)
        .await
        .unwrap();
    let b = auth::register(&mut client, &hasher, "b@example.test", &password_b)
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/013_owner_mfa.sql"
        ))
        .await
        .unwrap();
    let flags: i64 = client
        .query_one("SELECT count(*) FROM users WHERE mfa_enabled", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(flags, 0);
    assert!(validate_runtime_key(&client, None, false).await.is_ok());
    assert!(
        auth::verify_email(&mut client, &hasher, &a.verification_token)
            .await
            .unwrap()
    );
    assert!(
        auth::verify_email(&mut client, &hasher, &b.verification_token)
            .await
            .unwrap()
    );
    let sa = auth::login(&client, &hasher, "a@example.test", &password_a)
        .await
        .unwrap();
    let sb = auth::login(&client, &hasher, "b@example.test", &password_b)
        .await
        .unwrap();
    let pa = auth::authenticate_session(&client, &hasher, &sa.token)
        .await
        .unwrap();
    let pb = auth::authenticate_session(&client, &hasher, &sb.token)
        .await
        .unwrap();
    assert!(matches!(
        begin_enrollment(&mut client, &cipher, &pa, &wrong_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    let secondary = auth::login(&client, &hasher, "a@example.test", &password_a)
        .await
        .unwrap();
    let secondary_owner = auth::authenticate_session(&client, &hasher, &secondary.token)
        .await
        .unwrap();
    let pending = begin_enrollment(&mut client, &cipher, &secondary_owner, &password_a)
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
        ))
        .await
        .unwrap();
    let backfilled: (i32, bool) = {
        let row = client
                .query_one(
                    "SELECT failed_attempts,failed_window_started_at IS NOT NULL FROM owner_mfa WHERE account_id=$1",
                    &[&a.account_id],
                )
                .await
                .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(backfilled, (0, true));
    let pending_secret = Secret::try_from_base32(&pending.secret_base32).unwrap();
    let pending_code = Builder::new()
        .with_secret(pending_secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    assert!(
        auth::revoke_session(&client, &pa, secondary.id)
            .await
            .unwrap()
    );
    assert!(matches!(
        confirm_enrollment(
            &mut client,
            &cipher,
            &hasher,
            &secondary_owner,
            &pending_code
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    let ea = begin_enrollment(&mut client, &cipher, &pa, &password_a)
        .await
        .unwrap();
    assert!(ea.provisioning_uri.starts_with("otpauth://totp/"));
    let a_secret = Secret::try_from_base32(&ea.secret_base32).unwrap();
    let a_totp = Builder::new().with_secret(a_secret).build().unwrap();
    let now = unix_seconds().unwrap();
    let confirm_code = a_totp.generate(now).to_string();
    assert!(matches!(
        confirm_enrollment(&mut client, &cipher, &hasher, &pb, &confirm_code).await,
        Err(AuthError::Forbidden)
    ));
    let recovery = confirm_enrollment(&mut client, &cipher, &hasher, &pa, &confirm_code)
        .await
        .unwrap();
    assert_eq!(recovery.codes.len(), RECOVERY_COUNT);
    assert!(matches!(
        confirm_enrollment(&mut client, &cipher, &hasher, &pa, &confirm_code).await,
        Err(AuthError::Forbidden)
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE account_id=$1 AND revoked_at IS NULL",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert!(matches!(
        auth::login(&client, &hasher, "a@example.test", &password_a).await,
        Err(AuthError::MfaRequired { .. })
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    let challenge = begin_login_challenge(&client, &hasher, a.account_id, a.user_id, &password_a)
        .await
        .unwrap();
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &challenge,
            &confirm_code
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    let a_next_code = a_totp.generate(((now / 30) + 1) * 30).to_string();
    let session = complete_login(
        &mut client,
        Some(&cipher),
        &hasher,
        &challenge,
        &a_next_code,
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_session(&client, &hasher, &session.token)
            .await
            .is_ok()
    );
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &challenge,
            &a_next_code
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    let b_enrollment = begin_enrollment(&mut client, &cipher, &pb, &password_b)
        .await
        .unwrap();
    let b_secret = Secret::try_from_base32(&b_enrollment.secret_base32).unwrap();
    let b_code = Builder::new()
        .with_secret(b_secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let _ = confirm_enrollment(&mut client, &cipher, &hasher, &pb, &b_code)
        .await
        .unwrap();
    assert!(
        validate_runtime_key(&client, Some(&cipher), false)
            .await
            .is_ok()
    );
    assert!(matches!(
        validate_runtime_key(&client, None, false).await,
        Err(AuthError::Crypto)
    ));
    let mut wrong_key = vec![0u8; 32];
    rng().fill_bytes(&mut wrong_key);
    let wrong_cipher = MfaCipher::new(wrong_key).unwrap();
    assert!(matches!(
        validate_runtime_key(&client, Some(&wrong_cipher), false).await,
        Err(AuthError::Crypto)
    ));
    assert!(validate_runtime_key(&client, None, true).await.is_ok());
    let b_challenge = begin_login_challenge(&client, &hasher, b.account_id, b.user_id, &password_b)
        .await
        .unwrap();
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &b_challenge,
            &recovery.codes[0]
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    let b_sessions: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            &[&b.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(b_sessions, 1);
    let recovery_challenge =
        begin_login_challenge(&client, &hasher, a.account_id, a.user_id, &password_a)
            .await
            .unwrap();
    let recovered = complete_login(
        &mut client,
        None,
        &hasher,
        &recovery_challenge,
        &recovery.codes[0],
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_session(&client, &hasher, &recovered.token)
            .await
            .is_ok()
    );
    let replay_challenge =
        begin_login_challenge(&client, &hasher, a.account_id, a.user_id, &password_a)
            .await
            .unwrap();
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &replay_challenge,
            &recovery.codes[0]
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    for _ in 0..3 {
        let _ = complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &replay_challenge,
            &recovery.codes[0],
        )
        .await;
    }
    let fresh_challenge =
        begin_login_challenge(&client, &hasher, a.account_id, a.user_id, &password_a)
            .await
            .unwrap();
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &fresh_challenge,
            &recovery.codes[1]
        )
        .await,
        Err(AuthError::RateLimited)
    ));
    let recovered_principal = auth::authenticate_session(&client, &hasher, &recovered.token)
        .await
        .unwrap();
    assert!(matches!(
        disable(
            &mut client,
            Some(&cipher),
            &hasher,
            &recovered_principal,
            &wrong_password,
            &recovery.codes[1]
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(matches!(
        disable(
            &mut client,
            None,
            &hasher,
            &recovered_principal,
            &password_a,
            &recovery.codes[1]
        )
        .await,
        Err(AuthError::RateLimited)
    ));
    client
            .execute(
                "UPDATE owner_mfa SET failed_window_started_at=now()-interval '16 minutes' WHERE account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap();
    for _ in 0..5 {
        assert!(matches!(
            disable(
                &mut client,
                None,
                &hasher,
                &recovered_principal,
                &password_a,
                "zrc_AAAAAAAAAAAAAAAAAAAAAA"
            )
            .await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        complete_login(
            &mut client,
            None,
            &hasher,
            &fresh_challenge,
            &recovery.codes[1]
        )
        .await,
        Err(AuthError::RateLimited)
    ));
    client
            .execute(
                "UPDATE owner_mfa SET failed_window_started_at=now()-interval '16 minutes' WHERE account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap();
    disable(
        &mut client,
        None,
        &hasher,
        &recovered_principal,
        &password_a,
        &recovery.codes[1],
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_session(&client, &hasher, &session.token)
            .await
            .is_err()
    );
    assert!(matches!(
        complete_login(
            &mut client,
            Some(&cipher),
            &hasher,
            &replay_challenge,
            &recovery.codes[2]
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    let password_only = auth::login(&client, &hasher, "a@example.test", &password_a)
        .await
        .unwrap();
    assert!(
        auth::authenticate_session(&client, &hasher, &password_only.token)
            .await
            .is_ok()
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
