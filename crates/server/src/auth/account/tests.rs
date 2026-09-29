use super::*;
use crate::auth::{self, Scope, TokenHasher};
use std::sync::Arc;
use tokio_postgres::NoTls;
use totp_rs::{Builder, Secret};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn email_reset_preserves_mfa_and_revokes_owner_credentials() {
    assert_reset_preserves_mfa(ResetPath::Email).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn operator_reset_preserves_mfa_and_revokes_owner_credentials() {
    assert_reset_preserves_mfa(ResetPath::Operator).await;
}

enum ResetPath {
    Email,
    Operator,
}

async fn mfa_state(db: &Client, user_id: Uuid) -> (bool, String, Vec<(Vec<u8>, bool)>) {
    let owner = db.query_one(
        "SELECT u.mfa_enabled,row_to_json(m)::text FROM users u JOIN owner_mfa m ON m.user_id=u.id WHERE u.id=$1",
        &[&user_id],
    ).await.unwrap();
    let codes = db.query(
        "SELECT code_hash,used_at IS NOT NULL FROM owner_mfa_recovery_codes WHERE user_id=$1 ORDER BY code_hash",
        &[&user_id],
    ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1))).collect();
    (owner.get(0), owner.get(1), codes)
}

async fn assert_reset_preserves_mfa(path: ResetPath) {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("mfa_reset_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let old_password = Uuid::new_v4().to_string();
    let new_password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let first = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &first.token)
        .await
        .unwrap();
    let pending = mfa::begin_enrollment(&mut db, &cipher, &principal, &old_password)
        .await
        .unwrap();
    let code = Builder::new()
        .with_secret(Secret::try_from_base32(&pending.secret_base32).unwrap())
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
        .await
        .unwrap();

    // Enrollment revokes other sessions, so create the second session through
    // MFA before testing that a reset revokes both live sessions.
    let challenge =
        mfa::begin_login_challenge(&db, &hasher, owner.account_id, owner.user_id, &old_password)
            .await
            .unwrap();
    let second = mfa::complete_login(
        &mut db,
        Some(&cipher),
        &hasher,
        &challenge,
        &recovery.codes[0],
    )
    .await
    .unwrap();
    let key = auth::create_api_key(
        &mut db,
        &hasher,
        &principal,
        &[Scope::MessagesRead],
        None,
        auth::ApiKeyLifetime::Unspecified,
    )
    .await
    .unwrap();
    let stale_challenge =
        mfa::begin_login_challenge(&db, &hasher, owner.account_id, owner.user_id, &old_password)
            .await
            .unwrap();
    for token in [&first.token, &second.token] {
        assert!(
            auth::authenticate_session(&db, &hasher, token)
                .await
                .is_ok()
        );
    }
    assert!(
        auth::authenticate_api_key(&db, &hasher, &key.token)
            .await
            .is_ok()
    );
    assert!(
        mfa::login_challenge_is_live(&db, &hasher, &stale_challenge)
            .await
            .unwrap()
    );
    let before = mfa_state(&db, owner.user_id).await;
    assert!(before.0);

    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
    // Claim the synthetic outbox entry directly. No SMTP is used in either path.
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let emailed = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    match path {
        ResetPath::Email => assert!(
            confirm_password_reset(&mut db, &hasher, &emailed.token, &new_password)
                .await
                .unwrap()
        ),
        ResetPath::Operator => assert!(
            operator_reset_password(&mut db, "owner@example.test", &new_password)
                .await
                .unwrap()
        ),
    }
    assert_eq!(
        mfa_state(&db, owner.user_id).await,
        before,
        "reset must preserve enrollment, encrypted factor, replay state and recovery codes"
    );
    for token in [&first.token, &second.token] {
        assert!(matches!(
            auth::authenticate_session(&db, &hasher, token).await,
            Err(AuthError::Unauthorized)
        ));
    }
    assert!(matches!(
        auth::authenticate_api_key(&db, &hasher, &key.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        !mfa::login_challenge_is_live(&db, &hasher, &stale_challenge)
            .await
            .unwrap()
    );
    assert!(matches!(
        mfa::complete_login(
            &mut db,
            Some(&cipher),
            &hasher,
            &stale_challenge,
            &recovery.codes[1]
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        !confirm_password_reset(&mut db, &hasher, &emailed.token, &old_password)
            .await
            .unwrap()
    );
    assert!(matches!(
        auth::login(&db, &hasher, "owner@example.test", &old_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        matches!(auth::login(&db, &hasher, "owner@example.test", &new_password).await,
        Err(AuthError::MfaRequired { account_id, user_id }) if account_id == owner.account_id && user_id == owner.user_id)
    );
    let fresh_challenge =
        mfa::begin_login_challenge(&db, &hasher, owner.account_id, owner.user_id, &new_password)
            .await
            .unwrap();
    // The same unused factor rejected with the stale challenge still works
    // with a fresh proof of the new password; reset does not strand the owner.
    let restored = mfa::complete_login(
        &mut db,
        Some(&cipher),
        &hasher,
        &fresh_challenge,
        &recovery.codes[1],
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_session(&db, &hasher, &restored.token)
            .await
            .is_ok()
    );
    crate::outbox_test_support::backdate_queued_reset_notice(&db).await;
    assert_eq!(
        claim_reset_notice(&mut db).await.unwrap().unwrap().email,
        "owner@example.test"
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn expired_reset_mail_is_pruned_in_bounded_batches_before_live_mail() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("reset_mail_prune_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let owner = auth::register(
        &mut db,
        &hasher,
        "owner@example.test",
        &Uuid::new_v4().to_string(),
    )
    .await
    .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
    let live_id: Uuid = db
        .query_one("SELECT id FROM password_resets WHERE expires_at>now()", &[])
        .await
        .unwrap()
        .get(0);
    db.execute(
        "WITH seeded AS (
                INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at,created_at)
                SELECT gen_random_uuid(),$1,$2,
                       decode(lpad(to_hex(i),64,'0'),'hex'),
                       now()-interval '1 minute',now()-interval '2 hours'
                FROM generate_series(1,1200) i RETURNING id
             ) INSERT INTO password_reset_mail_outbox(reset_id,next_attempt_at)
             SELECT id,now()-interval '2 hours' FROM seeded",
        &[&owner.account_id, &owner.user_id],
    )
    .await
    .unwrap();
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let mail = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    assert_eq!(mail.reset_id, live_id);
    let stale: i64 = db.query_one(
            "SELECT count(*) FROM password_reset_mail_outbox o JOIN password_resets r ON r.id=o.reset_id WHERE r.expires_at<=now()",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(stale, 700);
    assert_eq!(prune_expired_password_resets(&db).await.unwrap(), 500);
    assert_eq!(prune_expired_password_resets(&db).await.unwrap(), 200);
    assert_eq!(prune_expired_password_resets(&db).await.unwrap(), 0);
    let queued: i64 = db
        .query_one("SELECT count(*) FROM password_reset_mail_outbox", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(queued, 1);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn api_key_mint_waits_for_recovery_lock_and_rechecks_session() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("key_recovery_lock_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut recovery_db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (mut mint_db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        recovery_db.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut recovery_db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut recovery_db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let session = auth::login(&recovery_db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&recovery_db, &hasher, &session.token)
        .await
        .unwrap();
    let tx = recovery_db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM users WHERE id=$1 FOR UPDATE",
        &[&owner.user_id],
    )
    .await
    .unwrap();
    let mint_hasher = hasher.clone();
    let mut mint = tokio::spawn(async move {
        auth::create_api_key(
            &mut mint_db,
            &mint_hasher,
            &principal,
            &[Scope::MessagesRead],
            None,
            auth::ApiKeyLifetime::Unspecified,
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut mint)
            .await
            .is_err()
    );
    tx.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2",
        &[&owner.account_id, &owner.user_id],
    )
    .await
    .unwrap();
    tx.execute("UPDATE api_keys SET revoked_at=now() WHERE account_id=$1 AND created_by_user_id=$2 AND revoked_at IS NULL", &[&owner.account_id, &owner.user_id]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(mint.await.unwrap(), Err(AuthError::Unauthorized)));
    let key_count: i64 = recovery_db
        .query_one(
            "SELECT count(*) FROM api_keys WHERE revoked_at IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(key_count, 0);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_password_session_and_reset_lifecycle() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("account_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let old_password = Uuid::new_v4().to_string();
    let changed_password = Uuid::new_v4().to_string();
    let reset_password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let first = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let second = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &first.token)
        .await
        .unwrap();
    let sessions = list_sessions(&db, &principal).await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.iter().filter(|session| session.current).count(), 1);
    let wrong_password = Uuid::new_v4().to_string();
    assert!(matches!(
        revoke_other_sessions(
            &mut db,
            None,
            &hasher,
            &principal,
            &wrong_password,
            None,
            true
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        auth::authenticate_session(&db, &hasher, &second.token)
            .await
            .is_ok()
    );
    assert_eq!(
        revoke_other_sessions(
            &mut db,
            None,
            &hasher,
            &principal,
            &old_password,
            None,
            true
        )
        .await
        .unwrap(),
        1
    );
    assert!(
        auth::authenticate_session(&db, &hasher, &second.token)
            .await
            .is_err()
    );
    let third = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let old_key = auth::create_api_key(
        &mut db,
        &hasher,
        &principal,
        &[Scope::MessagesRead],
        None,
        auth::ApiKeyLifetime::Unspecified,
    )
    .await
    .unwrap();
    change_password(
        &mut db,
        None,
        &hasher,
        &principal,
        &old_password,
        &changed_password,
        None,
    )
    .await
    .unwrap();
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &old_password)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_session(&db, &hasher, &third.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_session(&db, &hasher, &first.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&db, &hasher, &old_key.token)
            .await
            .is_err()
    );
    let fourth = auth::login(&db, &hasher, "owner@example.test", &changed_password)
        .await
        .unwrap();
    let fourth_principal = auth::authenticate_session(&db, &hasher, &fourth.token)
        .await
        .unwrap();
    let reset_key = auth::create_api_key(
        &mut db,
        &hasher,
        &fourth_principal,
        &[Scope::MessagesRead],
        None,
        auth::ApiKeyLifetime::Unspecified,
    )
    .await
    .unwrap();

    request_password_reset(&mut db, &hasher, "unknown@example.test")
        .await
        .unwrap();
    assert!(claim_reset_mail(&mut db, &hasher).await.unwrap().is_none());
    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let reset = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    assert_eq!(reset.email, "owner@example.test");
    assert!(ack_reset_mail(&db, &reset, true).await.unwrap());
    assert!(
        confirm_password_reset(&mut db, &hasher, &reset.token, &reset_password)
            .await
            .unwrap()
    );
    crate::outbox_test_support::backdate_queued_reset_notice(&db).await;
    let notice = claim_reset_notice(&mut db).await.unwrap().unwrap();
    assert_eq!(notice.email, "owner@example.test");
    assert!(ack_reset_notice(&db, &notice, true).await.unwrap());
    assert!(claim_reset_notice(&mut db).await.unwrap().is_none());
    assert!(
        !confirm_password_reset(&mut db, &hasher, &reset.token, &reset_password)
            .await
            .unwrap()
    );
    assert!(
        auth::authenticate_session(&db, &hasher, &first.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_session(&db, &hasher, &fourth.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&db, &hasher, &reset_key.token)
            .await
            .is_err()
    );
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &changed_password)
            .await
            .is_err()
    );
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &reset_password)
            .await
            .is_ok()
    );

    db.execute(
        "UPDATE password_resets SET created_at=now()-interval '16 minutes' WHERE user_id=$1",
        &[&owner.user_id],
    )
    .await
    .unwrap();
    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let expired = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    db.execute(
        "UPDATE password_resets SET expires_at=now()-interval '5 minutes' WHERE id=$1",
        &[&expired.reset_id],
    )
    .await
    .unwrap();
    assert!(
        !confirm_password_reset(&mut db, &hasher, &expired.token, &reset_password)
            .await
            .unwrap()
    );

    let mfa_session = auth::login(&db, &hasher, "owner@example.test", &reset_password)
        .await
        .unwrap();
    let mfa_owner = auth::authenticate_session(&db, &hasher, &mfa_session.token)
        .await
        .unwrap();
    let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let pending = mfa::begin_enrollment(&mut db, &cipher, &mfa_owner, &reset_password)
        .await
        .unwrap();
    let secret = Secret::try_from_base32(&pending.secret_base32).unwrap();
    let code = Builder::new()
        .with_secret(secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &mfa_owner, &code)
        .await
        .unwrap();
    assert!(matches!(
        revoke_other_sessions(
            &mut db,
            Some(&cipher),
            &hasher,
            &mfa_owner,
            &reset_password,
            None,
            true,
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert_eq!(
        revoke_other_sessions(
            &mut db,
            Some(&cipher),
            &hasher,
            &mfa_owner,
            &reset_password,
            Some(&recovery.codes[2]),
            true,
        )
        .await
        .unwrap(),
        0
    );
    assert!(matches!(
        auth::login(&db, &hasher, "owner@example.test", &reset_password).await,
        Err(AuthError::MfaRequired { .. })
    ));
    let mfa_password = Uuid::new_v4().to_string();
    assert!(matches!(
        change_password(
            &mut db,
            Some(&cipher),
            &hasher,
            &mfa_owner,
            &reset_password,
            &mfa_password,
            None,
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    change_password(
        &mut db,
        Some(&cipher),
        &hasher,
        &mfa_owner,
        &reset_password,
        &mfa_password,
        Some(&recovery.codes[0]),
    )
    .await
    .unwrap();
    assert!(matches!(
        auth::login(&db, &hasher, "owner@example.test", &reset_password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(matches!(
        auth::login(&db, &hasher, "owner@example.test", &mfa_password).await,
        Err(AuthError::MfaRequired { .. })
    ));
    assert!(matches!(
        mfa::begin_login_challenge(
            &db,
            &hasher,
            owner.account_id,
            owner.user_id,
            &reset_password
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    let challenge =
        mfa::begin_login_challenge(&db, &hasher, owner.account_id, owner.user_id, &mfa_password)
            .await
            .unwrap();
    assert!(
        mfa::complete_login(
            &mut db,
            Some(&cipher),
            &hasher,
            &challenge,
            &recovery.codes[1],
        )
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
async fn postgres_operator_reset_revokes_all_owner_credentials() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("operator_reset_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let old_password = Uuid::new_v4().to_string();
    let new_password = Uuid::new_v4().to_string();
    assert!(matches!(
        operator_reset_password(&mut db, "owner@example.test", &old_password[..5]).await,
        Err(AuthError::InvalidInput)
    ));
    let pending = auth::register(&mut db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    assert!(
        !operator_reset_password(&mut db, "owner@example.test", &new_password)
            .await
            .unwrap(),
        "an unverified registration must not be recoverable by the operator path"
    );
    assert!(
        auth::verify_email(&mut db, &hasher, &pending.verification_token)
            .await
            .unwrap()
    );
    assert!(
        !operator_reset_password(&mut db, "unknown@example.test", &new_password)
            .await
            .unwrap()
    );
    let first = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let second = auth::login(&db, &hasher, "owner@example.test", &old_password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &first.token)
        .await
        .unwrap();
    let key = auth::create_api_key(
        &mut db,
        &hasher,
        &principal,
        &[Scope::MessagesRead],
        None,
        auth::ApiKeyLifetime::Unspecified,
    )
    .await
    .unwrap();
    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
    crate::outbox_test_support::backdate_queued_reset_mail(&db).await;
    let emailed = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    assert!(ack_reset_mail(&db, &emailed, false).await.unwrap());

    assert!(
        operator_reset_password(&mut db, " Owner@Example.test ", &new_password)
            .await
            .unwrap()
    );
    for token in [&first.token, &second.token] {
        assert!(
            auth::authenticate_session(&db, &hasher, token)
                .await
                .is_err()
        );
    }
    assert!(
        auth::authenticate_api_key(&db, &hasher, &key.token)
            .await
            .is_err()
    );
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &old_password)
            .await
            .is_err()
    );
    assert!(
        auth::login(&db, &hasher, "owner@example.test", &new_password)
            .await
            .is_ok()
    );
    assert!(
        !confirm_password_reset(&mut db, &hasher, &emailed.token, &old_password)
            .await
            .unwrap(),
        "an outstanding emailed code must not survive an operator reset"
    );
    let canceled: i64 = db
        .query_one(
            "SELECT count(*) FROM password_reset_mail_outbox WHERE canceled_at IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(canceled, 1);
    crate::outbox_test_support::backdate_queued_reset_notice(&db).await;
    let notice = claim_reset_notice(&mut db).await.unwrap().unwrap();
    assert_eq!(notice.email, "owner@example.test");
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

async fn live_key_count(db: &Client) -> i64 {
    db.query_one(
        "SELECT count(*) FROM api_keys WHERE revoked_at IS NULL",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

/// An owner with confirmed MFA and one live session in a private schema.
struct MfaOwner {
    setup: Client,
    db: Client,
    schema: String,
    hasher: TokenHasher,
    cipher: mfa::MfaCipher,
    account_id: Uuid,
    user_id: Uuid,
    password: String,
    principal: SessionPrincipal,
    recovery: Vec<String>,
}

impl MfaOwner {
    async fn new(prefix: &str) -> Self {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!(
                "../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"
            ),
            include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
            include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let password = Uuid::new_v4().to_string();
        let owner = auth::register(&mut db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut db, &hasher, &owner.verification_token)
                .await
                .unwrap()
        );
        let session = auth::login(&db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &session.token)
            .await
            .unwrap();
        let pending = mfa::begin_enrollment(&mut db, &cipher, &principal, &password)
            .await
            .unwrap();
        let code = Builder::new()
            .with_secret(Secret::try_from_base32(&pending.secret_base32).unwrap())
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
            .await
            .unwrap()
            .codes;
        Self {
            setup,
            db,
            schema,
            hasher,
            cipher,
            account_id: owner.account_id,
            user_id: owner.user_id,
            password,
            principal,
            recovery,
        }
    }

    async fn challenge(&self) -> String {
        mfa::begin_login_challenge(
            &self.db,
            &self.hasher,
            self.account_id,
            self.user_id,
            &self.password,
        )
        .await
        .unwrap()
    }

    async fn complete_login(
        &mut self,
        challenge: &str,
        code: &str,
    ) -> Result<auth::SessionCredentials, AuthError> {
        mfa::complete_login(
            &mut self.db,
            Some(&self.cipher),
            &self.hasher,
            challenge,
            code,
        )
        .await
    }

    async fn finish(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// Never a valid recovery code for any owner, and never a TOTP code.
const WRONG_FACTOR: &str = "zrc_AAAAAAAAAAAAAAAAAAAAAA";

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn failed_sign_in_factors_do_not_block_a_signed_in_owner_step_up() {
    let mut owner = MfaOwner::new("step_up_budget").await;
    // Someone holding only the password spends the whole sign-in budget.
    let stranger = owner.challenge().await;
    for _ in 0..5 {
        assert!(matches!(
            owner.complete_login(&stranger, WRONG_FACTOR).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    let fresh = owner.challenge().await;
    let code = owner.recovery[2].clone();
    assert!(matches!(
        owner.complete_login(&fresh, &code).await,
        Err(AuthError::RateLimited)
    ));

    // The signed-in owner can still present a correct factor.
    assert_eq!(
        revoke_other_sessions(
            &mut owner.db,
            Some(&owner.cipher),
            &owner.hasher,
            &owner.principal,
            &owner.password,
            Some(&owner.recovery[1]),
            false,
        )
        .await
        .unwrap(),
        0
    );
    let new_password = Uuid::new_v4().to_string();
    change_password(
        &mut owner.db,
        Some(&owner.cipher),
        &owner.hasher,
        &owner.principal,
        &owner.password,
        &new_password,
        Some(&owner.recovery[0]),
    )
    .await
    .unwrap();
    assert!(matches!(
        auth::login(
            &owner.db,
            &owner.hasher,
            "owner@example.test",
            &new_password
        )
        .await,
        Err(AuthError::MfaRequired { .. })
    ));
    owner.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn api_key_issuance_needs_step_up_expires_by_default_and_revoke_others_needs_opt_in() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("key_step_up_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let password = Uuid::new_v4().to_string();
    let wrong_password = Uuid::new_v4().to_string();
    let owner = auth::register(&mut db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    assert!(
        auth::verify_email(&mut db, &hasher, &owner.verification_token)
            .await
            .unwrap()
    );
    let session = auth::login(&db, &hasher, "owner@example.test", &password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &session.token)
        .await
        .unwrap();
    let request = || ApiKeyRequest {
        scopes: &[Scope::MessagesRead],
        bound_device_id: None,
        lifetime: auth::ApiKeyLifetime::Unspecified,
    };

    // A session cookie alone (the stolen-cookie case) is not enough.
    assert!(matches!(
        create_api_key_with_proof(
            &mut db,
            Some(&cipher),
            &hasher,
            &principal,
            &wrong_password,
            None,
            request(),
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    let default_key = create_api_key_with_proof(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        None,
        request(),
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_api_key(&db, &hasher, &default_key.token)
            .await
            .is_ok()
    );
    // Omitting the lifetime yields the bounded default, never NULL.
    let default_days: Option<f64> = db
        .query_one(
            "SELECT (extract(epoch FROM expires_at-created_at)/86400)::double precision FROM api_keys WHERE id=$1",
            &[&default_key.id],
        )
        .await
        .unwrap()
        .get(0);
    let default_days = default_days.expect("default lifetime stored");
    assert!(
        (default_days - f64::from(auth::API_KEY_DEFAULT_LIFETIME_DAYS)).abs() < 0.01,
        "expected {} days, stored {default_days}",
        auth::API_KEY_DEFAULT_LIFETIME_DAYS
    );
    let explicit_key = create_api_key_with_proof(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        None,
        ApiKeyRequest {
            scopes: &[Scope::MessagesRead],
            bound_device_id: None,
            lifetime: auth::ApiKeyLifetime::Days(7),
        },
    )
    .await
    .unwrap();
    let explicit_days: f64 = db
        .query_one(
            "SELECT (extract(epoch FROM expires_at-created_at)/86400)::double precision FROM api_keys WHERE id=$1",
            &[&explicit_key.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!((explicit_days - 7.0).abs() < 0.01);
    // The explicit, discouraged null opt-in stores no expiry at all, exactly
    // like the keys minted before the default existed.
    let never_key = create_api_key_with_proof(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        None,
        ApiKeyRequest {
            scopes: &[Scope::MessagesRead],
            bound_device_id: None,
            lifetime: auth::ApiKeyLifetime::Never,
        },
    )
    .await
    .unwrap();
    let never_expires: Option<String> = db
        .query_one(
            "SELECT expires_at::text FROM api_keys WHERE id=$1",
            &[&never_key.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(never_expires.is_none());
    assert!(
        auth::authenticate_api_key(&db, &hasher, &never_key.token)
            .await
            .is_ok()
    );

    // Once MFA is enabled the password alone stops working; a wrong code is
    // rejected and a recovery code is accepted.
    let pending = mfa::begin_enrollment(&mut db, &cipher, &principal, &password)
        .await
        .unwrap();
    let secret = Secret::try_from_base32(&pending.secret_base32).unwrap();
    let code = Builder::new()
        .with_secret(secret)
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
        .await
        .unwrap();
    assert!(matches!(
        create_api_key_with_proof(
            &mut db,
            Some(&cipher),
            &hasher,
            &principal,
            &password,
            None,
            request(),
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(matches!(
        create_api_key_with_proof(
            &mut db,
            Some(&cipher),
            &hasher,
            &principal,
            &password,
            Some("000000"),
            request(),
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    let mfa_key = create_api_key_with_proof(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        Some(&recovery.codes[0]),
        request(),
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_api_key(&db, &hasher, &mfa_key.token)
            .await
            .is_ok()
    );
    assert_eq!(live_key_count(&db).await, 4);

    // By default the keys survive the sessions; only the explicit opt-in takes them.
    revoke_other_sessions(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        Some(&recovery.codes[1]),
        false,
    )
    .await
    .unwrap();
    assert_eq!(live_key_count(&db).await, 4);
    revoke_other_sessions(
        &mut db,
        Some(&cipher),
        &hasher,
        &principal,
        &password,
        Some(&recovery.codes[2]),
        true,
    )
    .await
    .unwrap();
    assert_eq!(live_key_count(&db).await, 0);
    for key in [&default_key, &explicit_key, &never_key, &mfa_key] {
        assert!(
            auth::authenticate_api_key(&db, &hasher, &key.token)
                .await
                .is_err()
        );
    }
    // The calling session survives, as before.
    assert!(
        auth::authenticate_session(&db, &hasher, &session.token)
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
async fn successful_sign_in_factor_resets_the_sign_in_failure_window() {
    let mut owner = MfaOwner::new("login_budget_reset").await;
    let first = owner.challenge().await;
    for _ in 0..4 {
        assert!(matches!(
            owner.complete_login(&first, WRONG_FACTOR).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    let code = owner.recovery[0].clone();
    owner.complete_login(&first, &code).await.unwrap();
    let failures: i32 = owner
        .db
        .query_one(
            "SELECT failed_attempts FROM owner_mfa WHERE account_id=$1",
            &[&owner.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failures, 0);

    // Without the reset these would be failures five through eight.
    let second = owner.challenge().await;
    for _ in 0..4 {
        assert!(matches!(
            owner.complete_login(&second, WRONG_FACTOR).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    let code = owner.recovery[1].clone();
    owner.complete_login(&second, &code).await.unwrap();
    owner.finish().await;
}
