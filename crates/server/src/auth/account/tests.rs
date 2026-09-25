
use super::*;
use crate::auth::{self, Scope, TokenHasher};
use std::sync::Arc;
use tokio_postgres::NoTls;
use totp_rs::{Builder, Secret};

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
            None,
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
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
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
        revoke_other_sessions(&mut db, None, &hasher, &principal, &wrong_password, None).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        auth::authenticate_session(&db, &hasher, &second.token)
            .await
            .is_ok()
    );
    assert_eq!(
        revoke_other_sessions(&mut db, None, &hasher, &principal, &old_password, None)
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
        None,
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
        None,
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
    let reset = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    assert_eq!(reset.email, "owner@example.test");
    assert!(ack_reset_mail(&db, &reset, true).await.unwrap());
    assert!(
        confirm_password_reset(&mut db, &hasher, &reset.token, &reset_password)
            .await
            .unwrap()
    );
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
    let expired = claim_reset_mail(&mut db, &hasher).await.unwrap().unwrap();
    db.execute(
        "UPDATE password_resets SET expires_at=now()-interval '1 second' WHERE id=$1",
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
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let old_password = Uuid::new_v4().to_string();
    let new_password = Uuid::new_v4().to_string();
    assert!(matches!(
        operator_reset_password(&mut db, "owner@example.test", "short").await,
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
        None,
    )
    .await
    .unwrap();
    request_password_reset(&mut db, &hasher, "owner@example.test")
        .await
        .unwrap();
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
    let notice = claim_reset_notice(&mut db).await.unwrap().unwrap();
    assert_eq!(notice.email, "owner@example.test");
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
