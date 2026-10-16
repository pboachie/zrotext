// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{self, verification_token_for_id};
use std::time::SystemTime;
use tokio_postgres::{Config, NoTls};

pub(crate) struct Fixture {
    pub(crate) db: Client,
    admin: Client,
    config: Config,
    schema: String,
    pub(crate) hasher: TokenHasher,
    pub(crate) dsn: String,
}

impl Fixture {
    pub(crate) async fn new() -> Self {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("use a disposable PostgreSQL fixture");
        let config: Config = url.parse().unwrap();
        let mut uri = url::Url::parse(&url).expect("disposable fixture URL");
        let (admin, connection) = config.connect(NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let schema = format!("registration_intent_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut config = config.clone();
        config.options(format!("-c search_path={schema}"));
        uri.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let (db, connection) = config.connect(NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        auth::test_schema::apply(&db).await;
        Self {
            db,
            admin,
            config,
            schema,
            hasher: TokenHasher::new(crate::test_keys::key(180)).unwrap(),
            dsn: uri.to_string(),
        }
    }
    pub(crate) async fn signup(&mut self) -> (auth::Signup, Credentials) {
        let credentials = Credentials::random();
        let signup = auth::register_with_intent(
            &mut self.db,
            &self.hasher,
            &format!("{}@example.test", Uuid::new_v4().simple()),
            &crate::test_keys::password(180),
            Some(&credentials),
        )
        .await
        .unwrap();
        (signup, credentials)
    }
    pub(crate) fn verification_token(&self, id: Uuid) -> String {
        verification_token_for_id(&self.hasher, id)
    }
    pub(crate) async fn cleanup(self) {
        drop(self.db);
        assert!(self.schema.starts_with("registration_intent_"));
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[test]
fn cookies_are_independent_bounded_and_only_intent_is_httponly() {
    let credentials = Credentials::random();
    assert!(credentials.valid());
    assert_ne!(credentials.token.as_str(), credentials.csrf.as_str());
    let cookies = credentials.cookies();
    assert!(cookies[0].contains("; HttpOnly;"));
    assert!(!cookies[1].contains("HttpOnly"));
    for cookie in cookies {
        assert!(cookie.ends_with("SameSite=Strict; Path=/; Max-Age=900"));
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn original_browser_consumes_code_and_intent_once_without_creating_a_session() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    assert!(
        !verify(
            &mut f.db,
            &f.hasher,
            &Credentials::random(),
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    assert!(
        !resend(&mut f.db, &f.hasher, &Credentials::random())
            .await
            .unwrap()
    );
    assert!(
        !verify(&mut f.db, &f.hasher, &credentials, "wrong-code")
            .await
            .unwrap()
    );
    assert!(
        verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    assert!(
        !verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    let row = f.db.query_one("SELECT i.verification_attempts,i.consumed_at IS NOT NULL,u.email_verified_at IS NOT NULL,(SELECT count(*) FROM sessions) FROM registration_browser_intents i JOIN users u ON u.id=i.user_id", &[]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 2);
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2));
    assert_eq!(row.get::<_, i64>(3), 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn changed_password_email_membership_account_or_mfa_cannot_reuse_original_intent() {
    let mut f = Fixture::new().await;
    for update in [
        "UPDATE users SET password_hash='changed-synthetic-binding' WHERE id=$1",
        "UPDATE users SET email='changed@example.test' WHERE id=$1",
        "DELETE FROM memberships WHERE user_id=$1",
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=(SELECT account_id FROM memberships WHERE user_id=$1)",
        "UPDATE users SET mfa_enabled=true WHERE id=$1",
    ] {
        let (signup, credentials) = f.signup().await;
        f.db.execute(update, &[&signup.user_id]).await.unwrap();
        assert!(
            !live_code_for_budget(&f.db, &f.hasher, &credentials, &signup.verification_token)
                .await
                .unwrap()
        );
        assert!(
            !verify(
                &mut f.db,
                &f.hasher,
                &credentials,
                &signup.verification_token
            )
            .await
            .unwrap()
        );
        assert!(!resend(&mut f.db, &f.hasher, &credentials).await.unwrap());
        let code =
            f.db.query_opt(
                "SELECT used_at IS NOT NULL FROM email_verifications WHERE user_id=$1",
                &[&signup.user_id],
            )
            .await
            .unwrap();
        assert!(code.is_none_or(|row| !row.get::<_, bool>(0)));
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn resend_replaces_code_and_mail_but_preserves_expiry_and_attempt_budget() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    let expiry: SystemTime =
        f.db.query_one("SELECT expires_at FROM registration_browser_intents", &[])
            .await
            .unwrap()
            .get(0);
    assert!(
        !verify(&mut f.db, &f.hasher, &credentials, "wrong-code")
            .await
            .unwrap()
    );
    assert!(resend(&mut f.db, &f.hasher, &credentials).await.unwrap());
    assert!(
        !resend(&mut f.db, &f.hasher, &credentials).await.unwrap(),
        "spacing is not reset by the intent"
    );
    let row = f.db.query_one("SELECT verification_id,expires_at,verification_attempts FROM registration_browser_intents", &[]).await.unwrap();
    assert_eq!(row.get::<_, SystemTime>(1), expiry);
    assert_eq!(row.get::<_, i32>(2), 1);
    let token = verification_token_for_id(&f.hasher, row.get(0));
    assert_ne!(token, signup.verification_token);
    assert!(f.db.query_one("SELECT canceled_at IS NOT NULL AND lease_id IS NULL FROM verification_mail_outbox WHERE verification_id=(SELECT id FROM email_verifications WHERE token_hash=$1)", &[&&f.hasher.digest(b"email-verification-v1", &signup.verification_token)[..]]).await.unwrap().get::<_, bool>(0));
    assert!(
        !verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    assert!(
        verify(&mut f.db, &f.hasher, &credentials, &token)
            .await
            .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn opaque_signup_collision_invalidates_old_generation_without_binding_another_browser() {
    let mut f = Fixture::new().await;
    let (signup, original) = f.signup().await;
    let email: String =
        f.db.query_one("SELECT email FROM users WHERE id=$1", &[&signup.user_id])
            .await
            .unwrap()
            .get(0);
    let decoy = Credentials::random();
    assert!(
        auth::register_with_intent(
            &mut f.db,
            &f.hasher,
            &email,
            &crate::test_keys::password(181),
            Some(&decoy)
        )
        .await
        .is_err()
    );
    auth::cancel_pending_verification(&mut f.db, &email)
        .await
        .unwrap();
    for credentials in [&original, &decoy] {
        assert!(
            !verify(
                &mut f.db,
                &f.hasher,
                credentials,
                &signup.verification_token
            )
            .await
            .unwrap()
        );
        assert!(!resend(&mut f.db, &f.hasher, credentials).await.unwrap());
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM registration_browser_intents", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn exhausted_attempts_fail_closed_while_password_bound_fallback_still_works() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    for _ in 0..8 {
        assert!(
            !verify(&mut f.db, &f.hasher, &credentials, "wrong-code")
                .await
                .unwrap()
        );
    }
    assert!(
        !verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    assert!(!resend(&mut f.db, &f.hasher, &credentials).await.unwrap());
    assert!(
        !auth::verify_email_with_password(
            &mut f.db,
            &f.hasher,
            &signup.verification_token,
            &crate::test_keys::password(181)
        )
        .await
        .unwrap()
    );
    assert!(
        auth::verify_email_with_password(
            &mut f.db,
            &f.hasher,
            &signup.verification_token,
            &crate::test_keys::password(180)
        )
        .await
        .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn two_connections_cannot_consume_the_same_intent_twice() {
    let mut f = Fixture::new().await;
    let (signup, first) = f.signup().await;
    let second = Credentials {
        token: Zeroizing::new(first.token.to_string()),
        csrf: Zeroizing::new(first.csrf.to_string()),
    };
    let (mut other, connection) = f.config.connect(NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let (a, b) = tokio::join!(
        verify(&mut f.db, &f.hasher, &first, &signup.verification_token),
        verify(&mut other, &f.hasher, &second, &signup.verification_token)
    );
    assert_eq!(
        [a, b]
            .into_iter()
            .filter(|result| matches!(result, Ok(true)))
            .count(),
        1
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(other);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn expired_binding_cannot_verify_or_renew_trust() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    // A directly constructed fixture row is already expired; production has
    // no clock override and the immutable trigger refuses expiry rewrites.
    let hash = f
        .hasher
        .digest(b"registration-browser-intent-v1", &credentials.token);
    f.db.execute(
        "DELETE FROM registration_browser_intents WHERE intent_hash=$1",
        &[&&hash[..]],
    )
    .await
    .unwrap();
    let csrf = f
        .hasher
        .digest(b"registration-browser-csrf-v1", &credentials.csrf);
    let password: String =
        f.db.query_one(
            "SELECT password_hash FROM users WHERE id=$1",
            &[&signup.user_id],
        )
        .await
        .unwrap()
        .get(0);
    let password = f
        .hasher
        .digest(b"registration-browser-password-v1", &password);
    f.db.execute("WITH stamp AS (SELECT clock_timestamp()-interval '16 minutes' AS issued) INSERT INTO registration_browser_intents(intent_hash,csrf_hash,account_id,user_id,email,password_binding,verification_id,created_at,expires_at) SELECT $1,$2,$3,u.id,u.email,$5,v.id,issued,issued+interval '15 minutes' FROM users u JOIN email_verifications v ON v.user_id=u.id CROSS JOIN stamp WHERE u.id=$4", &[&&hash[..], &&csrf[..], &signup.account_id, &signup.user_id, &&password[..]]).await.unwrap();
    assert!(
        !verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    assert!(!resend(&mut f.db, &f.hasher, &credentials).await.unwrap());
    assert!(
        f.db.execute(
            "UPDATE registration_browser_intents SET expires_at=expires_at+interval '1 minute'",
            &[]
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn database_clock_expiry_during_consumption_rolls_back_every_effect() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    // Reconstruct only this synthetic fixture with a fixed fifteen-minute
    // lifetime ending shortly. The production immutable guard stays enabled.
    f.db.batch_execute("CREATE TEMP TABLE intent_fixture AS TABLE registration_browser_intents; DELETE FROM registration_browser_intents").await.unwrap();
    // Both timestamps must come from the same database-clock observation.
    f.db.batch_execute("WITH stamp AS (SELECT clock_timestamp() AS issued) INSERT INTO registration_browser_intents SELECT intent_hash,csrf_hash,account_id,user_id,email,password_binding,verification_id,issued-interval '899 seconds',issued+interval '1 second',verification_attempts,consumed_at,retired_at FROM intent_fixture CROSS JOIN stamp").await.unwrap();
    f.db.batch_execute("CREATE FUNCTION delay_intent_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.2); RETURN NEW; END $$; CREATE TRIGGER delay_intent_consume BEFORE UPDATE OF consumed_at ON registration_browser_intents FOR EACH ROW WHEN (NEW.consumed_at IS NOT NULL) EXECUTE FUNCTION delay_intent_consume()").await.unwrap();
    assert!(matches!(
        verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await,
        Err(AuthError::Conflict)
    ));
    let row = f.db.query_one("SELECT i.verification_attempts,i.consumed_at IS NULL,u.email_verified_at IS NULL,v.used_at IS NULL FROM registration_browser_intents i JOIN users u ON u.id=i.user_id JOIN email_verifications v ON v.id=i.verification_id",&[]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 0);
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2) && row.get::<_, bool>(3));
    assert!(!resend(&mut f.db, &f.hasher, &credentials).await.unwrap());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn held_user_lock_refuses_without_waiting_or_consuming_then_fresh_retry_succeeds() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    let (mut other, connection) = f.config.connect(NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let tx = other.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM users WHERE id=$1 FOR UPDATE",
        &[&signup.user_id],
    )
    .await
    .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token,
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(result,Err(AuthError::Database(ref error)) if error.code()==Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE))
    );
    tx.rollback().await.unwrap();
    assert!(
        verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    drop(other);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn database_clock_expiry_during_resend_preserves_original_code_and_mail() {
    let mut f = Fixture::new().await;
    let (_, credentials) = f.signup().await;
    f.db.batch_execute("CREATE TEMP TABLE intent_fixture AS TABLE registration_browser_intents; DELETE FROM registration_browser_intents; WITH stamp AS (SELECT clock_timestamp() AS issued) INSERT INTO registration_browser_intents SELECT intent_hash,csrf_hash,account_id,user_id,email,password_binding,verification_id,issued-interval '899 seconds',issued+interval '1 second',verification_attempts,consumed_at,retired_at FROM intent_fixture CROSS JOIN stamp").await.unwrap();
    f.db.batch_execute("CREATE FUNCTION delay_intent_resend() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.2); RETURN NEW; END $$; CREATE TRIGGER delay_intent_resend BEFORE UPDATE OF verification_id ON registration_browser_intents FOR EACH ROW EXECUTE FUNCTION delay_intent_resend()").await.unwrap();
    assert!(matches!(
        resend(&mut f.db, &f.hasher, &credentials).await,
        Err(AuthError::Conflict)
    ));
    let row=f.db.query_one("SELECT (SELECT count(*) FROM email_verifications),(SELECT count(*) FROM email_verifications WHERE used_at IS NOT NULL),(SELECT count(*) FROM verification_mail_outbox WHERE canceled_at IS NOT NULL)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL pointing to a disposable PostgreSQL cluster"]
async fn ordinary_generated_role_consumes_intent_without_owner_or_role_bypass() {
    let mut f = Fixture::new().await;
    let (signup, credentials) = f.signup().await;
    let (other_signup, _) = f.signup().await;
    let other_generation: Uuid =
        f.db.query_one(
            "SELECT id FROM email_verifications WHERE user_id=$1",
            &[&other_signup.user_id],
        )
        .await
        .unwrap()
        .get(0);
    let role = format!("zt_intent_r_{}", Uuid::new_v4().simple());
    f.admin.batch_execute(&format!("CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA {} TO {role}; GRANT SELECT ON {}.accounts,{}.memberships TO {role}; GRANT UPDATE(id) ON {}.accounts TO {role}; GRANT UPDATE(user_id) ON {}.memberships TO {role}; GRANT SELECT,UPDATE ON {}.users,{}.email_verifications,{}.verification_mail_outbox,{}.registration_browser_intents TO {role}",f.schema,f.schema,f.schema,f.schema,f.schema,f.schema,f.schema,f.schema,f.schema)).await.unwrap();
    f.db.batch_execute(&format!("SET ROLE {role}"))
        .await
        .unwrap();
    let row=f.db.query_one("SELECT current_user::text,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), role);
    for index in 1..5 {
        assert!(!row.get::<_, bool>(index));
    }
    assert!(
        f.db.execute(
            "UPDATE registration_browser_intents SET expires_at=expires_at+interval '1 minute'",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        !f.db
            .query_one(
                "SELECT has_function_privilege(current_user,$1,'EXECUTE')",
                &[&format!(
                    "{}.registration_browser_intent_binding_guard()",
                    f.schema
                )]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.db.batch_execute(
        "CREATE TEMP TABLE email_verifications(id uuid,account_id uuid,user_id uuid)",
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO pg_temp.email_verifications VALUES($1,$2,$3)",
        &[&other_generation, &signup.account_id, &signup.user_id],
    )
    .await
    .unwrap();
    let shadow_attempt =
        f.db.execute(
            &format!(
                "UPDATE {}.registration_browser_intents SET verification_id=$1 WHERE user_id=$2",
                f.schema
            ),
            &[&other_generation, &signup.user_id],
        )
        .await
        .unwrap_err();
    assert_eq!(
        shadow_attempt.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    f.db.batch_execute("DROP TABLE pg_temp.email_verifications")
        .await
        .unwrap();

    assert!(
        verify(
            &mut f.db,
            &f.hasher,
            &credentials,
            &signup.verification_token
        )
        .await
        .unwrap()
    );
    f.db.batch_execute("RESET ROLE").await.unwrap();
    let admin = &f.admin;
    admin
        .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
        .await
        .unwrap();
    f.cleanup().await;
}
