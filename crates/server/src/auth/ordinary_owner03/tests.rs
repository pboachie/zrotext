// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{SessionCredentials, random_token as token};
use crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, error::SqlState};
use uuid::Uuid;
use zrotext_root_material::sealed_root_enrollment;

const ORIGIN: &str = "https://gateway.example.test";
type Driver = tokio::task::JoinHandle<std::result::Result<(), tokio_postgres::Error>>;
async fn connect(config: &Config) -> (Client, Driver) {
    let (db, connection) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(connection))
}
async fn close(db: Client, driver: Driver) {
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

// The administrator creates disposable LOGINs/database only. The real numbered
// migrations and fixture writes use their ordinary owner; authentication runs
// with a separate narrowly granted, non-owning runtime LOGIN.
struct Fixture {
    admin: Client,
    admin_driver: Driver,
    owner: Client,
    owner_driver: Driver,
    reader: Client,
    reader_driver: Driver,
    database: String,
    owner_role: String,
    reader_role: String,
    hasher: TokenHasher,
}
impl Fixture {
    async fn new() -> Self {
        let mut config: Config = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL cluster")
            .parse()
            .unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("cookie_auth_{suffix}");
        let owner_role = format!("cookie_owner_{suffix}");
        let reader_role = format!("cookie_reader_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        for role in [&owner_role, &reader_role] {
            admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS", escape_identifier(role), escape_literal(&verifier))).await.unwrap();
        }
        admin
            .batch_execute(&format!(
                "CREATE DATABASE {} OWNER {}",
                escape_identifier(&database),
                escape_identifier(&owner_role)
            ))
            .await
            .unwrap();
        config
            .dbname(&database)
            .user(&owner_role)
            .password(&password);
        let (mut owner, owner_driver) = connect(&config).await;
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/compose/migrations");
        zrotext_migrator::apply(&mut owner, &migrations, false)
            .await
            .unwrap();
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {r}; GRANT SELECT ON public.accounts,public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.users,public.memberships,public.sessions,public.owner_mfa TO {r}; GRANT UPDATE(id) ON public.accounts,public.users,public.sessions TO {r}; GRANT UPDATE(account_id) ON public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.memberships,public.owner_mfa TO {r}",r=escape_identifier(&reader_role))).await.unwrap();
        config.user(&reader_role);
        let (reader, reader_driver) = connect(&config).await;
        assert!(!reader.query_one("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user",&[]).await.unwrap().get::<_,bool>(0));
        assert!(!reader.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace AND relowner=current_user::regrole)",&[]).await.unwrap().get::<_,bool>(0));
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            reader,
            reader_driver,
            database,
            owner_role,
            reader_role,
            hasher: TokenHasher::new(crate::test_keys::key(91)).unwrap(),
        }
    }
    async fn finish(self) {
        close(self.reader, self.reader_driver).await;
        close(self.owner, self.owner_driver).await;
        self.admin
            .batch_execute(&format!(
                "DROP DATABASE {}",
                escape_identifier(&self.database)
            ))
            .await
            .unwrap();
        for role in [&self.owner_role, &self.reader_role] {
            self.admin
                .batch_execute(&format!("DROP ROLE {}", escape_identifier(role)))
                .await
                .unwrap();
        }
        close(self.admin, self.admin_driver).await;
    }
}

struct Seed {
    selector: Selector,
    session: SessionCredentials,
    root_fingerprint: [u8; 32],
}
impl Seed {
    async fn new(db: &Client, hasher: &TokenHasher, role: &str) -> Self {
        let selector = Selector {
            account: Uuid::new_v4(),
            user: Uuid::new_v4(),
            session: Uuid::new_v4(),
        };
        let session = SessionCredentials {
            id: selector.session,
            token: token("zts_"),
            csrf_token: token("ztc_"),
        };
        let hash = hasher.digest(b"session-v1", &session.token);
        let csrf = hasher.digest(b"csrf-v1", &session.csrf_token);
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(selector.account.as_bytes());
        pin.extend_from_slice(&1u64.to_be_bytes());
        pin.extend_from_slice(root.verifying_key().to_sec1_point(false).as_bytes());
        let root_fingerprint =
            sealed_root_enrollment::root_fingerprint(&pin, selector.account.as_bytes()).unwrap();
        static PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let password = PASSWORD.get_or_init(|| {
            use argon2::PasswordHasher;
            argon2::Argon2::default()
                .hash_password(b"cookie-source-fixture")
                .unwrap()
                .to_string()
        });
        let email = format!("owner-{}@example.invalid", selector.user.simple());
        db.execute(
            "INSERT INTO public.accounts(id) VALUES($1)",
            &[&selector.account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO public.users(id,email,password_hash,email_verified_at,mfa_enabled) VALUES($1,$2,$3,clock_timestamp(),TRUE)",&[&selector.user,&email,&password]).await.unwrap();
        db.execute(
            "INSERT INTO public.memberships(account_id,user_id,role) VALUES($1,$2,$3)",
            &[&selector.account, &selector.user, &role],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO public.sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 day')",&[&selector.session,&selector.account,&selector.user,&&hash[..],&&csrf[..]]).await.unwrap();
        // MFA/root rows are synthetic prerequisites, not a fresh MFA or root
        // ceremony. The tested proof authenticates only actual cookie/CSRF HMACs.
        db.execute("INSERT INTO public.owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) VALUES($1,$2,$3,$4,clock_timestamp())",&[&selector.account,&selector.user,&&[2u8;12][..],&&[3u8;36][..]]).await.unwrap();
        db.execute("INSERT INTO public.sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",&[&selector.account,&pin,&&root_fingerprint[..],&&[0u8;32][..]]).await.unwrap();
        Self {
            selector,
            session,
            root_fingerprint,
        }
    }
    fn source(&self) -> RequestSource<'_> {
        RequestSource {
            session_cookie: &self.session.token,
            origin: ORIGIN,
            csrf_cookie: &self.session.csrf_token,
            csrf_header: &self.session.csrf_token,
        }
    }
}

#[test]
fn raw_request_format_and_configured_origin_are_bounded_before_database_access() {
    let session = token("zts_");
    let csrf = token("ztc_");
    let source = RequestSource {
        session_cookie: &session,
        origin: ORIGIN,
        csrf_cookie: &csrf,
        csrf_header: &csrf,
    };
    assert_eq!(
        check_source(ORIGIN, source).unwrap(),
        adapter_contract::origin_digest(ORIGIN).unwrap()
    );
    for cookie in [
        String::new(),
        token("ztk_"),
        format!("{session}="),
        "zts_".repeat(4096),
    ] {
        assert!(matches!(
            check_source(
                ORIGIN,
                RequestSource {
                    session_cookie: &cookie,
                    ..source
                }
            ),
            Err(Error::Refused)
        ));
    }
    for configured in [
        "http://gateway.example.test",
        "https://gateway.example.test/",
        "https://gateway.example.test/path",
    ] {
        assert!(matches!(
            check_source(
                configured,
                RequestSource {
                    origin: configured,
                    ..source
                }
            ),
            Err(Error::Refused)
        ));
    }
    assert!(matches!(
        check_source(
            ORIGIN,
            RequestSource {
                origin: "https://other.example.test",
                ..source
            }
        ),
        Err(Error::Refused)
    ));
    let other_csrf = token("ztc_");
    assert!(matches!(
        check_source(
            ORIGIN,
            RequestSource {
                csrf_header: &other_csrf,
                ..source
            }
        ),
        Err(Error::Refused)
    ));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn actual_cookie_and_csrf_authenticate_without_activity_or_credential_writes() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let before: String = f
        .owner
        .query_one(
            "SELECT row_to_json(s)::text FROM public.sessions s WHERE id=$1",
            &[&s.selector.session],
        )
        .await
        .unwrap()
        .get(0);
    let tx = f.reader.transaction().await.unwrap();
    let mut proof = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let identity = OwnerSessionIdentity03 {
        account_id: *s.selector.account.as_bytes(),
        user_id: *s.selector.user.as_bytes(),
        session_id: *s.selector.session.as_bytes(),
    };
    assert_eq!(proof.canonical_identity(), identity.canonical().unwrap());
    assert_eq!(proof.identity_digest(), &identity.digest().unwrap());
    assert_eq!(
        proof.origin_digest(),
        &adapter_contract::origin_digest(ORIGIN).unwrap()
    );
    assert_eq!(proof.selection_epoch(), 0);
    assert_eq!(proof.root_fingerprint(), &s.root_fingerprint);
    proof.revalidate().await.unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    let after: String = f
        .owner
        .query_one(
            "SELECT row_to_json(s)::text FROM public.sessions s WHERE id=$1",
            &[&s.selector.session],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, after);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn wrong_cookie_pepper_domain_and_foreign_session_csrf_cannot_authenticate() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let other = Seed::new(&f.owner, &f.hasher, "owner").await;
    let absent = token("zts_");
    for source in [
        RequestSource {
            session_cookie: &absent,
            ..s.source()
        },
        RequestSource {
            csrf_cookie: &other.session.csrf_token,
            csrf_header: &other.session.csrf_token,
            ..s.source()
        },
    ] {
        let tx = f.reader.transaction().await.unwrap();
        assert!(matches!(
            authenticate(&tx, &f.hasher, ORIGIN, source).await,
            Err(Error::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    let wrong = TokenHasher::new(crate::test_keys::key(92)).unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        authenticate(&tx, &wrong, ORIGIN, s.source()).await,
        Err(Error::Refused)
    ));
    tx.rollback().await.unwrap();
    let wrong_domain = f.hasher.digest(b"api-key-v1", &s.session.token);
    f.owner
        .execute(
            "UPDATE public.sessions SET token_hash=$2 WHERE id=$1",
            &[&s.selector.session, &&wrong_domain[..]],
        )
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        authenticate(&tx, &f.hasher, ORIGIN, s.source()).await,
        Err(Error::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn valid_cookie_does_not_replace_live_owner_membership_mfa_or_session_state() {
    let mut f = Fixture::new().await;
    let observer = Seed::new(&f.owner, &f.hasher, "observer").await;
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        authenticate(&tx, &f.hasher, ORIGIN, observer.source()).await,
        Err(Error::Records(OwnerRecordsError::Refused))
    ));
    tx.rollback().await.unwrap();
    for change in [
        "UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        "UPDATE public.sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        "UPDATE public.sessions SET created_at=clock_timestamp()-interval '74 hours' WHERE id=$1",
        "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=(SELECT account_id FROM public.sessions WHERE id=$1)",
        "UPDATE public.users SET email_verified_at=NULL WHERE id=(SELECT user_id FROM public.sessions WHERE id=$1)",
        "UPDATE public.users SET mfa_enabled=FALSE WHERE id=(SELECT user_id FROM public.sessions WHERE id=$1)",
        "DELETE FROM public.owner_mfa WHERE user_id=(SELECT user_id FROM public.sessions WHERE id=$1)",
    ] {
        let s = Seed::new(&f.owner, &f.hasher, "owner").await;
        f.owner
            .execute(change, &[&s.selector.session])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(
            matches!(
                authenticate(&tx, &f.hasher, ORIGIN, s.source()).await,
                Err(Error::Records(OwnerRecordsError::Refused))
            ),
            "inactive ordinary owner must refuse"
        );
        tx.rollback().await.unwrap();
    }
    // Owner membership revocation is forbidden by the numbered schema. Exercise
    // the actual supported membership removal and its session/MFA cascades.
    let removed = Seed::new(&f.owner, &f.hasher, "owner").await;
    let error = f
        .owner
        .execute(
            "UPDATE public.memberships SET revoked_at=clock_timestamp() WHERE user_id=$1",
            &[&removed.selector.user],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    f.owner
        .execute(
            "DELETE FROM public.memberships WHERE account_id=$1 AND user_id=$2",
            &[&removed.selector.account, &removed.selector.user],
        )
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        authenticate(&tx, &f.hasher, ORIGIN, removed.source()).await,
        Err(Error::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn committed_token_rotation_between_hint_and_owner_locks_refuses_old_cookie() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let tx = f.reader.transaction().await.unwrap();
    pin(&tx).await.unwrap();
    let hash = f.hasher.digest(b"session-v1", &s.session.token);
    let selector = credential_hint(&tx, &hash).await.unwrap();
    let replacement = f.hasher.digest(b"session-v1", &token("zts_"));
    f.owner
        .execute(
            "UPDATE public.sessions SET token_hash=$2 WHERE id=$1",
            &[&s.selector.session, &&replacement[..]],
        )
        .await
        .unwrap();
    assert!(matches!(
        lock_and_verify(
            &tx,
            &f.hasher,
            ORIGIN,
            s.source(),
            selector,
            &hash,
            check_source(ORIGIN, s.source()).unwrap()
        )
        .await,
        Err(Error::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn held_authentication_refuses_own_transaction_credential_changes() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    for column in ["token_hash", "csrf_hash"] {
        let tx = f.owner.transaction().await.unwrap();
        let mut proof = authenticate(&tx, &f.hasher, ORIGIN, s.source())
            .await
            .unwrap();
        let different = f.hasher.digest(b"fixture-changed", &token("zts_"));
        tx.execute(
            &format!("UPDATE public.sessions SET {column}=$2 WHERE id=$1"),
            &[&s.selector.session, &&different[..]],
        )
        .await
        .unwrap();
        assert!(matches!(
            proof.revalidate().await,
            Err(Error::Records(OwnerRecordsError::Refused))
        ));
        drop(proof);
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn held_cookie_locks_protect_subject_without_blocking_an_unrelated_account() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let other = Seed::new(&f.owner, &f.hasher, "owner").await;
    let tx = f.reader.transaction().await.unwrap();
    let mut proof = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let writer = f.owner.transaction().await.unwrap();
    let error = writer
        .query_one(
            "SELECT id FROM public.sessions WHERE id=$1 FOR UPDATE NOWAIT",
            &[&s.selector.session],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    writer.rollback().await.unwrap();
    f.owner
        .execute(
            "UPDATE public.sessions SET last_used_at=clock_timestamp() WHERE id=$1",
            &[&other.selector.session],
        )
        .await
        .unwrap();
    proof.revalidate().await.unwrap();
    drop(proof);
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn held_cookie_expires_by_observed_primary_clock_without_activity_refresh() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let deadline:i64=f.owner.query_one("UPDATE public.sessions SET expires_at=clock_timestamp()+interval '3 seconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",&[&s.selector.session]).await.unwrap().get(0);
    let tx = f.reader.transaction().await.unwrap();
    let mut proof = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        loop {
            let now:i64=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.unwrap().get(0);
            if now>=deadline {break;}
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }).await.unwrap();
    assert!(matches!(
        proof.revalidate().await,
        Err(Error::Records(OwnerRecordsError::Refused))
    ));
    drop(proof);
    tx.rollback().await.unwrap();
    assert!(
        f.owner
            .query_one(
                "SELECT last_used_at IS NULL FROM public.sessions WHERE id=$1",
                &[&s.selector.session]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn stale_isolation_refuses_and_untrusted_namespace_does_not_supply_authentication() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let tx = f
            .reader
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        assert!(matches!(
            authenticate(&tx, &f.hasher, ORIGIN, s.source()).await,
            Err(Error::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    f.owner.batch_execute("CREATE SCHEMA untrusted; CREATE TABLE untrusted.sessions (LIKE public.sessions); CREATE TABLE untrusted.users (LIKE public.users); CREATE FUNCTION untrusted.clock_timestamp() RETURNS timestamptz LANGUAGE SQL AS 'SELECT to_timestamp(0)'").await.unwrap();
    f.owner
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA untrusted TO {}",
            escape_identifier(&f.reader_role)
        ))
        .await
        .unwrap();
    f.reader
        .batch_execute("SET search_path TO untrusted,public,pg_catalog")
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    let mut proof = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert_eq!(
        tx.query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
    proof.revalidate().await.unwrap();
    drop(proof);
    tx.rollback().await.unwrap();
    f.finish().await;
}
