// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use argon2::{Argon2, PasswordHasher};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, error::SqlState};
type Driver = tokio::task::JoinHandle<std::result::Result<(), tokio_postgres::Error>>;
async fn connect(config: &Config) -> (Client, Driver) {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    (client, tokio::spawn(connection))
}
async fn close(client: Client, driver: Driver) {
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

// Administrative access creates only disposable LOGIN roles/database. All
// migrations and data writes use their ordinary owner; reads use a different
// ordinary role with narrow SELECT and the column privilege required by SHARE.
struct Fixture {
    admin: Client,
    admin_driver: Driver,
    owner: Client,
    owner_driver: Driver,
    reader: Client,
    reader_driver: Driver,
    database: String,
    owner_role: String,
    read_role: String,
}
impl Fixture {
    async fn new() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable test cluster");
        let mut config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("owner_records_{suffix}");
        let owner_role = format!("owner_records_owner_{suffix}");
        let read_role = format!("owner_records_read_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        for role in [&owner_role, &read_role] {
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
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/compose/migrations");
        zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {r}; GRANT SELECT ON public.accounts,public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.users,public.memberships,public.sessions,public.owner_mfa TO {r}; GRANT UPDATE(id) ON public.accounts,public.users,public.sessions TO {r}; GRANT UPDATE(account_id) ON public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.memberships,public.owner_mfa TO {r}", r=escape_identifier(&read_role))).await.unwrap();
        config.user(&read_role);
        let (reader, reader_driver) = connect(&config).await;
        assert!(!reader.query_one("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user", &[]).await.unwrap().get::<_,bool>(0));
        assert!(!reader.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace AND relowner=current_user::regrole)", &[]).await.unwrap().get::<_,bool>(0));
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            reader,
            reader_driver,
            database,
            owner_role,
            read_role,
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
        for role in [&self.read_role, &self.owner_role] {
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
    root_fingerprint: [u8; 32],
}
fn fixture_verifier() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        Argon2::default()
            .hash_password(b"ordinary-owner-record-fixture")
            .unwrap()
            .to_string()
    })
}
impl Seed {
    async fn new(owner: &Client, role: &str) -> Self {
        let selector = Selector {
            account: Uuid::new_v4(),
            user: Uuid::new_v4(),
            session: Uuid::new_v4(),
        };
        let verifier = fixture_verifier();
        let email = format!("owner-{}@example.invalid", selector.user.simple());
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(selector.account.as_bytes());
        pin.extend_from_slice(&1u64.to_be_bytes());
        pin.extend_from_slice(root.verifying_key().to_sec1_point(false).as_bytes());
        let root_fingerprint =
            sealed_root_enrollment::root_fingerprint(&pin, selector.account.as_bytes()).unwrap();
        // These are synthetic stored metadata, not an authenticated cookie or
        // a successful password/TOTP journey. The reader never claims either.
        let token: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
        let csrf: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
        owner
            .execute(
                "INSERT INTO public.accounts(id) VALUES($1)",
                &[&selector.account],
            )
            .await
            .unwrap();
        owner.execute("INSERT INTO public.users(id,email,password_hash,email_verified_at,mfa_enabled) VALUES($1,$2,$3,clock_timestamp(),TRUE)",&[&selector.user,&email,&verifier]).await.unwrap();
        owner
            .execute(
                "INSERT INTO public.memberships(account_id,user_id,role) VALUES($1,$2,$3)",
                &[&selector.account, &selector.user, &role],
            )
            .await
            .unwrap();
        owner.execute("INSERT INTO public.sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 day')",&[&selector.session,&selector.account,&selector.user,&&token[..],&&csrf[..]]).await.unwrap();
        owner.execute("INSERT INTO public.owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) VALUES($1,$2,$3,$4,clock_timestamp())",&[&selector.account,&selector.user,&&[2u8;12][..],&&[3u8;36][..]]).await.unwrap();
        owner.execute("INSERT INTO public.sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",&[&selector.account,&pin,&&root_fingerprint[..],&&[0u8;32][..]]).await.unwrap();
        Self {
            selector,
            root_fingerprint,
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn actual_ordinary_owner_identity_revalidates_with_held_rows_and_null_activity() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    let tx = f.reader.transaction().await.unwrap();
    let mut held = lock(&tx, s.selector).await.unwrap();
    let expected = OwnerSessionIdentity03 {
        account_id: *s.selector.account.as_bytes(),
        user_id: *s.selector.user.as_bytes(),
        session_id: *s.selector.session.as_bytes(),
    };
    assert_eq!(held.canonical_identity(), expected.canonical().unwrap());
    assert_eq!(held.identity_digest(), &expected.digest().unwrap());
    assert_eq!(held.root_fingerprint(), &s.root_fingerprint);
    assert_eq!(held.selection_epoch(), 0);
    held.revalidate().await.unwrap();
    let writer = f.owner.transaction().await.unwrap();
    let e = writer
        .query_one(
            "SELECT id FROM public.sessions WHERE id=$1 FOR UPDATE NOWAIT",
            &[&s.selector.session],
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    writer.rollback().await.unwrap();
    drop(held);
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn copied_owner_role_or_session_uuid_cannot_replace_current_ordinary_records() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    for selector in [
        Selector {
            account: Uuid::new_v4(),
            ..s.selector
        },
        Selector {
            user: Uuid::new_v4(),
            ..s.selector
        },
        Selector {
            session: Uuid::new_v4(),
            ..s.selector
        },
    ] {
        let tx = f.reader.transaction().await.unwrap();
        assert!(matches!(
            lock(&tx, selector).await,
            Err(OwnerRecordsError::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    let observer = Seed::new(&f.owner, "observer").await;
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, observer.selector).await,
        Err(OwnerRecordsError::Refused)
    ));
    tx.rollback().await.unwrap();
    // An isolated reviewer-only UUID is no ordinary session record. This says
    // nothing about credential authentication or cross-realm UUID provenance.
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(
            &tx,
            Selector {
                session: Uuid::new_v4(),
                ..s.selector
            }
        )
        .await,
        Err(OwnerRecordsError::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn inactive_missing_pending_and_future_owner_state_refuses() {
    let mut f = Fixture::new().await;
    for query in [
        "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        "UPDATE public.users SET email_verified_at=NULL WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.users SET mfa_enabled=FALSE WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE public.sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE account_id=$1",
        "UPDATE public.sessions SET last_used_at=clock_timestamp()+interval '1 hour' WHERE account_id=$1",
        "UPDATE public.sessions SET created_at=clock_timestamp()+interval '1 hour' WHERE account_id=$1",
        "UPDATE public.users SET email_verified_at=clock_timestamp()+interval '1 hour' WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.owner_mfa SET enabled_at=clock_timestamp()+interval '1 hour' WHERE account_id=$1",
        "UPDATE public.owner_mfa SET enabled_at=NULL,pending_expires_at=clock_timestamp()+interval '1 minute',pending_session_id=gen_random_uuid() WHERE account_id=$1",
        "DELETE FROM public.owner_mfa WHERE account_id=$1",
        "DELETE FROM public.sessions WHERE account_id=$1",
        "DELETE FROM public.memberships WHERE account_id=$1",
        "UPDATE public.sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "DELETE FROM public.sealed_manifest_authorities WHERE account_id=$1",
    ] {
        let s = Seed::new(&f.owner, "owner").await;
        f.owner
            .execute(query, &[&s.selector.account])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(
            matches!(lock(&tx, s.selector).await, Err(OwnerRecordsError::Refused)),
            "{query}"
        );
        tx.rollback().await.unwrap();
    }
    let s = Seed::new(&f.owner, "owner").await;
    f.owner
        .batch_execute("ALTER TABLE public.payload_profile_account_anchors DISABLE TRIGGER USER")
        .await
        .unwrap();
    f.owner
        .execute(
            "DELETE FROM public.payload_profile_account_anchors WHERE account_id=$1",
            &[&s.selector.account],
        )
        .await
        .unwrap();
    f.owner
        .batch_execute("ALTER TABLE public.payload_profile_account_anchors ENABLE TRIGGER USER")
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, s.selector).await,
        Err(OwnerRecordsError::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn inactivity_uses_real_last_activity_or_creation_and_refuses_stale_windows() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    f.owner.execute("UPDATE public.sessions SET created_at=clock_timestamp()-interval '73 hours',last_used_at=NULL WHERE id=$1",&[&s.selector.session]).await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, s.selector).await,
        Err(OwnerRecordsError::Refused)
    ));
    tx.rollback().await.unwrap();
    f.owner
        .execute(
            "UPDATE public.sessions SET last_used_at=clock_timestamp() WHERE id=$1",
            &[&s.selector.session],
        )
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(lock(&tx, s.selector).await.is_ok());
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn same_transaction_credentials_and_precise_timestamps_cannot_revalidate_stale_records() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    for query in [
        "UPDATE public.users SET password_hash=password_hash||'changed' WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.users SET email='changed@example.invalid' WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.sessions SET token_hash=decode(repeat('04',32),'hex') WHERE account_id=$1",
        "UPDATE public.sessions SET csrf_hash=decode(repeat('05',32),'hex') WHERE account_id=$1",
        "UPDATE public.owner_mfa SET secret_nonce=decode(repeat('06',12),'hex') WHERE account_id=$1",
        "UPDATE public.owner_mfa SET secret_ciphertext=decode(repeat('07',36),'hex') WHERE account_id=$1",
        "UPDATE public.sessions SET expires_at=expires_at+interval '1 microsecond' WHERE account_id=$1",
        "UPDATE public.sessions SET last_used_at=created_at WHERE account_id=$1",
        "UPDATE public.users SET email_verified_at=email_verified_at-interval '1 microsecond' WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1)",
        "UPDATE public.owner_mfa SET enabled_at=enabled_at-interval '1 microsecond' WHERE account_id=$1",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.execute("UPDATE public.sessions SET expires_at=pg_catalog.date_trunc('milliseconds',pg_catalog.clock_timestamp()+interval '1 day') WHERE account_id=$1",&[&s.selector.account]).await.unwrap();
        let mut held = lock(&tx, s.selector).await.unwrap();
        tx.execute(query, &[&s.selector.account]).await.unwrap();
        assert!(
            matches!(held.revalidate().await, Err(OwnerRecordsError::Refused)),
            "{query}"
        );
        drop(held);
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn owner_record_fences_refuse_with_unrelated_account_progress() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    let other = Seed::new(&f.owner, "owner").await;
    let key = adapter_contract::account_fence_key(s.selector.account.as_bytes()).unwrap();
    let writer = f.owner.transaction().await.unwrap();
    writer
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&key])
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, s.selector).await,
        Err(OwnerRecordsError::Busy)
    ));
    tx.rollback().await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(lock(&tx, other.selector).await.is_ok());
    tx.rollback().await.unwrap();
    writer.rollback().await.unwrap();
    for query in [
        "SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE",
        "SELECT id FROM public.accounts WHERE id=$1 FOR UPDATE",
        "SELECT user_id FROM public.memberships WHERE account_id=$1 FOR UPDATE",
        "SELECT id FROM public.users WHERE id=(SELECT user_id FROM public.memberships WHERE account_id=$1) FOR UPDATE",
        "SELECT id FROM public.sessions WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.owner_mfa WHERE account_id=$1 FOR UPDATE",
    ] {
        let writer = f.owner.transaction().await.unwrap();
        writer
            .query_one(query, &[&s.selector.account])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(
            matches!(lock(&tx,s.selector).await,Err(OwnerRecordsError::Database(ref e)) if e.code()==Some(&SqlState::LOCK_NOT_AVAILABLE)),
            "{query}"
        );
        tx.rollback().await.unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(lock(&tx, other.selector).await.is_ok());
        tx.rollback().await.unwrap();
        writer.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn old_isolation_and_mutable_reader_credentials_do_not_create_owner_authority() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let tx = f
            .reader
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        assert!(matches!(
            lock(&tx, s.selector).await,
            Err(OwnerRecordsError::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    assert_eq!(
        f.reader
            .execute(
                "UPDATE public.sessions SET token_hash=decode(repeat('08',32),'hex') WHERE id=$1",
                &[&s.selector.session]
            )
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn owner_namespace_and_operator_shadows_never_supply_records_or_time() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, "owner").await;
    f.owner.batch_execute("CREATE SCHEMA owner_operator_shadow; CREATE FUNCTION owner_operator_shadow.forge_clock(numeric,integer) RETURNS numeric LANGUAGE sql IMMUTABLE STRICT AS 'SELECT 9000000000000::numeric'; CREATE OPERATOR owner_operator_shadow.* (LEFTARG=numeric,RIGHTARG=integer,FUNCTION=owner_operator_shadow.forge_clock)").await.unwrap();
    f.owner
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA owner_operator_shadow TO {}",
            escape_identifier(&f.read_role)
        ))
        .await
        .unwrap();
    f.reader.batch_execute("CREATE TEMP TABLE sessions(fake boolean); CREATE TEMP TABLE owner_mfa(fake boolean); SET search_path=owner_operator_shadow,pg_temp,pg_catalog").await.unwrap();
    let query =
        "SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint";
    assert_eq!(
        f.reader
            .query_one(query, &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        9_000_000_000_000
    );
    let tx = f.reader.transaction().await.unwrap();
    let mut held = lock(&tx, s.selector).await.unwrap();
    held.revalidate().await.unwrap();
    drop(held);
    tx.rollback().await.unwrap();
    assert_eq!(
        f.reader
            .query_one(query, &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        9_000_000_000_000
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn actual_primary_expiry_and_idle_boundaries_refuse_while_rows_stay_locked() {
    let mut f = Fixture::new().await;
    for expiry in [true, false] {
        let s = Seed::new(&f.owner, "owner").await;
        let query = if expiry {
            "UPDATE public.sessions SET expires_at=clock_timestamp()+interval '10 seconds' WHERE id=$1"
        } else {
            "UPDATE public.sessions SET last_used_at=clock_timestamp()-interval '72 hours'+interval '10 seconds' WHERE id=$1"
        };
        f.owner
            .execute(query, &[&s.selector.session])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        let mut held = lock(&tx, s.selector).await.unwrap();
        let cutoff = if expiry {
            held.records.expiry_ms
        } else {
            held.records.activity_ms + IDLE_MS
        };
        let observed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let now = clock(&tx, held.checked_ms).await.unwrap();
                if now >= cutoff {
                    break now;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("actual primary temporal boundary within finite fixture wait");
        assert!(observed >= cutoff);
        let result = held.revalidate().await;
        assert!(
            matches!(&result, Err(OwnerRecordsError::Refused)),
            "expiry={expiry}; primary={observed}; cutoff={cutoff}; result={result:?}"
        );
        drop(held);
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}
