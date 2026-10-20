// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use postgres_protocol::escape::{escape_identifier, escape_literal};
use sha2::{Digest, Sha256};
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
        let database = format!("context_{suffix}");
        let owner_role = format!("context_owner_{suffix}");
        let read_role = format!("context_read_{suffix}");
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
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {r}; GRANT SELECT ON public.accounts,public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.devices,public.device_keys,public.device_sessions,public.sites,public.deployment_authority TO {r}; GRANT UPDATE(id) ON public.accounts,public.devices TO {r}; GRANT UPDATE(account_id) ON public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.device_keys,public.device_sessions TO {r}; GRANT UPDATE(site_id) ON public.sites TO {r}; GRANT UPDATE(singleton) ON public.deployment_authority TO {r}", r=escape_identifier(&read_role))).await.unwrap();
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
    point: Vec<u8>,
    fingerprint: [u8; 32],
    root_fingerprint: [u8; 32],
}
impl Seed {
    async fn new(owner: &Client) -> Self {
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let site = format!("context-{}", Uuid::new_v4().simple());
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let device_key = SigningKey::generate_from_rng(&mut rand::rng());
        let point = device_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let fingerprint: [u8; 32] = Sha256::digest(&point).into();
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(account.as_bytes());
        pin.extend_from_slice(&1u64.to_be_bytes());
        pin.extend_from_slice(root.verifying_key().to_sec1_point(false).as_bytes());
        let root_fingerprint =
            sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes()).unwrap();
        owner
            .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        owner
            .execute("INSERT INTO public.sites(site_id) VALUES($1)", &[&site])
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                &[&device, &account],
            )
            .await
            .unwrap();
        owner.execute("INSERT INTO public.device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",&[&device,&account,&point,&&fingerprint[..]]).await.unwrap();
        owner.execute("INSERT INTO public.sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",&[&account,&pin,&&root_fingerprint[..],&&[0u8;32][..]]).await.unwrap();
        owner.execute("INSERT INTO public.device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,line_activation_version,lease_until) VALUES($1,$2,$3,'synthetic-instance',7,1,2,clock_timestamp()+interval '1 hour')",&[&device,&account,&site]).await.unwrap();
        Self {
            selector: Selector {
                account,
                device,
                site,
                instance: "synthetic-instance".into(),
                connection_epoch: 7,
                deployment_epoch: 1,
            },
            point,
            fingerprint,
            root_fingerprint,
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn held_actual_device_identity_is_complete_and_revalidates_in_its_transaction() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    let tx = f.reader.transaction().await.unwrap();
    let mut held = lock(&tx, &s.selector).await.unwrap();
    let signing_key_id =
        adapter_contract::enrollment_signing_key_id(&s.point, &s.fingerprint).unwrap();
    let expected = DeviceSessionIdentity03 {
        account_id: *s.selector.account.as_bytes(),
        device_id: *s.selector.device.as_bytes(),
        site_id: &s.selector.site,
        instance_id: &s.selector.instance,
        connection_epoch: 7,
        deployment_epoch: 1,
        line_activation_version: 2,
        enrollment_signing_key_id: signing_key_id,
    };
    assert_eq!(held.canonical_identity(), expected.canonical().unwrap());
    assert_eq!(held.identity_digest(), &expected.digest().unwrap());
    assert_eq!(held.root_fingerprint(), &s.root_fingerprint);
    assert_eq!(held.enrollment_signing_key_id(), &signing_key_id);
    assert_eq!(held.selection_epoch(), 0);
    held.revalidate().await.unwrap();
    drop(held);
    tx.rollback().await.unwrap();
    // Rolling the actual transaction back releases the retained account fence.
    let key = adapter_contract::account_fence_key(s.selector.account.as_bytes()).unwrap();
    let tx = f.owner.transaction().await.unwrap();
    assert!(
        tx.query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn every_full_lease_expectation_is_checked_against_persisted_rows() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    let mut wrong = Vec::new();
    let mut p = s.selector.clone();
    p.account = Uuid::new_v4();
    wrong.push(p);
    let mut p = s.selector.clone();
    p.device = Uuid::new_v4();
    wrong.push(p);
    let mut p = s.selector.clone();
    p.site = "other-site".into();
    wrong.push(p);
    let mut p = s.selector.clone();
    p.instance = "other-instance".into();
    wrong.push(p);
    let mut p = s.selector.clone();
    p.connection_epoch += 1;
    wrong.push(p);
    let mut p = s.selector.clone();
    p.deployment_epoch += 1;
    wrong.push(p);
    for p in wrong {
        let tx = f.reader.transaction().await.unwrap();
        assert!(matches!(lock(&tx, &p).await, Err(ContextError::Refused)));
        tx.rollback().await.unwrap();
    }
    // Protocol admission cannot be inherited from the copied three-field
    // DeviceSession: use a real newly claimed epoch with version one.
    f.owner.execute("UPDATE public.device_sessions SET connection_epoch=8,line_activation_version=1 WHERE device_id=$1",&[&s.selector.device]).await.unwrap();
    let mut version_one = s.selector.clone();
    version_one.connection_epoch = 8;
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, &version_one).await,
        Err(ContextError::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn inactive_lease_sources_missing_anchors_and_malformed_enrollment_refuse() {
    let mut f = Fixture::new().await;
    for query in [
        "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        "UPDATE public.devices SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE public.device_keys SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE public.sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "DELETE FROM public.sealed_manifest_authorities WHERE account_id=$1",
        "UPDATE public.device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE account_id=$1",
        "UPDATE public.device_sessions SET account_id=NULL WHERE account_id=$1",
    ] {
        let s = Seed::new(&f.owner).await;
        f.owner
            .execute(query, &[&s.selector.account])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(
            matches!(lock(&tx, &s.selector).await, Err(ContextError::Refused)),
            "{query}"
        );
        tx.rollback().await.unwrap();
    }
    for query in [
        "UPDATE public.sites SET enabled=FALSE WHERE site_id=$1",
        "UPDATE public.sites SET draining=TRUE WHERE site_id=$1",
    ] {
        let s = Seed::new(&f.owner).await;
        f.owner.execute(query, &[&s.selector.site]).await.unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(matches!(
            lock(&tx, &s.selector).await,
            Err(ContextError::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    let s = Seed::new(&f.owner).await;
    // Disposable owner corruption only: application immutability and grants
    // are unchanged, including the runtime's inability to alter these guards.
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
        lock(&tx, &s.selector).await,
        Err(ContextError::Refused)
    ));
    tx.rollback().await.unwrap();
    let s = Seed::new(&f.owner).await;
    let invalid = vec![4u8; 65];
    let invalid_fingerprint: [u8; 32] = Sha256::digest(&invalid).into();
    f.owner
        .execute(
            "UPDATE public.device_keys SET signing_key_sec1=$1,fingerprint=$2 WHERE device_id=$3",
            &[&invalid, &&invalid_fingerprint[..], &s.selector.device],
        )
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, &s.selector).await,
        Err(ContextError::Refused)
    ));
    tx.rollback().await.unwrap();
    let s = Seed::new(&f.owner).await;
    f.owner
        .batch_execute("UPDATE public.deployment_authority SET epoch=2")
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, &s.selector).await,
        Err(ContextError::Refused)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn held_advisory_and_account_rows_refuse_without_blocking_another_account() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    let other = Seed::new(&f.owner).await;
    let key = adapter_contract::account_fence_key(s.selector.account.as_bytes()).unwrap();
    let writer = f.owner.transaction().await.unwrap();
    writer
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&key])
        .await
        .unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(matches!(
        lock(&tx, &s.selector).await,
        Err(ContextError::Busy)
    ));
    tx.rollback().await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    assert!(lock(&tx, &other.selector).await.is_ok());
    tx.rollback().await.unwrap();
    writer.rollback().await.unwrap();
    for query in [
        "SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE",
        "SELECT id FROM public.accounts WHERE id=$1 FOR UPDATE",
        "SELECT id FROM public.devices WHERE account_id=$1 FOR UPDATE",
        "SELECT device_id FROM public.device_keys WHERE account_id=$1 FOR UPDATE",
        "SELECT device_id FROM public.device_sessions WHERE account_id=$1 FOR UPDATE",
    ] {
        let writer = f.owner.transaction().await.unwrap();
        writer
            .query_one(query, &[&s.selector.account])
            .await
            .unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(
            matches!(lock(&tx,&s.selector).await,Err(ContextError::Database(ref e)) if e.code()==Some(&SqlState::LOCK_NOT_AVAILABLE)),
            "{query}"
        );
        tx.rollback().await.unwrap();
        let tx = f.reader.transaction().await.unwrap();
        assert!(lock(&tx, &other.selector).await.is_ok());
        tx.rollback().await.unwrap();
        writer.rollback().await.unwrap();
    }
    // The witness retains every acquired tuple lock through its transaction.
    let tx = f.reader.transaction().await.unwrap();
    let held = lock(&tx, &s.selector).await.unwrap();
    let writer = f.owner.transaction().await.unwrap();
    let error = writer
        .query_one(
            "SELECT device_id FROM public.device_sessions WHERE device_id=$1 FOR UPDATE NOWAIT",
            &[&s.selector.device],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    writer.rollback().await.unwrap();
    drop(held);
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn stale_isolation_and_same_transaction_identity_changes_never_revalidate() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let tx = f
            .reader
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        assert!(matches!(
            lock(&tx, &s.selector).await,
            Err(ContextError::Refused)
        ));
        tx.rollback().await.unwrap();
    }
    // The ordinary reader has no mutation permission on lease or key state.
    assert_eq!(
        f.reader
            .execute(
                "UPDATE public.device_sessions SET instance_id='forged' WHERE device_id=$1",
                &[&s.selector.device]
            )
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    // A transaction owner can change its OWN held rows, so revalidation must
    // inspect them again rather than assuming row locks imply unchanged data.
    let tx = f.owner.transaction().await.unwrap();
    let mut held = lock(&tx, &s.selector).await.unwrap();
    tx.execute(
        "UPDATE public.device_sessions SET instance_id='changed' WHERE device_id=$1",
        &[&s.selector.device],
    )
    .await
    .unwrap();
    assert!(matches!(
        held.revalidate().await,
        Err(ContextError::Refused)
    ));
    drop(held);
    tx.rollback().await.unwrap();
    let tx = f.owner.transaction().await.unwrap();
    let mut held = lock(&tx, &s.selector).await.unwrap();
    tx.execute("UPDATE public.device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=$1",&[&s.selector.device]).await.unwrap();
    assert!(matches!(
        held.revalidate().await,
        Err(ContextError::Refused)
    ));
    drop(held);
    tx.rollback().await.unwrap();
    // Still-live mutations must reach exact Rows comparison, not merely fail
    // expiry. Start on a millisecond boundary to prove +1us is not rounded up.
    for (query, same_millisecond) in [
        (
            "UPDATE public.device_sessions SET lease_until=lease_until+interval '1 microsecond' WHERE device_id=$1",
            true,
        ),
        (
            "UPDATE public.device_sessions SET lease_until=lease_until+interval '1 second' WHERE device_id=$1",
            false,
        ),
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.execute("UPDATE public.device_sessions SET lease_until=pg_catalog.date_trunc('milliseconds',pg_catalog.clock_timestamp()+interval '1 hour') WHERE device_id=$1",&[&s.selector.device]).await.unwrap();
        let mut held = lock(&tx, &s.selector).await.unwrap();
        tx.execute(query, &[&s.selector.device]).await.unwrap();
        let actual=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM lease_until)*1000)::bigint,pg_catalog.timestamptz_send(lease_until),lease_until>pg_catalog.clock_timestamp() FROM public.device_sessions WHERE device_id=$1",&[&s.selector.device]).await.unwrap();
        assert!(actual.get::<_, bool>(2));
        if same_millisecond {
            assert_eq!(actual.get::<_, i64>(0) as u64, held.rows.lease_until_ms);
        }
        assert_ne!(actual.get::<_, Vec<u8>>(1), held.rows.lease_until_wire);
        assert!(matches!(
            held.revalidate().await,
            Err(ContextError::Refused)
        ));
        drop(held);
        tx.rollback().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn namespace_and_operator_shadows_cannot_change_current_device_identity() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    f.owner.batch_execute("CREATE SCHEMA device_operator_shadow; CREATE FUNCTION device_operator_shadow.forge_clock(numeric,integer) RETURNS numeric LANGUAGE sql IMMUTABLE STRICT AS 'SELECT 9000000000000::numeric'; CREATE OPERATOR device_operator_shadow.* (LEFTARG=numeric,RIGHTARG=integer,FUNCTION=device_operator_shadow.forge_clock)").await.unwrap();
    f.owner
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA device_operator_shadow TO {}",
            escape_identifier(&f.read_role)
        ))
        .await
        .unwrap();
    f.reader.batch_execute("CREATE TEMP TABLE device_sessions(fake boolean); CREATE TEMP TABLE device_keys(fake boolean); SET search_path=device_operator_shadow,pg_temp,pg_catalog").await.unwrap();
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
    let mut held = lock(&tx, &s.selector).await.unwrap();
    assert_eq!(
        tx.query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
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
async fn naturally_expired_lease_is_refused_even_while_every_tuple_stays_locked() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    f.owner.execute("UPDATE public.device_sessions SET lease_until=clock_timestamp()+interval '10 seconds' WHERE device_id=$1",&[&s.selector.device]).await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    let mut held = lock(&tx, &s.selector).await.unwrap();
    // transaction_timeout was added after PG16. This optional diagnostic must
    // not abort the real lease-expiry test on an otherwise supported backend.
    let settings=tx.query_one("SELECT pg_catalog.current_setting('idle_in_transaction_session_timeout'),pg_catalog.current_setting('transaction_timeout',true),pg_catalog.current_setting('statement_timeout')",&[]).await.unwrap();
    let limits = (
        settings.get::<_, String>(0),
        settings.get::<_, Option<String>>(1),
        settings.get::<_, String>(2),
    );
    let initial_clock = held.checked_ms;
    // A host timer and the container's primary clock need not advance at the
    // same rate. Observe the actual ten-second DB deadline while retaining all
    // tuple locks; the fixture wait is finite and changes no runtime deadline.
    let observed_clock=tokio::time::timeout(std::time::Duration::from_secs(30),async {
        loop {
            let now=clock(&tx,initial_clock).await.unwrap();
            if now>=held.rows.lease_until_ms { break now; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }).await.unwrap_or_else(|_|panic!("primary clock did not reach lease deadline within fixture wait: initial={initial_clock}; lease_cutoff={}; timeouts={limits:?}",held.rows.lease_until_ms));
    let revalidated = held.revalidate().await;
    assert!(
        observed_clock >= held.rows.lease_until_ms,
        "primary clock has not demonstrated expiry: revalidation={revalidated:?}; observed_clock={observed_clock:?}; initial_clock={initial_clock}; lease_cutoff={}; timeouts={limits:?}",
        held.rows.lease_until_ms
    );
    assert!(
        matches!(&revalidated, Err(ContextError::Refused)),
        "revalidation={revalidated:?}; observed_clock={observed_clock:?}; initial_clock={initial_clock}; lease_cutoff={}; timeouts={limits:?}",
        held.rows.lease_until_ms
    );
    drop(held);
    tx.rollback().await.unwrap();
    f.finish().await;
}
