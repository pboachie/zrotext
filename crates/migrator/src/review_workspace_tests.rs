// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::{Config, NoTls};

const BROKER: &str = "10000000-0000-4000-8000-000000000003";
const SESSION: &str = "10000000-0000-4000-8000-000000000004";
const EVENT: &str = "10000000-0000-4000-8000-000000000005";
const CREDENTIAL: &str = "10000000-0000-4000-8000-000000000009";
const ATTEMPT: &str = "10000000-0000-4000-8000-000000000006";
const ACCOUNT: &str = "10000000-0000-4000-8000-000000000007";
const USER: &str = "10000000-0000-4000-8000-000000000008";

async fn connect(config: &Config) -> (Client, tokio::task::JoinHandle<()>) {
    let (db, driver) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(async move { driver.await.unwrap() }))
}

async fn close(db: Client, driver: tokio::task::JoinHandle<()>) {
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap();
}

struct Fixture {
    admin: Client,
    admin_driver: tokio::task::JoinHandle<()>,
    db: Client,
    driver: tokio::task::JoinHandle<()>,
    config: Config,
    database: String,
    role: String,
}

impl Fixture {
    async fn create() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
        let mut config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let row = admin.query_one("SELECT replace(gen_random_uuid()::text,'-',''),replace(gen_random_uuid()::text,'-','')", &[]).await.unwrap();
        let suffix: String = row.get(0);
        let password: String = row.get(1);
        let role = format!("zt_review_owner_{suffix}");
        let database = format!("zt_review_{suffix}");
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        admin.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{verifier}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION")).await.unwrap();
        admin
            .batch_execute(&format!("CREATE DATABASE {database} OWNER {role}"))
            .await
            .unwrap();
        config.dbname(&database).user(&role).password(password);
        let (mut db, driver) = connect(&config).await;
        db.batch_execute("SET statement_timeout='10s'; SET lock_timeout='3s'")
            .await
            .unwrap();
        assert!(
            !db.query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
        let applied = apply(&mut db, &directory, false).await.unwrap();
        assert_eq!(applied.last().unwrap().version, 107);
        let ledger: String = db.query_one("SELECT json_agg(json_build_array(version,checksum_sha256,applied_at::text) ORDER BY version)::text FROM schema_migrations", &[]).await.unwrap().get(0);
        assert!(apply(&mut db, &directory, false).await.unwrap().is_empty());
        let replay: String = db.query_one("SELECT json_agg(json_build_array(version,checksum_sha256,applied_at::text) ORDER BY version)::text FROM schema_migrations", &[]).await.unwrap().get(0);
        assert_eq!(ledger, replay);
        assert_eq!(count(&db, "review_realm_installation").await, 0);
        db.batch_execute(&format!(r#"
            INSERT INTO review_realm_installation(realm_id,database_id,origin,deployment_digest,service_digest,
                auth_key_digest,enrollment_key_digest,reauthentication_key_digest,grant_key_digest,mfa_key_digest)
              VALUES('10000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000002','https://review.invalid',
                decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),
                decode(repeat('04',32),'hex'),decode(repeat('05',32),'hex'),decode(repeat('06',32),'hex'),decode(repeat('07',32),'hex'));
            INSERT INTO review_brokers(id,realm_id,credential_id,credential_revision,password_verifier)
              VALUES('{BROKER}','10000000-0000-4000-8000-000000000001','{CREDENTIAL}',1,'fixture-only');
            SELECT review_workspace_broker_session_create('{BROKER}','{SESSION}','{EVENT}',1,
                decode(repeat('08',32),'hex'),decode(repeat('09',32),'hex'),'https://review.invalid');
        "#)).await.unwrap();
        Self {
            admin,
            admin_driver,
            db,
            driver,
            config,
            database,
            role,
        }
    }

    async fn finish(self) {
        close(self.db, self.driver).await;
        self.admin
            .batch_execute(&format!("DROP DATABASE {}", self.database))
            .await
            .unwrap();
        self.admin
            .batch_execute(&format!("DROP ROLE {}", self.role))
            .await
            .unwrap();
        close(self.admin, self.admin_driver).await;
    }
}

async fn count(db: &Client, table: &str) -> i64 {
    // All identifiers come from fixed test literals, never production requests.
    db.query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap()
        .get(0)
}

fn reserve() -> String {
    format!(
        "SELECT review_workspace_reserve('{ATTEMPT}','{ACCOUNT}','{USER}','{SESSION}','{EVENT}',1,decode(repeat('0a',32),'hex'),decode(repeat('0b',32),'hex'),'https://review.invalid')"
    )
}

fn provision() -> String {
    format!(
        "SELECT * FROM review_workspace_provision('{ATTEMPT}','{SESSION}','{EVENT}',1,decode(repeat('0a',32),'hex'),decode(repeat('0b',32),'hex'),'https://review.invalid')"
    )
}

async fn rejects(db: &Client, sql: &str, code: &str) {
    let error = db.batch_execute(sql).await.unwrap_err();
    assert_eq!(error.code().map(|c| c.code()), Some(code), "{error}");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_workspace_factory_is_atomic_exact_scoped_unloginable_and_erased() {
    let f = Fixture::create().await;
    for mode in ["REPEATABLE READ", "SERIALIZABLE"] {
        f.db.batch_execute(&format!("BEGIN ISOLATION LEVEL {mode}"))
            .await
            .unwrap();
        rejects(&f.db, &reserve(), "25001").await;
        f.db.batch_execute("ROLLBACK").await.unwrap();
    }
    f.db.batch_execute(&reserve()).await.unwrap();
    for (from, to) in [
        (EVENT, "10000000-0000-4000-8000-000000000099"),
        ("repeat('0a',32)", "repeat('0c',32)"),
        ("repeat('0b',32)", "repeat('0c',32)"),
        ("https://review.invalid", "https://other.invalid"),
    ] {
        rejects(&f.db, &provision().replace(from, to), "23514").await;
    }
    rejects(
        &f.db,
        &provision().replace(&format!("'{EVENT}'"), "NULL"),
        "23514",
    )
    .await;
    for mode in ["REPEATABLE READ", "SERIALIZABLE"] {
        f.db.batch_execute(&format!("BEGIN ISOLATION LEVEL {mode}"))
            .await
            .unwrap();
        rejects(&f.db, &provision(), "25001").await;
        f.db.batch_execute("ROLLBACK").await.unwrap();
    }
    // Force a failure after each fresh write using a unique, disposable owner
    // trigger. No test hook is installed in the application migration.
    f.db.batch_execute("CREATE FUNCTION reject_fixture_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture write rejected' USING ERRCODE='23514'; END $$").await.unwrap();
    for table in [
        "users",
        "memberships",
        "review_workspaces",
        "review_bootstrap_attempts",
    ] {
        let operation = if table == "review_bootstrap_attempts" {
            "UPDATE"
        } else {
            "INSERT"
        };
        f.db.batch_execute(&format!("CREATE TRIGGER reject_fixture BEFORE {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION reject_fixture_write()" )).await.unwrap();
        rejects(&f.db, &provision(), "23514").await;
        for empty in [
            "accounts",
            "users",
            "memberships",
            "review_workspaces",
            "payload_profile_account_anchors",
        ] {
            assert_eq!(
                count(&f.db, empty).await,
                0,
                "atomic rollback: {table}/{empty}"
            );
        }
        assert_eq!(count(&f.db, "review_bootstrap_attempts").await, 1);
        f.db.batch_execute(&format!("DROP TRIGGER reject_fixture ON {table}"))
            .await
            .unwrap();
    }
    f.db.batch_execute(&provision()).await.unwrap();
    for operation in [
        provision(),
        format!("SELECT review_workspace_attempt_cleanup('{ATTEMPT}')"),
        format!("DELETE FROM users WHERE id='{USER}'"),
    ] {
        // A corrupt missing anchor is never an existing-account fallback. Only
        // the disposable owner removes it; rollback restores all metadata.
        f.db.batch_execute("BEGIN; ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change; DELETE FROM payload_profile_account_anchors").await.unwrap();
        rejects(&f.db, &operation, "23514").await;
        f.db.batch_execute("ROLLBACK").await.unwrap();
    }
    let result: String =
        f.db.query_one(
            "SELECT row_to_json(a)::text FROM review_bootstrap_attempts a",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for mode in ["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"] {
        f.db.batch_execute(&format!(
            "BEGIN ISOLATION LEVEL {mode}; {} ; COMMIT",
            provision()
        ))
        .await
        .unwrap();
    }
    let repeated: String =
        f.db.query_one(
            "SELECT row_to_json(a)::text FROM review_bootstrap_attempts a",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        result, repeated,
        "exact retry does not refresh result/expiry"
    );
    let user =
        f.db.query_one(
            "SELECT password_hash,email_verified_at IS NULL,mfa_enabled FROM users",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(user.get::<_, String>(0), "!");
    assert!(user.get::<_, bool>(1));
    assert!(!user.get::<_, bool>(2));
    assert_eq!(count(&f.db, "sessions").await, 0);
    assert_eq!(count(&f.db, "owner_mfa").await, 0);
    f.db.batch_execute(&format!("DELETE FROM users WHERE id='{USER}'"))
        .await
        .unwrap();
    assert_eq!(count(&f.db, "review_bootstrap_attempts").await, 0);
    assert_eq!(count(&f.db, "review_workspaces").await, 0);
    f.db.batch_execute(&format!("DELETE FROM accounts WHERE id='{ACCOUNT}'"))
        .await
        .unwrap();
    assert_eq!(count(&f.db, "payload_profile_account_anchors").await, 1);
    rejects(&f.db, &reserve(), "23514").await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_prospective_identity_collision_refuses_without_attaching_or_deleting_other_rows() {
    for table in ["accounts", "users"] {
        let f = Fixture::create().await;
        let (other, other_driver) = connect(&f.config).await;
        other
            .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT count(*) FROM accounts")
            .await
            .unwrap();
        f.db.batch_execute(&reserve()).await.unwrap();
        if table == "accounts" {
            other
                .batch_execute(&format!("INSERT INTO accounts(id) VALUES('{ACCOUNT}')"))
                .await
                .unwrap();
        } else {
            other.batch_execute(&format!("INSERT INTO users(id,email,password_hash) VALUES('{USER}','other@review.invalid','!')")).await.unwrap();
        }
        other.batch_execute("COMMIT").await.unwrap();
        rejects(&f.db, &provision(), "23514").await;
        assert_eq!(count(&f.db, table).await, 1);
        assert_eq!(count(&f.db, "review_workspaces").await, 0);
        assert_eq!(count(&f.db, "review_bootstrap_attempts").await, 1);
        f.db.batch_execute("ALTER TABLE review_bootstrap_attempts DISABLE TRIGGER review_workspace_identity_before_update;
            UPDATE review_bootstrap_attempts SET issued_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-7200000,
                expires_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-6900000,
                reconcile_until_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint+86400000;
            ALTER TABLE review_bootstrap_attempts ENABLE TRIGGER review_workspace_identity_before_update").await.unwrap();
        assert!(
            f.db.query_one(
                &format!("SELECT review_workspace_attempt_cleanup('{ATTEMPT}')"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        assert_eq!(
            count(&f.db, table).await,
            1,
            "cleanup leaves unrelated occupied parent untouched"
        );
        if table == "accounts" {
            other
                .batch_execute(&format!("DELETE FROM accounts WHERE id='{ACCOUNT}'"))
                .await
                .unwrap();
            rejects(&f.db, &reserve(), "23514").await;
        }
        close(other, other_driver).await;
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_workspace_broker_and_account_lock_contention_refuses_without_conversion() {
    let f = Fixture::create().await;
    f.db.batch_execute(&reserve()).await.unwrap();
    let (other, other_driver) = connect(&f.config).await;
    other
        .batch_execute(&format!(
            "BEGIN; SELECT id FROM review_brokers WHERE id='{BROKER}' FOR SHARE"
        ))
        .await
        .unwrap();
    rejects(&f.db, &provision(), "55P03").await;
    other.batch_execute("ROLLBACK").await.unwrap();
    other
        .batch_execute(&format!(
            "BEGIN; SELECT pg_advisory_xact_lock(payload_profile_account_fence_key('{ACCOUNT}'))"
        ))
        .await
        .unwrap();
    rejects(&f.db, &provision(), "55P03").await;
    other.batch_execute("ROLLBACK").await.unwrap();
    f.db.batch_execute("BEGIN; UPDATE review_broker_sessions SET last_used_ms=(EXTRACT(epoch FROM clock_timestamp())*1000)::bigint+60000").await.unwrap();
    rejects(&f.db, &provision(), "23514").await;
    f.db.batch_execute("ROLLBACK").await.unwrap();
    f.db.batch_execute(&provision()).await.unwrap();
    other.batch_execute(&format!("BEGIN; SELECT account_id FROM payload_profile_account_anchors WHERE account_id='{ACCOUNT}' FOR UPDATE")).await.unwrap();
    rejects(&f.db, &provision(), "55P03").await;
    other.batch_execute("ROLLBACK").await.unwrap();
    other
        .batch_execute(&format!(
            "UPDATE review_brokers SET credential_revision=2 WHERE id='{BROKER}'"
        ))
        .await
        .unwrap();
    rejects(&f.db, &provision(), "23514").await;
    // Invalidation does not prevent ordinary account-first erasure/cascades.
    f.db.batch_execute(&format!("DELETE FROM accounts WHERE id='{ACCOUNT}'"))
        .await
        .unwrap();
    assert_eq!(count(&f.db, "review_bootstrap_attempts").await, 0);
    assert_eq!(count(&f.db, "review_workspaces").await, 0);
    close(other, other_driver).await;
    f.finish().await;
}

async fn wait_for_lock(db: &Client, application: &str, relation: Option<&str>) {
    for _ in 0..100 {
        let found: bool = db.query_one("SELECT EXISTS(SELECT FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.application_name=$1 AND NOT l.granted AND (($2::text IS NULL AND l.locktype='advisory') OR l.relation=to_regclass($2)))", &[&application, &relation]).await.unwrap().get(0);
        if found {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("expected bounded fixture lock was not observed");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_capture_before_candidate_fence_does_not_skip_newly_provisioned_anchor_lock() {
    let f = Fixture::create().await;
    f.db.batch_execute(&reserve()).await.unwrap();
    let original: String =
        f.db.query_one(
            "SELECT pg_get_functiondef('payload_profile_account_fence_key(uuid)'::regprocedure)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let metadata_sql = "SELECT json_build_array(proowner,proacl::text,proconfig,prosrc,provolatile,prosecdef)::text FROM pg_proc WHERE oid='payload_profile_account_fence_key(uuid)'::regprocedure";
    let metadata: String = f.db.query_one(metadata_sql, &[]).await.unwrap().get(0);
    // Scheduling injection in this disposable database ONLY. The installed
    // provision function is unchanged; the gate sits at its real fence-key call
    // after initial capture. VOLATILE prevents planner folding of the test gate.
    f.db.batch_execute(r#"CREATE OR REPLACE FUNCTION payload_profile_account_fence_key(account uuid)
        RETURNS bigint LANGUAGE plpgsql VOLATILE STRICT SET search_path TO pg_catalog AS $fixture$
        BEGIN
            IF current_setting('application_name')='review-capture-race' THEN
                PERFORM pg_advisory_lock(71487); PERFORM pg_advisory_unlock(71487);
            END IF;
            RETURN ('x'||substr(encode(sha256(convert_to('ZTSE/line/payload-profile/account-fence/v1','UTF8')
                ||decode('00','hex')||int4send(16)||uuid_send(account)),'hex'),1,16))::bit(64)::bigint;
        END $fixture$"#).await.unwrap();
    let (gate, gate_driver) = connect(&f.config).await;
    gate.batch_execute("SELECT pg_advisory_lock(71487)")
        .await
        .unwrap();
    let (race, race_driver) = connect(&f.config).await;
    race.batch_execute("SET application_name='review-capture-race'; SET statement_timeout='10s'")
        .await
        .unwrap();
    let pending = tokio::spawn(async move {
        let result = race.batch_execute(&provision()).await;
        (race, result)
    });
    wait_for_lock(&f.db, "review-capture-race", None).await;
    f.db.batch_execute(&provision()).await.unwrap();
    gate.batch_execute(&format!("BEGIN; SELECT account_id FROM payload_profile_account_anchors WHERE account_id='{ACCOUNT}' FOR UPDATE; SELECT pg_advisory_unlock(71487)")).await.unwrap();
    let (race, result) = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().code().map(|c| c.code()), Some("55P03"));
    gate.batch_execute("ROLLBACK").await.unwrap();
    close(race, race_driver).await;
    close(gate, gate_driver).await;
    f.db.batch_execute(&original).await.unwrap();
    let restored: String = f.db.query_one(metadata_sql, &[]).await.unwrap().get(0);
    assert_eq!(
        metadata, restored,
        "exact function owner/ACL/config/body/volatility restored"
    );
    let restored_definition: String =
        f.db.query_one(
            "SELECT pg_get_functiondef('payload_profile_account_fence_key(uuid)'::regprocedure)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(original, restored_definition);
    // Positive installed-source qualification after dependency restoration.
    f.db.batch_execute(&provision()).await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_result_that_expires_while_association_read_waits_is_not_returned() {
    let f = Fixture::create().await;
    f.db.batch_execute(&reserve()).await.unwrap();
    f.db.batch_execute(&provision()).await.unwrap();
    f.db.batch_execute("ALTER TABLE review_bootstrap_attempts DISABLE TRIGGER review_workspace_identity_before_update;
        UPDATE review_bootstrap_attempts SET issued_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-600000000,
            expires_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-599700000,
            provisioned_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-599999000,
            reconcile_until_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint+1500;
        ALTER TABLE review_bootstrap_attempts ENABLE TRIGGER review_workspace_identity_before_update").await.unwrap();
    let (gate, gate_driver) = connect(&f.config).await;
    gate.batch_execute("BEGIN; LOCK TABLE review_workspaces IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let (race, race_driver) = connect(&f.config).await;
    race.batch_execute(
        "SET application_name='review-result-read-race'; SET statement_timeout='10s'",
    )
    .await
    .unwrap();
    let pending = tokio::spawn(async move {
        let result = race.batch_execute(&provision()).await;
        (race, result)
    });
    wait_for_lock(&f.db, "review-result-read-race", Some("review_workspaces")).await;
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
    gate.batch_execute("ROLLBACK").await.unwrap();
    let (race, result) = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().code().map(|c| c.code()), Some("23514"));
    assert_eq!(count(&f.db, "review_workspaces").await, 1);
    close(race, race_driver).await;
    close(gate, gate_driver).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_result_nulls_and_identity_rebinding_refuse_and_finite_cleanup_preserves_workspace()
{
    let f = Fixture::create().await;
    f.db.batch_execute(&reserve()).await.unwrap();
    f.db.batch_execute(&provision()).await.unwrap();
    for assignment in [
        "provisioned_ms=NULL",
        "bound_account_id=NULL",
        "bound_user_id=NULL",
        "state='reserved'",
        "bound_account_id=gen_random_uuid()",
        "bound_user_id=gen_random_uuid()",
    ] {
        // Exercise the CHECK itself, independently of the normal immutable-row
        // trigger. Rollback restores the trigger and original result each time.
        f.db.batch_execute("BEGIN; ALTER TABLE review_bootstrap_attempts DISABLE TRIGGER review_workspace_identity_before_update").await.unwrap();
        rejects(
            &f.db,
            &format!("UPDATE review_bootstrap_attempts SET {assignment}"),
            "23514",
        )
        .await;
        f.db.batch_execute("ROLLBACK").await.unwrap();
    }
    for assignment in [
        "issued_ms=issued_ms-1",
        "reserved_account_id=gen_random_uuid()",
        "broker_session_id=gen_random_uuid()",
        "request_digest=decode(repeat('22',32),'hex')",
        "origin='https://other.invalid'",
    ] {
        rejects(
            &f.db,
            &format!("UPDATE review_bootstrap_attempts SET {assignment}"),
            "23514",
        )
        .await;
    }
    assert!(
        !f.db
            .query_one(
                &format!("SELECT review_workspace_attempt_cleanup('{ATTEMPT}')"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    // Owner fixture ages only synthetic rows; installed helpers use actual
    // qualified clock_timestamp(), not an injectable authorization clock.
    f.db.batch_execute("ALTER TABLE review_bootstrap_attempts DISABLE TRIGGER review_workspace_identity_before_update;
        UPDATE review_bootstrap_attempts SET issued_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-864000000,
            expires_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-863700000,
            reconcile_until_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-259200000,
            provisioned_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-863800000;
        ALTER TABLE review_bootstrap_attempts ENABLE TRIGGER review_workspace_identity_before_update;").await.unwrap();
    assert!(
        f.db.query_one(
            &format!("SELECT review_workspace_attempt_cleanup('{ATTEMPT}')"),
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert_eq!(count(&f.db, "review_workspaces").await, 1);
    assert_eq!(count(&f.db, "accounts").await, 1);
    assert_eq!(count(&f.db, "users").await, 1);
    rejects(&f.db, &provision(), "P0002").await;
    f.db.batch_execute("ALTER TABLE review_broker_sessions DISABLE TRIGGER review_workspace_identity_before_update;
        UPDATE review_broker_sessions SET issued_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-864000000,
            last_used_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-432000000,
            expires_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint+300000000;
        ALTER TABLE review_broker_sessions ENABLE TRIGGER review_workspace_identity_before_update;").await.unwrap();
    assert_eq!(
        f.db.query_one(
            &format!("SELECT review_workspace_session_cleanup('{BROKER}')"),
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(count(&f.db, "review_workspaces").await, 1);
    assert_eq!(count(&f.db, "review_broker_sessions").await, 0);
    f.db.batch_execute(&format!(
        "DELETE FROM accounts WHERE id='{ACCOUNT}'; DELETE FROM users WHERE id='{USER}'"
    ))
    .await
    .unwrap();
    assert_eq!(count(&f.db, "review_workspaces").await, 0);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_bounded_slots_refuse_eviction_and_reuse_only_genuinely_cleaned_state() {
    let f = Fixture::create().await;
    f.db.batch_execute(&format!(r#"DO $fixture$
        DECLARE s uuid; e uuid; a uuid; u uuid; attempt uuid;
        BEGIN
            FOR i IN 1..128 LOOP
                IF i=1 THEN s:='{SESSION}'; e:='{EVENT}';
                ELSE
                    s:=gen_random_uuid(); e:=gen_random_uuid();
                    PERFORM review_workspace_broker_session_create('{BROKER}',s,e,1,sha256(uuid_send(s)),sha256(uuid_send(e)),'https://review.invalid');
                END IF;
                a:=gen_random_uuid(); u:=gen_random_uuid(); attempt:=gen_random_uuid();
                PERFORM review_workspace_reserve(attempt,a,u,s,e,1,sha256(uuid_send(attempt)),sha256(uuid_send(a)),'https://review.invalid');
                PERFORM review_workspace_provision(attempt,s,e,1,sha256(uuid_send(attempt)),sha256(uuid_send(a)),'https://review.invalid');
            END LOOP;
        END $fixture$"#)).await.unwrap();
    assert_eq!(count(&f.db, "review_workspaces").await, 128);
    rejects(&f.db, &format!("SELECT review_workspace_broker_session_create('{BROKER}',gen_random_uuid(),gen_random_uuid(),1,sha256(uuid_send(gen_random_uuid())),sha256(uuid_send(gen_random_uuid())),'https://review.invalid')"), "54000").await;
    rejects(&f.db, &reserve(), "54000").await;
    // Release one genuinely expired result. Its account/workspace stays, so
    // workspace capacity must STILL refuse the next factory without eviction.
    f.db.batch_execute(&format!("ALTER TABLE review_bootstrap_attempts DISABLE TRIGGER review_workspace_identity_before_update;
        UPDATE review_bootstrap_attempts SET issued_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-864000000,
            expires_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-863700000,
            reconcile_until_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-259200000,
            provisioned_ms=(EXTRACT(epoch FROM statement_timestamp())*1000)::bigint-863800000 WHERE broker_session_id='{SESSION}';
        ALTER TABLE review_bootstrap_attempts ENABLE TRIGGER review_workspace_identity_before_update;
        SELECT review_workspace_attempt_cleanup(id) FROM review_bootstrap_attempts WHERE broker_session_id='{SESSION}'")).await.unwrap();
    f.db.batch_execute(&reserve()).await.unwrap();
    rejects(&f.db, &provision(), "54000").await;
    assert_eq!(count(&f.db, "review_workspaces").await, 128);
    let row =
        f.db.query_one(
            "SELECT account_id::text,user_id::text FROM review_workspaces ORDER BY slot LIMIT 1",
            &[],
        )
        .await
        .unwrap();
    let removed_account: String = row.get(0);
    let removed_user: String = row.get(1);
    f.db.batch_execute(&format!("DELETE FROM accounts WHERE id='{removed_account}'; DELETE FROM users WHERE id='{removed_user}'")).await.unwrap();
    f.db.batch_execute(&provision()).await.unwrap();
    assert_eq!(count(&f.db, "review_workspaces").await, 128);
    assert_eq!(
        f.db.query_one(
            &format!("SELECT slot FROM review_workspaces WHERE account_id='{ACCOUNT}'"),
            &[]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn review_quoted_component_namespace_ignores_wrong_path_and_temp_shadows() {
    let f = Fixture::create().await;
    // Full public numbered-migrator qualification already ran in Fixture. This
    // separately relocates ONLY the actual component dependency files, without
    // pretending the entire historical stack supports relocation.
    let namespace = "\"review'quoted\"";
    f.db.batch_execute(&format!(
        "CREATE SCHEMA {namespace}; SET search_path TO {namespace}"
    ))
    .await
    .unwrap();
    for sql in [
        include_str!("../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../deploy/compose/migrations/100_payload_profile_account_anchors.sql"),
        include_str!("../../../deploy/compose/migrations/102_review_workspace_persistence.sql"),
    ] {
        f.db.batch_execute("BEGIN").await.unwrap();
        f.db.batch_execute(sql).await.unwrap();
        f.db.batch_execute("COMMIT").await.unwrap();
    }
    // Copy the exact original 102 component shapes. Public has later additive
    // marker/configuration and broker-credential columns, not part of this
    // independently qualified 102-only namespace.
    f.db.batch_execute(&format!("INSERT INTO {namespace}.review_realm_installation(singleton,realm_id,database_id,origin,deployment_digest,service_digest,
            auth_key_digest,enrollment_key_digest,reauthentication_key_digest,grant_key_digest,mfa_key_digest)
        SELECT singleton,realm_id,database_id,origin,deployment_digest,service_digest,
            auth_key_digest,enrollment_key_digest,reauthentication_key_digest,grant_key_digest,mfa_key_digest FROM public.review_realm_installation;
        INSERT INTO {namespace}.review_brokers(id,realm_id,credential_revision,password_verifier,disabled_ms)
        SELECT id,realm_id,credential_revision,password_verifier,disabled_ms FROM public.review_brokers;
        SET search_path TO public;
        CREATE TEMP TABLE accounts(id uuid);
        CREATE TEMP TABLE users(id uuid);
        CREATE TEMP TABLE memberships(account_id uuid,user_id uuid);
        CREATE TEMP TABLE payload_profile_account_anchors(account_id uuid,state text,selection_epoch bigint);
        CREATE TEMP TABLE review_brokers(id uuid);
        CREATE TEMP TABLE review_broker_sessions(id uuid);
        CREATE TEMP TABLE review_bootstrap_attempts(id uuid);
        CREATE TEMP TABLE review_workspaces(account_id uuid);
        SELECT {namespace}.review_workspace_broker_session_create('{BROKER}','{SESSION}','{EVENT}',1,
            decode(repeat('08',32),'hex'),decode(repeat('09',32),'hex'),'https://review.invalid')")).await.unwrap();
    f.db.batch_execute(&reserve().replace(
        "review_workspace_reserve",
        &format!("{namespace}.review_workspace_reserve"),
    ))
    .await
    .unwrap();
    f.db.batch_execute(&provision().replace(
        "review_workspace_provision",
        &format!("{namespace}.review_workspace_provision"),
    ))
    .await
    .unwrap();
    let rows = f.db.query_one(&format!("SELECT
        (SELECT id='{ACCOUNT}'::uuid FROM {namespace}.accounts),
        (SELECT id='{USER}'::uuid AND password_hash='!' AND email_verified_at IS NULL AND NOT mfa_enabled FROM {namespace}.users),
        (SELECT state='provisioned' AND bound_account_id='{ACCOUNT}'::uuid AND bound_user_id='{USER}'::uuid
            AND reserved_account_id=bound_account_id AND reserved_user_id=bound_user_id FROM {namespace}.review_bootstrap_attempts),
        (SELECT state='live' AND selection_epoch=0 FROM {namespace}.payload_profile_account_anchors),
        (SELECT count(*)=0 FROM public.accounts)") , &[]).await.unwrap();
    for column in 0..5 {
        assert!(rows.get::<_, bool>(column));
    }
    for table in [
        "accounts",
        "users",
        "memberships",
        "payload_profile_account_anchors",
        "review_brokers",
        "review_broker_sessions",
        "review_bootstrap_attempts",
        "review_workspaces",
    ] {
        assert_eq!(
            count(&f.db, &format!("pg_temp.{table}")).await,
            0,
            "shadow table untouched: {table}"
        );
    }
    // The exact quoted deletion trigger context must also resolve original IDs.
    f.db.batch_execute(&format!("DELETE FROM {namespace}.users WHERE id='{USER}'; DELETE FROM {namespace}.accounts WHERE id='{ACCOUNT}'")).await.unwrap();
    assert_eq!(
        count(&f.db, &format!("{namespace}.review_bootstrap_attempts")).await,
        0
    );
    assert_eq!(
        count(&f.db, &format!("{namespace}.review_workspaces")).await,
        0
    );
    assert_eq!(count(&f.db, "public.review_bootstrap_attempts").await, 0);
    f.finish().await;
}
