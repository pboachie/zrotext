// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Config, NoTls, types::ToSql};
use uuid::Uuid;

const ACCOUNT: Uuid = Uuid::from_u128(0x10000000000040008000000000000000 + 1);
const USER: Uuid = Uuid::from_u128(0x10000000000040008000000000000000 + 2);
const OTHER_ACCOUNT: Uuid = Uuid::from_u128(0x10000000000040008000000000000000 + 3);
const OTHER_USER: Uuid = Uuid::from_u128(0x10000000000040008000000000000000 + 4);

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
    owner: Client,
    owner_driver: tokio::task::JoinHandle<()>,
    db: Client,
    driver: tokio::task::JoinHandle<()>,
    config: Config,
    database: String,
    owner_role: String,
    runtime_role: String,
}

impl Fixture {
    async fn create() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
        let mut config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let values = admin.query_one("SELECT replace(gen_random_uuid()::text,'-',''),replace(gen_random_uuid()::text,'-',''),replace(gen_random_uuid()::text,'-','')", &[]).await.unwrap();
        let suffix: String = values.get(0);
        let owner_password: String = values.get(1);
        let runtime_password: String = values.get(2);
        let owner_role = format!("zt_member_owner_{suffix}");
        let runtime_role = format!("zt_member_runtime_{suffix}");
        let database = format!("zt_member_{suffix}");
        for (role, password) in [
            (&owner_role, &owner_password),
            (&runtime_role, &runtime_password),
        ] {
            let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
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
            .password(owner_password);
        let (mut owner, owner_driver) = connect(&config).await;
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
        let applied = apply(&mut owner, &directory, false).await.unwrap();
        assert_eq!(applied.last().unwrap().version, 112);
        let capture = "SELECT json_build_array((SELECT json_agg(json_build_array(version,checksum_sha256,applied_at::text) ORDER BY version) FROM schema_migrations),(SELECT json_build_array(proowner,proacl::text,prosrc,proconfig,prosecdef) FROM pg_proc WHERE oid='public.user_membership_freshness_guard()'::regprocedure))::text";
        let before: String = owner.query_one(capture, &[]).await.unwrap().get(0);
        assert!(
            apply(&mut owner, &directory, false)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            before,
            owner
                .query_one(capture, &[])
                .await
                .unwrap()
                .get::<_, String>(0)
        );
        // These are the narrow relationship DML grants needed by this fixture.
        // The complete stock provisioner/pollution repair is tested separately.
        let runtime_identifier = escape_identifier(&runtime_role);
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {runtime_identifier}; GRANT SELECT,INSERT,UPDATE,DELETE ON public.accounts,public.users,public.memberships TO {runtime_identifier}; GRANT SELECT,UPDATE(account_id) ON public.payload_profile_account_anchors TO {runtime_identifier}; REVOKE ALL ON FUNCTION public.user_membership_freshness_guard() FROM {runtime_identifier}")).await.unwrap();
        config.user(&runtime_role).password(runtime_password);
        let (db, driver) = connect(&config).await;
        let limited: bool = db.query_one("SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid) FROM pg_roles r WHERE rolname=current_user", &[]).await.unwrap().get(0);
        assert!(limited);
        assert!(!db.query_one("SELECT tableowner=current_user FROM pg_tables WHERE schemaname='public' AND tablename='users'", &[]).await.unwrap().get::<_, bool>(0));
        db.batch_execute("SET statement_timeout='10s'; SET lock_timeout='2s'")
            .await
            .unwrap();
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            db,
            driver,
            config,
            database,
            owner_role,
            runtime_role,
        }
    }

    async fn parents(&self, account: Uuid, user: Uuid) {
        let email = format!("{user}@review.invalid");
        self.db.batch_execute("BEGIN").await.unwrap();
        self.db
            .execute(
                "INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!')",
                &[&user, &email],
            )
            .await
            .unwrap();
        self.db
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        self.db.batch_execute("COMMIT").await.unwrap();
    }

    async fn joined(&self) {
        self.parents(ACCOUNT, USER).await;
        membership(&self.db, ACCOUNT, USER).await.unwrap();
    }

    async fn tombstone(&self) {
        let row = self.db.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1", &[&ACCOUNT]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "deleted");
        assert_eq!(row.get::<_, i64>(1), 1);
    }

    async fn finish(self) {
        close(self.db, self.driver).await;
        close(self.owner, self.owner_driver).await;
        for sql in [
            format!("DROP DATABASE {}", escape_identifier(&self.database)),
            format!("DROP ROLE {}", escape_identifier(&self.runtime_role)),
            format!("DROP ROLE {}", escape_identifier(&self.owner_role)),
        ] {
            self.admin.batch_execute(&sql).await.unwrap();
        }
        close(self.admin, self.admin_driver).await;
    }
}

async fn membership(db: &Client, account: Uuid, user: Uuid) -> Result<u64, tokio_postgres::Error> {
    db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
        &[&account, &user],
    )
    .await
}

async fn rejects_with_params(db: &Client, sql: &str, params: &[&(dyn ToSql + Sync)], code: &str) {
    let error = db.execute(sql, params).await.unwrap_err();
    assert_eq!(error.code().map(|c| c.code()), Some(code), "{error}");
}

async fn rejects(db: &Client, sql: &str, code: &str) {
    rejects_with_params(db, sql, &[], code).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn membership_writes_invalidate_old_user_snapshots_without_a_runtime_helper_api() {
    for mode in ["REPEATABLE READ", "SERIALIZABLE"] {
        for remove in [false, true] {
            let f = Fixture::create().await;
            f.parents(ACCOUNT, USER).await;
            if remove {
                membership(&f.db, ACCOUNT, USER).await.unwrap();
            }
            let (old, old_driver) = connect(&f.config).await;
            old.batch_execute(&format!("BEGIN ISOLATION LEVEL {mode}"))
                .await
                .unwrap();
            old.query(
                "SELECT count(*) FROM memberships WHERE user_id=$1",
                &[&USER],
            )
            .await
            .unwrap();
            if remove {
                f.db.execute("DELETE FROM memberships WHERE user_id=$1", &[&USER])
                    .await
                    .unwrap();
            } else {
                membership(&f.db, ACCOUNT, USER).await.unwrap();
            }
            rejects_with_params(
                &old,
                "UPDATE users SET password_hash='changed' WHERE id=$1",
                &[&USER],
                "40001",
            )
            .await;
            old.batch_execute("ROLLBACK").await.unwrap();
            close(old, old_driver).await;
            rejects(
                &f.db,
                "SELECT public.user_membership_freshness_guard()",
                "42501",
            )
            .await;
            rejects(
                &f.db,
                "ALTER TABLE users DISABLE TRIGGER user_membership_freshness_before_user_change",
                "42501",
            )
            .await;
            rejects(&f.db, "TRUNCATE users CASCADE", "42501").await;
            rejects(
                &f.db,
                "UPDATE payload_profile_account_anchors SET selection_epoch=selection_epoch+1",
                "42501",
            )
            .await;
            f.finish().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn member_user_guards_preserve_bootstrap_revocation_and_both_parent_cascade_orders() {
    for order in ["user", "account", "memberships_first"] {
        let f = Fixture::create().await;
        f.joined().await;
        f.parents(OTHER_ACCOUNT, OTHER_USER).await;
        f.db.batch_execute("BEGIN").await.unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&ACCOUNT, &OTHER_USER],
        )
        .await
        .unwrap();
        f.db.execute(
            "UPDATE memberships SET revoked_at=clock_timestamp() WHERE user_id=$1",
            &[&OTHER_USER],
        )
        .await
        .unwrap();
        f.db.execute("DELETE FROM users WHERE id=$1", &[&OTHER_USER])
            .await
            .unwrap();
        f.db.execute("DELETE FROM accounts WHERE id=$1", &[&OTHER_ACCOUNT])
            .await
            .unwrap();
        f.db.batch_execute("COMMIT").await.unwrap();
        f.db.batch_execute("BEGIN").await.unwrap();
        match order {
            "user" => {
                f.db.execute("DELETE FROM users WHERE id=$1", &[&USER])
                    .await
                    .unwrap();
                f.db.execute("DELETE FROM accounts WHERE id=$1", &[&ACCOUNT])
                    .await
                    .unwrap();
            }
            "account" => {
                f.db.execute("DELETE FROM accounts WHERE id=$1", &[&ACCOUNT])
                    .await
                    .unwrap();
                f.db.execute(
                    "UPDATE users SET password_hash='orphan' WHERE id=$1",
                    &[&USER],
                )
                .await
                .unwrap();
                f.db.execute("DELETE FROM users WHERE id=$1", &[&USER])
                    .await
                    .unwrap();
            }
            _ => {
                f.db.execute("DELETE FROM memberships WHERE account_id=$1", &[&ACCOUNT])
                    .await
                    .unwrap();
                f.db.execute("DELETE FROM users WHERE id=$1", &[&USER])
                    .await
                    .unwrap();
                f.db.execute("DELETE FROM accounts WHERE id=$1", &[&ACCOUNT])
                    .await
                    .unwrap();
            }
        }
        f.db.batch_execute("COMMIT").await.unwrap();
        assert_eq!(
            f.db.query_one("SELECT count(*) FROM memberships", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        f.tombstone().await;
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn actual_anchor_epoch_missing_anchor_and_held_locks_refuse_atomically() {
    let f = Fixture::create().await;
    f.joined().await;
    f.parents(OTHER_ACCOUNT, OTHER_USER).await;
    membership(&f.db, OTHER_ACCOUNT, OTHER_USER).await.unwrap();
    let (old, old_driver) = connect(&f.config).await;
    old.batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    old.query(
        "SELECT selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1",
        &[&ACCOUNT],
    )
    .await
    .unwrap();
    // Disposable owner instrumentation models a future actual epoch UPDATE.
    // No runtime advance API, trigger bypass or production policy is installed.
    f.owner.batch_execute("BEGIN; ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change").await.unwrap();
    f.owner
        .execute(
            "UPDATE payload_profile_account_anchors SET selection_epoch=1 WHERE account_id=$1",
            &[&ACCOUNT],
        )
        .await
        .unwrap();
    f.owner.batch_execute("ALTER TABLE payload_profile_account_anchors ENABLE TRIGGER payload_profile_anchor_before_change; COMMIT").await.unwrap();
    rejects_with_params(
        &old,
        "UPDATE users SET password_hash='changed' WHERE id=$1",
        &[&USER],
        "40001",
    )
    .await;
    old.batch_execute("ROLLBACK").await.unwrap();
    close(old, old_driver).await;
    for lock in [
        "SELECT account_id FROM payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE NOWAIT",
        "SELECT pg_advisory_xact_lock(payload_profile_account_fence_key($1))",
    ] {
        f.owner.batch_execute("BEGIN").await.unwrap();
        f.owner.query(lock, &[&ACCOUNT]).await.unwrap();
        rejects_with_params(
            &f.db,
            "UPDATE users SET password_hash='changed' WHERE id=$1",
            &[&USER],
            "55P03",
        )
        .await;
        f.db.execute(
            "UPDATE users SET password_hash='unrelated' WHERE id=$1",
            &[&OTHER_USER],
        )
        .await
        .unwrap();
        f.owner.batch_execute("ROLLBACK").await.unwrap();
    }
    f.owner.batch_execute("BEGIN; ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change; DELETE FROM payload_profile_account_anchors").await.unwrap();
    // The same owner transaction observes its deliberate corruption. Each
    // savepoint rolls back only the attempted guarded operation before restore.
    for operation in [
        "UPDATE users SET password_hash='changed' WHERE id=$1",
        "DELETE FROM users WHERE id=$1",
        "DELETE FROM memberships WHERE user_id=$1",
    ] {
        f.owner
            .batch_execute("SAVEPOINT missing_anchor")
            .await
            .unwrap();
        rejects_with_params(&f.owner, operation, &[&USER], "23514").await;
        f.owner
            .batch_execute("ROLLBACK TO SAVEPOINT missing_anchor")
            .await
            .unwrap();
    }
    f.owner.batch_execute("ROLLBACK").await.unwrap();
    for column in ["state", "selection_epoch"] {
        let column = escape_identifier(column);
        f.owner.batch_execute(&format!("BEGIN; ALTER TABLE payload_profile_account_anchors ALTER COLUMN {column} DROP NOT NULL; ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change")).await.unwrap();
        f.owner
            .execute(
                &format!(
                    "UPDATE payload_profile_account_anchors SET {column}=NULL WHERE account_id=$1"
                ),
                &[&ACCOUNT],
            )
            .await
            .unwrap();
        rejects_with_params(
            &f.owner,
            "UPDATE users SET password_hash='changed' WHERE id=$1",
            &[&USER],
            "23514",
        )
        .await;
        f.owner.batch_execute("ROLLBACK").await.unwrap();
    }
    assert_eq!(
        f.db.query_one("SELECT password_hash FROM users WHERE id=$1", &[&USER])
            .await
            .unwrap()
            .get::<_, String>(0),
        "!"
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn membership_tuple_contention_null_identity_and_atomic_rollback_are_bounded() {
    let f = Fixture::create().await;
    f.parents(ACCOUNT, USER).await;
    let (other, other_driver) = connect(&f.config).await;
    other.batch_execute("BEGIN").await.unwrap();
    other
        .query(
            "SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT",
            &[&USER],
        )
        .await
        .unwrap();
    let error = membership(&f.db, ACCOUNT, USER).await.unwrap_err();
    assert_eq!(error.code().map(|c| c.code()), Some("55P03"));
    other.batch_execute("ROLLBACK").await.unwrap();
    close(other, other_driver).await;
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM memberships", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    for (account, user) in [(None, Some(USER)), (Some(ACCOUNT), None)] {
        rejects_with_params(
            &f.db,
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
            "23514",
        )
        .await;
    }
    for sql in [
        "UPDATE users SET id=NULL WHERE id=$1",
        "UPDATE users SET id=gen_random_uuid() WHERE id=$1",
    ] {
        rejects_with_params(&f.db, sql, &[&USER], "23514").await;
    }
    membership(&f.db, ACCOUNT, USER).await.unwrap();
    f.parents(OTHER_ACCOUNT, OTHER_USER).await;
    membership(&f.db, OTHER_ACCOUNT, OTHER_USER).await.unwrap();
    for sql in [
        "UPDATE memberships SET account_id=gen_random_uuid()",
        "UPDATE memberships SET user_id=gen_random_uuid()",
    ] {
        rejects(&f.db, sql, "23514").await;
    }
    f.db.batch_execute("BEGIN; UPDATE users SET password_hash='rolledback'")
        .await
        .unwrap();
    rejects(&f.db, "UPDATE memberships SET role='observer'", "23514").await;
    f.db.batch_execute("ROLLBACK").await.unwrap();
    // Reassignment is forbidden since048, not a supported transition which
    // may leave a former user outside the mandatory freshness mechanism.
    let (old, old_driver) = connect(&f.config).await;
    old.batch_execute(
        "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT * FROM memberships; SELECT * FROM users",
    )
    .await
    .unwrap();
    f.db.batch_execute("BEGIN; UPDATE users SET password_hash='mustrollback'")
        .await
        .unwrap();
    rejects_with_params(
        &f.db,
        "UPDATE memberships SET user_id=$1 WHERE user_id=$2",
        &[&OTHER_USER, &USER],
        "23514",
    )
    .await;
    f.db.batch_execute("ROLLBACK").await.unwrap();
    old.batch_execute("UPDATE users SET password_hash='afterrefusal'; ROLLBACK")
        .await
        .unwrap();
    close(old, old_driver).await;
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM users WHERE password_hash='!'", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    f.finish().await;
}
