// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable current public-schema fixture with separate migration-owner and
//! ordinary runtime logins, using the real migrator and unchanged stock ACLs.
use futures_util::FutureExt;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use std::panic::{AssertUnwindSafe, resume_unwind};
use tokio_postgres::{Client, Config};
use uuid::Uuid;

pub(crate) type Driver = tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>;
async fn connect(config: &Config) -> (Client, Driver) {
    let (client, connection) = zrotext_postgres_connection::connect_config(config.clone())
        .await
        .unwrap();
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

pub(crate) struct Fixture {
    pub owner: Client,
    pub runtime: Client,
    pub runtime_role: String,
    pub owner_role: String,
    pub config: Config,
    pub runtime_url: String,
    admin: Client,
    admin_driver: Driver,
    owner_driver: Driver,
    runtime_driver: Driver,
    database: String,
}
impl Fixture {
    /// Current Store positives use the real migrator and stock ordinary role.
    pub async fn for_store(env_name: &str) -> Self {
        let fixture = Self::new(env_name).await;
        let qualified = AssertUnwindSafe(async {
            fixture.verify().await;
            zrotext_delivery_store::hosted_runtime_identity::require(&fixture.runtime)
                .await
                .unwrap();
        })
        .catch_unwind()
        .await;
        if let Err(panic) = qualified {
            fixture.finish().await;
            resume_unwind(panic);
        }
        fixture
    }
    pub async fn new(env_name: &str) -> Self {
        Self::with_history(env_name, 0, async |_| {}).await.0
    }
    /// Seed genuine historical rows through a complete numbered prefix, then
    /// run every remaining unchanged migration before creating the stock role.
    /// The callback is never a way to alter or re-pin the current graph.
    pub async fn with_history<T, F>(env_name: &str, through: usize, seed: F) -> (Self, T)
    where
        F: for<'a> std::ops::AsyncFnOnce(&'a mut Client) -> T,
    {
        assert!(through < 119);
        let base = std::env::var(env_name).expect("disposable CREATEDB/CREATEROLE cluster");
        let mut config = zrotext_postgres_connection::parse_config(&base).unwrap();
        config.connect_timeout(std::time::Duration::from_secs(5));
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("native_identity_{suffix}");
        let owner_role = format!("native_owner_{suffix}");
        let runtime_role = format!("native_runtime_{suffix}");
        let owner_password = Uuid::new_v4().simple().to_string();
        let runtime_password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        for (role, password) in [
            (&owner_role, &owner_password),
            (&runtime_role, &runtime_password),
        ] {
            let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
            admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",escape_identifier(role),escape_literal(&verifier))).await.unwrap();
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
            .password(&owner_password)
            .options("-csearch_path=pg_catalog,public");
        let (mut owner, owner_driver) = connect(&config).await;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/compose/migrations");
        let initialized = AssertUnwindSafe(async {
            let history = if through == 0 {
                seed(&mut owner).await
            } else {
                let prefix = MigrationPrefix::new(&directory, through);
                let applied = zrotext_migrator::apply(&mut owner, &prefix.0, false)
                    .await
                    .unwrap();
                assert_eq!(applied.len(), through);
                assert_eq!(applied.last().unwrap().version, through as i64);
                seed(&mut owner).await
            };
            let applied = zrotext_migrator::apply(&mut owner, &directory, false)
                .await
                .unwrap();
            assert_eq!(applied.last().unwrap().version, 120);
            assert_eq!(applied.len(), 120 - through);
            assert_eq!(
                owner
                    .query_one("SELECT count(*) FROM schema_migrations", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                120
            );
            let fixture_acl = Self::acl_text(&database, &runtime_role);
            owner.batch_execute(&fixture_acl).await.unwrap();
            config.user(&runtime_role).password(&runtime_password);
            let runtime_url = runtime_url(&base, &database, &runtime_role, &runtime_password);
            let (runtime, runtime_driver) = connect(&config).await;
            (history, runtime, runtime_driver, runtime_url)
        })
        .catch_unwind()
        .await;
        let (history, runtime, runtime_driver, runtime_url) = match initialized {
            Ok(value) => value,
            Err(panic) => {
                close(owner, owner_driver).await;
                admin
                    .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&database)))
                    .await
                    .unwrap();
                for role in [&runtime_role, &owner_role] {
                    admin
                        .batch_execute(&format!("DROP ROLE {}", escape_identifier(role)))
                        .await
                        .unwrap();
                }
                close(admin, admin_driver).await;
                resume_unwind(panic);
            }
        };
        (
            Self {
                owner,
                runtime,
                runtime_role,
                owner_role,
                config,
                runtime_url,
                admin,
                admin_driver,
                owner_driver,
                runtime_driver,
                database,
            },
            history,
        )
    }
    pub(crate) fn acl_text(database: &str, runtime: &str) -> String {
        // The stock SQL compares role-name text as well as identifiers. A quoted
        // identifier must never be substituted into those comparison literals.
        assert!(
            runtime.len() <= 63
                && runtime
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
        let stock = include_str!("../../../deploy/compose/runtime-role.sql");
        let marker = "REVOKE ALL ON SCHEMA public FROM PUBLIC, zrotext_runtime;";
        let (_, tail) = stock.split_once(marker).expect("stock ACL boundary");
        let (body, _) = tail
            .rsplit_once("\nCOMMIT;")
            .expect("stock transaction end");
        assert!(!body.lines().any(|line| line.starts_with('\\')));
        format!("REVOKE ALL ON DATABASE {db} FROM PUBLIC,{role}; GRANT CONNECT ON DATABASE {db} TO {role}; BEGIN; {marker}{body} COMMIT;",db=escape_identifier(database),role=escape_identifier(runtime)).replace("zrotext_runtime",runtime)
    }
    pub async fn verify(&self) {
        let sql = include_str!("../../../deploy/compose/verify_runtime_role.sql")
            .replace("zrotext_runtime", &self.runtime_role)
            .replace(
                "'SET ROLE zrotext'",
                &format!("'SET ROLE {}'", self.owner_role),
            );
        self.runtime.batch_execute(&sql).await.unwrap();
    }
    pub async fn another_runtime(&self) -> (Client, Driver) {
        connect(&self.config).await
    }
    pub async fn close_connection(client: Client, driver: Driver) {
        close(client, driver).await
    }
    pub async fn finish(self) {
        crate::runtime_db::close_fixture_connections(&self.runtime_url).await;
        close(self.runtime, self.runtime_driver).await;
        close(self.owner, self.owner_driver).await;
        self.admin
            .batch_execute(&format!(
                "DROP DATABASE {}",
                escape_identifier(&self.database)
            ))
            .await
            .unwrap();
        for role in [&self.runtime_role, &self.owner_role] {
            self.admin
                .batch_execute(&format!("DROP ROLE {}", escape_identifier(role)))
                .await
                .unwrap();
        }
        close(self.admin, self.admin_driver).await;
    }
}

// Temporary files are exact copies, not rewritten migrations or a fake ledger.
struct MigrationPrefix(std::path::PathBuf);
impl MigrationPrefix {
    fn new(directory: &std::path::Path, through: usize) -> Self {
        let prefix = Self(std::env::temp_dir().join(format!(
            "zrotext_migration_prefix_{}",
            Uuid::new_v4().simple()
        )));
        std::fs::create_dir(&prefix.0).unwrap();
        let mut versions = Vec::new();
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if !name.ends_with(".sql") {
                continue;
            }
            let version: usize = name.split_once('_').unwrap().0.parse().unwrap();
            if version > through {
                continue;
            }
            let original = std::fs::read(entry.path()).unwrap();
            let path = prefix.0.join(name);
            std::fs::write(&path, &original).unwrap();
            assert_eq!(std::fs::read(path).unwrap(), original);
            versions.push(version);
        }
        versions.sort_unstable();
        assert_eq!(versions, (1..=through).collect::<Vec<_>>());
        prefix
    }
}
impl Drop for MigrationPrefix {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

// Retain all supplied host/TLS policy options and override only fixture identity
// and the required canonical search path. Both documented URL and libpq keyword
// connection strings are accepted without formatting any credential in errors.
fn runtime_url(base: &str, database: &str, role: &str, password: &str) -> String {
    if base.starts_with("postgres://") || base.starts_with("postgresql://") {
        let mut url = url::Url::parse(base).expect("fixture PostgreSQL URL");
        url.set_username(role).unwrap();
        url.set_password(Some(password)).unwrap();
        url.set_path(&format!("/{database}"));
        let query: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(key, _)| !matches!(key.as_ref(), "user" | "password" | "dbname" | "options"))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(query)
            .append_pair("options", "-csearch_path=pg_catalog,public");
        url.into()
    } else {
        let quote = |value: &str| value.replace('\\', "\\\\").replace('\'', "\\'");
        format!(
            "{base} dbname='{}' user='{}' password='{}' options='-csearch_path=pg_catalog,public'",
            quote(database),
            quote(role),
            quote(password)
        )
    }
}

#[test]
fn current_fixture_url_retains_transport_policy_and_replaces_identity() {
    let value = runtime_url(
        "postgresql://bootstrap:placeholder@localhost/bootstrap?sslmode=require&connect_timeout=7&options=old&user=other&password=other&dbname=other",
        "fixture_database",
        "fixture_runtime",
        "synthetic password",
    );
    let config = zrotext_postgres_connection::parse_config(&value).unwrap();
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Require
    );
    assert_eq!(
        config.get_connect_timeout(),
        Some(&std::time::Duration::from_secs(7))
    );
    assert_eq!(config.get_dbname(), Some("fixture_database"));
    assert_eq!(config.get_user(), Some("fixture_runtime"));
    assert_eq!(
        config.get_password(),
        Some(b"synthetic password".as_slice())
    );
    assert_eq!(
        config.get_options(),
        Some("-csearch_path=pg_catalog,public")
    );
}

#[test]
fn current_fixture_keyword_connection_retains_policy_and_quotes_identity() {
    let value = runtime_url(
        "host=localhost user=bootstrap dbname=bootstrap sslmode=require connect_timeout=7",
        "fixture_database",
        "fixture_runtime",
        "synthetic \\ password's",
    );
    let config = zrotext_postgres_connection::parse_config(&value).unwrap();
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Require
    );
    assert_eq!(
        config.get_connect_timeout(),
        Some(&std::time::Duration::from_secs(7))
    );
    assert_eq!(config.get_dbname(), Some("fixture_database"));
    assert_eq!(config.get_user(), Some("fixture_runtime"));
    assert_eq!(
        config.get_password(),
        Some(b"synthetic \\ password's".as_slice())
    );
    assert_eq!(
        config.get_options(),
        Some("-csearch_path=pg_catalog,public")
    );
}
