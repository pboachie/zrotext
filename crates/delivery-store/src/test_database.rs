// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable real-public-schema fixture with the unchanged stock ACL reset.
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Client, Config, NoTls};
use uuid::Uuid;

type Driver = tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>;
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

pub(crate) struct Fixture {
    pub owner: Client,
    pub runtime: Client,
    pub runtime_role: String,
    pub owner_role: String,
    pub config: Config,
    admin: Client,
    admin_driver: Driver,
    owner_driver: Driver,
    runtime_driver: Driver,
    database: String,
}
impl Fixture {
    pub async fn new() -> Self {
        let mut config: Config = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
            .expect("disposable CREATEDB/CREATEROLE cluster")
            .parse()
            .unwrap();
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
        let applied = zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        assert_eq!(applied.last().unwrap().version, 116);
        assert_eq!(applied.len(), 116);
        let fixture_acl = Self::acl_text(&database, &runtime_role);
        owner.batch_execute(&fixture_acl).await.unwrap();
        config.user(&runtime_role).password(&runtime_password);
        let (runtime, runtime_driver) = connect(&config).await;
        Self {
            owner,
            runtime,
            runtime_role,
            owner_role,
            config,
            admin,
            admin_driver,
            owner_driver,
            runtime_driver,
            database,
        }
    }
    fn acl_text(database: &str, runtime: &str) -> String {
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
    pub async fn reprovision(&self) {
        self.owner
            .batch_execute(&Self::acl_text(&self.database, &self.runtime_role))
            .await
            .unwrap();
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
