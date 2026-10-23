// SPDX-License-Identifier: AGPL-3.0-only
//! Shared disposable full-public ordinary-owner/runtime database fixture.
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Client, Config, NoTls};
use uuid::Uuid;

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
pub(crate) struct Fixture {
    admin: Client,
    admin_driver: Driver,
    pub(crate) owner: Client,
    owner_driver: Driver,
    pub(crate) reader: Client,
    reader_driver: Driver,
    database: String,
    owner_role: String,
    pub(super) read_role: String,
    pub(super) reader_config: Config,
}
impl Fixture {
    pub(super) async fn new() -> Self {
        Self::build(false).await
    }
    pub(crate) async fn runtime() -> Self {
        Self::build(true).await
    }
    /// A distinct connection using this fixture's unchanged ordinary-role
    /// configuration. This creates no grant and exposes no retained credential.
    pub(crate) async fn runtime_peer(
        &self,
    ) -> (
        Client,
        tokio::task::JoinHandle<std::result::Result<(), tokio_postgres::Error>>,
    ) {
        connect(&self.reader_config).await
    }
    /// Only this disposable fixture's generated ordinary credential. Used by
    /// the real socket pool, without widening any database role or privilege.
    pub(crate) fn runtime_socket_url(&self) -> String {
        fn quote(s: &str) -> String {
            format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
        }
        let hosts = self
            .reader_config
            .get_hosts()
            .iter()
            .map(|host| match host {
                tokio_postgres::config::Host::Tcp(host) => host.clone(),
                #[cfg(unix)]
                tokio_postgres::config::Host::Unix(path) => path.to_str().unwrap().to_owned(),
            })
            .collect::<Vec<_>>()
            .join(",");
        let ports = if self.reader_config.get_ports().is_empty() {
            "5432".to_owned()
        } else {
            self.reader_config
                .get_ports()
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "host={} port={} dbname={} user={} password={} sslmode=disable options={}",
            quote(&hosts),
            quote(&ports),
            quote(self.reader_config.get_dbname().unwrap()),
            quote(self.reader_config.get_user().unwrap()),
            quote(std::str::from_utf8(self.reader_config.get_password().unwrap()).unwrap()),
            quote(self.reader_config.get_options().unwrap())
        )
    }
    /// Close only idle pool sockets for this generated fixture after its
    /// network server has stopped. Actual role/driver cleanup remains below.
    pub(crate) async fn drain_runtime_sockets(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                crate::runtime_db::discard_fixture_idle(&self.runtime_socket_url());
                let count: i64 = self.owner.query_one(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND usename=$1",
                    &[&self.read_role],
                ).await.unwrap().get(0);
                if count == 1 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.unwrap();
    }
    // Privileged-negative tests may corrupt data in an owner transaction, then
    // SET LOCAL ROLE to the genuine narrow runtime and roll the whole operation
    // back. The runtime role itself gets no membership or additional privilege.
    pub(super) async fn enable_negative_runtime_role_switch(&self) {
        self.admin
            .batch_execute(&format!(
                "GRANT {} TO {}",
                escape_identifier(&self.read_role),
                escape_identifier(&self.owner_role)
            ))
            .await
            .unwrap();
    }
    async fn build(runtime: bool) -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable test cluster");
        let mut config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("registration_{suffix}");
        let owner_role = format!("registration_owner_{suffix}");
        let read_role = format!("registration_read_{suffix}");
        let owner_password = Uuid::new_v4().simple().to_string();
        let reader_password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        for (role, password) in [
            (&owner_role, &owner_password),
            (&read_role, &reader_password),
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
            .password(&owner_password)
            .options("-csearch_path=pg_catalog,public");
        let (mut owner, owner_driver) = connect(&config).await;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/compose/migrations");
        zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        if runtime {
            provision_runtime(&owner, &database, &read_role).await;
        } else {
            owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {r}; GRANT SELECT ON public.accounts,public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.sealed_line_key_receipts,public.device_keys,public.line_owner_approval_keys TO {r}; GRANT UPDATE(id) ON public.accounts TO {r}; GRANT UPDATE(account_id) ON public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.sealed_line_key_receipts,public.device_keys,public.line_owner_approval_keys TO {r}", r=escape_identifier(&read_role))).await.unwrap();
        }
        config.user(&read_role).password(&reader_password);
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
            reader_config: config,
        }
    }
    pub(crate) async fn finish(self) {
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

// Reuse the stock post-role-create ACL reset verbatim, including future narrow
// protected-table/helper resets. Only a freshly generated role identifier is
// substituted. This does not bypass production validators or require psql.
async fn provision_runtime(owner: &Client, database: &str, role: &str) {
    // The stock block uses the role in BOTH SQL identifiers and rolname text
    // literals. Replacing with a prequoted identifier changes the literal's
    // value and silently skips the conditional narrow-helper grants.
    assert!(
        (1..=63).contains(&role.len())
            && role.as_bytes()[0].is_ascii_lowercase()
            && role
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let role_id = escape_identifier(role);
    owner
        .batch_execute(&format!(
            "REVOKE ALL ON DATABASE {} FROM PUBLIC,{role_id}; GRANT CONNECT ON DATABASE {} TO {role_id}",
            escape_identifier(database),
            escape_identifier(database)
        ))
        .await
        .unwrap();
    let stock = include_str!("../../../../deploy/compose/runtime-role.sql");
    let marker = "REVOKE ALL ON SCHEMA public FROM PUBLIC, zrotext_runtime;";
    let (_, after) = stock
        .split_once(marker)
        .expect("stock runtime ACL boundary");
    let (body, _) = after
        .rsplit_once("\nCOMMIT;")
        .expect("stock runtime transaction end");
    assert!(
        !body.lines().any(|line| line.starts_with('\\')),
        "unexpected psql instruction in stock ACL block"
    );
    let acl = format!("BEGIN; {marker}{body} COMMIT;").replace("zrotext_runtime", role);
    owner.batch_execute(&acl).await.unwrap();
}
