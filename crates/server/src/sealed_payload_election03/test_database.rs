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
    provision_runtime_from(owner, database, role, "zrotext_runtime").await;
}

// A migration may have granted its fixed runtime role before this fixture
// substitutes its isolated role. Remove that predecessor's rights only in this
// disposable database, then apply the unchanged stock reset in the SAME commit.
// Table-level REVOKE does not remove explicit column ACLs.
async fn provision_runtime_from(owner: &Client, database: &str, role: &str, prior_role: &str) {
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
    assert_ne!(role, prior_role);
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
    let cleanup = format!(
        "DO $fixture$ DECLARE relation record; BEGIN
         IF EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname={prior_literal}) THEN
          REVOKE ALL ON SCHEMA public FROM {prior_id};
          REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {prior_id};
          REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {prior_id};
          REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM {prior_id};
          FOR relation IN
           SELECT c.relname,string_agg(pg_catalog.quote_ident(a.attname),',' ORDER BY a.attnum) AS columns_sql
           FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
           WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p','v','m','f')
            AND a.attnum>0 AND NOT a.attisdropped GROUP BY c.oid,c.relname
          LOOP
           EXECUTE pg_catalog.format('REVOKE ALL (%s) ON TABLE public.%I FROM %I',relation.columns_sql,relation.relname,{prior_literal});
          END LOOP;
         END IF; END $fixture$;",
        prior_literal = escape_literal(prior_role),
        prior_id = escape_identifier(prior_role)
    );
    let mapped = format!("{marker}{body}").replace("zrotext_runtime", role);
    let acl = format!("BEGIN; {cleanup} {mapped} COMMIT;");
    owner.batch_execute(&acl).await.unwrap();
}

#[cfg(test)]
mod tests;
