// SPDX-License-Identifier: AGPL-3.0-only
//! Actual numbered public-schema and stock ACL coverage, separate from legacy107 isolation.
use super::TEST_MIGRATIONS;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Config, NoTls, error::SqlState};
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

// Use only a generated raw identifier: the stock reset also compares rolname
// text literals, so substituting an already quoted identifier would change data.
fn runtime_acl(database: &str, runtime: &str) -> String {
    assert!(
        !runtime.is_empty()
            && runtime.len() <= 63
            && runtime.as_bytes()[0].is_ascii_lowercase()
            && runtime
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let stock = include_str!("../../../deploy/compose/runtime-role.sql");
    let marker = "REVOKE ALL ON SCHEMA public FROM PUBLIC, zrotext_runtime;";
    let (_, tail) = stock
        .split_once(marker)
        .expect("stock post-role ACL boundary");
    let (body, _) = tail
        .rsplit_once("\nCOMMIT;")
        .expect("stock transaction end");
    assert!(!body.lines().any(|line| line.starts_with('\\')));
    format!("REVOKE ALL ON DATABASE {db} FROM PUBLIC,{role}; GRANT CONNECT ON DATABASE {db} TO {role};\nBEGIN; {marker}{body} COMMIT;",
        db = escape_identifier(database), role = escape_identifier(runtime)).replace("zrotext_runtime", runtime)
}
fn runtime_verifier(runtime: &str, owner: &str) -> String {
    // The unchanged negative SET ROLE check targets this fixture's EXISTING
    // migration owner, rather than a potentially absent global role.
    include_str!("../../../deploy/compose/verify_runtime_role.sql")
        .replace("zrotext_runtime", runtime)
        .replace("'SET ROLE zrotext'", &format!("'SET ROLE {owner}'"))
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn current_numbered_public_schema_uses_real_ledger_and_stock_ordinary_runtime_fences() {
    let mut config: Config = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("disposable test cluster")
        .parse()
        .unwrap();
    config.connect_timeout(std::time::Duration::from_secs(5));
    let (admin, admin_driver) = connect(&config).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let database = format!("delivery_current_{suffix}");
    let owner_role = format!("delivery_owner_{suffix}");
    let runtime_role = format!("delivery_runtime_{suffix}");
    let owner_password = Uuid::new_v4().simple().to_string();
    let runtime_password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    for (role, password) in [
        (&owner_role, &owner_password),
        (&runtime_role, &runtime_password),
    ] {
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
            escape_identifier(role), escape_literal(&verifier))).await.unwrap();
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
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let applied = zrotext_migrator::apply(&mut owner, &directory, false)
        .await
        .unwrap();
    assert_eq!(applied.len(), TEST_MIGRATIONS.len());
    assert_eq!(applied.last().unwrap().version, 118);
    let ledger = owner.query("SELECT version,filename,checksum_sha256 FROM public.schema_migrations ORDER BY version", &[]).await.unwrap();
    assert_eq!(ledger.len(), 118);
    for (index, (row, (filename, sql))) in ledger.iter().zip(TEST_MIGRATIONS).enumerate() {
        assert_eq!(row.get::<_, i64>(0), (index + 1) as i64);
        assert_eq!(row.get::<_, String>(1), filename);
        assert_eq!(
            row.get::<_, Vec<u8>>(2),
            Sha256::digest(sql.as_bytes()).as_slice()
        );
    }
    let graph: Vec<u8> = owner
        .query_one("SELECT public.payload_profile_writer_graph()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        graph,
        owner
            .query_one("SELECT public.payload_profile_writer_graph()", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0)
    );

    let acl = runtime_acl(&database, &runtime_role);
    owner.batch_execute(&acl).await.unwrap();
    config.user(&runtime_role).password(&runtime_password);
    let (runtime, runtime_driver) = connect(&config).await;
    let verifier = runtime_verifier(&runtime_role, &owner_role);
    runtime.batch_execute(&verifier).await.unwrap();
    assert!(
        runtime
            .query_one("SELECT public.conversation_reviewed_send03_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(!runtime.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=current_user AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) OR EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE member=current_user::regrole) OR EXISTS(SELECT FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace AND relowner=current_user::regrole)", &[]).await.unwrap().get::<_,bool>(0));
    for sql in [
        "SELECT * FROM public.schema_migrations",
        "DELETE FROM public.conversation_reviewed_sends03",
        "SELECT public.conversation_reviewed_send03_erasure_fence(NULL)",
    ] {
        assert_eq!(
            runtime.batch_execute(sql).await.unwrap_err().code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE)
        );
    }
    // A relation-level reset must also remove a previously injected column ACL.
    owner
        .batch_execute(&format!(
            "GRANT UPDATE(redacted_ms) ON public.conversation_reviewed_sends03 TO {}",
            escape_identifier(&runtime_role)
        ))
        .await
        .unwrap();
    assert!(
        !runtime
            .query_one("SELECT public.conversation_reviewed_send03_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    owner.batch_execute(&acl).await.unwrap();
    runtime.batch_execute(&verifier).await.unwrap();
    assert!(
        runtime
            .query_one("SELECT public.conversation_reviewed_send03_ready()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );

    let account = Uuid::new_v4();
    runtime
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    runtime
        .execute("DELETE FROM public.accounts WHERE id=$1", &[&account])
        .await
        .unwrap();
    assert!(runtime.query_one("SELECT state='deleted' AND selection_epoch=1 FROM public.payload_profile_account_anchors WHERE account_id=$1", &[&account]).await.unwrap().get::<_, bool>(0));
    close(runtime, runtime_driver).await;
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
}
