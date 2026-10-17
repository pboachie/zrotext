// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Config, NoTls};

async fn connect(
    config: &Config,
) -> (
    Client,
    tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    let (db, driver) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(driver))
}

async fn close(db: Client, driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>) {
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn ordinary_migrator_backfills_anchors_and_replay_preserves_lifecycle_and_ledger() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    let (admin, admin_driver) = connect(&config).await;
    let suffix: String = admin
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await
        .unwrap()
        .get(0);
    let password: String = admin
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await
        .unwrap()
        .get(0);
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    assert!(verifier.starts_with("SCRAM-SHA-256$") && verifier != password);
    let database = format!("zt_anchor_m_{suffix}");
    let role = format!("zt_anchor_m_role_{suffix}");
    // DDL identifiers cannot use bind parameters. Quote every generated name
    // and the SCRAM verifier through the driver's maintained SQL escapers.
    let sql_database = escape_identifier(&database);
    let sql_role = escape_identifier(&role);
    let sql_verifier = escape_literal(&verifier);
    admin.batch_execute(&format!("CREATE ROLE {sql_role} LOGIN PASSWORD {sql_verifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION"))
        .await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {sql_database} OWNER {sql_role}"))
        .await
        .unwrap();
    config.dbname(&database).user(&role).password(&password);
    let (mut db, driver) = connect(&config).await;
    assert!(
        !db.query_one(
            "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let position = migrations.iter().position(|m| m.version == 100).unwrap();
    apply_locked(&mut db, &migrations[..position], false)
        .await
        .unwrap();
    let existing: String = db
        .query_one(
            "INSERT INTO accounts(id) VALUES(gen_random_uuid()) RETURNING id::text",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        db.query_one(
            "SELECT to_regclass('public.payload_profile_account_anchors') IS NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let applied = apply(&mut db, &directory, false).await.unwrap();
    assert!(applied.iter().any(|m| m.version == 100));
    assert!(applied.iter().any(|m| m.version == 101));
    let first = db.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1::text::uuid", &[&existing]).await.unwrap();
    assert_eq!(first.get::<_, String>(0), "live");
    assert_eq!(first.get::<_, i64>(1), 0);
    let ledger = db
        .query(
            "SELECT checksum_sha256,applied_at::text FROM schema_migrations WHERE version IN (100,101) ORDER BY version",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(ledger.len(), 2);
    let metadata: String = db.query_one("SELECT json_agg(json_build_array(oid,proowner,proacl::text,prosecdef,proconfig,prosrc) ORDER BY proname)::text FROM pg_proc WHERE pronamespace='public'::regnamespace AND (proname LIKE 'payload_profile_a%' OR proname='parent_account_mirror_guard')", &[]).await.unwrap().get(0);
    assert!(apply(&mut db, &directory, false).await.unwrap().is_empty());
    let replay = db
        .query(
            "SELECT checksum_sha256,applied_at::text FROM schema_migrations WHERE version IN (100,101) ORDER BY version",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(replay.len(), ledger.len());
    for (before, after) in ledger.iter().zip(replay.iter()) {
        assert_eq!(before.get::<_, Vec<u8>>(0), after.get::<_, Vec<u8>>(0));
        assert_eq!(before.get::<_, String>(1), after.get::<_, String>(1));
    }
    let after: String = db.query_one("SELECT json_agg(json_build_array(oid,proowner,proacl::text,prosecdef,proconfig,prosrc) ORDER BY proname)::text FROM pg_proc WHERE pronamespace='public'::regnamespace AND (proname LIKE 'payload_profile_a%' OR proname='parent_account_mirror_guard')", &[]).await.unwrap().get(0);
    assert_eq!(metadata, after);
    let created: String = db
        .query_one(
            "INSERT INTO accounts(id) VALUES(gen_random_uuid()) RETURNING id::text",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for id in [&existing, &created] {
        db.execute("DELETE FROM accounts WHERE id=$1::text::uuid", &[id])
            .await
            .unwrap();
        let tombstone = db.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1::text::uuid", &[id]).await.unwrap();
        assert_eq!(tombstone.get::<_, String>(0), "deleted");
        assert_eq!(tombstone.get::<_, i64>(1), 1);
    }
    close(db, driver).await;
    admin
        .batch_execute(&format!("DROP DATABASE {sql_database}"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("DROP ROLE {sql_role}"))
        .await
        .unwrap();
    close(admin, admin_driver).await;
}
