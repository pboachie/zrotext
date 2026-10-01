// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn execution_schema_is_installed_by_numbered_migrator_and_replay_preserves_ledger() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let position = migrations
        .iter()
        .position(|migration| migration.filename == "082_conversation_execution_records.sql")
        .expect("execution schema must be in the numbered migrator directory");
    apply_locked(&mut client, &migrations[..position], false)
        .await
        .unwrap();
    let before: bool = client
        .query_one(
            "SELECT to_regclass('public.conversation_execution_records') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !before,
        "ordinary pre-upgrade schema must not install execution records"
    );

    apply(&mut client, &directory, false).await.unwrap();
    let present: bool = client
        .query_one(
            "SELECT to_regclass('public.conversation_execution_records') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(present, "dedicated migrator must install execution records");
    let column = client
        .query_one(
            "SELECT data_type,is_nullable,column_default FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='conversation_confirmation_records' \
         AND column_name='execution_metered'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(column.get::<_, String>(0), "boolean");
    assert_eq!(column.get::<_, String>(1), "YES");
    assert!(
        column.get::<_, Option<String>>(2).is_none(),
        "installation must not manufacture execution authority for legacy proofs"
    );
    let installed = client
        .query_one(
            "SELECT checksum_sha256,applied_at::text FROM schema_migrations WHERE version=82",
            &[],
        )
        .await
        .unwrap();
    let checksum: Vec<u8> = installed.get(0);
    let installed_at: String = installed.get(1);
    assert_eq!(checksum.len(), 32);
    apply(&mut client, &directory, false).await.unwrap();
    let replay = client
        .query_one(
            "SELECT checksum_sha256,applied_at::text FROM schema_migrations WHERE version=82",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(replay.get::<_, Vec<u8>>(0), checksum);
    assert_eq!(replay.get::<_, String>(1), installed_at);
    let records: i64 = client
        .query_one("SELECT count(*) FROM conversation_execution_records", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        records, 0,
        "schema installation must not create execution grants"
    );
    drop(client);
    finish_database(&name, &admin).await;
}
