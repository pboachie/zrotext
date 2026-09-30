// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;

/// The migrator drops the charge-amplifying updated_at index online before the
/// numbered gate records it, the gate refuses a leftover index, and a recorded
/// drop keeps refusing a re-created one (#500).
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_drops_abuse_counters_stale_index_and_rejects_leftovers() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == ABUSE_COUNTERS_INDEX_DROP_MIGRATION)
        .unwrap();

    // Before the drop, migration 012's index exists and gates the charge path.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    let indexed: bool = client
        .query_one(
            "SELECT to_regclass('public.auth_abuse_counters_stale') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(indexed);

    // The full run drops it online and records the gate.
    apply(&mut client, &directory, false).await.unwrap();
    let dropped: bool = client
        .query_one(
            "SELECT to_regclass('public.auth_abuse_counters_stale') IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(dropped, "the charge-amplifying index must be gone");
    assert!(verify_abuse_counters_index_dropped(&client).await.is_ok());

    // An operator re-creating the index must not survive an idempotent rerun:
    // the recorded gate refuses it.
    client
        .batch_execute(
            "CREATE INDEX auth_abuse_counters_stale ON public.auth_abuse_counters(updated_at)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::AbuseCountersStaleIndexPresent)
    ));
    client
        .batch_execute("DROP INDEX public.auth_abuse_counters_stale")
        .await
        .unwrap();
    assert!(apply(&mut client, &directory, false).await.is_ok());

    finish_database(&name, &admin).await;
    drop(client);
}

/// A drop interrupted after the CONCURRENTLY statement still completes: the
/// prepare is IF EXISTS, so a rerun applies the gate.
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn interrupted_abuse_counters_drop_is_idempotent() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == ABUSE_COUNTERS_INDEX_DROP_MIGRATION)
        .unwrap();
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    // A first prepare drops the index; a second (as after an interrupted run
    // before the ledger insert) must succeed again.
    prepare_abuse_counters_index_drop(&client).await.unwrap();
    prepare_abuse_counters_index_drop(&client).await.unwrap();
    apply(&mut client, &directory, false).await.unwrap();
    assert!(verify_abuse_counters_index_dropped(&client).await.is_ok());

    finish_database(&name, &admin).await;
    drop(client);
}
