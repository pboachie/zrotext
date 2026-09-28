// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;
use std::time::Duration;
use tokio::time::{sleep, timeout};

const WRONG_ORDER_INDEX: &str = "CREATE INDEX message_attempts_device_created \
     ON public.message_attempts(created_at,account_id,device_id)";

async fn wait_for_invalid(client: &Client) {
    timeout(Duration::from_secs(5), async {
        loop {
            if recent_attempt_index_status(client).await.unwrap() == Some((true, false)) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("concurrent build never exposed an invalid index");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_checks_recent_attempt_index_and_rejects_conflicting_or_lost_index() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow this one; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == RECENT_ATTEMPT_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and the
    // gate must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client.batch_execute(WRONG_ORDER_INDEX).await.unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RecentAttemptIndexConflict)
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&RECENT_ATTEMPT_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client
        .batch_execute(DROP_RECENT_ATTEMPT_INDEX)
        .await
        .unwrap();
    let applied = apply(&mut client, &directory, false).await.unwrap();
    assert_eq!(
        applied
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>(),
        from_index
    );
    verify_recent_attempt_index(&client).await.unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    client
        .batch_execute(DROP_RECENT_ATTEMPT_INDEX)
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RecentAttemptIndexUnavailable)
    ));
    client.batch_execute(WRONG_ORDER_INDEX).await.unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RecentAttemptIndexUnavailable)
    ));
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn recent_attempt_index_builds_concurrently_and_retries_an_interrupted_build() {
    let (name, admin, config) = disposable_database().await;
    let holder = connect(&config).await;
    let observer = connect(&config).await;
    holder
        .batch_execute(
            "CREATE TABLE public.message_attempts(id uuid PRIMARY KEY,account_id uuid NOT NULL,\
             device_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT now())",
        )
        .await
        .unwrap();
    let insert = |n: u8| {
        format!(
            "INSERT INTO public.message_attempts(id,account_id,device_id) VALUES(\
             '00000000-0000-4000-8000-0000000000{n:02}',\
             '00000000-0000-4000-8000-000000000100','00000000-0000-4000-8000-000000000200')"
        )
    };

    holder
        .batch_execute(&format!("BEGIN; {}", insert(1)))
        .await
        .unwrap();
    let builder = connect(&config).await;
    let first_build = tokio::spawn(async move { prepare_recent_attempt_index(&builder).await });
    wait_for_invalid(&observer).await;
    assert!(matches!(
        prepare_recent_attempt_index(&observer).await,
        Err(MigrationError::RecentAttemptIndexBuildInProgress)
    ));
    // A plain CREATE INDEX waiting behind holder's write lock would also
    // block this later writer. The concurrent build must allow it to finish.
    timeout(Duration::from_secs(2), observer.batch_execute(&insert(2)))
        .await
        .expect("index build blocked a concurrent writer")
        .unwrap();
    holder.batch_execute("COMMIT").await.unwrap();
    timeout(Duration::from_secs(10), first_build)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        recent_attempt_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    observer
        .batch_execute(include_str!(
            "../../../deploy/compose/migrations/050_message_attempts_recent_index.sql"
        ))
        .await
        .unwrap();
    verify_recent_attempt_index(&observer).await.unwrap();

    observer
        .batch_execute(DROP_RECENT_ATTEMPT_INDEX)
        .await
        .unwrap();
    holder
        .batch_execute(&format!("BEGIN; {}", insert(3)))
        .await
        .unwrap();
    let interrupted_builder = connect(&config).await;
    let backend_pid: i32 = interrupted_builder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let interrupted =
        tokio::spawn(async move { prepare_recent_attempt_index(&interrupted_builder).await });
    wait_for_invalid(&observer).await;
    let canceled: bool = observer
        .query_one("SELECT pg_cancel_backend($1)", &[&backend_pid])
        .await
        .unwrap()
        .get(0);
    assert!(canceled);
    assert!(interrupted.await.unwrap().is_err());
    holder.batch_execute("COMMIT").await.unwrap();
    assert_eq!(
        recent_attempt_index_status(&observer).await.unwrap(),
        Some((true, false))
    );
    assert!(matches!(
        verify_recent_attempt_index(&observer).await,
        Err(MigrationError::RecentAttemptIndexUnavailable)
    ));

    prepare_recent_attempt_index(&observer).await.unwrap();
    assert_eq!(
        recent_attempt_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    verify_recent_attempt_index(&observer).await.unwrap();
    finish_database(&name, &admin).await;
}
