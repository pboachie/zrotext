// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};
use tokio_postgres::{Config, NoTls};

async fn connect(config: &Config) -> Client {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn disposable_database() -> (String, Client, Config) {
    let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL to a disposable PostgreSQL cluster with CREATEDB");
    let admin_config: Config = base.parse().unwrap();
    let admin = connect(&admin_config).await;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("zt_online_index_{}_{nonce}", std::process::id());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let mut database_config = admin_config;
    database_config.dbname(&name);
    (name, admin, database_config)
}

async fn finish_database(name: &str, admin: &Client) {
    admin
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await
        .unwrap();
}

async fn wait_for_invalid(client: &Client) {
    timeout(Duration::from_secs(5), async {
        loop {
            if in_flight_index_status(client).await.unwrap() == Some((true, false)) {
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
async fn fresh_install_checks_index_and_rejects_conflicting_or_lost_index() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow 034; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == IN_FLIGHT_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and 034
    // must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX messages_in_flight_updated ON public.messages(id,updated_at) \
             WHERE state IN ('claimed','submitting','submitted')",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::InFlightIndexConflict)
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&IN_FLIGHT_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client.batch_execute(DROP_IN_FLIGHT_INDEX).await.unwrap();
    let applied = apply(&mut client, &directory, false).await.unwrap();
    assert_eq!(
        applied
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>(),
        from_index
    );
    verify_in_flight_index(&client).await.unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    client.batch_execute(DROP_IN_FLIGHT_INDEX).await.unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::InFlightIndexUnavailable)
    ));
    client
        .batch_execute(
            "CREATE INDEX messages_in_flight_updated ON public.messages(id,updated_at) \
             WHERE state IN ('claimed','submitting','submitted')",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::InFlightIndexUnavailable)
    ));
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn concurrent_build_allows_writes_and_retries_interrupted_invalid_index() {
    let (name, admin, config) = disposable_database().await;
    let holder = connect(&config).await;
    let observer = connect(&config).await;
    holder
        .batch_execute(
            "CREATE TABLE public.messages(id uuid PRIMARY KEY,state text NOT NULL,updated_at timestamptz NOT NULL)",
        )
        .await
        .unwrap();

    holder
        .batch_execute(
            "BEGIN; INSERT INTO public.messages VALUES('00000000-0000-4000-8000-000000000001','claimed',now())",
        )
        .await
        .unwrap();
    let builder = connect(&config).await;
    let first_build = tokio::spawn(async move { prepare_in_flight_index(&builder).await });
    wait_for_invalid(&observer).await;
    assert!(matches!(
        prepare_in_flight_index(&observer).await,
        Err(MigrationError::InFlightIndexBuildInProgress)
    ));
    // A plain CREATE INDEX waiting behind holder's write lock would also
    // block this later writer. The concurrent build must allow it to finish.
    timeout(
        Duration::from_secs(2),
        observer.batch_execute(
            "INSERT INTO public.messages VALUES('00000000-0000-4000-8000-000000000002','claimed',now())",
        ),
    )
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
        in_flight_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    observer
        .batch_execute(include_str!(
            "../../../deploy/compose/migrations/034_delivery_sweep_index.sql"
        ))
        .await
        .unwrap();
    verify_in_flight_index(&observer).await.unwrap();

    observer.batch_execute(DROP_IN_FLIGHT_INDEX).await.unwrap();
    holder
        .batch_execute(
            "BEGIN; INSERT INTO public.messages VALUES('00000000-0000-4000-8000-000000000003','submitted',now())",
        )
        .await
        .unwrap();
    let interrupted_builder = connect(&config).await;
    let backend_pid: i32 = interrupted_builder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let interrupted =
        tokio::spawn(async move { prepare_in_flight_index(&interrupted_builder).await });
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
        in_flight_index_status(&observer).await.unwrap(),
        Some((true, false))
    );
    assert!(matches!(
        verify_in_flight_index(&observer).await,
        Err(MigrationError::InFlightIndexUnavailable)
    ));

    prepare_in_flight_index(&observer).await.unwrap();
    assert_eq!(
        in_flight_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    verify_in_flight_index(&observer).await.unwrap();
    finish_database(&name, &admin).await;
}
