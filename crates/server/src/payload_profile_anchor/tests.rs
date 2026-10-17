// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_payload_election03::adapter_contract::account_fence_key;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, Error, NoTls, error::SqlState};

async fn connect(config: &Config) -> (Client, JoinHandle<Result<(), Error>>) {
    let (db, driver) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(driver))
}

async fn close(db: Client, driver: JoinHandle<Result<(), Error>>) {
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEROLE; unique disposable quoted schema"]
async fn ordinary_role_lifecycle_retains_identity_and_refuses_partial_or_unauthorized_changes() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    config.options("");
    let (owner, owner_driver) = connect(&config).await;
    let namespace = format!("anchor's schema {}", Uuid::new_v4().simple());
    let quoted = format!("\"{namespace}\"");
    owner
        .batch_execute(&format!(
            "CREATE SCHEMA {quoted}; SET search_path TO {quoted}"
        ))
        .await
        .unwrap();
    crate::auth::test_schema::apply(&owner).await;
    let role = format!("zt_anchor_r_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    assert!(verifier.starts_with("SCRAM-SHA-256$") && verifier != password);
    owner.batch_execute(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{verifier}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
         GRANT USAGE ON SCHEMA {quoted} TO {role};
         GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {quoted} TO {role};
         REVOKE ALL ON {quoted}.payload_profile_account_anchors FROM {role};
         GRANT SELECT ON {quoted}.payload_profile_account_anchors TO {role};
         GRANT UPDATE(account_id) ON {quoted}.payload_profile_account_anchors TO {role};
         GRANT EXECUTE ON FUNCTION {quoted}.payload_profile_account_fence_key(uuid) TO {role};"
    )).await.unwrap();
    let owner_config = config.clone();
    config.user(&role).password(&password);
    let (mut runtime, runtime_driver) = connect(&config).await;
    runtime
        .batch_execute(&format!(
            "SET search_path TO pg_catalog, {quoted}; SET statement_timeout='2s'"
        ))
        .await
        .unwrap();
    assert!(
        !runtime
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let first = Uuid::new_v4();
    runtime
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&first])
        .await
        .unwrap();
    assert!(matches!(
        retention(&runtime, first).await.unwrap(),
        Retention::Invalid
    ));
    let row = runtime.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1 FOR SHARE NOWAIT", &[&first]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "live");
    assert_eq!(row.get::<_, i64>(1), 0);
    let sql_key: i64 = runtime
        .query_one("SELECT payload_profile_account_fence_key($1)", &[&first])
        .await
        .unwrap()
        .get(0);
    assert_eq!(sql_key, account_fence_key(first.as_bytes()).unwrap());
    for command in [
        "UPDATE payload_profile_account_anchors SET selection_epoch=1",
        "UPDATE payload_profile_account_anchors SET state='deleted'",
        "INSERT INTO payload_profile_account_anchors(account_id) SELECT id FROM accounts",
        "DELETE FROM payload_profile_account_anchors",
        "TRUNCATE payload_profile_account_anchors",
        "ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER USER",
        "SELECT payload_profile_anchor_account_created()",
        "SELECT payload_profile_anchor_account_changing()",
        "SELECT payload_profile_anchor_account_deleted()",
        "SET session_replication_role=replica",
    ] {
        let denied = runtime.batch_execute(command).await.unwrap_err();
        assert_eq!(
            denied.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{command}"
        );
    }
    let denied = runtime
        .execute(
            "UPDATE payload_profile_account_anchors SET account_id=$2 WHERE account_id=$1",
            &[&first, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Some(&SqlState::CHECK_VIOLATION));
    let denied = runtime
        .execute(
            "UPDATE accounts SET id=$2 WHERE id=$1",
            &[&first, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Some(&SqlState::CHECK_VIOLATION));
    // Account invalidation remains an ordinary supported update.
    runtime
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&first],
        )
        .await
        .unwrap();

    let (mut blocker, blocker_driver) = connect(&owner_config).await;
    blocker
        .batch_execute(&format!("SET search_path TO {quoted}"))
        .await
        .unwrap();
    let held = blocker.transaction().await.unwrap();
    held.query_one("SELECT pg_advisory_xact_lock_shared($1)", &[&sql_key])
        .await
        .unwrap();
    let refused = runtime
        .execute("DELETE FROM accounts WHERE id=$1", &[&first])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    let second = Uuid::new_v4();
    runtime
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&second])
        .await
        .unwrap();
    held.rollback().await.unwrap();
    let held = blocker.transaction().await.unwrap();
    held.query_one(
        "SELECT state FROM payload_profile_account_anchors WHERE account_id=$1 FOR SHARE",
        &[&first],
    )
    .await
    .unwrap();
    let refused = runtime
        .execute("DELETE FROM accounts WHERE id=$1", &[&first])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    assert_eq!(
        owner
            .query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&first])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert!(matches!(
        retention(&runtime, first).await.unwrap(),
        Retention::Invalid
    ));
    held.rollback().await.unwrap();
    close(blocker, blocker_driver).await;

    // A later failure rolls the definer-owned new anchor back with its account.
    let cancelled = Uuid::new_v4();
    let tx = runtime.transaction().await.unwrap();
    tx.execute("INSERT INTO accounts(id) VALUES($1)", &[&cancelled])
        .await
        .unwrap();
    assert!(
        tx.batch_execute("UPDATE payload_profile_account_anchors SET selection_epoch=1")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(
        !owner
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM payload_profile_account_anchors WHERE account_id=$1)",
                &[&cancelled]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    runtime
        .execute("DELETE FROM accounts WHERE id=$1", &[&first])
        .await
        .unwrap();
    assert!(matches!(
        retention(&runtime, first).await.unwrap(),
        Retention::Deleted
    ));
    let reused = runtime
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&first])
        .await
        .unwrap_err();
    assert_eq!(reused.code(), Some(&SqlState::UNIQUE_VIOLATION));
    assert_eq!(
        owner
            .query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&first])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );

    // Stronger than stock runtime (which denies TEMP): a temporary relation
    // cannot become an application retention report or a definer's target.
    runtime.batch_execute("CREATE TEMP TABLE accounts(id uuid PRIMARY KEY); CREATE TEMP TABLE payload_profile_account_anchors(account_id uuid,state text,selection_epoch bigint)")
        .await.unwrap();
    runtime
        .execute(
            "INSERT INTO pg_temp.accounts VALUES($1),($2)",
            &[&first, &second],
        )
        .await
        .unwrap();
    runtime.execute("INSERT INTO pg_temp.payload_profile_account_anchors VALUES($1,'deleted',999),($2,'deleted',999)", &[&first,&second]).await.unwrap();
    assert!(matches!(
        retention(&runtime, first).await.unwrap(),
        Retention::Invalid
    ));
    runtime
        .execute(
            &format!("DELETE FROM {quoted}.accounts WHERE id=$1"),
            &[&second],
        )
        .await
        .unwrap();
    let real: String = owner
        .query_one(
            "SELECT state FROM payload_profile_account_anchors WHERE account_id=$1",
            &[&second],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(real, "deleted");
    runtime
        .batch_execute(
            "DROP TABLE pg_temp.accounts; DROP TABLE pg_temp.payload_profile_account_anchors",
        )
        .await
        .unwrap();

    // Explicit disposable corruption control: missing anchors fail closed.
    let missing = Uuid::new_v4();
    runtime
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&missing])
        .await
        .unwrap();
    owner.batch_execute("ALTER TABLE payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change").await.unwrap();
    owner
        .execute(
            "DELETE FROM payload_profile_account_anchors WHERE account_id=$1",
            &[&missing],
        )
        .await
        .unwrap();
    owner.batch_execute("ALTER TABLE payload_profile_account_anchors ENABLE TRIGGER payload_profile_anchor_before_change").await.unwrap();
    let refused = runtime
        .execute("DELETE FROM accounts WHERE id=$1", &[&missing])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some(&SqlState::CHECK_VIOLATION));
    assert!(matches!(
        retention(&runtime, missing).await.unwrap(),
        Retention::Invalid
    ));
    close(runtime, runtime_driver).await;
    owner
        .batch_execute(&format!(
            "SET search_path TO pg_catalog; DROP SCHEMA {quoted} CASCADE; DROP ROLE {role}"
        ))
        .await
        .unwrap();
    close(owner, owner_driver).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable pre-anchor schema"]
async fn retention_distinguishes_absent_installation_from_invalid_identity_state() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let config: Config = raw.parse().unwrap();
    let (db, driver) = connect(&config).await;
    let schema = format!("zt_anchor_legacy_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema}; CREATE TABLE accounts(id uuid PRIMARY KEY)"))
        .await.unwrap();
    assert!(matches!(
        retention(&db, Uuid::new_v4()).await.unwrap(),
        Retention::NotInstalled
    ));
    db.batch_execute("CREATE TABLE payload_profile_account_anchors(account_id uuid PRIMARY KEY,state text,selection_epoch bigint)").await.unwrap();
    assert!(matches!(
        retention(&db, Uuid::new_v4()).await.unwrap(),
        Retention::Invalid
    ));
    let malformed = Uuid::new_v4();
    db.execute(
        "INSERT INTO payload_profile_account_anchors(account_id) VALUES($1)",
        &[&malformed],
    )
    .await
    .unwrap();
    assert!(
        retention(&db, malformed).await.is_err(),
        "malformed retained rows fail without panicking"
    );
    db.batch_execute(&format!(
        "SET search_path TO pg_catalog; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
    close(db, driver).await;
}
