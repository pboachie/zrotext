// SPDX-License-Identifier: AGPL-3.0-only
//! The real migration against a minimal ownership fixture. Full numbered-schema
//! compatibility is separately exercised by the auth/mail/erasure/delivery tests.
use tokio_postgres::{Client, Config, NoTls, error::SqlState};
use uuid::Uuid;

const CHILDREN: [(&str, &str, &str, bool); 4] = [
    (
        "password_reset_mail_outbox",
        "reset_id",
        "password_resets",
        true,
    ),
    (
        "verification_mail_outbox",
        "verification_id",
        "email_verifications",
        true,
    ),
    (
        "sealed_event_delivery_attempts",
        "delivery_id",
        "sealed_event_deliveries",
        false,
    ),
    (
        "webhook_attempts",
        "delivery_id",
        "webhook_deliveries",
        false,
    ),
];

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEROLE; disposable quoted ownership fixture"]
async fn parent_mirrors_backfill_preserve_legacy_writers_and_keep_old_account_after_parent_deletion()
 {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    config.options("");
    let (owner, owner_driver) = config.connect(NoTls).await.unwrap();
    let owner_driver = tokio::spawn(owner_driver);
    let namespace = format!("mirror's schema {}", Uuid::new_v4().simple());
    let quoted = format!("\"{namespace}\"");
    owner.batch_execute(&format!("CREATE SCHEMA {quoted}; SET search_path TO {quoted}; CREATE TABLE accounts(id uuid PRIMARY KEY)")).await.unwrap();
    for (_, _, parent, _) in CHILDREN {
        owner.batch_execute(&format!("CREATE TABLE {parent}(id uuid PRIMARY KEY,account_id uuid NOT NULL REFERENCES accounts(id))")).await.unwrap();
    }
    // These exact unique parent keys already exist in the numbered schema.
    owner.batch_execute("ALTER TABLE sealed_event_deliveries ADD UNIQUE(account_id,id); ALTER TABLE webhook_deliveries ADD UNIQUE(account_id,id)").await.unwrap();
    for (child, key, parent, cascade) in CHILDREN {
        let action = if cascade { "ON DELETE CASCADE" } else { "" };
        owner.batch_execute(&format!("CREATE TABLE {child}({key} uuid PRIMARY KEY REFERENCES {parent}(id) {action}, marker integer NOT NULL DEFAULT 0)")).await.unwrap();
    }
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    owner
        .execute("INSERT INTO accounts VALUES($1),($2)", &[&first, &second])
        .await
        .unwrap();
    let before = Uuid::new_v4();
    let after = Uuid::new_v4();
    let alternate = Uuid::new_v4();
    for (child, key, parent, _) in CHILDREN {
        owner
            .execute(
                &format!("INSERT INTO {parent} VALUES($1,$2),($3,$4),($5,$2)"),
                &[&before, &first, &after, &second, &alternate],
            )
            .await
            .unwrap();
        owner
            .execute(
                &format!("INSERT INTO {child}({key}) VALUES($1)"),
                &[&before],
            )
            .await
            .unwrap();
    }
    let (mut blocker, blocker_driver) = config.connect(NoTls).await.unwrap();
    let blocker_driver = tokio::spawn(blocker_driver);
    let held = blocker.transaction().await.unwrap();
    held.batch_execute(&format!(
        "LOCK TABLE {quoted}.password_resets IN ROW EXCLUSIVE MODE"
    ))
    .await
    .unwrap();
    let migration_busy = owner
        .batch_execute(concat!(
            "BEGIN;",
            include_str!("../../../deploy/compose/migrations/101_parent_account_mirrors.sql"),
            "COMMIT;"
        ))
        .await
        .unwrap_err();
    assert_eq!(migration_busy.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    owner.batch_execute("ROLLBACK").await.unwrap();
    for (child, _, _, _) in CHILDREN {
        assert_eq!(owner.query_one("SELECT count(*) FROM pg_attribute WHERE attrelid=$1::text::regclass AND attname='account_id'", &[&child]).await.unwrap().get::<_,i64>(0),0);
    }
    held.rollback().await.unwrap();
    close(blocker, blocker_driver).await;
    owner
        .batch_execute(concat!(
            "BEGIN;",
            include_str!("../../../deploy/compose/migrations/101_parent_account_mirrors.sql"),
            "COMMIT;"
        ))
        .await
        .unwrap();
    for (child, key, _, _) in CHILDREN {
        assert_eq!(
            owner
                .query_one(
                    &format!("SELECT account_id FROM {child} WHERE {key}=$1"),
                    &[&before]
                )
                .await
                .unwrap()
                .get::<_, Uuid>(0),
            first
        );
        assert!(owner.query_one("SELECT attnotnull FROM pg_attribute WHERE attrelid=$1::text::regclass AND attname='account_id'", &[&child]).await.unwrap().get::<_,bool>(0));
    }
    let role = format!("zt_mirror_r_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    assert!(verifier.starts_with("SCRAM-SHA-256$") && verifier != password);
    owner.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{verifier}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
      GRANT USAGE ON SCHEMA {quoted} TO {role}; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {quoted} TO {role};
      CREATE TABLE mirror_deletions(child text,account_id uuid,parent_visible boolean);
      GRANT SELECT,INSERT ON mirror_deletions TO {role};
      CREATE FUNCTION mirror_delete_probe() RETURNS trigger LANGUAGE plpgsql AS $probe$
        DECLARE parent_visible boolean; parent_id uuid;
        BEGIN
          parent_id := (to_jsonb(OLD)->>TG_ARGV[1])::uuid;
          EXECUTE format('SELECT EXISTS(SELECT FROM %I.%I WHERE id=$1)',TG_TABLE_SCHEMA,TG_ARGV[0]) INTO parent_visible USING parent_id;
          INSERT INTO mirror_deletions VALUES(TG_TABLE_NAME,OLD.account_id,parent_visible);
          RETURN OLD;
        END $probe$;")).await.unwrap();
    // The test-only observer records OLD.account_id even when the parent is
    // already absent; it independently records parent visibility at deletion.
    for (child, key, parent, _) in CHILDREN {
        owner.batch_execute(&format!("CREATE TRIGGER mirror_delete_observer AFTER DELETE ON {child} FOR EACH ROW EXECUTE FUNCTION mirror_delete_probe('{parent}','{key}')")).await.unwrap();
    }
    config.user(&role).password(&password);
    let (mut runtime, runtime_driver) = config.connect(NoTls).await.unwrap();
    let runtime_driver = tokio::spawn(runtime_driver);
    runtime
        .batch_execute(&format!(
            "SET search_path TO pg_catalog,{quoted}; SET statement_timeout='2s'"
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
    assert_eq!(
        runtime
            .batch_execute("SELECT parent_account_mirror_guard()")
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    for (child, key, parent, cascade) in CHILDREN {
        runtime
            .execute(&format!("INSERT INTO {child}({key}) VALUES($1)"), &[&after])
            .await
            .unwrap();
        assert_eq!(
            runtime
                .query_one(
                    &format!("SELECT account_id FROM {child} WHERE {key}=$1"),
                    &[&after]
                )
                .await
                .unwrap()
                .get::<_, Uuid>(0),
            second
        );
        runtime
            .execute(
                &format!("UPDATE {child} SET marker=marker+1 WHERE {key}=$1"),
                &[&after],
            )
            .await
            .unwrap();
        for statement in [
            format!("UPDATE {child} SET account_id=$2 WHERE {key}=$1"),
            format!("INSERT INTO {child}({key},account_id) VALUES($1,$2)"),
        ] {
            let id = if statement.starts_with("INSERT") {
                alternate
            } else {
                after
            };
            let incorrect = if statement.starts_with("INSERT") {
                second
            } else {
                first
            };
            assert_eq!(
                runtime
                    .execute(&statement, &[&id, &incorrect])
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::CHECK_VIOLATION)
            );
        }
        assert_eq!(
            runtime
                .execute(
                    &format!("UPDATE {child} SET account_id=NULL WHERE {key}=$1"),
                    &[&after]
                )
                .await
                .unwrap_err()
                .code(),
            Some(&SqlState::CHECK_VIOLATION)
        );
        assert_eq!(
            runtime
                .execute(
                    &format!("UPDATE {child} SET {key}=$2 WHERE {key}=$1"),
                    &[&before, &alternate]
                )
                .await
                .unwrap_err()
                .code(),
            Some(&SqlState::CHECK_VIOLATION)
        );
        assert_eq!(
            runtime
                .execute(
                    &format!("INSERT INTO {child}({key}) VALUES($1)"),
                    &[&Uuid::new_v4()]
                )
                .await
                .unwrap_err()
                .code(),
            Some(&SqlState::CHECK_VIOLATION)
        );
        if !cascade {
            assert_eq!(
                runtime
                    .execute(&format!("DELETE FROM {parent} WHERE id=$1"), &[&after])
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::FOREIGN_KEY_VIOLATION)
            );
            runtime
                .execute(&format!("DELETE FROM {child} WHERE {key}=$1"), &[&after])
                .await
                .unwrap();
        }
        runtime
            .execute(&format!("DELETE FROM {parent} WHERE id=$1"), &[&after])
            .await
            .unwrap();
        let deletion = runtime
            .query_one(
                "SELECT account_id,parent_visible FROM mirror_deletions WHERE child=$1",
                &[&child],
            )
            .await
            .unwrap();
        assert_eq!(deletion.get::<_, Uuid>(0), second);
        assert_eq!(deletion.get::<_, bool>(1), !cascade);
        assert_eq!(
            runtime
                .query_one(
                    &format!("SELECT count(*) FROM {child} WHERE {key}=$1"),
                    &[&after]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    // No preceding parent/child writes survive a later immutable-identity error.
    let cancelled = Uuid::new_v4();
    let tx = runtime.transaction().await.unwrap();
    tx.execute(
        "INSERT INTO password_resets VALUES($1,$2)",
        &[&cancelled, &first],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO password_reset_mail_outbox(reset_id) VALUES($1)",
        &[&cancelled],
    )
    .await
    .unwrap();
    assert!(
        tx.execute(
            "UPDATE password_reset_mail_outbox SET account_id=$2 WHERE reset_id=$1",
            &[&cancelled, &second]
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        runtime
            .query_one(
                "SELECT count(*) FROM password_resets WHERE id=$1",
                &[&cancelled]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // Stronger than stock runtime, which denies TEMP: forged parent rows do not
    // change the qualified guard's derivation even with an implicit temp path.
    runtime
        .batch_execute("CREATE TEMP TABLE password_resets(id uuid,account_id uuid)")
        .await
        .unwrap();
    runtime
        .execute(
            "INSERT INTO pg_temp.password_resets VALUES($1,$2)",
            &[&alternate, &second],
        )
        .await
        .unwrap();
    runtime
        .execute(
            &format!("INSERT INTO {quoted}.password_reset_mail_outbox(reset_id) VALUES($1)"),
            &[&alternate],
        )
        .await
        .unwrap();
    assert_eq!(
        runtime
            .query_one(
                "SELECT account_id FROM password_reset_mail_outbox WHERE reset_id=$1",
                &[&alternate]
            )
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        first
    );
    close(runtime, runtime_driver).await;
    owner
        .batch_execute(&format!(
            "SET search_path TO pg_catalog; DROP SCHEMA {quoted} CASCADE; DROP ROLE {role}"
        ))
        .await
        .unwrap();
    close(owner, owner_driver).await;
}

async fn close(db: Client, driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>) {
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
