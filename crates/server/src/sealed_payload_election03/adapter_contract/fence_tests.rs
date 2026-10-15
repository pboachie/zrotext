// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic candidate primitive, not the production all-writer inventory.
use super::*;
use std::time::Duration;
use tokio::{task::JoinHandle, time::timeout};
use tokio_postgres::{Client, Config, Error, NoTls, error::SqlState};
use uuid::Uuid;

pub(super) async fn connect(config: &Config) -> (Client, JoinHandle<Result<(), Error>>) {
    let (db, connection) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(connection))
}

pub(super) async fn close(db: Client, driver: JoinHandle<Result<(), Error>>) {
    drop(db);
    timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEROLE on a disposable PostgreSQL cluster"]
async fn mandatory_try_fence_refuses_legacy_writers_without_tuple_cycles_or_cross_account_blocking()
{
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    config.connect_timeout(Duration::from_secs(5));
    let (mut owner, owner_driver) = connect(&config).await;
    let nonce = Uuid::new_v4().simple().to_string();
    let namespace = format!("zt_fence_{nonce}");
    let role = format!("zt_fence_r_{nonce}");
    let password = Uuid::new_v4().simple().to_string();
    // Identifiers/password are generated hex. No ambient application object is
    // changed. A failure retains the unique fixture; cleanup never kills peers.
    owner.batch_execute(&format!(
        "CREATE SCHEMA {namespace};
         CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
         SET search_path TO pg_catalog, {namespace};
         CREATE TABLE {namespace}.selection(account uuid PRIMARY KEY, epoch bigint NOT NULL);
         CREATE TABLE {namespace}.current_elections(account uuid PRIMARY KEY REFERENCES {namespace}.selection(account), profile smallint NOT NULL, evidence bytea NOT NULL);
         CREATE TABLE {namespace}.leases(account uuid PRIMARY KEY REFERENCES {namespace}.selection(account), counter bigint NOT NULL);
         CREATE TABLE {namespace}.queue(account uuid NOT NULL REFERENCES {namespace}.selection(account), id uuid PRIMARY KEY, profile smallint NOT NULL, evidence bytea);
         CREATE FUNCTION {namespace}.anchor_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog AS $$
         BEGIN
           IF NEW.account<>OLD.account OR NEW.epoch<OLD.epoch THEN
             RAISE EXCEPTION 'immutable account/monotonic epoch' USING ERRCODE='23514';
           END IF;
           RETURN NEW;
         END; $$;
         CREATE TRIGGER anchor_before BEFORE UPDATE ON {namespace}.selection FOR EACH ROW EXECUTE FUNCTION {namespace}.anchor_identity_guard();
         CREATE FUNCTION {namespace}.fence_key(account uuid) RETURNS bigint LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $$
           SELECT ('x'||substr(encode(sha256(convert_to('ZTSE/line/payload-profile/account-fence/v1','UTF8')||decode('00','hex')||int4send(16)||uuid_send(account)),'hex'),1,16))::bit(64)::bigint
         $$;
         CREATE FUNCTION {namespace}.queue_guard() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog, {namespace} AS $$
         DECLARE who uuid; selected smallint; proof bytea;
         BEGIN
           who := CASE WHEN TG_OP='DELETE' THEN OLD.account ELSE NEW.account END;
           IF TG_OP='UPDATE' AND NEW.account<>OLD.account THEN
             RAISE EXCEPTION 'immutable account' USING ERRCODE='23514';
           END IF;
           IF NOT pg_try_advisory_xact_lock_shared(fence_key(who)) THEN
             RAISE EXCEPTION 'account busy' USING ERRCODE='55P03';
           END IF;
           PERFORM epoch FROM {namespace}.selection WHERE account=who FOR SHARE NOWAIT;
           IF NOT FOUND THEN
             RAISE EXCEPTION 'missing account anchor' USING ERRCODE='23514';
           END IF;
           IF TG_OP='DELETE' THEN RETURN OLD; END IF;
           SELECT profile,evidence INTO selected,proof FROM {namespace}.current_elections WHERE account=who;
           IF NOT FOUND THEN selected:=2; proof:=NULL; END IF;
           IF NEW.profile<>selected OR (selected=2 AND NEW.evidence IS NOT NULL)
             OR (selected=3 AND NEW.evidence IS DISTINCT FROM proof) THEN
             RAISE EXCEPTION 'unsupported profile/provenance' USING ERRCODE='23514';
           END IF;
           RETURN NEW;
         END; $$;
         CREATE TRIGGER queue_before BEFORE INSERT OR UPDATE OR DELETE ON {namespace}.queue FOR EACH ROW EXECUTE FUNCTION {namespace}.queue_guard();
         GRANT USAGE ON SCHEMA {namespace} TO {role};
         GRANT SELECT ON ALL TABLES IN SCHEMA {namespace} TO {role};
         GRANT UPDATE(account) ON {namespace}.selection TO {role};
         GRANT INSERT,UPDATE,DELETE ON {namespace}.queue TO {role};
         GRANT UPDATE ON {namespace}.leases TO {role};"
    )).await.unwrap();
    let first = Uuid::from_bytes([1; 16]);
    let second = Uuid::from_bytes([2; 16]);
    for account in [first, second] {
        owner
            .execute("INSERT INTO selection VALUES($1,0)", &[&account])
            .await
            .unwrap();
        owner
            .execute("INSERT INTO leases VALUES($1,0)", &[&account])
            .await
            .unwrap();
    }
    let key = account_fence_key(first.as_bytes()).unwrap();
    let sql_key: i64 = owner
        .query_one("SELECT fence_key($1)", &[&first])
        .await
        .unwrap()
        .get(0);
    assert_eq!(key, sql_key);
    config.user(&role).password(&password);
    let (mut writer, writer_driver) = connect(&config).await;
    writer
        .batch_execute(&format!(
            "SET search_path TO pg_catalog, {namespace}; SET statement_timeout='2s'"
        ))
        .await
        .unwrap();

    super::snapshot_tests::old_snapshots_refuse(&mut owner, &mut writer, first, key).await;
    // An unchanged ordinary writer never calls the fence API itself.
    let work = writer.transaction().await.unwrap();
    work.execute(
        "INSERT INTO queue VALUES($1,$2,2,NULL)",
        &[&first, &Uuid::new_v4()],
    )
    .await
    .unwrap();
    let election = owner.transaction().await.unwrap();
    assert!(
        !election
            .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    election.rollback().await.unwrap();
    work.rollback().await.unwrap();

    // A legacy SELECT FOR UPDATE can precede its eventual guarded mutation.
    let work = writer.transaction().await.unwrap();
    work.query_one(
        "SELECT counter FROM leases WHERE account=$1 FOR UPDATE",
        &[&first],
    )
    .await
    .unwrap();
    let election = owner.transaction().await.unwrap();
    assert!(
        election
            .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let refusal = timeout(
        Duration::from_secs(1),
        election.query_one(
            "SELECT counter FROM leases WHERE account=$1 FOR UPDATE NOWAIT",
            &[&first],
        ),
    )
    .await
    .expect("no tuple wait/cycle")
    .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    election.rollback().await.unwrap();
    work.execute(
        "INSERT INTO queue VALUES($1,$2,2,NULL)",
        &[&first, &Uuid::new_v4()],
    )
    .await
    .unwrap();
    work.rollback().await.unwrap();

    let election = owner.transaction().await.unwrap();
    assert!(
        election
            .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    // Another account can commit while the first account fence is exclusive.
    writer
        .execute(
            "INSERT INTO queue VALUES($1,$2,2,NULL)",
            &[&second, &Uuid::new_v4()],
        )
        .await
        .unwrap();
    // A later account conflict aborts prior writes in the same transaction.
    let work = writer.transaction().await.unwrap();
    let rolled_back = Uuid::new_v4();
    work.execute(
        "INSERT INTO queue VALUES($1,$2,2,NULL)",
        &[&second, &rolled_back],
    )
    .await
    .unwrap();
    let refusal = timeout(
        Duration::from_secs(1),
        work.execute(
            "INSERT INTO queue VALUES($1,$2,2,NULL)",
            &[&first, &Uuid::new_v4()],
        ),
    )
    .await
    .expect("mandatory try fence cannot wait")
    .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    work.rollback().await.unwrap();
    assert!(
        !election
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM queue WHERE id=$1)",
                &[&rolled_back]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    // Same-transaction trigger acquisition cannot deadlock the owning election.
    election
        .execute(
            "INSERT INTO current_elections VALUES($1,3,$2)",
            &[&first, &vec![3u8; 32]],
        )
        .await
        .unwrap();
    election
        .execute(
            "UPDATE selection SET epoch=epoch+1 WHERE account=$1",
            &[&first],
        )
        .await
        .unwrap();
    election
        .execute(
            "INSERT INTO queue VALUES($1,$2,3,$3)",
            &[&first, &Uuid::new_v4(), &vec![3u8; 32]],
        )
        .await
        .unwrap();
    election.commit().await.unwrap();
    let refusal = writer
        .execute(
            "INSERT INTO queue VALUES($1,$2,2,NULL)",
            &[&first, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::CHECK_VIOLATION));
    // Even if this fixture role can create temp relations, it cannot shadow a
    // trusted anchor/selection. Stock runtime provisioning also denies TEMP.
    writer.batch_execute(
        "CREATE TEMP TABLE selection(account uuid PRIMARY KEY,epoch bigint);
         CREATE TEMP TABLE current_elections(account uuid PRIMARY KEY,profile smallint,evidence bytea)"
    ).await.unwrap();
    writer
        .execute("INSERT INTO pg_temp.selection VALUES($1,0)", &[&first])
        .await
        .unwrap();
    writer
        .execute(
            "INSERT INTO pg_temp.current_elections VALUES($1,2,NULL)",
            &[&first],
        )
        .await
        .unwrap();
    let refusal = writer
        .execute(
            "INSERT INTO queue VALUES($1,$2,2,NULL)",
            &[&first, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::CHECK_VIOLATION));
    let absent = Uuid::new_v4();
    writer
        .execute("INSERT INTO pg_temp.selection VALUES($1,0)", &[&absent])
        .await
        .unwrap();
    writer
        .execute(
            "INSERT INTO pg_temp.current_elections VALUES($1,2,NULL)",
            &[&absent],
        )
        .await
        .unwrap();
    let refusal = writer
        .execute(
            "INSERT INTO queue VALUES($1,$2,2,NULL)",
            &[&absent, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal.code(),
        Some(&SqlState::CHECK_VIOLATION),
        "temporary anchor cannot replace a missing trusted anchor"
    );
    writer
        .batch_execute("DROP TABLE pg_temp.current_elections; DROP TABLE pg_temp.selection")
        .await
        .unwrap();
    let refusal = writer
        .execute(
            "INSERT INTO queue VALUES($1,$2,3,$3)",
            &[&first, &Uuid::new_v4(), &vec![4u8; 32]],
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::CHECK_VIOLATION));
    // Holding the other account's lock never grants provenance for this UUID.
    let work = writer.transaction().await.unwrap();
    assert!(
        work.query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let refusal = work
        .execute(
            "INSERT INTO queue VALUES($1,$2,3,$3)",
            &[&second, &Uuid::new_v4(), &vec![3u8; 32]],
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::CHECK_VIOLATION));
    work.rollback().await.unwrap();
    // This candidate structural guard makes no signature-verification claim.
    // Only the not-yet-mounted cryptographic reader could authorize real bytes.

    let denied = writer
        .batch_execute(&format!("CREATE TABLE {namespace}.bypass(id integer)"))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));

    let refusal = writer
        .execute(
            "UPDATE selection SET account=$2 WHERE account=$1",
            &[&first, &Uuid::new_v4()],
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), Some(&SqlState::CHECK_VIOLATION));
    for command in [
        "UPDATE selection SET epoch=1",
        "INSERT INTO current_elections SELECT account,3,decode('03','hex') FROM selection",
        "ALTER TABLE queue DISABLE TRIGGER USER",
        "TRUNCATE queue",
        "SET session_replication_role=replica",
    ] {
        let denied = writer.batch_execute(command).await.unwrap_err();
        assert_eq!(
            denied.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{command}"
        );
    }
    close(writer, writer_driver).await;
    owner
        .batch_execute(&format!(
            "SET search_path TO pg_catalog; DROP SCHEMA {namespace} CASCADE; DROP ROLE {role}"
        ))
        .await
        .unwrap();
    close(owner, owner_driver).await;
}
