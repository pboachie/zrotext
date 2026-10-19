// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use std::{path::Path, time::Duration};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, error::SqlState};
use uuid::Uuid;

async fn connect(config: &Config) -> (Client, JoinHandle<()>) {
    let (db, connection) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(async move { connection.await.unwrap() }))
}
async fn close(db: Client, driver: JoinHandle<()>) {
    drop(db);
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap();
}

pub(crate) struct Fixture {
    admin: Client,
    admin_driver: JoinHandle<()>,
    pub(crate) owner: Client,
    owner_driver: JoinHandle<()>,
    pub(crate) db: Client,
    driver: JoinHandle<()>,
    config: Config,
    name: String,
    owner_role: String,
    pub(crate) runtime_role: String,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
        let mut config: Config = raw.parse().unwrap();
        config.connect_timeout(Duration::from_secs(5));
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let name = format!("zt_writers_{suffix}");
        let owner_role = format!("zt_writer_owner_{suffix}");
        let runtime_role = format!("zt_writer_runtime_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        for role in [&owner_role, &runtime_role] {
            admin.batch_execute(&format!(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS",
                escape_identifier(role), escape_literal(&verifier)
            )).await.unwrap();
        }
        admin
            .batch_execute(&format!(
                "CREATE DATABASE {} OWNER {}",
                escape_identifier(&name),
                escape_identifier(&owner_role)
            ))
            .await
            .unwrap();
        config.dbname(&name).user(&owner_role).password(&password);
        let (mut owner, owner_driver) = connect(&config).await;
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
        let applied = zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        assert_eq!(applied.last().unwrap().version, 109);
        let snapshot: Vec<u8> = owner
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
            snapshot,
            owner
                .query_one("SELECT public.payload_profile_writer_graph()", &[])
                .await
                .unwrap()
                .get::<_, Vec<u8>>(0)
        );
        let role = escape_identifier(&runtime_role);
        let database_identifier = escape_identifier(&name);
        owner.batch_execute(&format!(
            "REVOKE ALL ON DATABASE {database_identifier} FROM PUBLIC; GRANT CONNECT ON DATABASE {database_identifier} TO {role};
             GRANT USAGE ON SCHEMA public TO {role};
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role};
             REVOKE ALL ON public.schema_migrations,public.hosted_runtime_secrets,public.hosted_runtime_sessions,public.hosted_billing_resolutions FROM {role};
             GRANT UPDATE(account_id) ON public.payload_profile_account_anchors TO {role};
             GRANT UPDATE(review_required) ON public.hosted_billing_namespaces TO {role};
             GRANT INSERT,UPDATE,DELETE ON public.accounts,public.users,public.memberships,public.devices,public.device_sessions,public.auth_abuse_counters TO {role};
             GRANT EXECUTE ON FUNCTION public.payload_profile_account_fence_key(uuid),public.payload_profile_writer_json(json),public.payload_profile_writer_graph(),public.payload_profile_writer_version(),public.payload_profile_writer_ready(),public.auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer) TO {role};"
        )).await.unwrap();
        config.user(&runtime_role).password(&password);
        let (db, driver) = connect(&config).await;
        db.batch_execute("SET search_path TO pg_catalog, public; SET lock_timeout='2s'; SET statement_timeout='10s'").await.unwrap();
        require(&db).await.unwrap();
        assert!(matches!(
            require(&owner).await,
            Err(WriterSchemaError::Invalid)
        ));
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            db,
            driver,
            config,
            name,
            owner_role,
            runtime_role,
        }
    }
    async fn account(&self) -> Uuid {
        let id = Uuid::new_v4();
        self.db
            .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&id])
            .await
            .unwrap();
        id
    }
    async fn device(&self, account: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        self.db
            .execute(
                "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                &[&id, &account],
            )
            .await
            .unwrap();
        id
    }
    pub(crate) async fn finish(self) {
        close(self.db, self.driver).await;
        close(self.owner, self.owner_driver).await;
        self.admin
            .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&self.name)))
            .await
            .unwrap();
        for role in [&self.runtime_role, &self.owner_role] {
            self.admin
                .batch_execute(&format!("DROP ROLE {}", escape_identifier(role)))
                .await
                .unwrap();
        }
        close(self.admin, self.admin_driver).await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn unmodified_writers_hold_real_fences_in_both_contention_orders_and_allow_unrelated_accounts()
 {
    let mut f = Fixture::new().await;
    let account = f.account().await;
    let other = f.account().await;
    let device = f.device(account).await;
    let other_device = f.device(other).await;
    let key: i64 =
        f.db.query_one(
            "SELECT public.payload_profile_account_fence_key($1)",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);

    // Writer first: no application fence call occurs in the writer transaction.
    let writer = f.db.transaction().await.unwrap();
    writer
        .execute(
            "UPDATE public.devices SET display_name='writer first' WHERE id=$1",
            &[&device],
        )
        .await
        .unwrap();
    let transition = f.owner.transaction().await.unwrap();
    assert!(
        !transition
            .query_one("SELECT pg_catalog.pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    transition.rollback().await.unwrap();
    writer.commit().await.unwrap();

    // Transition first: writer has acquired its tuple before its BEFORE trigger
    // tries the fence. A bounded refusal releases it without a tuple/fence cycle.
    let transition = f.owner.transaction().await.unwrap();
    assert!(
        transition
            .query_one("SELECT pg_catalog.pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    transition.query("SELECT account_id FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE NOWAIT", &[&account]).await.unwrap();
    let error =
        f.db.execute(
            "UPDATE public.devices SET display_name='must rollback' WHERE id=$1",
            &[&device],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    transition
        .query(
            "SELECT id FROM public.devices WHERE id=$1 FOR UPDATE NOWAIT",
            &[&device],
        )
        .await
        .unwrap();
    f.db.execute(
        "UPDATE public.devices SET display_name='other progresses' WHERE id=$1",
        &[&other_device],
    )
    .await
    .unwrap();
    transition.rollback().await.unwrap();
    assert_eq!(
        f.db.query_one(
            "SELECT display_name FROM public.devices WHERE id=$1",
            &[&device]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "writer first"
    );
    require(&f.db).await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn old_snapshot_writers_refuse_after_actual_account_deletion_epoch_and_invisible_creation() {
    let f = Fixture::new().await;
    let unrelated = f.account().await;
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let account = f.account().await;
        let (mut old, old_driver) = connect(&f.config).await;
        let tx = old
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        tx.query_one("SELECT id FROM public.accounts WHERE id=$1", &[&unrelated])
            .await
            .unwrap();
        f.db.execute("DELETE FROM public.accounts WHERE id=$1", &[&account])
            .await
            .unwrap();
        let anchor=f.db.query_one("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1", &[&account]).await.unwrap();
        assert_eq!(anchor.get::<_, String>(0), "deleted");
        assert_eq!(anchor.get::<_, i64>(1), 1);
        let error=tx.execute("INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'must refuse')", &[&Uuid::new_v4(),&account]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::T_R_SERIALIZATION_FAILURE));
        tx.rollback().await.unwrap();

        let tx = old
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        tx.query_one("SELECT id FROM public.accounts WHERE id=$1", &[&unrelated])
            .await
            .unwrap();
        let created = f.account().await;
        let error = tx
            .execute(
                "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'invisible')",
                &[&Uuid::new_v4(), &created],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        tx.rollback().await.unwrap();
        close(old, old_driver).await;
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM public.devices", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn moved_account_sets_and_nullable_legacy_device_owners_cannot_escape_participation() {
    let mut f = Fixture::new().await;
    let old_account = f.account().await;
    let new_account = f.account().await;
    let device = f.device(old_account).await;
    f.owner
        .execute(
            "INSERT INTO public.sites(site_id) VALUES('writer-fixture')",
            &[],
        )
        .await
        .unwrap();
    for account in [old_account, new_account] {
        let held = f.owner.transaction().await.unwrap();
        assert!(held.query_one("SELECT pg_catalog.pg_try_advisory_xact_lock(public.payload_profile_account_fence_key($1))", &[&account]).await.unwrap().get::<_,bool>(0));
        let error =
            f.db.execute(
                "UPDATE public.devices SET account_id=$1 WHERE id=$2",
                &[&new_account, &device],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
        held.rollback().await.unwrap();
    }
    let held = f.owner.transaction().await.unwrap();
    assert!(held.query_one("SELECT pg_catalog.pg_try_advisory_xact_lock(public.payload_profile_account_fence_key($1))", &[&old_account]).await.unwrap().get::<_,bool>(0));
    // The caller omitted account_id, as the original legacy coordinator can.
    // Its real known device still contributes the actual account identity.
    let error=f.db.execute("INSERT INTO public.device_sessions(device_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,'writer-fixture','synthetic',1,clock_timestamp()+interval '1 minute',1)", &[&device]).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    held.rollback().await.unwrap();
    f.db.execute("INSERT INTO public.device_sessions(device_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,'writer-fixture','synthetic',1,clock_timestamp()+interval '1 minute',1)", &[&device]).await.unwrap();
    assert_eq!(
        f.db.query_one(
            "SELECT account_id FROM public.devices WHERE id=$1",
            &[&device]
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0),
        old_account
    );
    require(&f.db).await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn missing_anchor_refuses_real_writer_without_partial_effect_even_if_owner_corrupts_catalog()
{
    let mut f = Fixture::new().await;
    let account = f.account().await;
    let tx = f.owner.transaction().await.unwrap();
    tx.batch_execute("ALTER TABLE public.payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change").await.unwrap();
    tx.execute(
        "DELETE FROM public.payload_profile_account_anchors WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    let error = tx
        .execute(
            "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'must refuse')",
            &[&Uuid::new_v4(), &account],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    tx.rollback().await.unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM public.devices", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    require(&f.db).await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn complete_graph_rejects_unknown_missing_disabled_function_body_and_column_privilege_changes()
 {
    let mut f = Fixture::new().await;
    for mutation in [
        "CREATE TABLE public.unknown_writer(id uuid)",
        "CREATE VIEW public.unknown_view AS SELECT 1 AS value",
        "CREATE FUNCTION public.unknown_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "CREATE RULE unreviewed AS ON UPDATE TO public.devices DO INSTEAD NOTHING",
        "CREATE POLICY unreviewed ON public.devices USING (true)",
        "CREATE SCHEMA writer_inheritance_probe; CREATE TABLE writer_inheritance_probe.parent(); ALTER TABLE public.devices INHERIT writer_inheritance_probe.parent",
        "ALTER TABLE public.webhook_endpoints DROP CONSTRAINT webhook_endpoints_callback_url_check; ALTER TABLE public.webhook_endpoints ADD CONSTRAINT webhook_endpoints_callback_url_check CHECK(callback_url LIKE 'https://%')",
        "ALTER TABLE public.devices ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.devices DISABLE TRIGGER zz_payload_profile_writer_before_change",
        "DROP TRIGGER zz_payload_profile_writer_before_change ON public.devices",
        "ALTER TABLE public.devices DROP CONSTRAINT devices_account_id_fkey",
        "ALTER TABLE public.devices DISABLE TRIGGER ALL",
        "CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "GRANT UPDATE(graph_sha256) ON public.payload_profile_writer_catalog TO PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.payload_profile_writer_ready() TO PUBLIC",
        "INSERT INTO public.schema_migrations(version,filename,checksum_sha256,kind) VALUES(110,'110_unknown.sql',decode(repeat('01',32),'hex'),'applied')",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        // A migration owner may mutate only its own ordinary objects. Disabling
        // internal FK triggers requires superuser and must itself be refused.
        match tx.batch_execute(mutation).await {
            Ok(()) => assert!(optional(&tx, "public.devices").await.is_err(), "{mutation}"),
            Err(error) => assert!(
                mutation.ends_with("TRIGGER ALL")
                    && error.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "{mutation}: {error}"
            ),
        }
        tx.rollback().await.unwrap();
        require(&f.db).await.unwrap();
    }
    let role = escape_identifier(&f.runtime_role);
    for grant in [
        format!("GRANT EXECUTE ON FUNCTION public.payload_profile_writer_guard() TO {role}"),
        format!("GRANT UPDATE(revision) ON public.payload_profile_writer_global_fences TO {role}"),
        format!("GRANT UPDATE(graph_sha256) ON public.payload_profile_writer_catalog TO {role}"),
    ] {
        f.owner.batch_execute(&grant).await.unwrap();
        assert!(require(&f.db).await.is_err(), "{grant}");
        f.owner.batch_execute(&format!("REVOKE ALL ON FUNCTION public.payload_profile_writer_guard() FROM {role}; REVOKE ALL(revision) ON public.payload_profile_writer_global_fences FROM {role}; REVOKE ALL(graph_sha256) ON public.payload_profile_writer_catalog FROM {role}")).await.unwrap();
        require(&f.db).await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn management_budget_keeps_exact_atomic_policy_under_catalog_only_path() {
    let f = Fixture::new().await;
    f.db.batch_execute("SET search_path TO pg_catalog")
        .await
        .unwrap();
    let global = vec![1u8; 32];
    let subject = vec![2u8; 32];
    for expected in [true, false] {
        let allowed: bool =
            f.db.query_one(
                "SELECT public.auth_abuse_consume('writer-fixture',$1,$2,1,60,2,60)",
                &[&global, &subject],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(allowed, expected);
    }
    let rows =
        f.db.query(
            "SELECT subject_hash,attempts FROM public.auth_abuse_counters ORDER BY subject_hash",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.get::<_, i32>(1) == 1));
    require(&f.db).await.unwrap();
    f.finish().await;
}
