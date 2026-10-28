// SPDX-License-Identifier: AGPL-3.0-only
//! Regression coverage for the narrowly recognized logical-restore graph.
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Config, NoTls};
use uuid::Uuid;

const CANONICAL_GRAPH: &str = "d2348d448965a4c8fa28116a89571fa932bf8f05dc5eb5927c8aceb308c78d2b";
const RESTORED_GRAPH: &str = "3fb2f2389eb67957c58f5845752bf904c083110cd3afde1ff9be58cc4f5cbaec";

// These are the public, observed pg_dump/pg_restore renderings. They are an
// independent fixture, not generated from the compatibility implementation.
const RESTORED_CHECKS: [(&str, &str, &str); 3] = [
    (
        "sealed_inbound_events",
        "sealed_inbound_events_envelope_check",
        "CHECK (((envelope IS NULL) OR ((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode('5a5453450102'::text, 'hex'::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode('5a5453450202'::text, 'hex'::text)))))))",
    ),
    (
        "webhook_endpoints",
        "webhook_endpoints_callback_url_check",
        "CHECK (((length(callback_url) >= 9) AND (length(callback_url) <= 2048) AND (callback_url ~~ 'https://%'::text)))",
    ),
    (
        "workflow_action_versions",
        "workflow_action_versions_check",
        "CHECK (((revision >= 1) AND (revision <= 128) AND (expires_at_ms > not_before_ms)))",
    ),
];

async fn replace_check(client: &Client, table: &str, name: &str, definition: &str) {
    client
        .batch_execute(&format!(
            "ALTER TABLE public.{} DROP CONSTRAINT {}, ADD CONSTRAINT {} {}",
            escape_identifier(table),
            escape_identifier(name),
            escape_identifier(name),
            definition
        ))
        .await
        .unwrap();
}

async fn graph(client: &mut Client) -> String {
    let migration =
        include_str!("../../../deploy/compose/migrations/108_payload_profile_writer_fences.sql");
    let (prefix, _) = migration
        .split_once("DO $migration$")
        .expect("migration 108 verifier prefix");
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(prefix).await.unwrap();
    let digest: String = tx
        .query_one(
            "SELECT encode(public.payload_profile_writer_prior_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    tx.rollback().await.unwrap();
    digest
}

async fn ledger(client: &Client) -> Vec<(i64, String, Vec<u8>, String, String)> {
    client.query("SELECT version,filename,checksum_sha256,kind,applied_at::text FROM public.schema_migrations ORDER BY version", &[])
        .await.unwrap().into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3),r.get(4))).collect()
}

async fn checks(client: &Client) -> Vec<(String, String, String, bool, bool, bool, bool)> {
    client.query("SELECT c.relname,k.conname,pg_catalog.pg_get_constraintdef(k.oid),k.convalidated,k.condeferrable,k.condeferred,k.connoinherit FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relname,k.conname) IN (('sealed_inbound_events','sealed_inbound_events_envelope_check'),('webhook_endpoints','webhook_endpoints_callback_url_check'),('workflow_action_versions','workflow_action_versions_check')) ORDER BY c.relname COLLATE \"C\",k.conname COLLATE \"C\"", &[])
        .await.unwrap().into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3),r.get(4),r.get(5),r.get(6))).collect()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn restored_107_graph_is_normalized_atomically_without_blessing_unknown_shapes() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    let (admin, admin_connection) = config.connect(NoTls).await.unwrap();
    let admin_driver = tokio::spawn(admin_connection);
    let server_version: String = admin
        .query_one("SHOW server_version_num", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        server_version, "180006",
        "the graph fixture requires PostgreSQL 18.6"
    );
    let suffix = Uuid::new_v4().simple().to_string();
    let database = format!("zt_restore107_{suffix}");
    let role = format!("zt_restore107_owner_{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS", escape_identifier(&role), escape_literal(&verifier))).await.unwrap();
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {} OWNER {}",
            escape_identifier(&database),
            escape_identifier(&role)
        ))
        .await
        .unwrap();
    config.dbname(&database).user(&role).password(&password);
    let (mut owner, owner_connection) = config.connect(NoTls).await.unwrap();
    let owner_driver = tokio::spawn(owner_connection);
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let all = read_migrations(&directory).unwrap();
    let position = all.iter().position(|m| m.version == 108).unwrap();
    assert_eq!(
        apply_locked(&mut owner, &all[..position], false)
            .await
            .unwrap()
            .last()
            .unwrap()
            .version,
        107
    );
    let existing_account = Uuid::new_v4();
    owner
        .execute(
            "INSERT INTO public.accounts(id) VALUES($1)",
            &[&existing_account],
        )
        .await
        .unwrap();
    let before_ledger = ledger(&owner).await;
    assert_eq!(before_ledger.len(), 107);
    assert_eq!(graph(&mut owner).await, CANONICAL_GRAPH);
    let original_checks = checks(&owner).await;
    assert_eq!(original_checks.len(), 3);
    for (table, name, definition) in RESTORED_CHECKS {
        replace_check(&owner, table, name, definition).await;
    }
    assert_eq!(
        graph(&mut owner).await,
        RESTORED_GRAPH,
        "fixture must reproduce exact stock-restored graph"
    );
    let restored_checks = checks(&owner).await;
    assert_ne!(restored_checks, original_checks);

    // An apparently valid temporary ledger must not hide a tampered public one.
    owner.batch_execute("CREATE TEMP TABLE schema_migrations (LIKE public.schema_migrations INCLUDING ALL); INSERT INTO pg_temp.schema_migrations SELECT * FROM public.schema_migrations").await.unwrap();
    owner.batch_execute("UPDATE public.schema_migrations SET checksum_sha256=decode(repeat('00',32),'hex') WHERE version=1").await.unwrap();
    let changed_ledger = ledger(&owner).await;
    assert_ne!(changed_ledger, before_ledger);
    let shadow_error = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(shadow_error, MigrationError::ChecksumMismatch(1))
            || matches!(
                shadow_error,
                MigrationError::Restore107Compatibility(
                    "the public migration ledger does not match the pinned 001-107 inventory"
                )
            ),
        "unexpected shadow refusal: {shadow_error}"
    );
    assert_eq!(ledger(&owner).await, changed_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    owner
        .batch_execute("DROP TABLE pg_temp.schema_migrations")
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE public.schema_migrations SET checksum_sha256=$1 WHERE version=1",
            &[&before_ledger[0].2],
        )
        .await
        .unwrap();
    assert_eq!(ledger(&owner).await, before_ledger);

    // A competing migrator owns the session advisory lock; this attempt must
    // time out without performing normalization or changing the ledger.
    let (holder, holder_connection) = config.connect(NoTls).await.unwrap();
    let holder_driver = tokio::spawn(holder_connection);
    holder
        .query_one("SELECT pg_catalog.pg_advisory_lock($1)", &[&MIGRATION_LOCK])
        .await
        .unwrap();
    owner
        .batch_execute("SET statement_timeout = '250ms'")
        .await
        .unwrap();
    let locked = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        apply(&mut owner, &directory, false),
    )
    .await
    .expect("competing migration lock did not time out");
    assert!(
        matches!(locked, Err(MigrationError::Database(ref error)) if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)),
        "lock should time out in the database"
    );
    owner
        .batch_execute("SET statement_timeout = 0")
        .await
        .unwrap();
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    assert!(
        holder
            .query_one(
                "SELECT pg_catalog.pg_advisory_unlock($1)",
                &[&MIGRATION_LOCK]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    drop(holder);
    holder_driver.await.unwrap().unwrap();

    // A later unchanged 108 ACL guard must still reject, rolling back all
    // compatibility DDL and the ledger insertion as one transaction.
    owner
        .batch_execute("GRANT UPDATE ON public.devices TO PUBLIC")
        .await
        .unwrap();
    let error = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(error, MigrationError::Database(ref db) if db.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION) && db.as_db_error().is_some_and(|e| e.message() == "public application write/read grants are unsupported")),
        "expected historical 108 grant refusal, got: {error}"
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    assert_eq!(graph(&mut owner).await, RESTORED_GRAPH);
    owner
        .batch_execute("REVOKE ALL ON public.devices FROM PUBLIC")
        .await
        .unwrap();

    // The 108 graph does not include comments. Recreating a constraint must
    // not silently discard a comment even when the definition graph matches.
    owner.batch_execute("COMMENT ON CONSTRAINT webhook_endpoints_callback_url_check ON public.webhook_endpoints IS 'synthetic preserved comment'").await.unwrap();
    assert_eq!(graph(&mut owner).await, RESTORED_GRAPH);
    let error = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(
            error,
            MigrationError::Restore107Compatibility(
                "restored CHECK metadata has unsupported dependencies or annotations"
            )
        ),
        "expected annotation refusal, got: {error}"
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    let comment: Option<String> = owner.query_one("SELECT pg_catalog.obj_description(k.oid, 'pg_constraint') FROM pg_catalog.pg_constraint k WHERE k.conrelid='public.webhook_endpoints'::pg_catalog.regclass AND k.conname='webhook_endpoints_callback_url_check'", &[]).await.unwrap().get(0);
    assert_eq!(comment.as_deref(), Some("synthetic preserved comment"));
    owner.batch_execute("COMMENT ON CONSTRAINT webhook_endpoints_callback_url_check ON public.webhook_endpoints IS NULL").await.unwrap();

    // Any changed CHECK operand, extra object, or added PUBLIC grant remains a
    // refusal; no partial normalization or migration ledger may survive it.
    for (table, name, definition) in RESTORED_CHECKS {
        let changed = match table {
            "sealed_inbound_events" => definition.replacen("34082", "34083", 1),
            "webhook_endpoints" => definition.replacen("2048", "2049", 1),
            "workflow_action_versions" => definition.replacen("128", "129", 1),
            _ => unreachable!(),
        };
        assert_ne!(definition, changed);
        replace_check(&owner, table, name, &changed).await;
        let changed_checks = checks(&owner).await;
        let changed_graph = graph(&mut owner).await;
        assert_ne!(changed_graph, RESTORED_GRAPH);
        let error = apply(&mut owner, &directory, false).await.unwrap_err();
        assert!(
            matches!(
                error,
                MigrationError::Database(ref db)
                    if db.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
                    && db.as_db_error().is_some_and(|e| e.message() == "unreviewed complete pre-writer definition graph")
            ),
            "expected graph refusal, got: {error}"
        );
        assert_eq!(ledger(&owner).await, before_ledger);
        assert_eq!(checks(&owner).await, changed_checks);
        assert_eq!(graph(&mut owner).await, changed_graph);
        replace_check(&owner, table, name, definition).await;
    }
    owner
        .batch_execute(
            "ALTER TABLE public.devices ADD CONSTRAINT unreviewed_restore_check CHECK (true)",
        )
        .await
        .unwrap();
    let extra_graph = graph(&mut owner).await;
    let error = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(
            error,
            MigrationError::Database(ref db)
                if db.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
                && db.as_db_error().is_some_and(|e| e.message() == "unreviewed complete pre-writer definition graph")
        ),
        "expected graph refusal, got: {error}"
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(graph(&mut owner).await, extra_graph);
    owner
        .batch_execute("ALTER TABLE public.devices DROP CONSTRAINT unreviewed_restore_check")
        .await
        .unwrap();
    assert_eq!(graph(&mut owner).await, RESTORED_GRAPH);

    // Reproduce the restored 095 session-derived setting. A competing owner
    // changes it while compatibility is paused after its snapshot: the
    // migration must fail and the competing value must survive.
    owner.batch_execute("ALTER FUNCTION public.device_session_line_activation_version_guard() SET search_path TO pg_catalog, public; SET zrotext.restore107_test_barrier = 'enabled'").await.unwrap();
    owner.batch_execute("COMMENT ON FUNCTION public.device_session_line_activation_version_guard() IS 'synthetic preserved comment'").await.unwrap();
    let comment_sql = "SELECT pg_catalog.obj_description('public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure, 'pg_proc')";
    let dependency_sql = "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(d) ORDER BY pg_catalog.to_jsonb(d)::text COLLATE \"C\"), '[]'::jsonb)::text FROM pg_catalog.pg_depend d WHERE (d.classid='pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure) OR (d.refclassid='pg_catalog.pg_proc'::pg_catalog.regclass AND d.refobjid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure)";
    let original_comment: Option<String> = owner.query_one(comment_sql, &[]).await.unwrap().get(0);
    assert_eq!(
        original_comment.as_deref(),
        Some("synthetic preserved comment")
    );
    let original_dependencies: String = owner.query_one(dependency_sql, &[]).await.unwrap().get(0);
    assert_ne!(
        original_dependencies, "[]",
        "fixture must have actual pg_depend edges"
    );
    let metadata_sql = "SELECT pg_catalog.to_jsonb(p)::text FROM pg_catalog.pg_proc p WHERE p.oid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure";
    let original_metadata: String = owner.query_one(metadata_sql, &[]).await.unwrap().get(0);
    // A historical guard failure after normalization must roll back the
    // temporary function setting and all CHECK repairs with the ledger.
    owner
        .batch_execute("GRANT UPDATE ON public.devices TO PUBLIC")
        .await
        .unwrap();
    let guarded = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(guarded, MigrationError::Database(ref db) if db.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION) && db.as_db_error().is_some_and(|e| e.message() == "public application write/read grants are unsupported")),
        "historical 108 grant guard must remain authoritative: {guarded}"
    );
    let unchanged_config: String = owner.query_one("SELECT pg_catalog.array_to_json(proconfig)::text FROM pg_catalog.pg_proc WHERE oid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
    assert_eq!(unchanged_config, r#"["search_path=pg_catalog, public"]"#);
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    let metadata_after_guard: String = owner.query_one(metadata_sql, &[]).await.unwrap().get(0);
    assert_eq!(metadata_after_guard, original_metadata);
    let comment_after_guard: Option<String> =
        owner.query_one(comment_sql, &[]).await.unwrap().get(0);
    let dependencies_after_guard: String =
        owner.query_one(dependency_sql, &[]).await.unwrap().get(0);
    assert_eq!(comment_after_guard, original_comment);
    assert_eq!(dependencies_after_guard, original_dependencies);
    owner
        .batch_execute("REVOKE ALL ON public.devices FROM PUBLIC")
        .await
        .unwrap();

    // A preexisting temporary-name collision is an unreviewed function graph,
    // so the unchanged 108 function guard refuses before any normalization.
    owner.batch_execute("CREATE FUNCTION public.zrotext_restore107_function_lock() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'").await.unwrap();
    let collision = apply(&mut owner, &directory, false).await.unwrap_err();
    assert!(
        matches!(collision, MigrationError::Database(ref db) if db.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION) && db.as_db_error().is_some_and(|e| e.message() == "unreviewed pre-writer function bodies")),
        "historical 108 function guard must refuse a collision: {collision}"
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    owner
        .batch_execute("DROP FUNCTION public.zrotext_restore107_function_lock()")
        .await
        .unwrap();

    let (racer, racer_connection) = config.connect(NoTls).await.unwrap();
    let racer_driver = tokio::spawn(racer_connection);
    racer
        .query_one("SELECT pg_catalog.pg_advisory_lock(107108095)", &[])
        .await
        .unwrap();
    let owner_pid: i32 = owner
        .query_one("SELECT pg_catalog.pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    {
        let attempt = apply(&mut owner, &directory, false);
        tokio::pin!(attempt);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            tokio::select! {
                result = &mut attempt => panic!("apply ended before the test barrier: {result:?}"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
            let waiting: bool = racer.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=0 AND objid=107108095 AND objsubid=1 AND NOT granted)", &[&owner_pid]).await.unwrap().get(0);
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "apply never reached the race barrier"
            );
        }
        racer.batch_execute("BEGIN; ALTER FUNCTION public.device_session_line_activation_version_guard() SET search_path TO pg_catalog, public, pg_temp").await.unwrap();
        let unlocked: bool = racer
            .query_one("SELECT pg_catalog.pg_advisory_unlock(107108095)", &[])
            .await
            .unwrap()
            .get(0);
        assert!(unlocked);
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), &mut attempt)
            .await
            .expect("raced apply did not stop");
        assert!(
            matches!(result, Err(MigrationError::Database(ref db)) if db.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)),
            "concurrent proconfig update must hit the bounded tuple-lock timeout: {result:?}"
        );
    }
    racer.batch_execute("COMMIT").await.unwrap();
    let config_after: String = racer.query_one("SELECT pg_catalog.array_to_json(proconfig)::text FROM pg_catalog.pg_proc WHERE oid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
    assert_eq!(
        config_after,
        r#"["search_path=pg_catalog, public, pg_temp"]"#
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    owner.batch_execute("RESET zrotext.restore107_test_barrier; ALTER FUNCTION public.device_session_line_activation_version_guard() SET search_path TO pg_catalog, public").await.unwrap();
    // The other ordering also matters: a completed change between the
    // original snapshot and rename must be detected by the locked recheck.
    owner
        .batch_execute("SET zrotext.restore107_test_barrier = 'enabled'")
        .await
        .unwrap();
    racer
        .query_one("SELECT pg_catalog.pg_advisory_lock(107108095)", &[])
        .await
        .unwrap();
    {
        let attempt = apply(&mut owner, &directory, false);
        tokio::pin!(attempt);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            tokio::select! {
                result = &mut attempt => panic!("apply ended before the committed-race barrier: {result:?}"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
            let waiting: bool = racer.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=0 AND objid=107108095 AND objsubid=1 AND NOT granted)", &[&owner_pid]).await.unwrap().get(0);
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "apply never reached the committed-race barrier"
            );
        }
        racer.batch_execute("ALTER FUNCTION public.device_session_line_activation_version_guard() SET search_path TO pg_catalog, public, pg_temp").await.unwrap();
        let unlocked: bool = racer
            .query_one("SELECT pg_catalog.pg_advisory_unlock(107108095)", &[])
            .await
            .unwrap()
            .get(0);
        assert!(unlocked);
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), &mut attempt)
            .await
            .expect("committed-race apply did not stop");
        assert!(
            matches!(
                result,
                Err(MigrationError::Restore107Compatibility(
                    "the function graph changed before the target lock was acquired"
                ))
            ),
            "committed config change must be detected after lock: {result:?}"
        );
    }
    let committed_config: String = racer.query_one("SELECT pg_catalog.array_to_json(proconfig)::text FROM pg_catalog.pg_proc WHERE oid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
    assert_eq!(
        committed_config,
        r#"["search_path=pg_catalog, public, pg_temp"]"#
    );
    assert_eq!(ledger(&owner).await, before_ledger);
    assert_eq!(checks(&owner).await, restored_checks);
    owner.batch_execute("RESET zrotext.restore107_test_barrier; ALTER FUNCTION public.device_session_line_activation_version_guard() SET search_path TO pg_catalog, public").await.unwrap();
    // Competing identity and whole-inventory changes after the snapshot are
    // also refused; their committed changes remain intact until explicitly
    // repaired by the fixture owner.
    racer
        .batch_execute("CREATE SCHEMA synthetic_race")
        .await
        .unwrap();
    for (mutation, repair, identity_moved) in [
        (
            "ALTER FUNCTION public.device_session_line_activation_version_guard() SET SCHEMA synthetic_race",
            "ALTER FUNCTION synthetic_race.device_session_line_activation_version_guard() SET SCHEMA public",
            true,
        ),
        (
            "ALTER FUNCTION public.device_session_line_activation_version_guard() RENAME TO synthetic_original_guard; CREATE FUNCTION public.device_session_line_activation_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog, public AS 'BEGIN RETURN NEW; END'",
            "DROP FUNCTION public.device_session_line_activation_version_guard(); ALTER FUNCTION public.synthetic_original_guard() RENAME TO device_session_line_activation_version_guard",
            false,
        ),
        (
            "CREATE FUNCTION public.synthetic_other_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "DROP FUNCTION public.synthetic_other_function()",
            false,
        ),
    ] {
        owner
            .batch_execute("SET zrotext.restore107_test_barrier = 'enabled'")
            .await
            .unwrap();
        racer
            .query_one("SELECT pg_catalog.pg_advisory_lock(107108095)", &[])
            .await
            .unwrap();
        {
            let attempt = apply(&mut owner, &directory, false);
            tokio::pin!(attempt);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                tokio::select! {
                    result = &mut attempt => panic!("apply ended before the identity-race barrier: {result:?}"),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
                let waiting: bool = racer.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=0 AND objid=107108095 AND objsubid=1 AND NOT granted)", &[&owner_pid]).await.unwrap().get(0);
                if waiting {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "apply never reached the identity-race barrier"
                );
            }
            racer.batch_execute(mutation).await.unwrap();
            let unlocked: bool = racer
                .query_one("SELECT pg_catalog.pg_advisory_unlock(107108095)", &[])
                .await
                .unwrap()
                .get(0);
            assert!(unlocked);
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), &mut attempt)
                .await
                .expect("identity-race apply did not stop");
            if identity_moved {
                assert!(
                    matches!(result, Err(MigrationError::Database(ref db)) if db.code() == Some(&tokio_postgres::error::SqlState::UNDEFINED_FUNCTION)),
                    "moved target must refuse: {result:?}"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(MigrationError::Restore107Compatibility(
                            "the function graph changed before the target lock was acquired"
                        ))
                    ),
                    "changed identity/inventory must refuse: {result:?}"
                );
            }
        }
        assert_eq!(ledger(&owner).await, before_ledger);
        assert_eq!(checks(&owner).await, restored_checks);
        racer.batch_execute(repair).await.unwrap();
        let metadata_after_race: String = owner.query_one(metadata_sql, &[]).await.unwrap().get(0);
        assert_eq!(metadata_after_race, original_metadata);
    }
    owner
        .batch_execute("RESET zrotext.restore107_test_barrier")
        .await
        .unwrap();
    racer
        .batch_execute("DROP SCHEMA synthetic_race")
        .await
        .unwrap();
    drop(racer);
    racer_driver.await.unwrap().unwrap();

    // An attacker-controlled session search path must not shadow builtins used
    // by the compatibility or migration guards.
    owner.batch_execute("CREATE SCHEMA untrusted; CREATE FUNCTION untrusted.length(text) RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 0'; SET search_path TO untrusted, public").await.unwrap();
    let applied_108 = apply_locked(&mut owner, &all[..=position], false)
        .await
        .unwrap();
    assert_eq!(applied_108.first().unwrap().version, 108);
    assert_eq!(applied_108.last().unwrap().version, 108);
    let original_config: String = owner.query_one("SELECT pg_catalog.array_to_json(proconfig)::text FROM pg_catalog.pg_proc WHERE oid='public.device_session_line_activation_version_guard()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
    assert_eq!(original_config, r#"["search_path=pg_catalog, public"]"#);
    let graphs_match: bool = owner.query_one("SELECT public.payload_profile_writer_graph() = graph_sha256 FROM public.payload_profile_writer_catalog WHERE singleton AND migration_version=108", &[]).await.unwrap().get(0);
    let metadata_after_108: String = owner.query_one(metadata_sql, &[]).await.unwrap().get(0);
    assert_eq!(metadata_after_108, original_metadata);
    let comment_after_108: Option<String> = owner.query_one(comment_sql, &[]).await.unwrap().get(0);
    let dependencies_after_108: String = owner.query_one(dependency_sql, &[]).await.unwrap().get(0);
    assert_eq!(comment_after_108, original_comment);
    assert_eq!(dependencies_after_108, original_dependencies);
    assert!(
        graphs_match,
        "109 and later migrations preserve the 108 recorded graph"
    );
    let applied_tail = apply(&mut owner, &directory, false).await.unwrap();
    assert_eq!(applied_tail.first().unwrap().version, 109);
    assert_eq!(applied_tail.last().unwrap().version, 119);
    let after_ledger = ledger(&owner).await;
    assert_eq!(&after_ledger[..107], &before_ledger);
    assert_eq!(after_ledger.len(), 119);
    assert_eq!(checks(&owner).await, original_checks);
    assert_eq!(
        owner
            .query_one(
                "SELECT count(*) FROM public.accounts WHERE id=$1",
                &[&existing_account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert!(
        apply(&mut owner, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(ledger(&owner).await, after_ledger);
    drop(owner);
    owner_driver.await.unwrap().unwrap();
    admin
        .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&database)))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("DROP ROLE {}", escape_identifier(&role)))
        .await
        .unwrap();
    drop(admin);
    admin_driver.await.unwrap().unwrap();
}
