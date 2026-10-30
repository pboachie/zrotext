// SPDX-License-Identifier: AGPL-3.0-only
//! Exercises actual apply and strict graph gating in a disposable PostgreSQL cluster.
use super::*;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::{Config, NoTls};
use uuid::Uuid;

async fn apply_historical(
    client: &mut tokio_postgres::Client,
    directory: &Path,
) -> Result<Vec<AppliedMigration>, MigrationError> {
    let migrations: Vec<_> = read_migrations(directory)?
        .into_iter()
        .filter(|migration| migration.version <= 119)
        .collect();
    assert_eq!(
        migrations
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>(),
        (1..=119).collect::<Vec<_>>()
    );
    apply_inventory(client, &migrations, false).await
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on disposable PostgreSQL 18.6"]
async fn schema119_restore_reconstitution_is_atomic_and_replay_safe() {
    let raw = std::env::var("ZT_RESTORE119_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("ZT_AUTH_TEST_DATABASE_URL"))
        .expect("disposable PostgreSQL 18.6 database URL");
    let mut cfg: Config = raw.parse().unwrap();
    let (admin, driver) = cfg.connect(NoTls).await.unwrap();
    let admin_driver = tokio::spawn(driver);
    let version: String = admin
        .query_one("SHOW server_version_num", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(version, "180006");
    let db = format!("zt_restore119_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {}", escape_identifier(&db)))
        .await
        .unwrap();
    cfg.dbname(&db);
    let (mut client, driver) = cfg.connect(NoTls).await.unwrap();
    let db_driver = tokio::spawn(driver);
    let current_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    // Exercise the pinned historical inventory through the same lock and
    // apply path used by the complete on-disk migration directory.
    apply_historical(&mut client, &current_dir).await.unwrap();
    let row=client.query_one("SELECT encode(graph_sha256,'hex') FROM public.payload_profile_writer_catalog WHERE singleton AND migration_version=119",&[]).await.unwrap();
    let stored: String = row.get(0);
    assert_eq!(
        stored, "39964f6cb79f7792292515d8afb0d875f024490039aebcb4159cddd0b9f608d1",
        "synthetic fixture must match selected backup schema graph"
    );
    let before=client.query("SELECT version,filename,checksum_sha256,kind,applied_at::text FROM public.schema_migrations ORDER BY version",&[]).await.unwrap().into_iter().map(|r|(r.get::<_,i64>(0),r.get::<_,String>(1),r.get::<_,Vec<u8>>(2),r.get::<_,String>(3),r.get::<_,String>(4))).collect::<Vec<_>>();
    // A concurrent committed ledger change between apply's first validation
    // and the no-op snapshot must be refused, not hidden by the fast path.
    let (ledger_gate, ledger_gate_driver) = cfg.connect(NoTls).await.unwrap();
    let ledger_gate_driver = tokio::spawn(ledger_gate_driver);
    ledger_gate
        .batch_execute("SELECT pg_advisory_lock(119119096)")
        .await
        .unwrap();
    let original_checksum: Vec<u8> = ledger_gate
        .query_one(
            "SELECT checksum_sha256 FROM public.schema_migrations WHERE version=119",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    client
        .batch_execute("SET zrotext.restore119_snapshot_test_barrier='enabled'")
        .await
        .unwrap();
    let workdir = current_dir.clone();
    let ledger_task = tokio::spawn(async move {
        let result = apply_historical(&mut client, &workdir).await;
        (client, result)
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async { loop { let waiting: bool = ledger_gate.query_one("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=119119096 AND NOT granted)", &[]).await.unwrap().get(0); if waiting { break; } tokio::time::sleep(std::time::Duration::from_millis(10)).await; } }).await.unwrap();
    // Commit the changed ledger before releasing the waiting snapshot. A
    // single multi-statement simple query would release the session advisory
    // lock before its implicit transaction commits.
    ledger_gate.batch_execute("UPDATE public.schema_migrations SET checksum_sha256=decode(repeat('00',32),'hex') WHERE version=119").await.unwrap();
    ledger_gate
        .batch_execute("SELECT pg_advisory_unlock(119119096)")
        .await
        .unwrap();
    let (mut client, result) = ledger_task.await.unwrap();
    assert!(
        matches!(
            result,
            Err(MigrationError::Restore119Compatibility("ledger mismatch"))
        ),
        "unexpected ledger race result: {result:?}"
    );
    client
        .batch_execute("RESET zrotext.restore119_snapshot_test_barrier")
        .await
        .unwrap();
    ledger_gate
        .execute(
            "UPDATE public.schema_migrations SET checksum_sha256=$1 WHERE version=119",
            &[&original_checksum],
        )
        .await
        .unwrap();
    drop(ledger_gate);
    ledger_gate_driver.await.unwrap().unwrap();
    // No-op replay takes neither ledger nor writer-catalog write locks.
    let (noop_blocker, noop_driver) = cfg.connect(NoTls).await.unwrap();
    let noop_driver = tokio::spawn(noop_driver);
    noop_blocker.batch_execute("BEGIN; LOCK TABLE public.schema_migrations, public.payload_profile_writer_catalog IN SHARE ROW EXCLUSIVE MODE").await.unwrap();
    let replay = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        apply_historical(&mut client, &current_dir),
    )
    .await
    .expect("no-op replay must not wait for ledger write locks")
    .unwrap();
    assert!(replay.is_empty());
    noop_blocker.batch_execute("ROLLBACK").await.unwrap();
    drop(noop_blocker);
    noop_driver.await.unwrap().unwrap();
    client.batch_execute(r#"ALTER TABLE public.conversation_profile03_closure_challenges DROP CONSTRAINT conversation_profile03_closure_challenges_check4, ADD CONSTRAINT conversation_profile03_closure_challenges_check4 CHECK (octet_length(proof_site_id)>=1 AND octet_length(proof_site_id)<=256 AND (octet_length(proof_instance_id)>=1 AND octet_length(proof_instance_id)<=256));
ALTER TABLE public.conversation_profile03_closure_records DROP CONSTRAINT conversation_profile03_closure_records_check, ADD CONSTRAINT conversation_profile03_closure_records_check CHECK (segment_count>=1 AND segment_count<=6 AND closed_from IN(0,1) AND closed_ms>=submit_observed_ms);
ALTER TABLE public.conversation_profile03_outcomes DROP CONSTRAINT conversation_profile03_outcomes_check, ADD CONSTRAINT conversation_profile03_outcomes_check CHECK (segment_count>=1 AND segment_count<=6 AND (evidence>=0 AND evidence<=5));"#).await.unwrap();
    let restored: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        restored,
        "d8e5e8b412f5884af5d1d8e5d40f4afe445dac476725caf6daabbf469440a8f3"
    );
    // Historical index errors retain priority on an exact restored graph.
    // Refusal must leave the complete ledger, writer catalog and each CHECK
    // unchanged, including their identities and deparsed definitions.
    client
        .batch_execute(
            "CREATE INDEX auth_abuse_counters_stale ON public.auth_abuse_counters(updated_at)",
        )
        .await
        .unwrap();
    let checks_sql = "SELECT conrelid::regclass::text,conname,oid::bigint,pg_get_constraintdef(oid) FROM pg_constraint WHERE (conrelid,conname) IN (('public.conversation_profile03_closure_challenges'::regclass,'conversation_profile03_closure_challenges_check4'),('public.conversation_profile03_closure_records'::regclass,'conversation_profile03_closure_records_check'),('public.conversation_profile03_outcomes'::regclass,'conversation_profile03_outcomes_check')) ORDER BY conname";
    let capture_checks = |rows: Vec<tokio_postgres::Row>| {
        rows.into_iter()
            .map(|r| {
                (
                    r.get::<_, String>(0),
                    r.get::<_, String>(1),
                    r.get::<_, i64>(2),
                    r.get::<_, String>(3),
                )
            })
            .collect::<Vec<_>>()
    };
    let checks_before = capture_checks(client.query(checks_sql, &[]).await.unwrap());
    assert_eq!(checks_before.len(), 3);
    let catalog_before: String = client
        .query_one(
            "SELECT to_jsonb(t)::text FROM public.payload_profile_writer_catalog t WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(matches!(
        apply_historical(&mut client, &current_dir).await,
        Err(MigrationError::AbuseCountersStaleIndexPresent)
    ));
    assert_eq!(
        capture_checks(client.query(checks_sql, &[]).await.unwrap()),
        checks_before
    );
    let catalog_after: String = client
        .query_one(
            "SELECT to_jsonb(t)::text FROM public.payload_profile_writer_catalog t WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(catalog_before, catalog_after);
    let ledger_after=client.query("SELECT version,filename,checksum_sha256,kind,applied_at::text FROM public.schema_migrations ORDER BY version",&[]).await.unwrap().into_iter().map(|r|(r.get::<_,i64>(0),r.get::<_,String>(1),r.get::<_,Vec<u8>>(2),r.get::<_,String>(3),r.get::<_,String>(4))).collect::<Vec<_>>();
    assert_eq!(before, ledger_after);
    client
        .batch_execute("DROP INDEX public.auth_abuse_counters_stale")
        .await
        .unwrap();
    let graph_after: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(graph_after, restored);

    // A non-superuser must not perform the repair. Give it only the reads
    // needed for the preflight, then require refusal and unchanged graph.
    client.batch_execute("CREATE ROLE synthetic_no_priv; GRANT USAGE ON SCHEMA public TO synthetic_no_priv; GRANT SELECT ON public.schema_migrations, public.payload_profile_writer_catalog TO synthetic_no_priv; SET ROLE synthetic_no_priv").await.unwrap();
    let no_priv_error = apply_historical(&mut client, &current_dir)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &no_priv_error,
            MigrationError::Restore119Compatibility("cluster transaction visibility unavailable")
        ) || matches!(&no_priv_error, MigrationError::Database(e) if e.code()==Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)),
        "unexpected non-superuser refusal: {no_priv_error:?}"
    );
    client.batch_execute("RESET ROLE; REVOKE SELECT ON public.schema_migrations, public.payload_profile_writer_catalog FROM synthetic_no_priv; REVOKE USAGE ON SCHEMA public FROM synthetic_no_priv; DROP ROLE synthetic_no_priv").await.unwrap();
    let after_no_priv: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after_no_priv, restored);

    // An unrelated graph mutation must be refused before any compatibility DDL.
    client.batch_execute("ALTER TABLE public.conversation_profile03_outcomes ADD CONSTRAINT synthetic_extra CHECK (segment_count > 0)").await.unwrap();
    assert!(matches!(
        apply_historical(&mut client, &current_dir).await,
        Err(MigrationError::Restore119Compatibility(
            "unrecognized graph pair"
        ))
    ));
    assert!(matches!(
        apply(&mut client, &current_dir, false).await,
        Err(MigrationError::Restore119Compatibility(
            "unrecognized graph pair"
        ))
    ));
    assert!(client.query_one("SELECT EXISTS(SELECT FROM pg_constraint WHERE conname='synthetic_extra' AND conrelid='public.conversation_profile03_outcomes'::regclass)",&[]).await.unwrap().get::<_,bool>(0));
    client
        .batch_execute(
            "ALTER TABLE public.conversation_profile03_outcomes DROP CONSTRAINT synthetic_extra",
        )
        .await
        .unwrap();
    // Operator annotations are never silently discarded by drop/recreate.
    client.batch_execute("COMMENT ON CONSTRAINT conversation_profile03_outcomes_check ON public.conversation_profile03_outcomes IS 'synthetic annotation'").await.unwrap();
    let annotation_error = apply_historical(&mut client, &current_dir)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &annotation_error,
            MigrationError::Restore119Compatibility("unsafe CHECK metadata")
        ),
        "unexpected annotation refusal: {annotation_error:?}"
    );
    let comment:Option<String>=client.query_one("SELECT obj_description(oid,'pg_constraint') FROM pg_constraint WHERE conname='conversation_profile03_outcomes_check' AND conrelid='public.conversation_profile03_outcomes'::regclass",&[]).await.unwrap().get(0);
    assert_eq!(comment.as_deref(), Some("synthetic annotation"));
    client.batch_execute("COMMENT ON CONSTRAINT conversation_profile03_outcomes_check ON public.conversation_profile03_outcomes IS NULL").await.unwrap();
    // A writer already holding a catalog update lock makes the catalog
    // fence refuse NOWAIT; rollback leaves the candidate graph unchanged.
    let (writer, writer_driver) = cfg.connect(NoTls).await.unwrap();
    let writer_driver = tokio::spawn(writer_driver);
    writer
        .batch_execute("BEGIN; CREATE TABLE public.synthetic_inflight_ddl(id integer)")
        .await
        .unwrap();
    let inflight_error = apply_historical(&mut client, &current_dir)
        .await
        .unwrap_err();
    assert!(matches!(
        inflight_error,
        MigrationError::Restore119Compatibility("concurrent or prepared transaction present")
    ));
    writer.batch_execute("ROLLBACK").await.unwrap();
    drop(writer);
    writer_driver.await.unwrap().unwrap();
    let after_refusal: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after_refusal, restored);

    // A prepared schema transaction survives its originating backend and must
    // block reconstitution until explicitly rolled back in this owned fixture.
    let (prepared, prepared_driver) = cfg.connect(NoTls).await.unwrap();
    let prepared_driver = tokio::spawn(prepared_driver);
    prepared.batch_execute("BEGIN; CREATE TABLE public.synthetic_prepared_ddl(id integer); PREPARE TRANSACTION 'zt_synthetic_119'").await.unwrap();
    let prepared_error = apply_historical(&mut client, &current_dir)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &prepared_error,
            MigrationError::Restore119Compatibility("concurrent or prepared transaction present")
        ) || matches!(&prepared_error, MigrationError::Database(e) if e.code()==Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)),
        "unexpected prepared refusal: {prepared_error:?}"
    );
    prepared
        .batch_execute("ROLLBACK PREPARED 'zt_synthetic_119'")
        .await
        .unwrap();
    drop(prepared);
    prepared_driver.await.unwrap().unwrap();

    // A prior conflicting target lock refuses immediately and leaves the
    // restored graph untouched; no broad wait or partial repair is allowed.
    let (blocker, blocker_driver) = cfg.connect(NoTls).await.unwrap();
    let blocker_driver = tokio::spawn(blocker_driver);
    blocker
        .batch_execute(
            "BEGIN; LOCK TABLE public.conversation_profile03_outcomes IN ACCESS EXCLUSIVE MODE",
        )
        .await
        .unwrap();
    assert!(
        matches!(apply_historical(&mut client,&current_dir).await,Err(MigrationError::Database(e)) if e.code()==Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE))
    );
    blocker.batch_execute("ROLLBACK").await.unwrap();
    drop(blocker);
    blocker_driver.await.unwrap().unwrap();
    let still_restored: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(still_restored, restored);

    // Interrupt after all three DDL statements and require rollback of every one.
    client
        .batch_execute("SET zrotext.restore119_test_abort='enabled'")
        .await
        .unwrap();
    assert!(matches!(
        apply_historical(&mut client, &current_dir).await,
        Err(MigrationError::Restore119Compatibility(
            "synthetic interruption"
        ))
    ));
    client
        .batch_execute("RESET zrotext.restore119_test_abort")
        .await
        .unwrap();
    let failed_graph: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failed_graph, restored);

    // A second database on this disposable cluster exercises shared-catalog
    // role DDL, which must also be fenced until the repair commits.
    let other_database = format!("zt_restore119_cross_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {}",
            escape_identifier(&other_database)
        ))
        .await
        .unwrap();
    let mut cross_cfg = cfg.clone();
    cross_cfg.dbname(&other_database);
    let (cross, cross_driver) = cross_cfg.connect(NoTls).await.unwrap();
    let cross_driver = tokio::spawn(cross_driver);
    cross
        .batch_execute("SET lock_timeout='200ms'")
        .await
        .unwrap();

    cross
        .batch_execute("BEGIN; CREATE ROLE synthetic_preexisting_cross_role")
        .await
        .unwrap();
    let cross_busy = apply_historical(&mut client, &current_dir)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &cross_busy,
            MigrationError::Restore119Compatibility("concurrent or prepared transaction present")
        ) || matches!(&cross_busy,MigrationError::Database(e) if e.code()==Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)),
        "unexpected cross-database refusal: {cross_busy:?}"
    );
    cross.batch_execute("ROLLBACK").await.unwrap();

    // Hold the exact test-only rendezvous after the real catalog fence; a
    // different backend must fail to perform unrelated schema DDL.
    let (gate, gate_driver) = cfg.connect(NoTls).await.unwrap();
    let gate_driver = tokio::spawn(gate_driver);
    gate.batch_execute("SELECT pg_advisory_lock(119119095)")
        .await
        .unwrap();
    client
        .batch_execute("SET zrotext.restore119_test_barrier='enabled'")
        .await
        .unwrap();
    let workdir = current_dir.clone();
    let task = tokio::spawn(async move {
        let result = apply_historical(&mut client, &workdir).await;
        (client, result)
    });
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
        loop { let waiting:bool=gate.query_one("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=119119095 AND NOT granted)",&[]).await.unwrap().get(0);
            if waiting {break;} tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
    }).await.unwrap();
    let (other, other_driver) = cfg.connect(NoTls).await.unwrap();
    let other_driver = tokio::spawn(other_driver);
    other
        .batch_execute("SET lock_timeout='200ms'")
        .await
        .unwrap();
    let same_db: (i64, i64) = {
        let row=other.query_one("SELECT pg_backend_pid()::bigint,(SELECT oid::bigint FROM pg_database WHERE datname=current_database())",&[]).await.unwrap();
        (row.get(0), row.get(1))
    };
    let type_locks = other.query("SELECT pid::bigint,database::bigint,mode,granted FROM pg_locks WHERE relation='pg_catalog.pg_type'::regclass AND mode='ShareLock'",&[]).await.unwrap();
    eprintln!(
        "synthetic_competitor_pid_database={same_db:?} synthetic_pg_type_locks={:?}",
        type_locks
            .iter()
            .map(|r| (
                r.get::<_, Option<i64>>(0),
                r.get::<_, Option<i64>>(1),
                r.get::<_, String>(2),
                r.get::<_, bool>(3)
            ))
            .collect::<Vec<_>>()
    );
    for ddl in [
        "CREATE TABLE public.synthetic_concurrent_graph_change(id integer)",
        "CREATE FUNCTION public.synthetic_concurrent_function() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "ALTER FUNCTION public.payload_profile_writer_graph() SET search_path TO public",
        "CREATE ROLE synthetic_concurrent_role",
        "CREATE TYPE public.synthetic_concurrent_type AS ENUM ('one')",
        "CREATE INDEX synthetic_concurrent_idx ON public.accounts(id)",
        "CREATE POLICY synthetic_concurrent_policy ON public.accounts USING (true)",
        "CREATE TRIGGER synthetic_concurrent_trigger BEFORE INSERT ON public.accounts FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_guard()",
        "COMMENT ON TABLE public.accounts IS 'synthetic comment'",
        "GRANT SELECT ON public.accounts TO PUBLIC",
        "ALTER TABLE public.accounts ADD CONSTRAINT synthetic_concurrent_check CHECK(id IS NOT NULL)",
        "CREATE EXTENSION hstore",
    ] {
        let active: bool = other.query_one("SELECT EXISTS (SELECT FROM pg_locks t JOIN pg_locks a ON a.pid=t.pid AND a.database=t.database WHERE t.relation='pg_catalog.pg_type'::regclass AND t.mode='ShareLock' AND t.granted AND t.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.locktype='advisory' AND a.classid=0 AND a.objid=119119095 AND NOT a.granted)", &[]).await.unwrap().get(0);
        assert!(
            active,
            "repair must hold the same-database fence before {ddl}"
        );
        let err = other
            .batch_execute(ddl)
            .await
            .expect_err(&format!("competing DDL unexpectedly succeeded: {ddl}"));
        let active: bool = other.query_one("SELECT EXISTS (SELECT FROM pg_locks t JOIN pg_locks a ON a.pid=t.pid AND a.database=t.database WHERE t.relation='pg_catalog.pg_type'::regclass AND t.mode='ShareLock' AND t.granted AND t.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.locktype='advisory' AND a.classid=0 AND a.objid=119119095 AND NOT a.granted)", &[]).await.unwrap().get(0);
        assert!(
            active,
            "repair must hold the same-database fence after {ddl}"
        );
        assert_eq!(
            err.code(),
            Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        );
    }
    let cross_error = cross
        .batch_execute("CREATE ROLE synthetic_cross_database_role")
        .await
        .unwrap_err();
    assert_eq!(
        cross_error.code(),
        Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
    );
    gate.batch_execute("SELECT pg_advisory_unlock(119119095)")
        .await
        .unwrap();
    let (mut client, result) = task.await.unwrap();
    assert!(result.unwrap().is_empty());
    client
        .batch_execute("RESET zrotext.restore119_test_barrier")
        .await
        .unwrap();
    drop(other);
    other_driver.await.unwrap().unwrap();
    drop(gate);
    gate_driver.await.unwrap().unwrap();
    // Successful commit releases shared catalog locks for other databases.
    cross
        .batch_execute(
            "CREATE ROLE synthetic_cross_database_role; DROP ROLE synthetic_cross_database_role",
        )
        .await
        .unwrap();
    drop(cross);
    cross_driver.await.unwrap().unwrap();
    admin
        .batch_execute(&format!(
            "DROP DATABASE {}",
            escape_identifier(&other_database)
        ))
        .await
        .unwrap();
    let after: String = client
        .query_one(
            "SELECT encode(public.payload_profile_writer_graph(),'hex')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, stored);
    let ledger=client.query("SELECT version,filename,checksum_sha256,kind,applied_at::text FROM public.schema_migrations ORDER BY version",&[]).await.unwrap().into_iter().map(|r|(r.get::<_,i64>(0),r.get::<_,String>(1),r.get::<_,Vec<u8>>(2),r.get::<_,String>(3),r.get::<_,String>(4))).collect::<Vec<_>>();
    assert_eq!(before, ledger);
    assert!(
        apply_historical(&mut client, &current_dir)
            .await
            .unwrap()
            .is_empty()
    );
    let expected_tail: Vec<_> = read_migrations(&current_dir)
        .unwrap()
        .into_iter()
        .filter(|migration| migration.version > 119)
        .map(|migration| migration.version)
        .collect();
    assert_eq!(expected_tail.first(), Some(&120));
    // Exercise a restored schema directly against the current directory:
    // repair must still run before a later migration changes the graph.
    client.batch_execute(r#"ALTER TABLE public.conversation_profile03_closure_challenges DROP CONSTRAINT conversation_profile03_closure_challenges_check4, ADD CONSTRAINT conversation_profile03_closure_challenges_check4 CHECK (octet_length(proof_site_id)>=1 AND octet_length(proof_site_id)<=256 AND (octet_length(proof_instance_id)>=1 AND octet_length(proof_instance_id)<=256));
ALTER TABLE public.conversation_profile03_closure_records DROP CONSTRAINT conversation_profile03_closure_records_check, ADD CONSTRAINT conversation_profile03_closure_records_check CHECK (segment_count>=1 AND segment_count<=6 AND closed_from IN(0,1) AND closed_ms>=submit_observed_ms);
ALTER TABLE public.conversation_profile03_outcomes DROP CONSTRAINT conversation_profile03_outcomes_check, ADD CONSTRAINT conversation_profile03_outcomes_check CHECK (segment_count>=1 AND segment_count<=6 AND (evidence>=0 AND evidence<=5));"#).await.unwrap();
    let upgraded = apply(&mut client, &current_dir, false).await.unwrap();
    assert_eq!(
        upgraded
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>(),
        expected_tail
    );
    assert!(
        apply(&mut client, &current_dir, false)
            .await
            .unwrap()
            .is_empty()
    );
    drop(client);
    db_driver.await.unwrap().unwrap();
    admin
        .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&db)))
        .await
        .unwrap();
    drop(admin);
    admin_driver.await.unwrap().unwrap();
}
