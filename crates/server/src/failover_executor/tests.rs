// SPDX-License-Identifier: AGPL-3.0-only
//! Tests for the failover executor server wiring: environment parsing (the
//! default-off path above all), and — against a disposable PostgreSQL
//! database — the exact SQL semantics of the writer-authority port plus an
//! end-to-end executor failover with a restart.

use super::*;
use zrotext_failover_quorum::decision::{
    Decision, FailoverConfig, HoldReason, MemberReport, Round, SiteFenceState, WriterObservation,
};
use zrotext_failover_quorum::executor::Application;

const MIGRATION_FOUNDATION: &str =
    include_str!("../../../../deploy/compose/migrations/001_foundation.sql");
const MIGRATION_FAILOVER_JOURNAL: &str =
    include_str!("../../../../deploy/compose/migrations/051_failover_controller_state.sql");

#[test]
fn executor_env_is_disabled_by_default_and_reads_nothing_else() {
    for enabled in [None, Some("false")] {
        let env = ExecutorEnv::parse(enabled, None, None, None, None).unwrap();
        assert!(env.is_none(), "no executor while the flag is off");
        // Garbage in every other variable is not even read while off.
        let env = ExecutorEnv::parse(
            enabled,
            Some("not,three"),
            Some(""),
            Some("nope"),
            Some("zero"),
        )
        .unwrap();
        assert!(env.is_none());
    }
}

#[test]
fn executor_env_fails_closed_on_incomplete_or_invalid_configuration() {
    assert!(ExecutorEnv::parse(Some("true"), Some("a,b,c"), None, None, None).is_err());
    assert!(ExecutorEnv::parse(Some("true"), Some("a,b,c"), Some(""), None, None).is_err());
    assert!(ExecutorEnv::parse(Some("true"), Some("a,b,c"), Some("a"), Some("a"), None).is_err());
    assert!(ExecutorEnv::parse(Some("true"), Some("a,b"), Some("a"), Some("b"), None).is_err());
    assert!(
        ExecutorEnv::parse(Some("true"), Some("a,b,c"), Some("a"), Some("b"), Some("0")).is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            Some("soon")
        )
        .is_err()
    );
    assert!(ExecutorEnv::parse(Some("maybe"), None, None, None, None).is_err());
}

#[test]
fn executor_env_enabled_builds_a_validated_configuration() {
    let env = ExecutorEnv::parse(
        Some("true"),
        Some("workload-a, workload-b, witness"),
        Some("site-a"),
        Some("site-b"),
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(env.check_interval_ms(), DEFAULT_CHECK_INTERVAL_MS);
    assert_eq!(
        env.config().members(),
        ["workload-a", "workload-b", "witness"].as_slice()
    );
    assert_eq!(env.config().writer_site_id(), "site-a");
    assert_eq!(env.config().standby_site_id(), "site-b");
    let env = ExecutorEnv::parse(
        Some("true"),
        Some("workload-a,workload-b,witness"),
        Some("site-a"),
        Some("site-b"),
        Some("250"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(env.check_interval_ms(), 250);
}

#[test]
fn spawn_returns_none_and_spawns_nothing_while_disabled() {
    // The disabled path must not create the thread at all; None is the
    // proof the caller relies on (the flag-off zero-behavior contract).
    let handle = spawn_failover_executor(
        None,
        "postgres://disabled.example.invalid/db".to_owned(),
        Arc::new(AtomicBool::new(true)),
    );
    assert!(handle.is_none());
}

fn report(member_id: &str, writer: WriterObservation, now_ms: u64) -> MemberReport {
    MemberReport {
        member_id: member_id.to_owned(),
        observed_at_ms: now_ms,
        writer,
        writer_site_fence: None,
        writer_stop_confirmed: None,
        standby_ready: None,
        former_writer_healthy: None,
    }
}

fn evidence_round(members: [&str; 3], now_ms: u64) -> Round {
    Round {
        reports: members
            .iter()
            .map(|member| {
                let report = report(member, WriterObservation::Unreachable, now_ms);
                MemberReport {
                    writer_site_fence: Some(SiteFenceState {
                        enabled: true,
                        draining: true,
                    }),
                    writer_stop_confirmed: Some(true),
                    standby_ready: Some(true),
                    ..report
                }
            })
            .collect(),
    }
}

fn failure_round(members: [&str; 3], now_ms: u64) -> Round {
    Round {
        reports: members
            .iter()
            .map(|member| report(member, WriterObservation::Unreachable, now_ms))
            .collect(),
    }
}

fn healthy_round(members: [&str; 3], epoch: u64, now_ms: u64) -> Round {
    Round {
        reports: members
            .iter()
            .map(|member| report(member, WriterObservation::Reachable { epoch }, now_ms))
            .collect(),
    }
}

fn queued_source(rounds: Vec<Round>) -> InProcessSource {
    let mut source = InProcessSource::default();
    for round in rounds {
        source.queue(round);
    }
    source
}

async fn admin<F, Fut>(url: &str, body: F)
where
    F: FnOnce(tokio_postgres::Client) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (client, connection) = zrotext_postgres_connection::connect(url).await.unwrap();
    let driver = tokio::spawn(connection);
    body(client).await;
    let _ = driver.await;
}

/// The PostgreSQL-backed port semantics and an end-to-end failover, run
/// sequentially in one test function because they share one schema-private
/// `deployment_authority` and `failover_controller_state` pair.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn pg_writer_authority_is_idempotent_and_refuses_unsafe_writes() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-writer-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-standby-{}", uuid::Uuid::new_v4().simple());
    let missing_site = format!("failover-pg-missing-{}", uuid::Uuid::new_v4().simple());
    let members = ["member-a", "member-b", "member-c"];

    // Every connection in this test resolves unqualified table names through
    // a dedicated throwaway schema, so the shared database stays pristine for
    // later consumers (for example the CI migration smoke check).
    let schema = format!("failover_executor_{}", uuid::Uuid::new_v4().simple());
    let create_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("CREATE SCHEMA {create_schema}"))
            .await
            .unwrap();
    }));
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");

    // Setup: the foundation and journal migrations inside the fresh schema,
    // unique site rows, and the authority baseline this test resets between
    // its phases.
    let baseline_epoch: i64 = runtime.block_on(async {
        let (client, connection) = zrotext_postgres_connection::connect(&url).await.unwrap();
        let driver = tokio::spawn(connection);
        client.batch_execute(MIGRATION_FOUNDATION).await.unwrap();
        client
            .batch_execute(MIGRATION_FAILOVER_JOURNAL)
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO sites(site_id) VALUES($1),($2) ON CONFLICT (site_id) \
                 DO UPDATE SET enabled=TRUE, draining=FALSE",
                &[&writer_site, &standby_site],
            )
            .await
            .unwrap();
        // The promoted site starts disabled to prove the promotion enables it.
        client
            .execute(
                "UPDATE sites SET enabled=FALSE WHERE site_id=$1",
                &[&standby_site],
            )
            .await
            .unwrap();
        // Dispatch on to prove the promotion forces it off.
        let epoch: i64 = client
            .query_one(
                "UPDATE deployment_authority SET dispatch_enabled=TRUE RETURNING epoch",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        drop(client);
        let _ = driver.await;
        epoch
    });
    let base_epoch = u64::try_from(baseline_epoch).unwrap();
    let new_epoch = base_epoch + 7;

    let mut authority = PgWriterAuthority::new(url.clone()).unwrap();

    // 1. Snapshot shape, including a missing site row.
    let snapshot = authority.load_state(&writer_site, &missing_site).unwrap();
    assert_eq!(snapshot.epoch, base_epoch);
    assert!(snapshot.dispatch_enabled);
    assert_eq!(
        snapshot.writer_site,
        Some(SiteFenceState {
            enabled: true,
            draining: false
        })
    );
    assert_eq!(snapshot.standby_site, None);

    // 2. Fencing is idempotent and distinguishes a missing row.
    assert_eq!(
        authority.fence_writer_site(&writer_site).unwrap(),
        FenceOutcome::Fenced
    );
    assert_eq!(
        authority.fence_writer_site(&writer_site).unwrap(),
        FenceOutcome::AlreadyFenced
    );
    assert_eq!(
        authority.fence_writer_site(&missing_site).unwrap(),
        FenceOutcome::SiteRowMissing
    );

    // 3. Promotion: refuses a missing promoted row while the writer is
    //    fenced, refuses an unfenced writer, applies atomically, and never
    //    moves the epoch backward or twice.
    assert_eq!(
        authority
            .promote_standby(&missing_site, &writer_site, new_epoch)
            .unwrap(),
        PromoteOutcome::SiteRowMissing
    );
    let unfenced_writer = writer_site.clone();
    runtime.block_on(admin(&url, |client| async move {
        client
            .execute(
                "UPDATE sites SET draining=FALSE WHERE site_id=$1",
                &[&unfenced_writer],
            )
            .await
            .unwrap();
    }));
    assert_eq!(
        authority
            .promote_standby(&standby_site, &writer_site, new_epoch)
            .unwrap(),
        PromoteOutcome::RefusedWriterUnfenced
    );
    // The port itself re-applies the fence before the promotion retries.
    assert_eq!(
        authority.fence_writer_site(&writer_site).unwrap(),
        FenceOutcome::Fenced
    );
    assert_eq!(
        authority
            .promote_standby(&standby_site, &writer_site, new_epoch)
            .unwrap(),
        PromoteOutcome::Promoted
    );
    let snapshot = authority.load_state(&writer_site, &standby_site).unwrap();
    assert_eq!(snapshot.epoch, new_epoch);
    assert!(
        !snapshot.dispatch_enabled,
        "the promotion forces dispatch paused"
    );
    assert_eq!(
        snapshot.standby_site,
        Some(SiteFenceState {
            enabled: true,
            draining: false
        }),
        "the promoted site is enabled"
    );
    assert_eq!(
        authority
            .promote_standby(&standby_site, &writer_site, new_epoch)
            .unwrap(),
        PromoteOutcome::AlreadyAtEpoch
    );
    // Adversarial: an external same-epoch bump (or an operator toggling
    // dispatch back on) must not be answered as completion while dispatch
    // is enabled — the equal-epoch replay converges the full promoted
    // state in the same transaction instead of returning early.
    let dispatch_back_on = url.clone();
    runtime.block_on(admin(&dispatch_back_on, |client| async move {
        client
            .execute(
                "UPDATE deployment_authority SET dispatch_enabled=TRUE \
                 WHERE singleton=TRUE",
                &[],
            )
            .await
            .unwrap();
    }));
    assert_eq!(
        authority
            .promote_standby(&standby_site, &writer_site, new_epoch)
            .unwrap(),
        PromoteOutcome::AlreadyAtEpoch
    );
    let snapshot = authority.load_state(&writer_site, &standby_site).unwrap();
    assert!(!snapshot.dispatch_enabled, "the replay re-paused dispatch");
    assert_eq!(
        snapshot.epoch, new_epoch,
        "the epoch itself never bumps twice"
    );
    assert!(
        snapshot.standby_site.unwrap().enabled,
        "the promoted site stays enabled"
    );
    assert_eq!(
        authority
            .promote_standby(&standby_site, &writer_site, new_epoch - 1)
            .unwrap(),
        PromoteOutcome::RefusedHigherEpoch { current: new_epoch }
    );

    // 4. Journal round-trip.
    assert_eq!(authority.load_controller_state().unwrap(), None);
    let journal_line = format!(
        "v1 members={},{},{} writer={} standby={} max_epoch={} phase=fencing",
        members[0], members[1], members[2], writer_site, standby_site, base_epoch
    );
    authority.save_controller_state(&journal_line).unwrap();
    assert_eq!(
        authority.load_controller_state().unwrap().as_deref(),
        Some(journal_line.as_str())
    );

    // 5. End-to-end: a full failover against real PostgreSQL, then a
    //    restart that restores from the journal without re-promoting.
    let reset_writer = writer_site.clone();
    let reset_standby = standby_site.clone();
    runtime.block_on(admin(&url, |client| async move {
        client
            .batch_execute(&format!(
                "UPDATE sites SET enabled=TRUE, draining=FALSE \
                 WHERE site_id IN ('{reset_writer}','{reset_standby}'); \
                 UPDATE deployment_authority SET epoch={baseline_epoch}, dispatch_enabled=TRUE; \
                 DELETE FROM failover_controller_state"
            ))
            .await
            .unwrap();
    }));
    let config = FailoverConfig::new(
        members.iter().map(|member| (*member).to_owned()).collect(),
        writer_site.clone(),
        standby_site.clone(),
    )
    .unwrap();
    let mut executor = FailoverExecutor::new(
        config.clone(),
        queued_source(vec![
            healthy_round(members, base_epoch, 1_000),
            failure_round(members, 2_000),
            failure_round(members, 3_000),
            failure_round(members, 4_000),
            evidence_round(members, 5_000),
            evidence_round(members, 6_000),
        ]),
        authority,
    );
    let report = executor.tick(1_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterHealthy))
    );
    let _ = executor.tick(2_000);
    let _ = executor.tick(3_000);
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: writer_site.clone()
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: standby_site.clone(),
            new_epoch: base_epoch + 1
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    let report = executor.tick(6_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));

    // Restart: the journal restores the promoted phase; a replayed evidence
    // round applies nothing and bumps nothing.
    let (config, _, authority) = executor.into_parts();
    let mut executor = FailoverExecutor::new(
        config,
        queued_source(vec![evidence_round(members, 7_000)]),
        authority,
    );
    let report = executor.tick(7_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));
    assert_eq!(report.application, Application::None);
    let (_, _, mut authority) = executor.into_parts();
    let snapshot = authority.load_state(&writer_site, &standby_site).unwrap();
    assert_eq!(
        snapshot.epoch,
        base_epoch + 1,
        "the restart did not bump again"
    );
    assert!(!snapshot.dispatch_enabled);
    assert!(snapshot.writer_site.unwrap().draining);

    // Cleanup: drop the whole throwaway schema, tables and rows together.
    let cleanup_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    }));
}
