// SPDX-License-Identifier: AGPL-3.0-only
//! Tests for the failover executor server wiring: environment parsing (the
//! default-off path above all), the singleton-executor advisory-lock guard,
//! and — against a disposable PostgreSQL database — the exact SQL semantics
//! of the writer-authority port, the executor-role lock, plus an end-to-end
//! executor failover with a restart.

use super::*;
use std::collections::VecDeque;
use zrotext_failover_quorum::decision::{
    Decision, FailoverConfig, HoldReason, MemberReport, Round, SiteFenceState, WriterObservation,
};
use zrotext_failover_quorum::fence::{FenceAuthority, FenceStatus, FenceToken, HostFenceOutcome};

/// A fence backend that confirms on demand — the stand-in for the external
/// host-fencing backend these PostgreSQL tests do not have. The shipped
/// default is `NoopFenceAuthority`, which refuses everything.
struct ConfirmingFence;

impl FenceAuthority for ConfirmingFence {
    fn fence_status(&mut self, _host_site_id: &str) -> FenceStatus {
        FenceStatus::Unfenced
    }

    fn fence_host(&mut self, _host_site_id: &str, token: FenceToken) -> HostFenceOutcome {
        HostFenceOutcome::Fenced { token }
    }
}

/// An anchor that confirms and records — the stand-in for a real external
/// epoch authority these PostgreSQL tests do not have (the production
/// PgExternalEpochAnchor reads the database itself).
#[derive(Default)]
struct RecordingAnchor {
    anchored_epoch: u64,
}

impl zrotext_failover_quorum::fence::ExternalEpochAnchor for RecordingAnchor {
    fn confirmed_epoch(&mut self) -> zrotext_failover_quorum::fence::AnchorReading {
        zrotext_failover_quorum::fence::AnchorReading::Confirmed {
            epoch: self.anchored_epoch,
        }
    }

    fn record_promotion(&mut self, new_epoch: u64) -> zrotext_failover_quorum::fence::AnchorRecord {
        if new_epoch <= self.anchored_epoch {
            return zrotext_failover_quorum::fence::AnchorRecord::Refused {
                anchored_epoch: self.anchored_epoch,
            };
        }
        self.anchored_epoch = new_epoch;
        zrotext_failover_quorum::fence::AnchorRecord::Recorded
    }
}

/// Confirming external adapters for the PostgreSQL executor tests: every
/// external precondition is satisfiable, so those tests pin the port and
/// journal semantics rather than the fencing refusals (covered by the
/// crate's corpus and the refusing-backend test below).
fn confirming_external_fencing() -> ExternalFencing {
    ExternalFencing::new(ConfirmingFence, RecordingAnchor::default())
}
use zrotext_failover_quorum::executor::{
    Application, ExecutorStatus, InProcessSource, ObservationSource,
};
use zrotext_failover_quorum::observe::{
    AbstainReason, MemberObserver, RoundProbes, StopConfirmation, WriterProbe,
};
use zrotext_failover_quorum::report::{ConsensusStoreSink, ProbeSource, ReportLoop, RoundOutcome};

const MIGRATION_FOUNDATION: &str =
    include_str!("../../../../deploy/compose/migrations/001_foundation.sql");
const MIGRATION_FAILOVER_JOURNAL: &str =
    include_str!("../../../../deploy/compose/migrations/051_failover_controller_state.sql");

#[test]
fn executor_env_is_disabled_by_default_and_reads_nothing_else() {
    for enabled in [None, Some("false")] {
        let env =
            ExecutorEnv::parse(enabled, None, None, None, None, None, None, None, None).unwrap();
        assert!(env.is_none(), "no executor while the flag is off");
        // Garbage in every other variable is not even read while off,
        // including the consensus store directory and the reporting
        // variables.
        let env = ExecutorEnv::parse(
            enabled,
            Some("not,three"),
            Some(""),
            Some("nope"),
            Some("zero"),
            Some("relative/../unsafe\0dir"),
            Some("soon"),
            Some("-1"),
            Some("a-stranger"),
        )
        .unwrap();
        assert!(env.is_none());
    }
}

#[test]
fn executor_env_fails_closed_on_incomplete_or_invalid_configuration() {
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some(""),
            None,
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("a"),
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b"),
            Some("a"),
            Some("b"),
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            Some("0"),
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            Some("soon"),
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("maybe"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
}

#[test]
fn executor_env_requires_a_consensus_store_directory_when_enabled() {
    // The store directory is explicit configuration, never a silent default
    // that writes somewhere surprising.
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            None,
            None,
            None,
            None,
            None
        )
        .is_err()
    );
    assert!(
        ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            None,
            Some(""),
            None,
            None,
            None
        )
        .is_err()
    );
}

/// A platform-absolute directory derived only from the compile-time
/// manifest directory (the Git-ignored workspace `target/`), so the tests
/// need no machine-specific path literal. Parsing never touches it.
fn absolute_root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&root).expect("create workspace target directory");
    root.canonicalize()
        .expect("canonical workspace target directory")
}

fn absolute_dir(leaf: &str) -> String {
    absolute_root()
        .join(leaf)
        .to_str()
        .expect("utf-8 workspace path")
        .to_owned()
}

#[test]
fn executor_env_enabled_builds_a_validated_configuration() {
    let store_dir = absolute_dir("failover-store");
    let env = ExecutorEnv::parse(
        Some("true"),
        Some("workload-a, workload-b, witness"),
        Some("site-a"),
        Some("site-b"),
        None,
        Some(&store_dir),
        None,
        Some("1500"),
        Some("witness"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(env.check_interval_ms(), DEFAULT_CHECK_INTERVAL_MS);
    // An unset probe interval defaults to lockstep with the checks.
    assert_eq!(env.probe_interval_ms(), DEFAULT_CHECK_INTERVAL_MS);
    assert_eq!(env.probe_timeout_ms(), 1500);
    assert_eq!(env.report_member_id(), "witness");
    assert_eq!(
        env.config().members(),
        ["workload-a", "workload-b", "witness"].as_slice()
    );
    assert_eq!(env.config().writer_site_id(), "site-a");
    assert_eq!(env.config().standby_site_id(), "site-b");
    assert_eq!(env.store_dir(), std::path::Path::new(&store_dir));
    // The value is taken literally: no variable expansion.
    let literal_dir = absolute_dir("${STORE_DIR}");
    let env = ExecutorEnv::parse(
        Some("true"),
        Some("workload-a,workload-b,witness"),
        Some("site-a"),
        Some("site-b"),
        Some("250"),
        Some(&literal_dir),
        Some("250"),
        Some("1500"),
        Some("workload-a"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(env.check_interval_ms(), 250);
    assert_eq!(env.probe_interval_ms(), 250);
    assert_eq!(env.store_dir(), std::path::Path::new(&literal_dir));
}

#[test]
fn executor_env_parses_the_reporting_variables_strictly() {
    let store_dir = absolute_dir("failover-store");
    let valid = |interval: Option<&str>, timeout: Option<&str>, member: Option<&str>| {
        ExecutorEnv::parse(
            Some("true"),
            Some("workload-a,workload-b,witness"),
            Some("site-a"),
            Some("site-b"),
            None,
            Some(&store_dir),
            interval,
            timeout,
            member,
        )
    };
    // The reporting identity and the probe timeout are required and must be
    // well-formed; anything else fails startup closed.
    assert!(
        valid(None, Some("1500"), None).is_err(),
        "a reporting member identity is required when the module is enabled"
    );
    assert!(valid(None, Some("1500"), Some("")).is_err());
    assert!(
        valid(None, Some("1500"), Some("rogue")).is_err(),
        "an identity outside the configured membership must fail closed"
    );
    assert!(valid(None, None, Some("witness")).is_err());
    assert!(valid(None, Some(""), Some("witness")).is_err());
    assert!(
        valid(Some("0"), Some("1500"), Some("witness")).is_err(),
        "a zero probe interval would spin"
    );
    assert!(valid(Some("soon"), Some("1500"), Some("witness")).is_err());
    assert!(
        valid(None, Some("0"), Some("witness")).is_err(),
        "a zero probe timeout is not a bound"
    );
    assert!(valid(None, Some("soon"), Some("witness")).is_err());
    assert!(valid(None, Some("1500"), Some("workload-b")).is_ok());
}

#[test]
fn executor_env_refuses_a_relative_or_dot_segment_store_directory() {
    let root = absolute_dir("zrotext");
    let separator = std::path::MAIN_SEPARATOR;
    let refused = [
        "failover-store".to_owned(),
        "./failover-store".to_owned(),
        ".\\failover-store".to_owned(),
        "../failover-store".to_owned(),
        format!("{root}{separator}..{separator}failover-store"),
        format!("{root}{separator}.{separator}failover-store"),
        format!("{root}/../failover-store"),
        format!("{root}/./failover-store"),
        format!("{root}{separator}.."),
    ];
    for dir in &refused {
        let error = ExecutorEnv::parse(
            Some("true"),
            Some("a,b,c"),
            Some("a"),
            Some("b"),
            None,
            Some(dir),
            None,
            Some("1500"),
            Some("c"),
        )
        .expect_err(dir);
        assert!(
            error.contains("absolute path"),
            "{dir:?} must be refused as a store directory, got {error:?}"
        );
    }
}

#[test]
fn spawn_returns_none_and_spawns_nothing_while_disabled() {
    // The disabled path must not create the thread at all; None is the
    // proof the caller relies on (the flag-off zero-behavior contract).
    let healthy = Arc::new(AtomicBool::new(true));
    let handle = spawn_failover_executor(
        None,
        "postgres://disabled.example.invalid/db".to_owned(),
        Arc::new(AtomicBool::new(true)),
        healthy.clone(),
    );
    assert!(handle.is_none());
    assert!(
        healthy.load(Ordering::Acquire),
        "the disabled path never reports an executor failure"
    );
}

/// A scratch store directory, removed on drop. The root is derived only from
/// the compile-time manifest directory — never from an environment variable,
/// argument or the system temp dir — under the workspace `target/`, which
/// Git ignores. It is canonicalized so it satisfies the executor's
/// absolute-path, no-`..` store-directory rule.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/zrotext-failover-executor-tests");
        std::fs::create_dir_all(&root).expect("create scratch root");
        let path = root
            .canonicalize()
            .expect("canonical scratch root")
            .join(format!("{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch directory");
        Self(path)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn enabled_env(store_dir: &Path) -> ExecutorEnv {
    ExecutorEnv::parse(
        Some("true"),
        Some("workload-a,workload-b,witness"),
        Some("site-a"),
        Some("site-b"),
        Some("50"),
        Some(store_dir.to_str().expect("utf-8 scratch path")),
        None,
        Some("5000"),
        Some("witness"),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn a_consensus_store_that_cannot_open_fails_the_executor_visibly() {
    let scratch = ScratchDir::new("corrupt-store");
    // A torn membership record: the store must fail closed on open, before
    // any thread runs.
    std::fs::write(scratch.0.join("membership"), "v1 members=workload-a").unwrap();
    let healthy = Arc::new(AtomicBool::new(true));
    // Building the authority port does not connect, so no database is
    // needed to reach the store-open failure.
    let threads = spawn_failover_executor(
        Some(enabled_env(&scratch.0)),
        "postgres://unused.example.invalid/db".to_owned(),
        Arc::new(AtomicBool::new(false)),
        healthy.clone(),
    );
    assert!(
        threads.is_none(),
        "a store that cannot open must fail the executor before any thread runs"
    );
    assert!(
        !healthy.load(Ordering::Acquire),
        "a store-open failure must be visible to operators, not only logged"
    );
}

#[test]
fn a_consensus_store_that_opens_keeps_the_executor_healthy() {
    let scratch = ScratchDir::new("fresh-store");
    let healthy = AtomicBool::new(true);
    let store = open_consensus_store(&enabled_env(&scratch.0), &healthy);
    assert!(store.is_some(), "a fresh directory initializes a store");
    assert!(healthy.load(Ordering::Acquire));
    // A second open of a foreign membership fails closed and is visible.
    drop(store);
    let foreign = ExecutorEnv::parse(
        Some("true"),
        Some("workload-a,workload-b,witness-2"),
        Some("site-a"),
        Some("site-b"),
        None,
        Some(scratch.0.to_str().expect("utf-8 scratch path")),
        None,
        Some("5000"),
        Some("witness-2"),
    )
    .unwrap()
    .unwrap();
    assert!(open_consensus_store(&foreign, &healthy).is_none());
    assert!(!healthy.load(Ordering::Acquire));
}

/// Deterministic scripted probe source for wiring tests: replays one
/// outcome per round.
struct ScriptedProbes(VecDeque<RoundProbes>);

impl ProbeSource for ScriptedProbes {
    fn probe(&mut self) -> RoundProbes {
        self.0
            .pop_front()
            .expect("the script must cover every round")
    }
}

fn healthy_probes(epoch: u64) -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Reachable { epoch },
        writer_site_fence: Ok(SiteFenceState {
            enabled: true,
            draining: false,
        }),
        writer_stop: Ok(StopConfirmation { confirmed: false }),
        standby: Ok(true),
        former_writer: Ok(true),
    }
}

#[test]
fn the_deterministic_probe_placeholder_abstains_and_records_nothing() {
    let scratch = ScratchDir::new("placeholder-probes");
    let store = Arc::new(std::sync::Mutex::new(
        ConsensusStore::open(
            &scratch.0,
            ["workload-a", "workload-b", "witness"]
                .iter()
                .map(|member| (*member).to_owned())
                .collect(),
            10_000,
        )
        .unwrap(),
    ));
    // The placeholder is the stand-in until a production probe source
    // exists: every probe is indeterminate, so the observer abstains each
    // round and nothing is ever recorded — fail-closed, never fabricated.
    let mut reporting = ReportLoop::new(
        MemberObserver::new("witness").unwrap(),
        AbstainingProbeSource,
        ConsensusStoreSink::new(store.clone()),
    );
    for at_ms in [1_000_u64, 2_000, 3_000] {
        assert_eq!(
            reporting.run_round(at_ms),
            RoundOutcome::Abstained(AbstainReason::WriterIndeterminate)
        );
    }
    let store = store.lock().unwrap();
    assert_eq!(store.round(3_000), Round::default());
    for member in ["workload-a", "workload-b", "witness"] {
        let journal = scratch
            .0
            .join("observations")
            .join(format!("{member}.journal"));
        assert_eq!(std::fs::read_to_string(journal).unwrap(), "");
    }
}

#[test]
fn the_shared_store_source_serves_exactly_what_the_reporting_loop_records() {
    let scratch = ScratchDir::new("shared-store");
    let store = Arc::new(std::sync::Mutex::new(
        ConsensusStore::open(
            &scratch.0,
            ["workload-a", "workload-b", "witness"]
                .iter()
                .map(|member| (*member).to_owned())
                .collect(),
            10_000,
        )
        .unwrap(),
    ));
    let mut reporting = ReportLoop::new(
        MemberObserver::new("witness").unwrap(),
        ScriptedProbes(vec![healthy_probes(5)].into()),
        ConsensusStoreSink::new(store.clone()),
    );
    assert_eq!(reporting.run_round(1_000), RoundOutcome::Reported);
    // The executor side of the shared store serves the recorded report once
    // and never re-serves it inside its freshness window.
    let mut source = SharedStoreSource::new(store);
    let round = source.collect(1_000);
    assert_eq!(round.reports.len(), 1);
    assert_eq!(round.reports[0].member_id, "witness");
    assert_eq!(
        round.reports[0].writer,
        WriterObservation::Reachable { epoch: 5 }
    );
    for now in [1_001_u64, 5_000, 9_999] {
        assert_eq!(
            source.collect(now),
            Round::default(),
            "a served report must not be re-served while fresh"
        );
    }
}

#[test]
fn the_enabled_threads_run_and_stop_at_the_drain_flag() {
    let scratch = ScratchDir::new("drain-flag");
    let healthy = Arc::new(AtomicBool::new(true));
    // The graceful-drain flag is set before the threads start: both loops
    // must observe it and exit without a single round, leaving the store
    // untouched and readiness healthy. The executor thread never connects
    // (building the authority port opens no connection).
    let threads = spawn_failover_executor(
        Some(enabled_env(&scratch.0)),
        "postgres://unused.example.invalid/db".to_owned(),
        Arc::new(AtomicBool::new(true)),
        healthy.clone(),
    )
    .expect("the enabled wiring spawns its threads");
    threads
        .reporter
        .join()
        .expect("the reporter thread exits cleanly");
    threads
        .executor
        .join()
        .expect("the executor thread exits cleanly");
    assert!(
        healthy.load(Ordering::Acquire),
        "a clean drain is not an executor failure"
    );
    for member in ["workload-a", "workload-b", "witness"] {
        let journal = scratch
            .0
            .join("observations")
            .join(format!("{member}.journal"));
        assert_eq!(std::fs::read_to_string(journal).unwrap(), "");
    }
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

/// A socket that accepts nothing and speaks nothing: the TCP handshake
/// completes out of the listen backlog, so a PostgreSQL client connected to
/// it hangs forever waiting for the startup reply — the exact hang the
/// connect ceiling exists to bound, with no server required.
#[test]
fn a_silent_socket_fails_the_connect_within_the_ceiling() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind silent listener");
    let port = listener
        .local_addr()
        .expect("silent listener address")
        .port();
    let mut authority = PgWriterAuthority::new(format!("postgres://127.0.0.1:{port}/postgres"))
        .expect("authority port");
    let started = std::time::Instant::now();
    let Err(error) = authority.open_connection(Duration::from_millis(250)) else {
        panic!("a silent server must fail the connect")
    };
    assert!(
        matches!(error, PgAuthorityError::ConnectTimedOut(_)),
        "got {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the connect must fail near its 250ms ceiling, took {:?}",
        started.elapsed()
    );
    assert!(
        authority.client.is_none() && authority.reconnect_pending,
        "a failed connect marks a jittered reconnect for the next operation"
    );
}

/// The wait ceiling turns a never-completing operation into a failed one.
/// (The bound is proven here on the wait helper directly; injecting a
/// wedged operation through the port needs a live connection, which the
/// PostgreSQL-gated reuse test does with a shortened ceiling.)
#[test]
fn an_operation_that_never_completes_fails_at_its_wait_ceiling() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let started = std::time::Instant::now();
    let result: Result<(), PgAuthorityError> = runtime.block_on(wait_bounded(
        Duration::from_millis(100),
        std::future::pending(),
    ));
    assert!(
        matches!(result, Err(PgAuthorityError::OperationTimedOut(_))),
        "got {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the wait must fail near its 100ms ceiling, took {:?}",
        started.elapsed()
    );
}

/// The ceiling only bounds waiting; results pass through unchanged.
#[test]
fn the_wait_ceiling_passes_operation_results_through() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let ceiling = Duration::from_secs(5);
    let delivered: Result<u8, PgAuthorityError> =
        runtime.block_on(wait_bounded(ceiling, async { Ok(7) }));
    assert_eq!(delivered.expect("ok result"), 7);
    let refused: Result<u8, PgAuthorityError> = runtime.block_on(wait_bounded(ceiling, async {
        Err(PgAuthorityError::EpochOutOfRange(-1))
    }));
    assert!(
        matches!(refused, Err(PgAuthorityError::EpochOutOfRange(-1))),
        "got {refused:?}"
    );
}

#[test]
fn a_failed_lock_attempt_parks_the_guard_dormant_until_the_retry_interval_elapses() {
    let (mut guard, role) = SingletonExecutorGuard::new(Duration::from_millis(50));
    let now = Instant::now();
    assert!(
        matches!(guard.poll(now), GuardDecision::Proceed),
        "the first attempt is due immediately"
    );
    guard.resolved(false, now);
    assert_eq!(
        role.load(),
        ExecutorRole::Dormant,
        "the wiring loop must see the dormancy through the shared role cell"
    );
    assert!(
        matches!(guard.poll(now), GuardDecision::Dormant),
        "an operation inside the retry interval fails closed"
    );
    assert!(matches!(
        guard.poll(now + Duration::from_millis(25)),
        GuardDecision::Dormant
    ));
    assert!(
        matches!(
            guard.poll(now + Duration::from_millis(50)),
            GuardDecision::Proceed
        ),
        "the retry is due again after the interval"
    );
}

#[test]
fn an_acquired_lock_runs_operations_until_its_connection_is_lost() {
    let (mut guard, role) = SingletonExecutorGuard::new(Duration::from_millis(50));
    let now = Instant::now();
    guard.resolved(true, now);
    assert_eq!(role.load(), ExecutorRole::Active);
    for offset in [0, 25, 50, 100] {
        assert!(
            matches!(
                guard.poll(now + Duration::from_millis(offset)),
                GuardDecision::Proceed
            ),
            "an active connection runs operations without re-attempting the lock"
        );
    }
    guard.connection_lost();
    assert_eq!(
        role.load(),
        ExecutorRole::Pending,
        "the lock died with the connection: the role is not assumed"
    );
    assert!(
        matches!(guard.poll(now), GuardDecision::Proceed),
        "the re-attempt is due immediately, on the fresh connection"
    );
}

#[test]
fn a_lost_connection_does_not_wake_a_dormant_guard_early() {
    let (mut guard, _role) = SingletonExecutorGuard::new(Duration::from_millis(50));
    let now = Instant::now();
    guard.resolved(false, now);
    // An unrelated connection discard must not reset the dormancy floor.
    guard.connection_lost();
    assert!(matches!(guard.poll(now), GuardDecision::Dormant));
    assert!(matches!(
        guard.poll(now + Duration::from_millis(49)),
        GuardDecision::Dormant
    ));
    assert!(matches!(
        guard.poll(now + Duration::from_millis(50)),
        GuardDecision::Proceed
    ));
}

#[test]
fn a_reacquired_lock_fails_operations_until_the_reload_is_acknowledged() {
    // Stale-state safety (issue #513): only a re-acquisition — an
    // acquisition after a previous exclusive period — invalidates cached
    // executor state, and while it is unacknowledged every operation fails
    // closed, however much time passes (it is a reload signal, not a retry
    // interval).
    let (mut guard, role) = SingletonExecutorGuard::new(Duration::from_millis(50));
    let now = Instant::now();
    assert_eq!(
        guard.resolved(true, now),
        LockAttempt::AcquiredFirst,
        "the first acquisition lets the triggering operation run"
    );
    assert!(matches!(guard.poll(now), GuardDecision::Proceed));
    // The lock dies with the connection; a later acquisition is a
    // re-acquisition: another executor may have run in between.
    guard.connection_lost();
    assert_eq!(guard.resolved(true, now), LockAttempt::AcquiredAgain);
    assert_eq!(role.load(), ExecutorRole::Active);
    assert!(
        matches!(guard.poll(now), GuardDecision::Stale),
        "no operation may run on the re-acquired lock before the reload"
    );
    assert!(
        matches!(
            guard.poll(now + Duration::from_secs(1)),
            GuardDecision::Stale
        ),
        "the stale verdict is sticky, not a retry interval"
    );
    assert!(guard.take_reacquired(), "exactly one reload signal");
    assert!(!guard.take_reacquired(), "the signal is read-and-clear");
    assert!(
        matches!(guard.poll(now), GuardDecision::Proceed),
        "after the acknowledged reload, operations run again"
    );
    // A refused attempt never reads as a re-acquisition, but every
    // acquisition after the first exclusive period does — dormancy in
    // between changes nothing.
    assert_eq!(guard.resolved(false, now), LockAttempt::Refused);
    assert_eq!(role.load(), ExecutorRole::Dormant);
    guard.connection_lost();
    assert_eq!(
        guard.resolved(true, now + Duration::from_secs(2)),
        LockAttempt::AcquiredAgain,
        "every acquisition after the first exclusive period is a re-acquisition"
    );
}

#[test]
fn only_an_executor_constructed_port_carries_the_singleton_lock_guard() {
    // The plain port never attempts the lock — and the disabled wiring
    // (proven above: `spawn_returns_none_and_spawns_nothing_while_disabled`)
    // never constructs a port at all — so the lock path is reached only
    // through the executor wiring with the flag on.
    let plain = PgWriterAuthority::new("postgres://plain.example.invalid/db".to_owned()).unwrap();
    assert!(
        plain.guard.is_none(),
        "a plain port never attempts the singleton lock"
    );
    let (guarded, role) = PgWriterAuthority::new_for_executor(
        "postgres://guarded.example.invalid/db".to_owned(),
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(guarded.guard.is_some());
    assert_eq!(
        role.load(),
        ExecutorRole::Pending,
        "no role is claimed before the first attempt"
    );
}

#[test]
fn the_executor_lock_key_is_pinned_and_distinct_from_the_migrator_lock() {
    // Both the executor's singleton lock and the migrator's lock are
    // session-level advisory locks in the same 64-bit key space of one
    // database: a shared key would let whichever holder came first defeat
    // the other's exclusivity entirely (a migrator "holding the executor",
    // an executor "holding the migration"). The executor's key is pinned to
    // its self-describing value (big-endian `ZROFAILO`, so `pg_locks` names
    // it) and pinned distinct from the migrator's namespace
    // (big-endian `ZROTEXT`).
    assert_eq!(
        EXECUTOR_ADVISORY_LOCK_KEY,
        i64::from_be_bytes(*b"ZROFAILO"),
        "the executor lock key must stay fixed at its documented value"
    );
    assert_eq!(
        zrotext_migrator::MIGRATION_LOCK,
        i64::from_be_bytes(*b"\0ZROTEXT"),
        "the migrator lock key must stay fixed at its documented value"
    );
    assert_ne!(
        EXECUTOR_ADVISORY_LOCK_KEY,
        zrotext_migrator::MIGRATION_LOCK,
        "the executor singleton lock and the migration lock must never share \
         a key: each would defeat the other's exclusivity"
    );
}
#[test]
fn a_dormant_guard_fails_operations_closed_without_a_connection() {
    // Port 1 refuses connections immediately, so a reached connect would
    // fail fast with a transport error — anything but dormancy.
    let (mut authority, _role) = PgWriterAuthority::new_for_executor(
        "postgres://127.0.0.1:1/postgres".to_owned(),
        Duration::from_secs(30),
    )
    .unwrap();
    // Park the guard dormant, exactly as a failed lock attempt would.
    authority
        .guard
        .as_mut()
        .expect("guarded port")
        .resolved(false, Instant::now());
    let started = std::time::Instant::now();
    let Err(error) = authority.load_state("site-a", "site-b") else {
        panic!("a dormant executor must fail the operation closed");
    };
    assert!(
        matches!(error, PgAuthorityError::ExecutorDormant),
        "got {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the fail-fast path must not wait out any ceiling, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        authority.connections_opened, 0,
        "a dormant operation must not open a connection"
    );
}

#[test]
fn role_changes_log_once_per_change_and_nothing_logs_while_pending() {
    let env = enabled_env(&ScratchDir::new("role-log-store").0);
    assert_eq!(role_change_log(None, ExecutorRole::Pending, &env), None);
    assert_eq!(
        role_change_log(Some(ExecutorRole::Pending), ExecutorRole::Pending, &env),
        None
    );
    assert_eq!(
        role_change_log(Some(ExecutorRole::Active), ExecutorRole::Active, &env),
        None,
        "a steady role logs nothing: no per-tick spam"
    );
    assert_eq!(
        role_change_log(Some(ExecutorRole::Dormant), ExecutorRole::Dormant, &env),
        None
    );
    let dormant = role_change_log(None, ExecutorRole::Dormant, &env).expect("dormancy is logged");
    assert!(
        dormant.contains("dormant") && dormant.contains("50ms"),
        "the dormant line names the state and the retry cadence: {dormant}"
    );
    let active = role_change_log(None, ExecutorRole::Active, &env).expect("acquisition is logged");
    assert!(
        active.contains("running")
            && active.contains("3 members")
            && active.contains("site-a")
            && active.contains("site-b"),
        "the acquisition line is the running banner: {active}"
    );
    assert!(role_change_log(Some(ExecutorRole::Dormant), ExecutorRole::Active, &env).is_some());
    assert!(role_change_log(Some(ExecutorRole::Active), ExecutorRole::Dormant, &env).is_some());
}

/// PIDs of the live backends currently serving connections whose
/// `application_name` is the authority's, observed through one persistent
/// admin session so the observer itself never adds a connection.
fn authority_backend_pids(
    runtime: &tokio::runtime::Runtime,
    admin: &tokio_postgres::Client,
    app_name: &str,
) -> Vec<i32> {
    runtime.block_on(async {
        admin
            .query(
                "SELECT pid FROM pg_stat_activity WHERE application_name = $1 \
                 AND datname = current_database()",
                &[&app_name],
            )
            .await
            .expect("observe authority backends")
            .iter()
            .map(|row| row.get(0))
            .collect()
    })
}

/// The authority's connection lifecycle: sequential operations must ride one
/// dedicated, long-lived connection instead of opening a new one each time,
/// and a broken connection must be replaced before the next operation. The
/// database itself is the observer — `pg_stat_activity` names the authority's
/// backends by `application_name` — so the proof does not depend on port
/// internals.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn pg_writer_authority_reuses_one_connection_across_operations() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-reuse-w-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-reuse-s-{}", uuid::Uuid::new_v4().simple());
    let schema = format!("failover_executor_reuse_{}", uuid::Uuid::new_v4().simple());
    let app_name = format!("zt-failover-authority-{}", uuid::Uuid::new_v4().simple());

    // One persistent admin connection both sets the schema up and observes
    // it; opened before the baseline below so it stays out of every count.
    // Its socket is driven by a task on the test runtime for the client's
    // whole lifetime, exactly like the port's own driver.
    let (admin, admin_driver) = {
        let (client, connection) = runtime
            .block_on(zrotext_postgres_connection::connect(&base_url))
            .expect("admin connection");
        let driver = runtime.spawn(connection);
        (client, driver)
    };
    let setup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {setup_schema}; SET search_path TO {setup_schema}"
            ))
            .await
            .unwrap();
        admin.batch_execute(MIGRATION_FOUNDATION).await.unwrap();
        admin
            .batch_execute(MIGRATION_FAILOVER_JOURNAL)
            .await
            .unwrap();
    });
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{base_url}{separator}options=-csearch_path%3D{schema}&application_name={app_name}"
    );

    let mut authority = PgWriterAuthority::new(url).unwrap();
    let mut live_pids = Vec::new();
    for round in 0..12 {
        match round % 4 {
            0 | 1 => {
                authority.load_state(&writer_site, &standby_site).unwrap();
            }
            2 => {
                authority
                    .save_controller_state(&format!("v1 reuse round={round}"))
                    .unwrap();
            }
            _ => {
                authority.load_controller_state().unwrap();
            }
        }
        live_pids.push(authority_backend_pids(&runtime, &admin, &app_name));
    }

    eprintln!(
        "reuse measurement: live authority backends after each of 12 operations: {live_pids:?}"
    );

    for (index, pids) in live_pids.iter().enumerate() {
        assert_eq!(
            pids.len(),
            1,
            "operation {index} must leave exactly one live authority backend, got {pids:?}"
        );
    }
    let first = live_pids[0][0];
    assert!(
        live_pids.iter().all(|pids| pids[0] == first),
        "the authority must reuse ONE connection (same backend pid) across operations; saw {live_pids:?}"
    );
    assert_eq!(
        authority.connections_opened, 1,
        "12 sequential operations must ride one dedicated connection"
    );
    // Break the dedicated connection server-side: the operation riding it
    // must fail closed, and only the NEXT operation may reconnect.
    runtime.block_on(async {
        admin
            .execute("SELECT pg_terminate_backend($1)", &[&first])
            .await
            .unwrap();
    });
    assert!(
        authority.load_state(&writer_site, &standby_site).is_err(),
        "an operation on a terminated connection must fail closed"
    );
    assert_eq!(
        authority.connections_opened, 1,
        "a failed operation must not reconnect before the next one"
    );
    assert!(
        authority.load_state(&writer_site, &standby_site).is_ok(),
        "the operation after a failure must ride a fresh connection"
    );
    let reconnected = authority_backend_pids(&runtime, &admin, &app_name);
    assert_eq!(reconnected.len(), 1, "exactly one live authority backend");
    let second = reconnected[0];
    assert_ne!(
        second, first,
        "the broken connection must be replaced, not reused"
    );
    assert_eq!(
        authority.connections_opened, 2,
        "the operation after a failure reconnects exactly once"
    );

    // A wedged operation surfaces as a bounded failure, not a hang, and the
    // port reconnects before the next operation.
    let started = std::time::Instant::now();
    let stalled: Result<(), PgAuthorityError> = authority
        .call_bounded(Duration::from_millis(300), |_client| {
            Box::pin(std::future::pending())
        });
    assert!(
        matches!(stalled, Err(PgAuthorityError::OperationTimedOut(_))),
        "a never-completing operation must fail at its ceiling, got {stalled:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the failed wait must sit near its 300ms ceiling, took {:?}",
        started.elapsed()
    );
    assert!(
        authority.load_state(&writer_site, &standby_site).is_ok(),
        "the operation after a timeout must ride a fresh connection"
    );
    let revived = authority_backend_pids(&runtime, &admin, &app_name);
    assert_eq!(revived.len(), 1, "exactly one live authority backend");
    assert_ne!(
        revived[0], second,
        "the timed-out connection must be replaced, not reused"
    );
    assert_eq!(
        authority.connections_opened, 3,
        "the operation after a timeout reconnects exactly once"
    );

    drop(authority);
    let cleanup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    });
    drop(admin);
    let _ = runtime.block_on(admin_driver);
}

/// The singleton-executor guard against real PostgreSQL: two guarded
/// authorities against the same database cannot both be the executor — the
/// second goes dormant, fails closed without holding a connection, and
/// cannot retry inside the lock interval — and when the active executor's
/// connection dies, the dormant replica acquires the lock on a later retry
/// and then owns the journal, while the demoted first cannot steal the role
/// back. The database is the observer through `pg_stat_activity` and the
/// role cells, so the proof does not depend on port internals.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn a_dormant_executor_takes_over_when_the_active_executors_connection_dies() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-takeover-w-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-takeover-s-{}", uuid::Uuid::new_v4().simple());
    let schema = format!(
        "failover_executor_takeover_{}",
        uuid::Uuid::new_v4().simple()
    );
    let app_first = format!("zt-failover-authority-a-{}", uuid::Uuid::new_v4().simple());
    let app_second = format!("zt-failover-authority-b-{}", uuid::Uuid::new_v4().simple());

    let (admin, admin_driver) = {
        let (client, connection) = runtime
            .block_on(zrotext_postgres_connection::connect(&base_url))
            .expect("admin connection");
        let driver = runtime.spawn(connection);
        (client, driver)
    };
    let setup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {setup_schema}; SET search_path TO {setup_schema}"
            ))
            .await
            .unwrap();
        admin.batch_execute(MIGRATION_FOUNDATION).await.unwrap();
        admin
            .batch_execute(MIGRATION_FAILOVER_JOURNAL)
            .await
            .unwrap();
    });
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = |app_name: &str| {
        format!("{base_url}{separator}options=-csearch_path%3D{schema}&application_name={app_name}")
    };

    let retry_interval = Duration::from_millis(150);
    // CI runs PostgreSQL tests in parallel on one shared database, and
    // advisory locks are per-database (not per-schema), so this test's two
    // executors contend on a test-private key instead of the production
    // one: the race below is still real, but no other test can fence it.
    let test_lock_key = i64::from_be_bytes(*b"ZROTEST1");
    let (mut first, first_role) = PgWriterAuthority::new_for_executor_with_lock_key(
        url(&app_first),
        retry_interval,
        test_lock_key,
    )
    .unwrap();
    assert_eq!(first_role.load(), ExecutorRole::Pending);
    first.load_state(&writer_site, &standby_site).unwrap();
    assert_eq!(first_role.load(), ExecutorRole::Active);

    // The second executor loses the race: it goes dormant, and its
    // operation fails closed instead of touching the singleton rows.
    let (mut second, second_role) = PgWriterAuthority::new_for_executor_with_lock_key(
        url(&app_second),
        retry_interval,
        test_lock_key,
    )
    .unwrap();
    let Err(error) = second.load_state(&writer_site, &standby_site) else {
        panic!("a second executor must not run rounds against the singleton journal row");
    };
    assert!(
        matches!(error, PgAuthorityError::ExecutorDormant),
        "got {error:?}"
    );
    assert_eq!(second_role.load(), ExecutorRole::Dormant);

    // A retry inside the lock interval fails fast, without a connection.
    let started = std::time::Instant::now();
    assert!(matches!(
        second.load_state(&writer_site, &standby_site),
        Err(PgAuthorityError::ExecutorDormant)
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the in-interval retry must fail fast, took {:?}",
        started.elapsed()
    );
    // The dormant replica holds no backend: its one attempt connection is
    // gone (polled, because backend exit is observed asynchronously).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if authority_backend_pids(&runtime, &admin, &app_second).is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        authority_backend_pids(&runtime, &admin, &app_second).is_empty(),
        "a dormant replica must not hold a writer connection"
    );

    // The first keeps the role on its one connection.
    first.load_state(&writer_site, &standby_site).unwrap();
    assert_eq!(first_role.load(), ExecutorRole::Active);

    // Terminate the first's dedicated connection server-side: the lock
    // dies with the session, and the second acquires on a later retry.
    let first_pids = authority_backend_pids(&runtime, &admin, &app_first);
    assert_eq!(first_pids.len(), 1, "exactly one active-executor backend");
    runtime.block_on(async {
        admin
            .execute("SELECT pg_terminate_backend($1)", &[&first_pids[0]])
            .await
            .unwrap();
    });
    let mut took_over = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if second.load_state(&writer_site, &standby_site).is_ok() {
            took_over = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        took_over,
        "the dormant executor must take over after the owner's connection dies"
    );
    assert_eq!(second_role.load(), ExecutorRole::Active);

    // The takeover executor owns the journal; the demoted first cannot
    // steal the role back: its broken connection is replaced, but the
    // lock attempt on the fresh connection fails closed.
    assert!(
        first.load_state(&writer_site, &standby_site).is_err(),
        "an operation on the terminated connection must fail closed"
    );
    let Err(error) = first.load_state(&writer_site, &standby_site) else {
        panic!("the demoted executor must not re-assume the role");
    };
    assert!(
        matches!(error, PgAuthorityError::ExecutorDormant),
        "got {error:?}"
    );
    assert_eq!(first_role.load(), ExecutorRole::Dormant);
    second.save_controller_state("v1 takeover owner").unwrap();
    assert_eq!(
        second.load_controller_state().unwrap().as_deref(),
        Some("v1 takeover owner")
    );

    drop(first);
    drop(second);
    let cleanup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    });
    drop(admin);
    let _ = runtime.block_on(admin_driver);
}

/// The stale-state safety of a re-acquired singleton executor (issue #513):
/// a FORMER executor that re-acquires the advisory lock after a takeover
/// must never act on the in-memory state of its previous incarnation — it
/// reloads the authority snapshot and the durable journal row (the
/// database's current truth) and continues from there, or fails closed
/// without writing. Driving scenario: executor A fences the writer and
/// saves its promotion intent, then loses its dedicated connection; B takes
/// over, completes the promotion, records the operator's reconciliation
/// (journal `reconciled=true`) while the operator re-enables dispatch; after
/// B's connection dies, A re-acquires the lock with A's stale pending
/// promotion intent still queued — and must neither re-pause dispatch nor
/// overwrite the journal row, whatever rounds it runs.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn a_reacquired_executor_reloads_from_the_database_instead_of_replaying_stale_intent() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-stale-w-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-stale-s-{}", uuid::Uuid::new_v4().simple());
    let schema = format!("failover_executor_stale_{}", uuid::Uuid::new_v4().simple());
    let app_a = format!("zt-failover-stale-a-{}", uuid::Uuid::new_v4().simple());
    let app_b = format!("zt-failover-stale-b-{}", uuid::Uuid::new_v4().simple());
    let members = ["member-a", "member-b", "member-c"];

    let (admin, admin_driver) = {
        let (client, connection) = runtime
            .block_on(zrotext_postgres_connection::connect(&base_url))
            .expect("admin connection");
        let driver = runtime.spawn(connection);
        (client, driver)
    };
    let setup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {setup_schema}; SET search_path TO {setup_schema}"
            ))
            .await
            .unwrap();
        admin.batch_execute(MIGRATION_FOUNDATION).await.unwrap();
        admin
            .batch_execute(MIGRATION_FAILOVER_JOURNAL)
            .await
            .unwrap();
    });
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = |app_name: &str| {
        format!("{base_url}{separator}options=-csearch_path%3D{schema}&application_name={app_name}")
    };
    // The authority baseline: both site rows (the standby disabled so the
    // promotion must enable it), dispatch on so the failover must pause it.
    let insert_writer = writer_site.clone();
    let insert_standby = standby_site.clone();
    let baseline_epoch: i64 = runtime.block_on(async {
        admin
            .execute(
                "INSERT INTO sites(site_id) VALUES($1),($2)",
                &[&insert_writer, &insert_standby],
            )
            .await
            .unwrap();
        admin
            .execute(
                "UPDATE sites SET enabled=FALSE WHERE site_id=$1",
                &[&insert_standby],
            )
            .await
            .unwrap();
        admin
            .query_one(
                "UPDATE deployment_authority SET dispatch_enabled=TRUE RETURNING epoch",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    });
    let base_epoch = u64::try_from(baseline_epoch).unwrap();
    let promoted_epoch = base_epoch + 1;

    // Observers over the singleton rows, through the persistent admin
    // session only.
    let authority_row = || -> (i64, bool) {
        runtime.block_on(async {
            let row = admin
                .query_one(
                    "SELECT epoch, dispatch_enabled FROM deployment_authority \
                     WHERE singleton=TRUE",
                    &[],
                )
                .await
                .expect("read deployment_authority");
            (row.get::<_, i64>(0), row.get::<_, bool>(1))
        })
    };
    let journal_row = || -> Option<String> {
        runtime.block_on(async {
            admin
                .query_opt(
                    "SELECT state FROM failover_controller_state WHERE singleton=TRUE",
                    &[],
                )
                .await
                .expect("read failover_controller_state")
                .map(|row| row.get(0))
        })
    };
    let terminate = |app_name: &str| {
        let pids = authority_backend_pids(&runtime, &admin, app_name);
        assert_eq!(pids.len(), 1, "exactly one backend for {app_name}");
        runtime.block_on(async {
            admin
                .execute("SELECT pg_terminate_backend($1)", &[&pids[0]])
                .await
                .unwrap();
        });
        // The session-level advisory lock dies with the backend; wait for the
        // exit so the next lock attempt is deterministic.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if authority_backend_pids(&runtime, &admin, app_name).is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the terminated backend {app_name} must exit");
    };

    let config = FailoverConfig::new(
        members.iter().map(|member| (*member).to_owned()).collect(),
        writer_site.clone(),
        standby_site.clone(),
    )
    .unwrap();

    // Executor A acquires the lock and drives the failover to the fence; the
    // promotion intent is saved durably, then A's connection dies before the
    // promote can run (the takeover window: intent durable, not applied).
    let retry_interval = Duration::from_millis(150);
    let (mut authority_a, role_a) = PgWriterAuthority::new_for_executor_with_lock_key(
        url(&app_a),
        retry_interval,
        // Test-private key: A and B must fence each other, but no
        // parallel test on CI's shared database can fence either.
        i64::from_be_bytes(*b"ZROTEST2"),
    )
    .unwrap();
    // The eager initial connect can fail once under runner overhead; the guard
    // then parks Dormant behind the retry floor while the scripted ticks run
    // in microseconds of wall time. Drive the acquisition with cheap read-only
    // operations until it holds, so the first scripted tick starts Active.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while role_a.load() != ExecutorRole::Active {
        assert!(
            std::time::Instant::now() < deadline,
            "executor A never acquired the lock"
        );
        let _ = authority_a.load_state(&writer_site, &standby_site);
        std::thread::sleep(Duration::from_millis(60));
    }
    let mut executor_a = FailoverExecutor::new(
        config.clone(),
        queued_source(vec![
            healthy_round(members, base_epoch, 1_000),
            failure_round(members, 2_000),
            failure_round(members, 3_000),
            failure_round(members, 4_000),
            evidence_round(members, 5_000),
            evidence_round(members, 7_000),
            evidence_round(members, 8_000),
        ]),
        authority_a,
        confirming_external_fencing(),
    );
    executor_a.tick(1_000);
    assert_eq!(role_a.load(), ExecutorRole::Active);
    executor_a.tick(2_000);
    executor_a.tick(3_000);
    let report = executor_a.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: writer_site.clone()
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    terminate(&app_a);
    let report = executor_a.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: standby_site.clone(),
            new_epoch: promoted_epoch,
        })
    );
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "A's promotion intent is saved but the application did not run on the \
         dead connection; the stale intent stays queued: {:?}",
        report.application
    );

    // Executor B takes over and completes the promotion from the durable
    // intent; the operator reconciles through B and re-enables dispatch.
    let (mut authority_b, role_b) = PgWriterAuthority::new_for_executor_with_lock_key(
        url(&app_b),
        retry_interval,
        i64::from_be_bytes(*b"ZROTEST2"),
    )
    .unwrap();
    // Same acquisition drive for B: its eager connect ran while A still held
    // the lock, so it starts Dormant and needs the retry floor to elapse.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while role_b.load() != ExecutorRole::Active {
        assert!(
            std::time::Instant::now() < deadline,
            "executor B never acquired the lock after A's death"
        );
        let _ = authority_b.load_state(&writer_site, &standby_site);
        std::thread::sleep(Duration::from_millis(60));
    }
    let mut executor_b = FailoverExecutor::new(
        config.clone(),
        queued_source(vec![evidence_round(members, 6_000)]),
        authority_b,
        confirming_external_fencing(),
    );
    let report = executor_b.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: standby_site.clone(),
            new_epoch: promoted_epoch,
        })
    );
    assert_eq!(role_b.load(), ExecutorRole::Active);
    assert!(matches!(report.application, Application::Applied { .. }));
    executor_b.reconcile_complete().unwrap();
    runtime.block_on(async {
        admin
            .execute(
                "UPDATE deployment_authority SET dispatch_enabled=TRUE WHERE singleton=TRUE",
                &[],
            )
            .await
            .unwrap();
    });
    // The database's truth after the takeover: promoted, reconciled, and the
    // operator's dispatch re-enable stands.
    let (epoch, dispatch) = authority_row();
    assert_eq!(u64::try_from(epoch).unwrap(), promoted_epoch);
    assert!(dispatch);
    let journal_after_takeover = journal_row().expect("the journal row exists");
    assert!(
        journal_after_takeover.contains("phase=promoted")
            && journal_after_takeover.contains("reconciled=true"),
        "the takeover executor reconciled: {journal_after_takeover:?}"
    );

    // B dies; A re-acquires the lock with the stale in-memory state of its
    // previous incarnation (a mid-failover controller, the fencing journal
    // and the pending promotion intent). A must reload from the database
    // instead of replaying any of it.
    terminate(&app_b);
    let _ = executor_a.tick(7_000);
    let _ = executor_a.tick(8_000);
    // The scripted source is exhausted; empty rounds decide Hold, so extra
    // ticks safely drive the lock retry until A actually re-acquires.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while role_a.load() != ExecutorRole::Active {
        assert!(
            std::time::Instant::now() < deadline,
            "executor A never re-acquired the lock after B's death"
        );
        let _ = executor_a.tick(9_000);
        std::thread::sleep(Duration::from_millis(60));
    }

    let (epoch, dispatch) = authority_row();
    assert_eq!(
        u64::try_from(epoch).unwrap(),
        promoted_epoch,
        "the epoch never bumps again"
    );
    assert!(
        dispatch,
        "a re-acquired executor must not re-pause dispatch from stale intent"
    );
    let journal_after_reacquisition = journal_row().expect("the journal row exists");
    assert_eq!(
        journal_after_reacquisition, journal_after_takeover,
        "a re-acquired executor must not overwrite the durable journal with \
         stale intent"
    );
    // A continues from the current truth: running as the executor again,
    // restored into the promoted-and-reconciled phase B left behind.
    assert!(matches!(executor_a.status(), ExecutorStatus::Running));

    drop(executor_a);
    drop(executor_b);
    let cleanup_schema = schema.clone();
    runtime.block_on(async {
        admin
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    });
    drop(admin);
    let _ = runtime.block_on(admin_driver);
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
        confirming_external_fencing(),
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
        confirming_external_fencing(),
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

/// The PostgreSQL epoch anchor (issue #647): the served epoch reads back as
/// a confirmed anchor, and a promotion is witnessed only once the authority
/// row already serves it — the anchor follows the authority forward and
/// never writes the epoch itself.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn pg_epoch_anchor_witnesses_only_applied_promotions() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-anchor-w-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-anchor-s-{}", uuid::Uuid::new_v4().simple());
    let schema = format!("failover_epoch_anchor_{}", uuid::Uuid::new_v4().simple());
    let create_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("CREATE SCHEMA {create_schema}"))
            .await
            .unwrap();
    }));
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");

    let (writer, standby) = (writer_site.clone(), standby_site.clone());
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
                "INSERT INTO sites(site_id) VALUES($1),($2)",
                &[&writer, &standby],
            )
            .await
            .unwrap();
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
    let new_epoch = base_epoch + 3;

    let mut anchor = PgExternalEpochAnchor::new(url.clone()).unwrap();
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: base_epoch },
        "the served epoch is the confirmed anchor"
    );
    assert_eq!(
        anchor.record_promotion(new_epoch),
        AnchorRecord::Refused {
            anchored_epoch: base_epoch
        },
        "a promotion the authority never applied is not witnessed"
    );
    // The Pg adapter's record is a verification, not a write: the row
    // serving an epoch IS the anchor's confirmation of it, so recording the
    // currently served epoch is witnessed. The refused record above is what
    // keeps the anchor from ever claiming an epoch the authority lacks.
    assert_eq!(
        anchor.record_promotion(base_epoch),
        AnchorRecord::Recorded,
        "the row serving the epoch is the anchor's own confirmation"
    );
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: base_epoch },
        "nothing moved: the anchor reads exactly what the row serves"
    );

    // Apply a promotion through the writer-authority port (fence, then the
    // epoch compare-and-set); only now does the witness record succeed.
    let mut authority = PgWriterAuthority::new(url.clone()).unwrap();
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
    assert_eq!(anchor.record_promotion(new_epoch), AnchorRecord::Recorded);
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: new_epoch },
        "the anchor follows the authority forward"
    );

    drop(authority);
    drop(anchor);
    let cleanup_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    }));
}

/// The anchor folds every transport failure into `Unconfirmed`: a database
/// that cannot be reached is never a confirmed anchor, and it records
/// nothing. The refused port fails the connect immediately (nothing
/// listens), so this runs without a database.
#[test]
fn the_pg_epoch_anchor_is_unconfirmed_when_the_database_is_unreachable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to a free port");
    let port = listener.local_addr().expect("listener address").port();
    drop(listener);
    let mut anchor = PgExternalEpochAnchor::new(format!("postgres://127.0.0.1:{port}/postgres"))
        .expect("anchor port");
    assert_eq!(anchor.confirmed_epoch(), AnchorReading::Unconfirmed);
    assert_eq!(
        anchor.record_promotion(5),
        AnchorRecord::RefusedUnconfirmed,
        "an unreachable authority records nothing"
    );
}

/// The shipped external-fencing wiring fails closed: an enabled executor
/// with the production combination — the real PostgreSQL epoch anchor beside
/// the refusing `NoopFenceAuthority` — never promotes, even with full
/// fencing and readiness evidence from every member. Until a real external
/// fence backend exists, the promotion is refused at the external-fence
/// precondition and the epoch compare-and-set never runs.
#[test]
#[ignore = "requires ZT_FAILOVER_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
fn an_enabled_executor_with_the_refusing_fence_backend_never_promotes() {
    let base_url = std::env::var("ZT_FAILOVER_TEST_DATABASE_URL")
        .expect("set ZT_FAILOVER_TEST_DATABASE_URL for PostgreSQL-backed failover tests");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    let writer_site = format!("failover-pg-noop-w-{}", uuid::Uuid::new_v4().simple());
    let standby_site = format!("failover-pg-noop-s-{}", uuid::Uuid::new_v4().simple());
    let members = ["member-a", "member-b", "member-c"];
    let schema = format!("failover_executor_noop_{}", uuid::Uuid::new_v4().simple());
    let create_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("CREATE SCHEMA {create_schema}"))
            .await
            .unwrap();
    }));
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");

    let (writer, standby) = (writer_site.clone(), standby_site.clone());
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
                "INSERT INTO sites(site_id) VALUES($1),($2)",
                &[&writer, &standby],
            )
            .await
            .unwrap();
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

    let config = FailoverConfig::new(
        members.iter().map(|member| (*member).to_owned()).collect(),
        writer_site.clone(),
        standby_site.clone(),
    )
    .unwrap();
    let mut anchor = PgExternalEpochAnchor::new(url.clone()).unwrap();
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: base_epoch },
        "the anchor half of the shipped wiring works"
    );
    let mut executor = FailoverExecutor::new(
        config,
        queued_source(vec![
            healthy_round(members, base_epoch, 1_000),
            failure_round(members, 2_000),
            failure_round(members, 3_000),
            failure_round(members, 4_000),
            evidence_round(members, 5_000),
            evidence_round(members, 6_000),
            evidence_round(members, 7_000),
        ]),
        PgWriterAuthority::new(url.clone()).unwrap(),
        // The production shape: a real anchor beside the refusing fence.
        ExternalFencing::new(NoopFenceAuthority, anchor),
    );
    let _ = executor.tick(1_000);
    let _ = executor.tick(2_000);
    let _ = executor.tick(3_000);
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: writer_site.clone()
        })
    );
    assert!(
        matches!(report.application, Application::Applied { .. }),
        "the site-row fence is independent of the external fence"
    );
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: standby_site.clone(),
            new_epoch: base_epoch + 1
        })
    );
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "the refusing fence backend holds the promotion: {:?}",
        report.application
    );
    // Later rounds hold the promoted phase (dispatch paused) while the
    // promotion stays pending on the external-fence refusal.
    for now_ms in [6_000_u64, 7_000] {
        let report = executor.tick(now_ms);
        assert_eq!(
            report.decision,
            Some(Decision::KeepDispatchPaused),
            "the decision loop itself is unaffected at {now_ms}ms"
        );
        assert!(
            matches!(report.application, Application::Pending { .. }),
            "the refusing fence backend holds the promotion at {now_ms}ms: {:?}",
            report.application
        );
    }
    let (_, _, mut authority) = executor.into_parts();
    let snapshot = authority.load_state(&writer_site, &standby_site).unwrap();
    assert_eq!(
        snapshot.epoch, base_epoch,
        "the epoch compare-and-set never ran"
    );
    assert!(
        snapshot.writer_site.unwrap().draining,
        "the site-row fence stays applied"
    );

    drop(authority);
    let cleanup_schema = schema.clone();
    runtime.block_on(admin(&base_url, |client| async move {
        client
            .batch_execute(&format!("DROP SCHEMA {cleanup_schema} CASCADE"))
            .await
            .unwrap();
    }));
}
