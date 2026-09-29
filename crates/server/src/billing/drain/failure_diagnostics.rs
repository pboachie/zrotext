// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only failure classes; never format error messages, sources or panic payloads.

use super::BillingError;
use crate::{
    billing::worker::{JobOutcome, ProviderFailure},
    runtime_db::ConnectError,
};
use std::cell::RefCell;
use tokio::task::JoinError;

type JobResult = Result<Result<JobOutcome, BillingError>, JoinError>;

const PREFIX: &str = "billing drain test failure: ";

thread_local! {
    /// Lines emitted on this thread, so tests can observe the exact output
    /// without re-running the test binary in a child process.
    static EMITTED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Writes the fixed failure class for a failed job to the test output.
pub(super) fn emit(result: &JobResult) {
    if let Some(diagnostic) = classify(result) {
        let line = format!("{PREFIX}{diagnostic}");
        eprintln!("{line}");
        EMITTED.with(|emitted| emitted.borrow_mut().push(line));
    }
}

fn take_emitted() -> Vec<String> {
    EMITTED.with(|emitted| std::mem::take(&mut *emitted.borrow_mut()))
}

pub(super) fn classify(result: &JobResult) -> Option<String> {
    let error = match result {
        Ok(Ok(_)) => return None,
        Ok(Err(error)) => error,
        Err(error) => {
            return Some(
                if error.is_cancelled() {
                    "task_cancelled"
                } else if error.is_panic() {
                    "task_panicked"
                } else {
                    "task_failed"
                }
                .to_owned(),
            );
        }
    };
    Some(match error {
        BillingError::RuntimeDatabase(error) => match error {
            ConnectError::Capacity => "runtime_capacity".to_owned(),
            ConnectError::Timeout => "runtime_timeout".to_owned(),
            ConnectError::Database(error) => database("runtime_database", error),
            ConnectError::Transport(error) => match error {
                zrotext_postgres_connection::ConnectError::Configuration(_) => {
                    "runtime_transport_configuration".to_owned()
                }
                zrotext_postgres_connection::ConnectError::Database(error) => {
                    database("runtime_transport_database", error)
                }
            },
        },
        BillingError::InvalidSignature => "invalid_signature".to_owned(),
        BillingError::InvalidEvent => "invalid_event".to_owned(),
        BillingError::EventConflict => "event_conflict".to_owned(),
        BillingError::TenantConflict => "tenant_conflict".to_owned(),
        BillingError::Database(error) => database("database", error),
        BillingError::Provider(error) => match error {
            ProviderFailure::HttpStatus(_) => "provider_http_status",
            ProviderFailure::RateLimited { .. } => "provider_rate_limited",
            ProviderFailure::Transport => "provider_transport",
            ProviderFailure::InvalidResponse => "provider_invalid_response",
        }
        .to_owned(),
    })
}

fn database(class: &'static str, error: &tokio_postgres::Error) -> String {
    format!(
        "{class} sqlstate={}",
        sqlstate(error.code().map(|code| code.code()))
    )
}

fn sqlstate(code: Option<&str>) -> &str {
    code.filter(|value| {
        value.len() == 5
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
    .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "synthetic-diagnostic-sentinel";

    fn diagnostic(error: BillingError) -> String {
        classify(&Ok(Err(error))).expect("failed job has a class")
    }

    #[test]
    fn fixed_classes_exclude_error_payloads_and_successes() {
        let cases = [
            (BillingError::InvalidSignature, "invalid_signature"),
            (BillingError::InvalidEvent, "invalid_event"),
            (BillingError::EventConflict, "event_conflict"),
            (BillingError::TenantConflict, "tenant_conflict"),
            (
                BillingError::RuntimeDatabase(ConnectError::Capacity),
                "runtime_capacity",
            ),
            (
                BillingError::RuntimeDatabase(ConnectError::Timeout),
                "runtime_timeout",
            ),
            (
                BillingError::RuntimeDatabase(ConnectError::Transport(
                    zrotext_postgres_connection::ConnectError::Configuration(SENTINEL.to_owned()),
                )),
                "runtime_transport_configuration",
            ),
            (
                BillingError::Provider(ProviderFailure::HttpStatus(503)),
                "provider_http_status",
            ),
            (
                BillingError::Provider(ProviderFailure::Transport),
                "provider_transport",
            ),
            (
                BillingError::Provider(ProviderFailure::InvalidResponse),
                "provider_invalid_response",
            ),
        ];
        for (error, expected) in cases {
            let actual = diagnostic(error);
            assert_eq!(actual, expected);
            assert!(!actual.contains(SENTINEL));
        }
        assert_eq!(classify(&Ok(Ok(JobOutcome::WorkDone))), None);
        assert_eq!(classify(&Ok(Ok(JobOutcome::Empty))), None);
    }

    #[test]
    fn only_exact_uppercase_alphanumeric_sqlstate_is_visible() {
        for code in ["23514", "P0001", "08006"] {
            assert_eq!(sqlstate(Some(code)), code);
        }
        for code in [
            "",
            "2351",
            "235140",
            "p0001",
            "23 14",
            "23\n14",
            "23_14",
            SENTINEL,
            "\u{00e9}001",
        ] {
            assert_eq!(sqlstate(Some(code)), "unknown");
        }
        assert_eq!(sqlstate(None), "unknown");
    }

    #[test]
    fn database_errors_without_sqlstate_do_not_expose_text() {
        for class in ["database", "runtime_database", "runtime_transport_database"] {
            let error = format!("unknown_{SENTINEL}=value")
                .parse::<tokio_postgres::Config>()
                .unwrap_err();
            let error = match class {
                "database" => BillingError::Database(error),
                "runtime_database" => BillingError::RuntimeDatabase(ConnectError::Database(error)),
                _ => BillingError::RuntimeDatabase(ConnectError::Transport(
                    zrotext_postgres_connection::ConnectError::Database(error),
                )),
            };
            let actual = diagnostic(error);
            assert_eq!(actual, format!("{class} sqlstate=unknown"));
            assert!(!actual.contains(SENTINEL));
        }
    }

    #[tokio::test]
    async fn task_failures_exclude_panic_payloads() {
        let panic = tokio::spawn(async { std::panic::panic_any(vec![SENTINEL]) })
            .await
            .unwrap_err();
        let actual = classify(&Err(panic));
        assert_eq!(actual.as_deref(), Some("task_panicked"));
        assert!(!actual.unwrap().contains(SENTINEL));
        let task = tokio::spawn(std::future::pending::<()>());
        task.abort();
        let cancelled = task.await.unwrap_err();
        assert_eq!(classify(&Err(cancelled)).as_deref(), Some("task_cancelled"));
    }

    // The drain loop runs on the test thread with the current-thread runtime,
    // so the thread-local record holds exactly what this batch wrote.
    #[tokio::test(flavor = "current_thread")]
    async fn failed_batch_emits_safe_diagnostic() {
        use super::super::{BillingJobs, drain_jobs};
        use std::sync::{Arc, atomic::AtomicBool};
        use tokio::sync::Semaphore;

        struct CapacityJobs;
        impl BillingJobs for CapacityJobs {
            async fn reconcile(
                &self,
                _url: String,
                _risk: bool,
            ) -> Result<JobOutcome, BillingError> {
                Err(BillingError::RuntimeDatabase(ConnectError::Capacity))
            }
        }
        take_emitted();
        assert!(
            drain_jobs(
                &Arc::new(CapacityJobs),
                SENTINEL,
                1,
                1,
                false,
                &Arc::new(AtomicBool::new(false)),
                &Arc::new(Semaphore::new(1)),
            )
            .await
        );
        let emitted = take_emitted();
        assert_eq!(
            emitted,
            ["billing drain test failure: runtime_capacity"],
            "failed drain must emit the fixed typed diagnostic"
        );
        assert!(
            emitted.iter().all(|line| !line.contains(SENTINEL)),
            "diagnostic must omit synthetic input"
        );
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_sqlstate_excludes_message_and_detail() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("set disposable database URL");
        let (db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        for class in ["database", "runtime_database", "runtime_transport_database"] {
            let error = db.batch_execute("DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='synthetic-diagnostic-sentinel', DETAIL='synthetic-diagnostic-sentinel'; END $$")
                .await.expect_err("synthetic query must raise a check violation");
            assert_eq!(error.as_db_error().unwrap().message(), SENTINEL);
            let error = match class {
                "database" => BillingError::Database(error),
                "runtime_database" => BillingError::RuntimeDatabase(ConnectError::Database(error)),
                _ => BillingError::RuntimeDatabase(ConnectError::Transport(
                    zrotext_postgres_connection::ConnectError::Database(error),
                )),
            };
            let actual = diagnostic(error);
            assert_eq!(actual, format!("{class} sqlstate=23514"));
            assert!(!actual.contains(SENTINEL));
        }
        drop(db);
        driver.await.unwrap();
    }
}
