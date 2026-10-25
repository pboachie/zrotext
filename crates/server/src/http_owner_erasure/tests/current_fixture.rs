// SPDX-License-Identifier: AGPL-3.0-only
//! Current HTTP cases use the unchanged numbered schema and stock runtime ACL.
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::{
    cell::RefCell,
    ops::AsyncFnOnce,
    panic::{AssertUnwindSafe, resume_unwind},
};
use tokio_postgres::Client;

#[derive(Default)]
struct Owned {
    urls: Vec<String>,
    completed: Vec<tokio::sync::oneshot::Receiver<()>>,
}
tokio::task_local! { static OWNED: RefCell<Owned>; }
struct Completion<F: std::future::Future> {
    future: Option<std::pin::Pin<Box<F>>>,
    finished: Option<tokio::sync::oneshot::Sender<()>>,
}
impl<F: std::future::Future> std::future::Future for Completion<F> {
    type Output = F::Output;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.future.as_mut().unwrap().as_mut().poll(cx)
    }
}
impl<F: std::future::Future> Drop for Completion<F> {
    fn drop(&mut self) {
        // Explicit ordering also covers cancellation before the first poll:
        // captured clients/transactions leave before cleanup can proceed.
        drop(self.future.take());
        let _ = self.finished.take().unwrap().send(());
    }
}

/// A failed barrier assertion must not detach a still-running erasure request.
/// Successful requests retain the same JoinHandle result and are awaited.
pub(super) struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T> std::future::Future for OwnedTask<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) fn spawn<F>(future: F) -> OwnedTask<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (finished, completed) = tokio::sync::oneshot::channel();
    let _ = OWNED.try_with(|owned| owned.borrow_mut().completed.push(completed));
    OwnedTask(tokio::spawn(Completion {
        future: Some(Box::pin(future)),
        finished: Some(finished),
    }))
}

pub(super) fn handler_url(base: &str, name: &str) -> String {
    assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    let value = if base.starts_with("postgres://") || base.starts_with("postgresql://") {
        let mut url = url::Url::parse(base).unwrap();
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(key, _)| key != "application_name")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("application_name", name);
        url.into()
    } else {
        format!("{base} application_name='{name}'")
    };
    let _ = OWNED.try_with(|owned| {
        let mut owned = owned.borrow_mut();
        if !owned.urls.contains(&value) {
            owned.urls.push(value.clone());
        }
    });
    value
}

pub(super) async fn current_case<F>(test: F)
where
    F: for<'a> AsyncFnOnce(&'a mut Client, &'a Client, &'a str),
{
    with_fixture(Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await, test).await;
}

pub(super) async fn with_fixture<F>(mut fixture: Fixture, test: F)
where
    F: for<'a> AsyncFnOnce(&'a mut Client, &'a Client, &'a str),
{
    // Observer identity is never passed to the router. Its sole purpose is
    // barrier observation and owner-only disposable corruption/statistics;
    // no monitoring or DDL capability is granted to the runtime role.
    let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let mut observer_config = zrotext_postgres_connection::parse_config(&base).unwrap();
    observer_config
        .connect_timeout(std::time::Duration::from_secs(5))
        .dbname(fixture.config.get_dbname().unwrap())
        .options("-csearch_path=pg_catalog,public");
    let (observer, driver) = zrotext_postgres_connection::connect_config(observer_config)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let (result, owned) = OWNED
        .scope(RefCell::new(Owned::default()), async {
            let result =
                AssertUnwindSafe(test(&mut fixture.runtime, &observer, &fixture.runtime_url))
                    .catch_unwind()
                    .await;
            (
                result,
                OWNED.with(|owned| std::mem::take(&mut *owned.borrow_mut())),
            )
        })
        .await;
    for completed in owned.completed {
        tokio::time::timeout(std::time::Duration::from_secs(5), completed)
            .await
            .unwrap()
            .unwrap();
    }
    for url in owned.urls {
        crate::runtime_db::close_fixture_connections(&url).await;
    }
    Fixture::close_connection(observer, driver).await;
    fixture.finish().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

#[test]
fn tagged_runtime_url_preserves_transport_policy_and_replaces_only_application_name() {
    let url = handler_url(
        "postgresql://fixture:placeholder@localhost/fixture?sslmode=require&connect_timeout=7&options=-csearch_path%3Dpg_catalog%2Cpublic&application_name=old",
        "erasure_probe",
    );
    let config = zrotext_postgres_connection::parse_config(&url).unwrap();
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Require
    );
    assert_eq!(
        config.get_connect_timeout(),
        Some(&std::time::Duration::from_secs(7))
    );
    assert_eq!(
        config.get_options(),
        Some("-csearch_path=pg_catalog,public")
    );
    assert_eq!(config.get_application_name(), Some("erasure_probe"));
    assert_eq!(config.get_dbname(), Some("fixture"));
    assert_eq!(
        url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .filter(|(key, _)| key == "application_name")
            .count(),
        1
    );
}

#[test]
fn tagged_keyword_connection_preserves_transport_and_identity() {
    let url = handler_url(
        "host=localhost user=fixture dbname=fixture sslmode=require connect_timeout=7 application_name=old",
        "erasure_probe",
    );
    let config = zrotext_postgres_connection::parse_config(&url).unwrap();
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Require
    );
    assert_eq!(
        config.get_connect_timeout(),
        Some(&std::time::Duration::from_secs(7))
    );
    assert_eq!(config.get_application_name(), Some("erasure_probe"));
    assert_eq!(config.get_user(), Some("fixture"));
    assert_eq!(config.get_dbname(), Some("fixture"));
}

#[tokio::test]
async fn owned_completion_follows_resource_drop_even_before_the_first_poll() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Resource(Arc<AtomicBool>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    for first_poll in [false, true] {
        OWNED
            .scope(RefCell::new(Owned::default()), async {
                let dropped = Arc::new(AtomicBool::new(false));
                let resource = Resource(dropped.clone());
                let (started, ready) = tokio::sync::oneshot::channel();
                let request = spawn(async move {
                    let _resource = resource;
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                if first_poll {
                    ready.await.unwrap();
                }
                // The current-thread test has not yielded at all in the false
                // case, so that cancellation is before the task's first poll.
                drop(request);
                let completed = OWNED.with(|owned| owned.borrow_mut().completed.pop().unwrap());
                tokio::time::timeout(std::time::Duration::from_secs(5), completed)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(dropped.load(Ordering::SeqCst));
            })
            .await;
    }
}
