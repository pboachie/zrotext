// SPDX-License-Identifier: AGPL-3.0-only
//! Exact-URL cleanup for disposable databases, absent from production builds.
use super::*;
use std::collections::HashMap;

#[derive(Default)]
struct Counts {
    resets: usize,
    drivers: usize,
}
static ACTIVE: LazyLock<Mutex<HashMap<Arc<str>, Counts>>> = LazyLock::new(Default::default);
static CHANGED: Notify = Notify::const_new();

pub(super) struct Activity {
    url: Arc<str>,
    reset: bool,
}
impl Activity {
    fn new(url: Arc<str>, reset: bool) -> Self {
        let mut active = ACTIVE.lock().unwrap();
        let counts = active.entry(url.clone()).or_default();
        if reset {
            counts.resets += 1;
        } else {
            counts.drivers += 1;
        }
        Self { url, reset }
    }
    pub(super) fn reset(url: Arc<str>) -> Self {
        Self::new(url, true)
    }
    pub(super) fn driver(url: Arc<str>) -> Self {
        Self::new(url, false)
    }
}
impl Drop for Activity {
    fn drop(&mut self) {
        let mut active = ACTIVE.lock().unwrap();
        let counts = active.get_mut(&self.url).unwrap();
        if self.reset {
            counts.resets -= 1;
        } else {
            counts.drivers -= 1;
        }
        if counts.resets == 0 && counts.drivers == 0 {
            active.remove(&self.url);
        }
        drop(active);
        CHANGED.notify_waiters();
    }
}

async fn wait_for(url: &str, idle: impl Fn(&Counts) -> bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            let changed = CHANGED.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if ACTIVE.lock().unwrap().get(url).is_none_or(&idle) {
                return;
            }
            changed.await;
        }
    })
    .await
    .expect("all owned fixture clients must be dropped before database cleanup");
}

/// The caller has stopped its fixture operations and dropped its checked-out
/// clients. Wait for only this URL's resets, discard only its idle clients,
/// then await their drivers. Never terminate a backend or force-drop a DB.
pub(crate) async fn close_fixture_connections(url: &str) {
    wait_for(url, |counts| counts.resets == 0).await;
    discard_fixture_idle(url);
    wait_for(url, |counts| counts.drivers == 0).await;
    HOSTED_BINDINGS.lock().unwrap().remove(url);
}

#[tokio::test]
async fn reset_completion_is_isolated_by_exact_fixture_url() {
    let first: Arc<str> = format!("fixture-first-{}", uuid::Uuid::new_v4()).into();
    let second: Arc<str> = format!("fixture-second-{}", uuid::Uuid::new_v4()).into();
    let first_reset = Activity::reset(first.clone());
    let second_reset = Activity::reset(second.clone());
    assert!(
        timeout(
            Duration::from_millis(1),
            wait_for(&first, |counts| counts.resets == 0)
        )
        .await
        .is_err()
    );
    drop(first_reset);
    wait_for(&first, |counts| counts.resets == 0).await;
    assert_eq!(ACTIVE.lock().unwrap().get(&second).unwrap().resets, 1);
    drop(second_reset);
    assert!(!ACTIVE.lock().unwrap().contains_key(&first));
    assert!(!ACTIVE.lock().unwrap().contains_key(&second));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn closing_one_fixture_preserves_other_idle_backend_and_normal_database_cleanup() {
    let first = crate::test_database::Fixture::new("ZT_AUTH_TEST_DATABASE_URL").await;
    let second = crate::test_database::Fixture::new("ZT_AUTH_TEST_DATABASE_URL").await;
    let first_client = connect(&first.runtime_url).await.unwrap();
    let second_client = connect(&second.runtime_url).await.unwrap();
    let second_pid: i32 = second_client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    drop(first_client);
    drop(second_client);
    wait_for(&second.runtime_url, |counts| counts.resets == 0).await;
    first.finish().await;
    let second_client = connect(&second.runtime_url).await.unwrap();
    assert_eq!(
        second_client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        second_pid,
        "cleaning one URL must not close another fixture's reusable backend"
    );
    drop(second_client);
    second.finish().await;
}
