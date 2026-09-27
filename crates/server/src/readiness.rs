// SPDX-License-Identifier: AGPL-3.0-only
//! Single-flight, short-lived cache for the database half of `/readyz`.
//!
//! `/readyz` is unauthenticated. Without a cache every probe, from each load
//! balancer or from anyone who can reach the port, takes one of the request
//! connections that real API traffic needs. Under a saturated pool that makes
//! readiness itself fail and flap. The cache allows at most one database probe
//! at a time and reuses its result for [`READINESS_TTL`]. Cheap in-memory
//! checks (draining, billing authorization flags) stay outside the cache so
//! they take effect on the very next probe.
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::Mutex,
    time::{Instant, timeout},
};

/// How long a computed database readiness result is reused.
pub const READINESS_TTL: Duration = Duration::from_secs(1);
/// Upper bound on one database probe, so a hung connection cannot keep every
/// queued probe waiting for the full statement timeout. A probe that exceeds
/// it counts as not ready.
pub const READINESS_PROBE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct ReadinessCache {
    last: Arc<Mutex<Option<(Instant, bool)>>>,
}

impl ReadinessCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached result if it is younger than [`READINESS_TTL`];
    /// otherwise runs `probe` once while concurrent callers wait for it.
    ///
    /// The probe runs in its own task that holds the cache lock, so a caller
    /// that disconnects mid-probe neither cancels the probe nor lets a second
    /// one start alongside it.
    pub async fn get_or_refresh<F, Fut>(&self, probe: F) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let mut last = self.last.clone().lock_owned().await;
        if let Some((at, ready)) = *last
            && at.elapsed() < READINESS_TTL
        {
            return ready;
        }
        let probe = probe();
        tokio::spawn(async move {
            let ready = timeout(READINESS_PROBE_DEADLINE, probe)
                .await
                .unwrap_or(false);
            *last = Some((Instant::now(), ready));
            ready
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting_probe(
        calls: &Arc<AtomicUsize>,
        ready: bool,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = bool> + Send>> + use<> {
        let calls = calls.clone();
        move || {
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                // Stand-in for a database round trip, so callers overlap.
                tokio::time::sleep(Duration::from_millis(50)).await;
                ready
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_burst_runs_one_probe_per_ttl() {
        let cache = Arc::new(ReadinessCache::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let burst = (0..64)
            .map(|_| {
                let cache = cache.clone();
                let probe = counting_probe(&calls, true);
                tokio::spawn(async move { cache.get_or_refresh(probe).await })
            })
            .collect::<Vec<_>>();
        for task in burst {
            assert!(task.await.unwrap());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Still fresh: no new probe, and a probe that would fail is not run.
        assert!(cache.get_or_refresh(counting_probe(&calls, false)).await);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(READINESS_TTL).await;
        assert!(!cache.get_or_refresh(counting_probe(&calls, false)).await);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Failures are cached too, so a saturated pool is not hammered.
        assert!(!cache.get_or_refresh(counting_probe(&calls, true)).await);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_probe_times_out_as_not_ready() {
        let cache = ReadinessCache::new();
        let started = Instant::now();
        let ready = cache.get_or_refresh(std::future::pending::<bool>).await;
        assert!(!ready);
        assert_eq!(started.elapsed(), READINESS_PROBE_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_caller_does_not_cancel_or_duplicate_probe() {
        let cache = Arc::new(ReadinessCache::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let first = {
            let cache = cache.clone();
            let probe = counting_probe(&calls, true);
            tokio::spawn(async move { cache.get_or_refresh(probe).await })
        };
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "probe did not start");
        first.abort();
        assert!(cache.get_or_refresh(counting_probe(&calls, false)).await);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
