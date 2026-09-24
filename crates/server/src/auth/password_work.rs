// SPDX-License-Identifier: AGPL-3.0-only
//! Bound CPU/memory work independently of HTTP request lifetime and offload it
//! from Tokio workers. Waiting futures never submit work to the blocking queue. HTTP admission
//! limits bound requests before they reach this shared worker gate.
use super::{AuthError, dummy_password_hash, password_engine};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

fn capacity() -> Arc<Semaphore> {
    static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
    // Two concurrent 64 MiB hashes, shared by all authentication entry points.
    CAPACITY.get_or_init(|| Arc::new(Semaphore::new(2))).clone()
}

async fn run<T: Send + 'static>(
    capacity: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, AuthError> + Send + 'static,
) -> Result<T, AuthError> {
    let permit = capacity
        .acquire_owned()
        .await
        .map_err(|_| AuthError::RateLimited)?;
    tokio::task::spawn_blocking(move || {
        // An aborted HTTP future must not release capacity while hashing continues.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| AuthError::Password)?
}

pub(super) async fn hash(password: &str) -> Result<String, AuthError> {
    let password = Zeroizing::new(password.to_owned());
    run(capacity(), move || {
        password_engine()?
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(|_| AuthError::Password)
    })
    .await
}

pub(super) async fn verify(password: &str, stored: Option<String>) -> Result<(), AuthError> {
    // Bound allocation and prehash work even for non-HTTP callers.
    if password.len() > 1024 {
        return Err(AuthError::InvalidCredentials);
    }
    let password = Zeroizing::new(password.to_owned());
    #[cfg(test)]
    let counter = super::tests::PASSWORD_VERIFICATIONS.with(Arc::clone);
    run(capacity(), move || {
        // Lazy dummy initialization also runs under the same worker permit.
        let parsed = PasswordHash::new(stored.as_deref().unwrap_or_else(|| dummy_password_hash()))
            .map_err(|_| AuthError::InvalidCredentials)?;
        #[cfg(test)]
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthError::InvalidCredentials)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_retains_capacity_until_blocking_work_finishes() {
        let capacity = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_capacity = capacity.clone();
        let task = tokio::spawn(run(worker_capacity, move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        }));
        // This single-thread runtime can make progress while the worker is blocked.
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(capacity.available_permits(), 0);
        let (queued_tx, mut queued_rx) = tokio::sync::oneshot::channel();
        let next_capacity = capacity.clone();
        let next = run(next_capacity, move || {
            queued_tx.send(()).unwrap();
            Ok(())
        });
        tokio::pin!(next);
        // Explicitly poll the next operation: its closure must not be submitted
        // while the canceled operation still owns the worker permit.
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(next.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(matches!(
            queued_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        next.await.unwrap();
        queued_rx.await.unwrap();
        // Waiting for the permit synchronizes with actual worker completion.
        let permit = capacity.acquire().await.unwrap();
        drop(permit);
        assert!(run(capacity, || Ok(())).await.is_ok());
    }

    #[tokio::test]
    async fn errors_and_panics_release_capacity_and_fail_closed() {
        let capacity = Arc::new(Semaphore::new(1));
        assert!(matches!(
            run::<()>(capacity.clone(), || Err(AuthError::InvalidCredentials)).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            run::<()>(capacity.clone(), || panic!("synthetic worker failure")).await,
            Err(AuthError::Password)
        ));
        assert!(run(capacity.clone(), || Ok(())).await.is_ok());
        capacity.close();
        assert!(matches!(
            run(capacity, || Ok(())).await,
            Err(AuthError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn malformed_and_oversized_credentials_fail_closed() {
        let password = uuid::Uuid::new_v4().to_string();
        assert!(matches!(
            verify(&password, Some("invalid verifier".to_owned())).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            verify(&password.repeat(1025 / password.len() + 1), None).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
}
