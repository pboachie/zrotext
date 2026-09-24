// SPDX-License-Identifier: AGPL-3.0-only
//! Fail-fast admission before request extraction, authentication, or PostgreSQL.
//! This bounds application work per process; the edge still must bound sockets
//! and headers, and upgraded WebSockets have separate lifetime limits.
use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

pub fn protect(router: Router) -> Router {
    protect_with(router, 64, Duration::from_secs(30))
}

fn protect_with(router: Router, capacity: usize, deadline: Duration) -> Router {
    router.layer(middleware::from_fn_with_state(
        (Arc::new(Semaphore::new(capacity)), deadline),
        admit,
    ))
}

async fn admit(
    State((slots, deadline)): State<(Arc<Semaphore>, Duration)>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = slots.try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, "1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    };
    match tokio::time::timeout(deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::post};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    #[tokio::test]
    async fn saturated_router_rejects_before_handler_and_releases_after_cancellation() {
        let entered = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let app = protect_with(
            Router::new().route(
                "/work",
                post({
                    let entered = entered.clone();
                    let calls = calls.clone();
                    move || {
                        let entered = entered.clone();
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            entered.notify_one();
                            std::future::pending::<StatusCode>().await
                        }
                    }
                }),
            ),
            1,
            Duration::from_secs(30),
        );
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/work")
                .body(Body::empty())
                .unwrap()
        };
        let first = tokio::spawn(app.clone().oneshot(request()));
        entered.notified().await;
        let rejected = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        first.abort();
        let _ = first.await;
        let third = tokio::spawn(app.oneshot(request()));
        entered.notified().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        third.abort();
        let _ = third.await;
    }

    #[tokio::test]
    async fn slow_body_times_out_and_does_not_leak_admission() {
        let app = protect_with(
            Router::new().route("/work", post(|_: String| async { StatusCode::NO_CONTENT })),
            1,
            Duration::from_millis(20),
        );
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<Vec<u8>, std::io::Error>,
        >());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/work")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/work")
                    .body(Body::from("ok"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
