// SPDX-License-Identifier: AGPL-3.0-only
//! Fail-fast admission before request extraction, authentication, or PostgreSQL.
//! Requests are split into route classes, each with its own permit pool, so a
//! flood of one class (for example slow anonymous logins) cannot take permits
//! from provider ingress, device reconnects, or owner/API routes. A request body
//! must finish arriving within a short deadline measured from admission, so a
//! client that trickles its body releases its permit long before the handler
//! deadline. This bounds application work per process; the edge still must
//! bound sockets, headers, and per-address connections, and upgraded WebSockets
//! have separate lifetime limits.
use axum::{
    Router,
    body::{Body, Bytes, HttpBody},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::Semaphore, time::Sleep};

/// Concurrent handlers per process for each route class.
const OWNER_AND_API_PERMITS: usize = 64;
const ANONYMOUS_PERMITS: usize = 32;
const DEVICE_UPGRADE_PERMITS: usize = 16;
const PROVIDER_PERMITS: usize = 16;
/// Time from admission until the request body must be fully received.
const BODY_DEADLINE: Duration = Duration::from_secs(10);
/// Time from admission until the handler must produce a response.
const HANDLER_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteClass {
    /// Signed third-party callbacks (Stripe events).
    Provider,
    /// Device WebSocket upgrades.
    Device,
    /// Routes reachable without a session, API key, or device key.
    Anonymous,
    /// Owner (cookie) and API-key routes, static pages, health, and unknown paths.
    Default,
}

/// Decides the route class from the path alone, before any extraction.
fn classify(path: &str) -> RouteClass {
    if path == "/v1/billing/stripe-events" {
        return RouteClass::Provider;
    }
    if path == "/v1/device-stream" {
        return RouteClass::Device;
    }
    if let Some(rest) = path.strip_prefix("/v1/auth/") {
        return match rest {
            "login"
            | "login/mfa"
            | "register"
            | "resend-verification"
            | "verify-email"
            | "password/reset/request"
            | "password/reset/confirm" => RouteClass::Anonymous,
            _ => RouteClass::Default,
        };
    }
    if let Some(rest) = path.strip_prefix("/v1/enrollment/") {
        let segments: Vec<&str> = rest.split('/').collect();
        return match segments.as_slice() {
            ["pairings", id, "claim" | "prove"] if !id.is_empty() => RouteClass::Anonymous,
            ["devices", "authenticate"] => RouteClass::Anonymous,
            ["devices", id, "challenge"] if !id.is_empty() => RouteClass::Anonymous,
            _ => RouteClass::Default,
        };
    }
    RouteClass::Default
}

#[derive(Clone, Copy, Debug)]
struct Limits {
    provider: usize,
    device: usize,
    anonymous: usize,
    default: usize,
    body_deadline: Duration,
    handler_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            provider: PROVIDER_PERMITS,
            device: DEVICE_UPGRADE_PERMITS,
            anonymous: ANONYMOUS_PERMITS,
            default: OWNER_AND_API_PERMITS,
            body_deadline: BODY_DEADLINE,
            handler_deadline: HANDLER_DEADLINE,
        }
    }
}

struct Admission {
    provider: Arc<Semaphore>,
    device: Arc<Semaphore>,
    anonymous: Arc<Semaphore>,
    default: Arc<Semaphore>,
    body_deadline: Duration,
    handler_deadline: Duration,
}

impl Admission {
    fn new(limits: Limits) -> Self {
        Self {
            provider: Arc::new(Semaphore::new(limits.provider)),
            device: Arc::new(Semaphore::new(limits.device)),
            anonymous: Arc::new(Semaphore::new(limits.anonymous)),
            default: Arc::new(Semaphore::new(limits.default)),
            body_deadline: limits.body_deadline,
            handler_deadline: limits.handler_deadline,
        }
    }

    fn slots(&self, class: RouteClass) -> &Arc<Semaphore> {
        match class {
            RouteClass::Provider => &self.provider,
            RouteClass::Device => &self.device,
            RouteClass::Anonymous => &self.anonymous,
            RouteClass::Default => &self.default,
        }
    }
}

pub fn protect(router: Router) -> Router {
    protect_with(router, Limits::default())
}

fn protect_with(router: Router, limits: Limits) -> Router {
    router.layer(middleware::from_fn_with_state(
        Arc::new(Admission::new(limits)),
        admit,
    ))
}

async fn admit(State(admission): State<Arc<Admission>>, request: Request, next: Next) -> Response {
    let class = classify(request.uri().path());
    let Ok(_permit) = admission.slots(class).clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, "1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    };
    let body_expired = Arc::new(AtomicBool::new(false));
    let request = request.map(|inner| {
        Body::new(DeadlineBody {
            inner,
            deadline: Box::pin(tokio::time::sleep(admission.body_deadline)),
            expired: body_expired.clone(),
        })
    });
    match tokio::time::timeout(admission.handler_deadline, next.run(request)).await {
        // The extractor saw the deadline as a body error; report it as a timeout.
        Ok(_) if body_expired.load(Ordering::Acquire) => request_timeout(),
        Ok(response) => response,
        Err(_) => request_timeout(),
    }
}

fn request_timeout() -> Response {
    (
        StatusCode::REQUEST_TIMEOUT,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

/// Fails the body with an error once `deadline` passes before the last frame,
/// however steadily the client trickles data.
struct DeadlineBody {
    inner: Body,
    deadline: Pin<Box<Sleep>>,
    expired: Arc<AtomicBool>,
}

impl HttpBody for DeadlineBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        if !this.inner.is_end_stream() && this.deadline.as_mut().poll(cx).is_ready() {
            this.expired.store(true, Ordering::Release);
            return Poll::Ready(Some(Err(axum::Error::new(
                "request body not received before the deadline",
            ))));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    fn limits(capacity: usize, handler_deadline: Duration) -> Limits {
        Limits {
            provider: capacity,
            device: capacity,
            anonymous: capacity,
            default: capacity,
            body_deadline: BODY_DEADLINE,
            handler_deadline,
        }
    }

    fn post_to(uri: &str, body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(body)
            .unwrap()
    }

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
            limits(1, Duration::from_secs(30)),
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
            limits(1, Duration::from_millis(20)),
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

    #[test]
    fn classifies_routes_by_path_before_extraction() {
        for path in [
            "/v1/auth/login",
            "/v1/auth/login/mfa",
            "/v1/auth/register",
            "/v1/auth/resend-verification",
            "/v1/auth/verify-email",
            "/v1/auth/password/reset/request",
            "/v1/auth/password/reset/confirm",
            "/v1/enrollment/pairings/p1/claim",
            "/v1/enrollment/pairings/p1/prove",
            "/v1/enrollment/devices/authenticate",
            "/v1/enrollment/devices/d1/challenge",
        ] {
            assert_eq!(classify(path), RouteClass::Anonymous, "{path}");
        }
        assert_eq!(classify("/v1/billing/stripe-events"), RouteClass::Provider);
        assert_eq!(classify("/v1/device-stream"), RouteClass::Device);
        for path in [
            "/",
            "/readyz",
            "/v1/auth/session",
            "/v1/auth/api-keys",
            "/v1/auth/password",
            "/v1/enrollment/pairings",
            "/v1/enrollment/pairings/p1/approve",
            "/v1/enrollment/pairings//claim",
            "/v1/enrollment/devices",
            "/v1/enrollment/devices/d1",
            "/v1/billing/stripe-events/extra",
            "/v1/device-stream/extra",
            "/v1/owner/messages",
        ] {
            assert_eq!(classify(path), RouteClass::Default, "{path}");
        }
    }

    #[tokio::test]
    async fn saturated_class_leaves_other_classes_admitted() {
        let entered = Arc::new(Notify::new());
        let quick = || async { StatusCode::NO_CONTENT };
        let app = protect_with(
            Router::new()
                .route(
                    "/v1/auth/login",
                    post({
                        let entered = entered.clone();
                        move || async move {
                            entered.notify_one();
                            std::future::pending::<StatusCode>().await
                        }
                    }),
                )
                .route("/v1/auth/register", post(quick))
                .route("/v1/billing/stripe-events", post(quick))
                .route("/v1/device-stream", get(quick))
                .route("/v1/owner/messages", get(quick)),
            limits(1, Duration::from_secs(30)),
        );
        let flood = tokio::spawn(
            app.clone()
                .oneshot(post_to("/v1/auth/login", Body::empty())),
        );
        entered.notified().await;

        let same_class = app
            .clone()
            .oneshot(post_to("/v1/auth/register", Body::empty()))
            .await
            .unwrap();
        assert_eq!(same_class.status(), StatusCode::SERVICE_UNAVAILABLE);
        let provider = app
            .clone()
            .oneshot(post_to("/v1/billing/stripe-events", Body::empty()))
            .await
            .unwrap();
        assert_eq!(provider.status(), StatusCode::NO_CONTENT);
        for uri in ["/v1/device-stream", "/v1/owner/messages"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{uri}");
        }
        flood.abort();
        let _ = flood.await;
    }

    async fn assert_body_deadline_releases_admission(body: Body) {
        let app = protect_with(
            Router::new().route(
                "/v1/auth/login",
                post(|_: String| async { StatusCode::NO_CONTENT }),
            ),
            limits(1, HANDLER_DEADLINE),
        );
        let started = tokio::time::Instant::now();
        let response = app
            .clone()
            .oneshot(post_to("/v1/auth/login", body))
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(elapsed >= BODY_DEADLINE, "{elapsed:?}");
        assert!(elapsed < HANDLER_DEADLINE / 2, "{elapsed:?}");
        let response = app
            .oneshot(post_to("/v1/auth/login", Body::from("ok")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_body_is_rejected_at_body_deadline_and_releases_admission() {
        assert_body_deadline_releases_admission(Body::from_stream(
            futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>(),
        ))
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn trickled_body_is_rejected_at_body_deadline_and_releases_admission() {
        let trickle = futures_util::stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, std::io::Error>(vec![b'x']), ()))
        });
        assert_body_deadline_releases_admission(Body::from_stream(trickle)).await;
    }
}
