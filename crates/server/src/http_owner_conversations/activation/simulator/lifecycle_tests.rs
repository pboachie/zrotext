// SPDX-License-Identifier: AGPL-3.0-only
//! Actual HTTP/WebSocket shutdown interleavings, without PostgreSQL or Android substitutes.
use super::*;
use futures_util::StreamExt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant, timeout};

struct Probe {
    fixture: Arc<()>,
    sockets: SocketTasks,
    done: Arc<Notify>,
    release: watch::Receiver<bool>,
    rejected: Mutex<Option<oneshot::Sender<()>>>,
    registered: Mutex<Option<oneshot::Sender<()>>>,
}

async fn held_socket(State(probe): State<Arc<Probe>>, upgrade: WebSocketUpgrade) -> Response {
    let task = probe.sockets.register(probe.fixture.clone(), ()).unwrap();
    let mut release = probe.release.clone();
    upgrade
        .on_upgrade(move |mut socket| async move {
            socket
                .send(Message::Text("registered".into()))
                .await
                .unwrap();
            // Deliberately retain the upgraded owner after HTTP finish to force the race.
            socket_shutdown(&mut release).await;
            let _ = socket.close().await;
            drop(task);
        })
        .into_response()
}

async fn rejected_socket(State(probe): State<Arc<Probe>>, upgrade: WebSocketUpgrade) -> Response {
    let task = probe.sockets.register(probe.fixture.clone(), ()).unwrap();
    let rejected = probe.rejected.lock().await.take().unwrap();
    let response = upgrade
        .on_failed_upgrade(move |_| {
            let _ = rejected.send(());
        })
        .on_upgrade(move |_| async move {
            drop(task);
            panic!("rejected response must not upgrade");
        });
    probe
        .registered
        .lock()
        .await
        .take()
        .unwrap()
        .send(())
        .unwrap();
    let mut release = probe.release.clone();
    // The client resets its actual TCP connection before permitting a response write.
    socket_shutdown(&mut release).await;
    response
}

async fn idle_socket(State(probe): State<Arc<Probe>>, upgrade: WebSocketUpgrade) -> Response {
    let task = probe.sockets.register(probe.fixture.clone(), ()).unwrap();
    let mut shutdown = probe.sockets.shutdown.subscribe();
    upgrade
        .on_upgrade(move |mut socket| async move {
            socket
                .send(Message::Text("registered".into()))
                .await
                .unwrap();
            loop {
                tokio::select! {
                    biased;
                    _ = socket_shutdown(&mut shutdown) => break,
                    received = socket.recv() => if received.is_none() { break },
                }
            }
            let _ = socket.close().await;
            drop(task);
        })
        .into_response()
}

async fn finish(State(probe): State<Arc<Probe>>) -> StatusCode {
    probe.sockets.stop();
    probe.done.notify_one();
    StatusCode::OK
}

struct Harness {
    fixture: Arc<()>,
    sockets: SocketTasks,
    release: watch::Sender<bool>,
    rejected: oneshot::Receiver<()>,
    registered: oneshot::Receiver<()>,
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
}

async fn harness() -> Harness {
    let fixture = Arc::new(());
    let sockets = SocketTasks::new();
    let done = Arc::new(Notify::new());
    let (release, receiver) = watch::channel(false);
    let (rejected, rejected_receiver) = oneshot::channel();
    let (registered, registered_receiver) = oneshot::channel();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/socket", get(held_socket))
        .route("/idle", get(idle_socket))
        .route("/reject", get(rejected_socket))
        .route("/finish", post(finish))
        .with_state(Arc::new(Probe {
            fixture: fixture.clone(),
            sockets: sockets.clone(),
            done: done.clone(),
            release: receiver,
            rejected: Mutex::new(Some(rejected)),
            registered: Mutex::new(Some(registered)),
        }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { done.notified().await })
            .await
            .unwrap();
    });
    Harness {
        fixture,
        sockets,
        release,
        rejected: rejected_receiver,
        registered: registered_receiver,
        address,
        server,
    }
}

async fn request_finish(harness: &Harness) {
    let response = reqwest::Client::new()
        .post(format!("http://{}/finish", harness.address))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn finish_http(harness: &mut Harness) {
    request_finish(harness).await;
    timeout(Duration::from_secs(5), &mut harness.server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn waits_for_upgraded_owner_after_http_shutdown() {
    let mut h = harness().await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{}/socket", h.address))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "registered"
    );
    finish_http(&mut h).await;
    // The former HTTP-only teardown fails deterministically under this interleaving.
    h.fixture = Arc::try_unwrap(h.fixture).expect_err("upgrade must still own fixture");
    let mut drain = Box::pin(h.sockets.wait());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        drain.as_mut().poll(&mut context).is_pending(),
        "HTTP completion cannot prove upgraded completion"
    );
    h.release.send_replace(true);
    timeout(Duration::from_secs(5), drain).await.unwrap();
    Arc::try_unwrap(h.fixture).expect("upgraded task must release before cleanup");
}

#[tokio::test]
async fn stuck_upgraded_owner_refuses_cleanup_at_deadline() {
    let mut h = harness().await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{}/socket", h.address))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "registered"
    );
    request_finish(&h).await;
    timeout(Duration::from_secs(5), async {
        while !h.server.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_millis(25);
    // Exercise the production helper: HTTP join succeeds, then upgraded drain expires.
    // Re-polling the consumed JoinHandle here would panic instead of returning refusal.
    assert!(
        finish_server(&mut h.server, &h.sockets, deadline)
            .await
            .is_err()
    );
    h.fixture = Arc::try_unwrap(h.fixture).expect_err("stuck owner cannot be cleaned");
    h.release.send_replace(true);
    timeout(Duration::from_secs(5), h.sockets.wait())
        .await
        .unwrap();
    Arc::try_unwrap(h.fixture).expect("explicit callback release permits cleanup");
}

#[tokio::test]
async fn rejected_upgrade_releases_registered_owner() {
    let mut h = harness().await;
    let connection = tokio::net::TcpSocket::new_v4().unwrap();
    socket2::SockRef::from(&connection)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    let mut connection = connection.connect(h.address).await.unwrap();
    connection.write_all(format!("GET /reject HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n",
        h.address, STANDARD.encode([0u8;16])).as_bytes()).await.unwrap();
    timeout(Duration::from_secs(5), &mut h.registered)
        .await
        .unwrap()
        .unwrap();
    drop(connection);
    h.release.send_replace(true);
    timeout(Duration::from_secs(5), &mut h.rejected)
        .await
        .unwrap()
        .unwrap();
    finish_http(&mut h).await;
    timeout(Duration::from_secs(5), h.sockets.wait())
        .await
        .unwrap();
    Arc::try_unwrap(h.fixture).expect("failed upgrade must release its captured owner");
    assert!(h.sockets.register(Arc::new(()), ()).is_none());
}

#[tokio::test]
async fn server_deadline_aborts_and_releases_unjoined_http_owner() {
    let mut h = harness().await;
    assert!(
        finish_server(
            &mut h.server,
            &h.sockets,
            Instant::now() + Duration::from_millis(25)
        )
        .await
        .is_err()
    );
    assert!(h.server.is_finished());
    assert!(h.sockets.register(Arc::new(()), ()).is_none());
    Arc::try_unwrap(h.fixture).expect("aborted HTTP owner must release before cleanup");
}

#[tokio::test]
async fn finish_wakes_idle_upgraded_socket() {
    let mut h = harness().await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{}/idle", h.address))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "registered"
    );
    finish_http(&mut h).await;
    timeout(Duration::from_secs(5), h.sockets.wait())
        .await
        .unwrap();
    Arc::try_unwrap(h.fixture).expect("finish must release an idle receiver without client close");
    assert!(matches!(
        timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap(),
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
    ));
}

struct Resource(Arc<AtomicBool>);
impl Drop for Resource {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
struct Owner(Arc<AtomicBool>);
impl Drop for Owner {
    fn drop(&mut self) {
        assert!(
            self.0.load(Ordering::SeqCst),
            "resource must drop before owner"
        );
    }
}

#[tokio::test]
async fn cancellation_and_unwind_drop_resource_and_owner_before_drain() {
    for panic in [false, true] {
        let sockets = SocketTasks::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(Owner(dropped.clone()));
        let weak = Arc::downgrade(&owner);
        let task = sockets.register(owner, Resource(dropped.clone())).unwrap();
        let (entered, ready) = oneshot::channel();
        let running = tokio::spawn(async move {
            entered.send(()).unwrap();
            if panic {
                let _task = task;
                panic!("controlled upgraded callback panic");
            }
            let _task = task;
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        if !panic {
            running.abort();
        }
        let error = running.await.unwrap_err();
        assert_eq!(error.is_cancelled(), !panic);
        assert_eq!(error.is_panic(), panic);
        timeout(Duration::from_secs(5), sockets.wait())
            .await
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(weak.upgrade().is_none());
    }
}
