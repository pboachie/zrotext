// SPDX-License-Identifier: AGPL-3.0-only
//! Cancellation-safe reuse of SMTP sessions (issue #485).
//!
//! lettre's session pool returns a checked-out connection to the pool
//! whenever the send future is dropped, even when it was dropped mid-
//! transaction by the caller's send timeout. Such a session is in an
//! unknown protocol state: a late reply is still unread, or the server is
//! still inside an open DATA section, so the next message's commands would
//! be read out of step or written into the previous message.
//!
//! Every session is therefore owned by its own lettre transport whose pool
//! parks at most one session, and a send leases that whole transport
//! exclusively: no other send can reach the session while it is in use. The
//! lease goes back to the idle list only after the transaction finished with
//! a 2xx reply. Any other outcome - a timeout or any other cancellation, an
//! error, or an unexpected reply - drops the lease, and with it the transport
//! and every session it holds; lettre then closes those sessions and never
//! hands them out again. Each dispatcher owns its own `SmtpSessions`, built
//! from exactly one relay configuration, so sessions are never shared across
//! configurations.
//!
//! lettre's pool is enabled only off-Windows (the target-specific dependency
//! in Cargo.toml). On Windows a transport opens and closes one connection
//! per message, so the idle list holds transports without sessions.

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::{AsyncSmtpTransportBuilder, Error, response::Severity},
};
use std::sync::{Mutex, PoisonError};

/// Idle transports (each holding at most one parked session) kept between
/// sends. Two sessions cover the mail worker's per-tick burst width; a send
/// that finds none idle opens its own connection instead of waiting.
const IDLE_SESSIONS: usize = 2;

/// Parked sessions close after one idle minute, so a quiet hub holds no
/// provider login open.
#[cfg(not(windows))]
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Why a send or connection test did not complete with a definite 2xx reply.
#[derive(Debug)]
pub(super) enum SessionError {
    Smtp(Error),
    /// The server answered the end of the message with a positive reply that
    /// is not a completion (for example `354`), so the transaction state is
    /// unknown.
    UnexpectedReply,
}

/// The reusable SMTP sessions of one relay configuration.
pub(super) struct SmtpSessions {
    builder: AsyncSmtpTransportBuilder,
    idle: Mutex<Vec<Transport>>,
}

impl SmtpSessions {
    pub(super) fn new(builder: AsyncSmtpTransportBuilder) -> Self {
        #[cfg(not(windows))]
        let builder = builder.pool_config(
            lettre::transport::smtp::PoolConfig::new()
                .max_size(1)
                .idle_timeout(IDLE_TIMEOUT),
        );
        Self {
            builder,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Sends one message. `Ok` only for a 2xx reply to the end of the
    /// message; only then may the session carry another message.
    pub(super) async fn send(&self, message: Message) -> Result<(), SessionError> {
        let lease = self.lease();
        let response = lease
            .transport()
            .send(message)
            .await
            .map_err(SessionError::Smtp)?;
        if response.code().severity != Severity::PositiveCompletion {
            return Err(SessionError::UnexpectedReply);
        }
        lease.release().await;
        Ok(())
    }

    /// Opens (or health-checks) a session with NOOP.
    pub(super) async fn test_connection(&self) -> Result<bool, Error> {
        let lease = self.lease();
        let connected = lease.transport().test_connection().await?;
        if connected {
            lease.release().await;
        }
        Ok(connected)
    }

    fn lease(&self) -> Lease<'_> {
        let idle = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        // Building a transport starts lettre's idle sweeper, which needs the
        // Tokio runtime every send already runs on.
        let transport = idle.unwrap_or_else(|| Transport(Some(self.builder.clone().build())));
        Lease {
            sessions: self,
            transport: Some(transport),
        }
    }
}

/// Exclusive use of one transport for one send. Dropping it without
/// `release` - on error, unexpected reply, timeout or any other
/// cancellation - discards the transport and its session.
struct Lease<'a> {
    sessions: &'a SmtpSessions,
    transport: Option<Transport>,
}

impl Lease<'_> {
    fn transport(&self) -> &AsyncSmtpTransport<Tokio1Executor> {
        self.transport
            .as_ref()
            .and_then(|transport| transport.0.as_ref())
            .expect("a lease holds its transport until released or dropped")
    }

    /// Returns a transport whose transaction completed to the idle list.
    async fn release(mut self) {
        // lettre parks the finished session from a task it spawned when the
        // send returned; yielding once lets it land before another send can
        // lease this transport. If this future is cancelled here, the lease
        // is dropped and the (clean) session is merely not reused.
        tokio::task::yield_now().await;
        let transport = self.transport.take();
        let mut idle = self
            .sessions
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if idle.len() < IDLE_SESSIONS {
            idle.extend(transport);
        }
    }
}

/// A lettre transport whose pool needs a live Tokio reactor when it is
/// dropped: lettre spawns the close-out of parked sessions from `Drop`, which
/// panics outside a runtime. Dropping inside a runtime defers the close-out
/// to it; with no reactor at all there is nothing left to run it, so the
/// transport is forgotten - that only happens in tests and at process exit.
struct Transport(Option<AsyncSmtpTransport<Tokio1Executor>>);

impl Drop for Transport {
    fn drop(&mut self) {
        let Some(transport) = self.0.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    drop(transport);
                });
            }
            Err(_) => std::mem::forget(transport),
        }
    }
}

#[cfg(all(test, not(windows)))]
pub(super) mod tests {
    //! A scripted plain-text SMTP server records every line each connection
    //! receives, so the tests assert what the server observed rather than
    //! what the client believes it sent. The dispatcher tests reuse it.
    use super::{SessionError, SmtpSessions};
    use lettre::{AsyncSmtpTransport, Message, Tokio1Executor};
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        sync::Notify,
    };

    /// How the server answers the end of the n-th message (counted across
    /// all connections) or the n-th DATA command.
    #[derive(Clone, Copy)]
    pub(in super::super) enum Script {
        Accept,
        /// Hold the `354` to DATA until `release` is notified.
        StallDataReply,
        /// Hold the reply to the end of the message until `release`.
        StallFinalReply,
        RejectFinal,
        /// Answer the end of the message with `354` instead of `250`.
        IntermediateFinal,
    }

    #[derive(Default)]
    struct Log {
        /// `(connection, line)` for every line received, body lines prefixed
        /// with `body:`.
        lines: Vec<(usize, String)>,
        connections: usize,
        /// Connections on which a message was terminated with `.`.
        completed: Vec<usize>,
    }

    pub(in super::super) struct Server {
        address: SocketAddr,
        log: Arc<Mutex<Log>>,
        /// Notified when a stalled step is reached.
        stalled: Arc<Notify>,
        /// Notify to send the held reply.
        release: Arc<Notify>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Server {
        pub(in super::super) async fn start(scripts: Vec<Script>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let log = Arc::new(Mutex::new(Log::default()));
            let stalled = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let scripts = Arc::new(Mutex::new(scripts.into_iter()));
            let (task_log, task_stalled, task_release) =
                (log.clone(), stalled.clone(), release.clone());
            let task = tokio::spawn(async move {
                let mut handlers = tokio::task::JoinSet::new();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let connection = {
                        let mut log = task_log.lock().unwrap();
                        log.connections += 1;
                        log.connections
                    };
                    let (log, stalled, release, scripts) = (
                        task_log.clone(),
                        task_stalled.clone(),
                        task_release.clone(),
                        scripts.clone(),
                    );
                    handlers.spawn(async move {
                        let record =
                            |line: String| log.lock().unwrap().lines.push((connection, line));
                        let (reader, mut writer) = stream.into_split();
                        let mut lines = BufReader::new(reader).lines();
                        writer.write_all(b"220 stub ready\r\n").await.unwrap();
                        while let Ok(Some(line)) = lines.next_line().await {
                            record(line.clone());
                            let upper = line.to_ascii_uppercase();
                            if upper.starts_with("QUIT") {
                                let _ = writer.write_all(b"221 bye\r\n").await;
                                return;
                            }
                            if !upper.starts_with("DATA") {
                                let _ = writer.write_all(b"250 ok\r\n").await;
                                continue;
                            }
                            let script = scripts.lock().unwrap().next().unwrap_or(Script::Accept);
                            if let Script::StallDataReply = script {
                                stalled.notify_one();
                                release.notified().await;
                            }
                            let _ = writer.write_all(b"354 go\r\n").await;
                            let mut terminated = false;
                            while let Ok(Some(body)) = lines.next_line().await {
                                if body == "." {
                                    terminated = true;
                                    break;
                                }
                                record(format!("body:{body}"));
                            }
                            if !terminated {
                                return;
                            }
                            log.lock().unwrap().completed.push(connection);
                            let reply: &[u8] = match script {
                                Script::StallFinalReply => {
                                    stalled.notify_one();
                                    release.notified().await;
                                    b"250 queued late\r\n"
                                }
                                Script::RejectFinal => b"550 rejected\r\n",
                                Script::IntermediateFinal => b"354 unexpected\r\n",
                                Script::Accept | Script::StallDataReply => b"250 queued\r\n",
                            };
                            let _ = writer.write_all(reply).await;
                        }
                    });
                }
            });
            Self {
                address,
                log,
                stalled,
                release,
                task,
            }
        }

        pub(in super::super) fn sessions(&self) -> SmtpSessions {
            // Plain text: the stub cannot speak TLS, and the property under
            // test is session reuse, not encryption.
            SmtpSessions::new(
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
                    self.address.ip().to_string(),
                )
                .port(self.address.port()),
            )
        }

        /// The connection that received the MAIL FROM of `sender`.
        fn connection_of(&self, sender: &str) -> usize {
            let log = self.log.lock().unwrap();
            let lines: Vec<_> = log
                .lines
                .iter()
                .filter(|(_, line)| line.starts_with("MAIL FROM") && line.contains(sender))
                .collect();
            assert_eq!(lines.len(), 1, "{sender} must be announced exactly once");
            lines[0].0
        }

        fn lines_on(&self, connection: usize) -> Vec<String> {
            let log = self.log.lock().unwrap();
            log.lines
                .iter()
                .filter(|(on, _)| *on == connection)
                .map(|(_, line)| line.clone())
                .collect()
        }

        pub(in super::super) fn connections(&self) -> usize {
            self.log.lock().unwrap().connections
        }

        fn completed(&self) -> Vec<usize> {
            self.log.lock().unwrap().completed.clone()
        }
    }

    fn mail(sender: &str) -> Message {
        Message::builder()
            .from(format!("{sender}@example.test").parse().unwrap())
            .to("recipient@example.test".parse().unwrap())
            .body(format!("content-of-{sender}"))
            .unwrap()
    }

    /// Bounds a send that must finish; a hang is reported as a failure.
    async fn send(sessions: &SmtpSessions, sender: &str) -> Result<(), SessionError> {
        tokio::time::timeout(Duration::from_secs(10), sessions.send(mail(sender)))
            .await
            .unwrap_or_else(|_| panic!("mail from {sender} hung"))
    }

    /// Asserts that the server saw nothing from another message on
    /// `connection` after its DATA command: no command of a later
    /// transaction and no foreign body line was written into the open DATA
    /// section. A trailing QUIT from closing the discarded session is fine.
    fn assert_nothing_injected(server: &Server, connection: usize, own: &str) {
        let lines = server.lines_on(connection);
        let data = lines
            .iter()
            .rposition(|line| line == "DATA")
            .expect("the abandoned message reached DATA");
        for line in &lines[data + 1..] {
            let body = line.strip_prefix("body:").unwrap_or(line);
            assert!(
                !body.starts_with("MAIL FROM")
                    && !body.starts_with("RCPT TO")
                    && !body.starts_with("NOOP")
                    && !body.starts_with("RSET")
                    && (!body.contains("content-of-") || body.contains(own)),
                "line {line:?} was injected into the open DATA section of connection {connection}: {lines:?}"
            );
        }
    }

    #[tokio::test]
    async fn completed_transactions_reuse_one_session() {
        let server = Server::start(vec![]).await;
        let sessions = server.sessions();
        for i in 0..5 {
            send(&sessions, &format!("sequential{i}")).await.unwrap();
        }
        assert_eq!(
            server.connections(),
            1,
            "sequential mails share one session"
        );
        assert_eq!(server.completed(), vec![1; 5]);
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_data_discards_the_session() {
        let server = Server::start(vec![Script::Accept, Script::StallDataReply]).await;
        let sessions = server.sessions();
        send(&sessions, "warmup").await.unwrap();
        tokio::select! {
            result = sessions.send(mail("cancelled")) => panic!("the stalled send finished: {result:?}"),
            () = server.stalled.notified() => {}
        }
        // Give lettre time to hand the abandoned session back to its pool, so
        // a lease that failed to discard it would offer it to the next send.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The late 354 now opens a DATA section the client abandoned.
        server.release.notify_one();
        send(&sessions, "next").await.unwrap();
        let cancelled = server.connection_of("cancelled");
        let next = server.connection_of("next");
        assert_ne!(next, cancelled, "the next mail must use a new connection");
        assert!(
            server
                .lines_on(next)
                .contains(&"body:content-of-next".to_owned()),
            "the next mail's content arrived on its own connection"
        );
        // Let any late writes to the abandoned connection arrive.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_nothing_injected(&server, cancelled, "cancelled");
        assert_eq!(
            server.completed(),
            vec![server.connection_of("warmup"), next],
            "the abandoned message was never terminated"
        );
    }

    #[tokio::test]
    async fn send_timeout_after_the_message_discards_the_session_and_reports_rejection() {
        let server = Server::start(vec![
            Script::Accept,
            Script::StallFinalReply,
            Script::RejectFinal,
        ])
        .await;
        let sessions = server.sessions();
        send(&sessions, "warmup").await.unwrap();
        let timed_out =
            tokio::time::timeout(Duration::from_millis(300), sessions.send(mail("timedout"))).await;
        assert!(timed_out.is_err(), "the stalled send must time out");
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The late 250 is now unread on the abandoned session.
        server.release.notify_one();
        let rejected = send(&sessions, "rejected").await;
        assert!(
            matches!(&rejected, Err(SessionError::Smtp(error)) if error.is_permanent()),
            "the server's 550 must surface as a permanent error, got {rejected:?}"
        );
        let timed_out = server.connection_of("timedout");
        let rejected = server.connection_of("rejected");
        assert_ne!(
            rejected, timed_out,
            "the next mail must use a new connection"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_nothing_injected(&server, timed_out, "timedout");
        // A rejection is a failed transaction, so its session is not reused
        // either.
        send(&sessions, "after").await.unwrap();
        let after = server.connection_of("after");
        assert_ne!(after, rejected);
        assert_ne!(after, timed_out);
    }

    #[tokio::test]
    async fn rejection_is_an_error_and_is_not_reused() {
        let server = Server::start(vec![Script::Accept, Script::RejectFinal]).await;
        let sessions = server.sessions();
        send(&sessions, "warmup").await.unwrap();
        let rejected = send(&sessions, "rejected").await;
        assert!(
            matches!(&rejected, Err(SessionError::Smtp(error)) if error.is_permanent()),
            "a 550 must surface as a permanent error, got {rejected:?}"
        );
        send(&sessions, "after").await.unwrap();
        assert_ne!(
            server.connection_of("after"),
            server.connection_of("rejected")
        );
    }

    #[tokio::test]
    async fn unexpected_reply_is_an_error_and_is_not_reused() {
        let server = Server::start(vec![Script::Accept, Script::IntermediateFinal]).await;
        let sessions = server.sessions();
        send(&sessions, "warmup").await.unwrap();
        let unexpected = send(&sessions, "unexpected").await;
        assert!(
            matches!(unexpected, Err(SessionError::UnexpectedReply)),
            "a 354 after the message must not count as delivered, got {unexpected:?}"
        );
        send(&sessions, "after").await.unwrap();
        assert_ne!(
            server.connection_of("after"),
            server.connection_of("unexpected")
        );
    }

    #[tokio::test]
    async fn separate_configurations_never_share_sessions() {
        let first = Server::start(vec![]).await;
        let second = Server::start(vec![]).await;
        let (first_sessions, second_sessions) = (first.sessions(), second.sessions());
        for i in 0..3 {
            send(&first_sessions, &format!("first{i}")).await.unwrap();
            send(&second_sessions, &format!("second{i}")).await.unwrap();
        }
        for (server, own, other) in [(&first, "first", "second"), (&second, "second", "first")] {
            let log = server.log.lock().unwrap();
            assert_eq!(log.connections, 1);
            assert_eq!(log.completed.len(), 3);
            assert!(
                log.lines.iter().all(|(_, line)| !line.contains(other)),
                "{own} server received {other} traffic"
            );
        }
    }
}
