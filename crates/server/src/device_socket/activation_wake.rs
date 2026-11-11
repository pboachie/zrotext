// SPDX-License-Identifier: AGPL-3.0-only
//! Each socket retains its own unread activation wake, including while busy.
use tokio::sync::watch;

pub(super) struct ActivationWake {
    sender: watch::Sender<()>,
}

impl ActivationWake {
    pub(super) fn new() -> Self {
        Self {
            sender: watch::channel(()).0,
        }
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<()> {
        self.sender.subscribe()
    }

    pub(super) fn wake(&self) {
        // Unlike a shared pending flag, observing a version in one socket
        // cannot consume another socket's wake. Coalescing is safe: each poll
        // reads current persisted exchange state rather than a queued event.
        self.sender.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[tokio::test]
    async fn every_busy_socket_observes_each_wake_independently() {
        let wake = ActivationWake::new();
        let mut first = wake.subscribe();
        let mut second = wake.subscribe();
        for _ in 0..2 {
            wake.wake();
            assert!(matches!(first.changed().now_or_never(), Some(Ok(()))));
            assert!(first.changed().now_or_never().is_none());
            // No future was waiting for this receiver when the wake fired.
            assert!(matches!(second.changed().now_or_never(), Some(Ok(()))));
            assert!(second.changed().now_or_never().is_none());
        }
    }

    #[tokio::test]
    async fn one_wake_reaches_all_parked_sockets() {
        let wake = ActivationWake::new();
        let mut first = wake.subscribe();
        let mut second = wake.subscribe();
        let first_wait = first.changed();
        let second_wait = second.changed();
        tokio::pin!(first_wait, second_wait);
        assert!(first_wait.as_mut().now_or_never().is_none());
        assert!(second_wait.as_mut().now_or_never().is_none());
        wake.wake();
        assert!(matches!(first_wait.now_or_never(), Some(Ok(()))));
        assert!(matches!(second_wait.now_or_never(), Some(Ok(()))));
    }

    #[tokio::test]
    async fn cancelled_select_wait_keeps_later_wakes_and_coalesces_them() {
        let wake = ActivationWake::new();
        let mut receiver = wake.subscribe();
        // A different select branch wins and drops this pending wait.
        assert!(receiver.changed().now_or_never().is_none());
        wake.wake();
        wake.wake();
        assert!(matches!(receiver.changed().now_or_never(), Some(Ok(()))));
        assert!(receiver.changed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn slow_and_disconnected_receivers_do_not_consume_other_sockets_wakes() {
        let wake = ActivationWake::new();
        let mut sockets: Vec<_> = (0..8).map(|_| wake.subscribe()).collect();
        let disconnected = wake.subscribe();
        wake.wake();
        drop(disconnected);
        for socket in &mut sockets[..7] {
            assert!(matches!(socket.changed().now_or_never(), Some(Ok(()))));
        }
        // Another signal arrives while the last socket is still handling work.
        wake.wake();
        for socket in &mut sockets {
            assert!(matches!(socket.changed().now_or_never(), Some(Ok(()))));
            assert!(socket.changed().now_or_never().is_none());
        }
    }

    #[tokio::test]
    async fn wake_during_handling_remains_unread_for_the_next_wait() {
        let wake = ActivationWake::new();
        let mut receiver = wake.subscribe();
        wake.wake();
        assert!(matches!(receiver.changed().now_or_never(), Some(Ok(()))));
        // The socket has selected a wake and is now polling persisted state.
        wake.wake();
        assert!(matches!(receiver.changed().now_or_never(), Some(Ok(()))));
        assert!(receiver.changed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn new_socket_observes_only_future_wakes() {
        let wake = ActivationWake::new();
        // No subscribers: send_replace must still keep the broadcaster usable.
        wake.wake();
        let mut receiver = wake.subscribe();
        // run_socket starts with an immediate poll of persisted state after
        // subscribing, so pre-subscription work needs no historical wake.
        assert!(receiver.changed().now_or_never().is_none());
        wake.wake();
        assert!(matches!(receiver.changed().now_or_never(), Some(Ok(()))));
    }
}
