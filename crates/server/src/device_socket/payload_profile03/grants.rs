// SPDX-License-Identifier: AGPL-3.0-only
//! Retained reader readiness is only a comparison candidate. Every distinct
//! queued message still obtains actual current permission and its own attempt.
use super::*;
use crate::sealed_dispatch::wire03::ReadyFrame03;

pub(in crate::device_socket) struct Readiness03 {
    ready: Option<ReadyFrame03>,
    publications: usize,
    issued: usize,
    last_grant: Option<Instant>,
}
impl Readiness03 {
    pub(in crate::device_socket) fn new() -> Self {
        Self {
            ready: None,
            publications: 0,
            issued: 0,
            last_grant: None,
        }
    }
    pub(in crate::device_socket) fn accept(
        &mut self,
        ready: ReadyFrame03,
        session: DeviceSession,
        deployment: i64,
    ) -> Option<()> {
        let claims = ready.claims();
        if claims.connection_epoch != session.connection_epoch
            || claims.deployment_epoch != deployment
            || self.publications >= 64
        {
            return None;
        }
        self.publications += 1;
        self.ready = Some(ready);
        Some(())
    }
    pub(in crate::device_socket) fn present(&self) -> bool {
        self.ready.is_some()
    }
    fn due(&self, now: Instant) -> bool {
        self.ready.is_some()
            && self.issued < 1024
            && self.last_grant.is_none_or(|last| {
                now.checked_duration_since(last)
                    .is_some_and(|age| age >= Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS))
            })
    }
    fn committed(&mut self, now: Instant) {
        self.issued += 1;
        self.last_grant = Some(now);
        // Keep readiness for a different explicit reviewed message. Neither
        // a new publication nor a failed write resets this connection budget.
    }
    fn exhausted(&self, now: Instant) -> bool {
        self.issued >= 1024
            && self.last_grant.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_some_and(|age| age >= Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS))
            })
    }
    pub(in crate::device_socket) async fn poll(
        &mut self,
        socket: &mut WebSocket,
        state: &DeviceSocketState,
        socket_actor: crate::device_socket::SocketActor,
        origin: &str,
    ) -> Option<()> {
        // Explicit reconnect after the last grant's entire bounded lifetime,
        // rather than silently stranding new messages at a lifetime counter.
        // Any unresolved attempt remains durably fenced across that reconnect.
        if self.exhausted(Instant::now()) {
            return None;
        }
        if !self.due(Instant::now()) {
            return Some(());
        }
        let ready = self.ready.as_ref()?;
        let session = socket_actor.session();
        let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
        let deployment = u64::try_from(state.deployment_epoch)
            .ok()
            .filter(|n| *n > 0)?;
        let actor = crate::conversation_interval03::live::DeviceInterval03 {
            session,
            site: &state.site_id,
            instance: &state.instance_id,
            deployment,
            origin,
        };
        let grant = crate::conversation_grant03::issue_next(&mut db, socket_actor, actor, ready)
            .await
            .ok()?;
        drop(db);
        if let Some(grant) = grant {
            let raw = grant.frame().to_json().ok()?;
            self.committed(Instant::now());
            if raw.len() > MAX_FRAME_BYTES {
                return None;
            }
            // This is the first write of an already committed grant. Failure
            // closes this socket and preserves the durable one-attempt fence.
            socket
                .send(Message::Text(String::from_utf8(raw).ok()?.into()))
                .await
                .ok()?;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests;
