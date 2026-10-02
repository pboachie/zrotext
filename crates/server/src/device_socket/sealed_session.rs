// SPDX-License-Identifier: AGPL-3.0-only
//! Socket-local challenge custody; samples never renew dispatch readiness.
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(super) struct Samples {
    session_id: Uuid,
    challenges: Vec<Uuid>,
    last: Option<Instant>,
    sampled: bool,
}

impl Samples {
    pub(super) fn new() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            challenges: Vec::new(),
            last: None,
            sampled: false,
        }
    }
    pub(super) fn admit(&mut self, challenge: Uuid, now: Instant) -> bool {
        if challenge.is_nil()
            || self.challenges.len() >= 64
            || self.challenges.contains(&challenge)
            || self.last.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_none_or(|age| age < Duration::from_secs(5))
            })
        {
            return false;
        }
        self.challenges.push(challenge);
        self.last = Some(now);
        true
    }
    pub(super) fn session_id(&self) -> Uuid {
        self.session_id
    }
    pub(super) fn sampled(&mut self) {
        self.sampled = true;
    }
    pub(super) fn is_sampled(&self) -> bool {
        self.sampled
    }
}

#[cfg(test)]
mod tests;
