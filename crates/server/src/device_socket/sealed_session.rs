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
mod tests {
    use super::*;
    #[test]
    fn request_parser_rejects_unknown_authority_fields_and_missing_challenge() {
        let base = serde_json::json!({"v":1,"type":"sealed_session_request","connection_epoch":1,"challenge":Uuid::new_v4()});
        assert!(matches!(
            serde_json::from_value::<super::super::ClientFrame>(base.clone()),
            Ok(super::super::ClientFrame::SealedSessionRequest { v: 1, .. })
        ));
        let mut extra = base.clone();
        extra["authorized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<super::super::ClientFrame>(extra).is_err());
        let mut missing = base;
        missing.as_object_mut().unwrap().remove("challenge");
        assert!(serde_json::from_value::<super::super::ClientFrame>(missing).is_err());
    }
    #[test]
    fn replay_rate_and_lifetime_budget_fail_closed_without_evicting_nonces() {
        let mut samples = Samples::new();
        let start = Instant::now();
        let first = Uuid::new_v4();
        let session = samples.session_id();
        assert!(!samples.is_sampled());
        assert!(!samples.admit(Uuid::nil(), start));
        assert!(samples.admit(first, start));
        assert!(!samples.admit(Uuid::new_v4(), start + Duration::from_secs(4)));
        assert!(!samples.admit(first, start + Duration::from_secs(5)));
        samples.sampled();
        for index in 1..64 {
            assert!(samples.admit(Uuid::new_v4(), start + Duration::from_secs(index * 5)));
        }
        assert!(!samples.admit(Uuid::new_v4(), start + Duration::from_secs(320)));
        assert!(!samples.admit(first, start + Duration::from_secs(325)));
        assert_eq!(samples.session_id(), session);
        assert!(samples.is_sampled());
        assert_ne!(Samples::new().session_id(), session);
    }
}
