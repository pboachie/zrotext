// SPDX-License-Identifier: AGPL-3.0-only
//! Outcome projection never treats elapsed time or transport receipts as approval.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageOutcome {
    Waiting,
    InFlight,
    Unknown,
    Completed,
    Failed,
}

/// These are existing delivery states, rather than a second delivery machine.
/// Unrecognized states remain uncertain and cannot release recurrence pacing.
pub fn message_outcome(state: &str) -> MessageOutcome {
    match state {
        "accepted" | "queued" | "claimed" => MessageOutcome::Waiting,
        "submitting" | "submitted" => MessageOutcome::InFlight,
        "delivered" => MessageOutcome::Completed,
        "failed" | "cancelled" | "expired" => MessageOutcome::Failed,
        _ => MessageOutcome::Unknown,
    }
}

/// A grant winner is durable uncertainty until the authoritative delivery
/// record resolves it. Window expiry cannot turn it back into cancellable work.
pub fn reconcile_phase(current: &str, message_state: &str) -> Option<&'static str> {
    if !matches!(current, "dispatching" | "unknown") {
        return None;
    }
    Some(match message_outcome(message_state) {
        MessageOutcome::Completed => "completed",
        MessageOutcome::Failed => "failed",
        MessageOutcome::Unknown => "unknown",
        MessageOutcome::Waiting | MessageOutcome::InFlight => "dispatching",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_winners_keep_uncertainty_until_authoritative_terminal_outcome() {
        for state in ["unknown", "unexpected", "missing"] {
            assert_eq!(reconcile_phase("dispatching", state), Some("unknown"));
        }
        assert_eq!(reconcile_phase("unknown", "submitted"), Some("dispatching"));
        assert_eq!(reconcile_phase("unknown", "delivered"), Some("completed"));
        assert_eq!(reconcile_phase("dispatching", "failed"), Some("failed"));
    }

    #[test]
    fn terminal_and_unclaimed_occurrences_cannot_adopt_delivery_outcomes() {
        for current in [
            "completed",
            "failed",
            "cancelled",
            "expired",
            "claimed",
            "waiting_window",
        ] {
            assert_eq!(reconcile_phase(current, "delivered"), None);
        }
    }
}
