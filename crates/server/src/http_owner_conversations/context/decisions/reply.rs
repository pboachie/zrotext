// SPDX-License-Identifier: AGPL-3.0-only
//! Timing classification only: no approval, completion or authority is produced.
use super::model::Phase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyDisposition {
    Qualifying,
    Ambiguous,
    Late,
    Unrelated,
}

/// The store supplies the exact explicitly correlated request and verified source.
/// Selecting the sole request to a peer is never a substitute for correlation.
pub fn disposition(
    phase: Phase,
    not_before_ms: i64,
    expires_at_ms: i64,
    issued_at_ms: Option<i64>,
    observed_at_ms: i64,
    now_ms: i64,
) -> ReplyDisposition {
    if not_before_ms < 0 || expires_at_ms <= not_before_ms || observed_at_ms > now_ms {
        return ReplyDisposition::Ambiguous;
    }
    if observed_at_ms < not_before_ms {
        return ReplyDisposition::Unrelated;
    }
    if observed_at_ms >= expires_at_ms || now_ms >= expires_at_ms {
        return ReplyDisposition::Late;
    }
    if !matches!(phase, Phase::Dispatching | Phase::Unknown) {
        return ReplyDisposition::Ambiguous;
    }
    match issued_at_ms {
        Some(issued) if issued >= not_before_ms && issued <= observed_at_ms => {
            ReplyDisposition::Qualifying
        }
        _ => ReplyDisposition::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unissued_request_cannot_infer_a_response_from_the_peer_or_receipt() {
        for phase in [
            Phase::Proposed,
            Phase::Approved,
            Phase::Invalidated,
            Phase::Succeeded,
            Phase::Failed,
            Phase::Cancelled,
            Phase::Expired,
        ] {
            assert_eq!(
                disposition(phase, 10, 100, Some(20), 30, 40),
                ReplyDisposition::Ambiguous
            );
        }
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, None, 30, 40),
            ReplyDisposition::Ambiguous
        );
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, Some(35), 30, 40),
            ReplyDisposition::Ambiguous
        );
    }

    #[test]
    fn reply_timing_is_exclusive_and_late_arrival_cannot_fence_a_new_request() {
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, Some(20), 20, 99),
            ReplyDisposition::Qualifying
        );
        assert_eq!(
            disposition(Phase::Unknown, 10, 100, Some(20), 30, 40),
            ReplyDisposition::Qualifying
        );
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, Some(20), 100, 100),
            ReplyDisposition::Late
        );
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, Some(20), 30, 100),
            ReplyDisposition::Late
        );
        assert_eq!(
            disposition(Phase::Dispatching, 10, 100, Some(20), 9, 40),
            ReplyDisposition::Unrelated
        );
    }
}
