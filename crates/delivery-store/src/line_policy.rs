// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0004 step 2: the writer-side not-ready routing decision for
//! owner-named lines. This module is a pure decision over observed line
//! state; it performs no I/O, holds no locks and grants no authority of its
//! own. The caller must re-check every decision input at the existing
//! transaction and phone boundaries after waits.

/// The owner's per-line choice of what happens when the addressed line is
/// not ready. `Ignore` is the approved default: an explicit refusal before
/// acceptance that creates no message record and no unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyMode {
    Ignore,
    Queue,
    Fallback,
}

impl NotReadyMode {
    /// The storage representation from migration 098. Unknown values are a
    /// database integrity failure, not a policy choice; the caller rejects
    /// them before reaching a decision.
    pub fn from_storage(value: &str) -> Option<Self> {
        match value {
            "ignore" => Some(Self::Ignore),
            "queue" => Some(Self::Queue),
            "fallback" => Some(Self::Fallback),
            _ => None,
        }
    }
}

/// Why a line is not ready. Each case names the failure without telephony
/// identifiers: no SIM slot, subscription identifier or card identifier
/// appears in a refusal or a stored decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessReason {
    /// The line's activation state is `pending` or `revoked`.
    Inactive,
    /// The line's approved binding is missing or no longer active.
    BindingNotActive,
    /// A card-continuity or re-pairing check is in progress for the line.
    ContinuityPending,
    /// The approved binding's card changed; the old identity must not send.
    CardChanged,
    /// The line's phone has been disconnected longer than the line's
    /// configured offline threshold.
    OfflinePastThreshold,
}

impl ReadinessReason {
    /// The stable refusal code carried in an `ignore` decision's response.
    pub fn refusal_code(self) -> &'static str {
        match self {
            Self::Inactive => "line_not_ready_inactive",
            Self::BindingNotActive => "line_not_ready_binding_not_active",
            Self::ContinuityPending => "line_not_ready_continuity_pending",
            Self::CardChanged => "line_not_ready_card_changed",
            Self::OfflinePastThreshold => "line_not_ready_offline",
        }
    }
}

/// The facts the decision needs about the addressed line. They are
/// observations, not promises: `last_seen_ms` is the freshest authenticated
/// observation the caller holds for the line's phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineFacts {
    pub label: Option<String>,
    pub line_active: bool,
    pub binding_active: bool,
    pub continuity_pending: bool,
    pub card_changed: bool,
    /// Elapsed milliseconds since the freshest authenticated observation of
    /// the line's phone, or `None` when no observation exists yet.
    pub since_last_seen_ms: Option<u64>,
}

impl LineFacts {
    /// The caller's readiness view of the line: `None` means ready, so no
    /// not-ready decision is needed and routing proceeds on this line.
    pub fn not_ready(&self, offline_threshold_ms: u64) -> Option<ReadinessReason> {
        self.not_ready_reason(offline_threshold_ms)
    }

    fn not_ready_reason(&self, offline_threshold_ms: u64) -> Option<ReadinessReason> {
        if !self.line_active {
            Some(ReadinessReason::Inactive)
        } else if !self.binding_active {
            Some(ReadinessReason::BindingNotActive)
        } else if self.card_changed {
            Some(ReadinessReason::CardChanged)
        } else if self.continuity_pending {
            Some(ReadinessReason::ContinuityPending)
        } else if self
            .since_last_seen_ms
            .is_none_or(|seen| seen >= offline_threshold_ms)
        {
            Some(ReadinessReason::OfflinePastThreshold)
        } else {
            None
        }
    }
}

/// A not-ready outcome for the caller to apply at the accept boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotReadyDecision {
    /// Refuse before acceptance: no message record, attempt or unknown
    /// outcome is created. The response carries the stable code and the
    /// targeted line's label.
    Refuse {
        code: &'static str,
        label: Option<String>,
    },
    /// Hold the message `queued` on the addressed line until it is ready or
    /// `expires_at_ms` passes (then `expired`). It never converts to another
    /// line on its own; dispatch still requires every existing fence.
    QueueOnLine { label: Option<String> },
    /// Send from the named fallback line. The decision already verified the
    /// fallback line's own admission; the caller must record which line
    /// actually sent so status, replies and audit stay truthful.
    SendFromFallback {
        fallback_line_id: [u8; 16],
        fallback_label: Option<String>,
    },
}

/// Admission facts a fallback line must independently satisfy: activated,
/// sealed/approved like any active line, and itself ready right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackFacts {
    pub line_id: [u8; 16],
    pub label: Option<String>,
    pub line_active: bool,
    pub binding_active: bool,
    pub continuity_pending: bool,
    pub card_changed: bool,
    pub since_last_seen_ms: Option<u64>,
    /// The fallback line's own suppression state for the recipient.
    pub recipient_suppressed: bool,
}

/// Inputs from the request and the addressed line's own suppression state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFacts {
    /// The recipient is suppressed on the addressed (target) line.
    pub target_recipient_suppressed: bool,
    /// The caller set the per-request no-fallback flag for this message.
    pub fallback_forbidden: bool,
    /// The submission's outcome is already ambiguous (`unknown`): it must
    /// never be retried on another line, because that could double-send.
    pub outcome_is_unknown: bool,
}

/// Decide what happens to a submission whose addressed line is not ready.
///
/// Suppression on the target line always refuses regardless of mode: a STOP
/// recorded on the target line must not be bypassed by queueing or falling
/// back. An `unknown` outcome likewise never produces a fallback send.
pub fn decide_not_ready(
    mode: NotReadyMode,
    offline_threshold_ms: u64,
    target: &LineFacts,
    fallback: Option<&FallbackFacts>,
    request: RequestFacts,
) -> NotReadyDecision {
    let reason = match target.not_ready_reason(offline_threshold_ms) {
        Some(reason) => reason,
        // A ready line needs no not-ready decision; routing proceeds on the
        // addressed line. The caller treats this decision as unreachable.
        None => {
            return NotReadyDecision::Refuse {
                code: reason_placeholder(),
                label: target.label.clone(),
            };
        }
    };
    if request.target_recipient_suppressed {
        return NotReadyDecision::Refuse {
            code: "recipient_suppressed",
            label: target.label.clone(),
        };
    }
    match mode {
        NotReadyMode::Ignore => NotReadyDecision::Refuse {
            code: reason.refusal_code(),
            label: target.label.clone(),
        },
        NotReadyMode::Queue => NotReadyDecision::QueueOnLine {
            label: target.label.clone(),
        },
        NotReadyMode::Fallback => {
            if request.outcome_is_unknown || request.fallback_forbidden {
                return NotReadyDecision::Refuse {
                    code: if request.outcome_is_unknown {
                        "line_not_ready_unknown_no_fallback"
                    } else {
                        "line_not_ready_fallback_forbidden"
                    },
                    label: target.label.clone(),
                };
            }
            let fallback = match fallback {
                Some(facts)
                    if facts.line_active
                        && facts.binding_active
                        && !facts.continuity_pending
                        && !facts.card_changed
                        && facts
                            .since_last_seen_ms
                            .is_some_and(|seen| seen < offline_threshold_ms)
                        && !facts.recipient_suppressed =>
                {
                    facts
                }
                _ => {
                    return NotReadyDecision::Refuse {
                        code: "line_not_ready_no_eligible_fallback",
                        label: target.label.clone(),
                    };
                }
            };
            NotReadyDecision::SendFromFallback {
                fallback_line_id: fallback.line_id,
                fallback_label: fallback.label.clone(),
            }
        }
    }
}

fn reason_placeholder() -> &'static str {
    // A ready line must not reach a not-ready decision; refusing keeps the
    // failure explicit instead of inventing a send.
    "line_ready_no_decision"
}

#[cfg(test)]
mod tests;
