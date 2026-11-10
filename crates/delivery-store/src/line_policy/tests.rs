// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const THRESHOLD_MS: u64 = 300_000;

fn ready_line() -> LineFacts {
    LineFacts {
        label: Some("Business".to_owned()),
        line_active: true,
        binding_active: true,
        continuity_pending: false,
        card_changed: false,
        since_last_seen_ms: Some(1_000),
    }
}

fn not_ready(offline_ms: Option<u64>) -> LineFacts {
    LineFacts {
        since_last_seen_ms: offline_ms,
        ..ready_line()
    }
}

fn ready_fallback() -> FallbackFacts {
    FallbackFacts {
        line_id: [7u8; 16],
        label: Some("Personal".to_owned()),
        line_active: true,
        binding_active: true,
        continuity_pending: false,
        card_changed: false,
        since_last_seen_ms: Some(1_000),
        offline_threshold_ms: THRESHOLD_MS,
        recipient_suppressed: false,
    }
}

fn plain_request() -> RequestFacts {
    RequestFacts {
        target_recipient_suppressed: false,
        fallback_forbidden: false,
        outcome_is_unknown: false,
    }
}

#[test]
fn ignore_refuses_with_a_stable_code_and_the_line_label() {
    let decision = decide_not_ready(
        NotReadyMode::Ignore,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        None,
        plain_request(),
    );
    assert_eq!(
        decision,
        NotReadyDecision::Refuse {
            code: "line_not_ready_offline",
            label: Some("Business".to_owned()),
        }
    );
}

#[test]
fn ignore_is_the_mode_for_a_line_with_no_selection() {
    // Migration 098 defaults not_ready_mode to 'ignore'; the storage mapping
    // must therefore never treat the default as absent policy.
    assert_eq!(
        NotReadyMode::from_storage("ignore"),
        Some(NotReadyMode::Ignore)
    );
    assert_eq!(
        NotReadyMode::from_storage("queue"),
        Some(NotReadyMode::Queue)
    );
    assert_eq!(
        NotReadyMode::from_storage("fallback"),
        Some(NotReadyMode::Fallback)
    );
    assert_eq!(NotReadyMode::from_storage("tolerate"), None);
}

#[test]
fn queue_holds_on_the_addressed_line() {
    let decision = decide_not_ready(
        NotReadyMode::Queue,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        None,
        plain_request(),
    );
    assert_eq!(
        decision,
        NotReadyDecision::QueueOnLine {
            label: Some("Business".to_owned()),
        }
    );
}

#[test]
fn fallback_sends_from_the_named_eligible_line() {
    let fallback = ready_fallback();
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&fallback),
        plain_request(),
    );
    assert_eq!(
        decision,
        NotReadyDecision::SendFromFallback {
            fallback_line_id: [7u8; 16],
            fallback_label: Some("Personal".to_owned()),
        }
    );
}

#[test]
fn fallback_uses_its_own_offline_threshold() {
    let mut fallback = ready_fallback();
    fallback.since_last_seen_ms = Some(2_000);
    fallback.offline_threshold_ms = 1_000;
    assert!(matches!(
        decide_not_ready(
            NotReadyMode::Fallback,
            THRESHOLD_MS,
            &not_ready(None),
            Some(&fallback),
            plain_request()
        ),
        NotReadyDecision::Refuse {
            code: "line_not_ready_no_eligible_fallback",
            ..
        }
    ));
    fallback.offline_threshold_ms = 3_000;
    assert!(matches!(
        decide_not_ready(
            NotReadyMode::Fallback,
            1_000,
            &not_ready(None),
            Some(&fallback),
            plain_request()
        ),
        NotReadyDecision::SendFromFallback { .. }
    ));
}

#[test]
fn a_not_ready_line_without_any_observation_fails_closed_as_offline() {
    for mode in [
        NotReadyMode::Ignore,
        NotReadyMode::Queue,
        NotReadyMode::Fallback,
    ] {
        let decision = decide_not_ready(
            mode,
            THRESHOLD_MS,
            &not_ready(None),
            Some(&ready_fallback()),
            plain_request(),
        );
        match mode {
            // A hold on a never-observed line is still fail-closed: nothing
            // sends, and the message only leaves the queue if the line is
            // later observed ready.
            NotReadyMode::Queue => assert_eq!(
                decision,
                NotReadyDecision::QueueOnLine {
                    label: Some("Business".to_owned()),
                }
            ),
            _ => match decision {
                // Nothing ever sends from the never-observed line itself:
                // ignore refuses with the offline code, and fallback mode
                // routes to the eligible fallback instead of the target.
                NotReadyDecision::Refuse { code, .. } => assert_eq!(code, "line_not_ready_offline"),
                NotReadyDecision::SendFromFallback { .. } => {
                    assert_eq!(mode, NotReadyMode::Fallback)
                }
                other => panic!("no observation must not send from the target, got {other:?}"),
            },
        }
    }
}

#[test]
fn each_readiness_case_names_its_own_stable_code() {
    let cases: [(LineFacts, &str); 5] = [
        (
            LineFacts {
                line_active: false,
                ..ready_line()
            },
            "line_not_ready_inactive",
        ),
        (
            LineFacts {
                binding_active: false,
                ..ready_line()
            },
            "line_not_ready_binding_not_active",
        ),
        (
            LineFacts {
                card_changed: true,
                ..ready_line()
            },
            "line_not_ready_card_changed",
        ),
        (
            LineFacts {
                continuity_pending: true,
                ..ready_line()
            },
            "line_not_ready_continuity_pending",
        ),
        (
            LineFacts {
                since_last_seen_ms: Some(THRESHOLD_MS + 1),
                ..ready_line()
            },
            "line_not_ready_offline",
        ),
    ];
    for (facts, expected) in cases {
        let decision = decide_not_ready(
            NotReadyMode::Ignore,
            THRESHOLD_MS,
            &facts,
            None,
            plain_request(),
        );
        let NotReadyDecision::Refuse { code, .. } = decision else {
            panic!("expected refusal for {facts:?}");
        };
        assert_eq!(code, expected);
    }
}

#[test]
fn target_suppression_refuses_even_in_queue_or_fallback_mode() {
    let suppressed = RequestFacts {
        target_recipient_suppressed: true,
        ..plain_request()
    };
    for mode in [NotReadyMode::Queue, NotReadyMode::Fallback] {
        let decision = decide_not_ready(
            mode,
            THRESHOLD_MS,
            &not_ready(Some(THRESHOLD_MS * 2)),
            Some(&ready_fallback()),
            suppressed,
        );
        assert_eq!(
            decision,
            NotReadyDecision::Refuse {
                code: "recipient_suppressed",
                label: Some("Business".to_owned()),
            }
        );
    }
}

#[test]
fn fallback_line_suppression_blocks_the_fallback_send() {
    let suppressed_fallback = FallbackFacts {
        recipient_suppressed: true,
        ..ready_fallback()
    };
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&suppressed_fallback),
        plain_request(),
    );
    assert_eq!(
        decision,
        NotReadyDecision::Refuse {
            code: "line_not_ready_no_eligible_fallback",
            label: Some("Business".to_owned()),
        }
    );
}

#[test]
fn an_unknown_outcome_never_falls_back() {
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&ready_fallback()),
        RequestFacts {
            outcome_is_unknown: true,
            ..plain_request()
        },
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("an unknown outcome must not fall back");
    };
    assert_eq!(code, "line_not_ready_unknown_no_fallback");
}

#[test]
fn the_per_request_flag_forbids_fallback_as_a_refusal() {
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&ready_fallback()),
        RequestFacts {
            fallback_forbidden: true,
            ..plain_request()
        },
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("a forbidden fallback must refuse");
    };
    assert_eq!(code, "line_not_ready_fallback_forbidden");
}

#[test]
fn an_unready_fallback_line_is_not_eligible() {
    let stale = FallbackFacts {
        since_last_seen_ms: Some(THRESHOLD_MS * 3),
        ..ready_fallback()
    };
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&stale),
        plain_request(),
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("a stale fallback line must not send");
    };
    assert_eq!(code, "line_not_ready_no_eligible_fallback");
}

#[test]
fn a_fallback_line_with_a_changed_card_is_not_eligible() {
    let changed = FallbackFacts {
        card_changed: true,
        ..ready_fallback()
    };
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        Some(&changed),
        plain_request(),
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("a card-changed fallback line must not send");
    };
    assert_eq!(code, "line_not_ready_no_eligible_fallback");
}

#[test]
fn a_missing_fallback_nominates_no_line() {
    let decision = decide_not_ready(
        NotReadyMode::Fallback,
        THRESHOLD_MS,
        &not_ready(Some(THRESHOLD_MS * 2)),
        None,
        plain_request(),
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("fallback mode without a fallback line must refuse");
    };
    assert_eq!(code, "line_not_ready_no_eligible_fallback");
}

#[test]
fn a_ready_line_reaches_no_not_ready_decision() {
    let decision = decide_not_ready(
        NotReadyMode::Ignore,
        THRESHOLD_MS,
        &ready_line(),
        None,
        plain_request(),
    );
    // The caller must never consult a not-ready decision for a ready line;
    // the explicit refusal keeps an accidental call visible instead of
    // inventing a send or a hold.
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("a ready line must not be routed by the not-ready decision");
    };
    assert_eq!(code, "line_ready_no_decision");
}

#[test]
fn the_offline_threshold_is_per_line_not_global() {
    let short_threshold = 5_000;
    let decision = decide_not_ready(
        NotReadyMode::Ignore,
        short_threshold,
        &not_ready(Some(10_000)),
        None,
        plain_request(),
    );
    let NotReadyDecision::Refuse { code, .. } = decision else {
        panic!("a line past its own tighter threshold must refuse");
    };
    assert_eq!(code, "line_not_ready_offline");
}
