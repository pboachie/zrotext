// SPDX-License-Identifier: AGPL-3.0-only
//! Deterministic two-hub fault matrix. Both hubs share one modeled writer.
//! Radio calls are counters at the durable-intent boundary, not device I/O.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zrotext_domain::{Authority, Evidence, MessageState, Rejection};

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[derive(Default)]
struct ModelPhone {
    journaled: BTreeSet<Uuid>,
    radio_calls: BTreeMap<Uuid, u8>,
}

impl ModelPhone {
    fn submit(&mut self, writer: &mut Authority, message: Uuid) -> bool {
        // The modeled local journal records intent before the radio. A
        // repeated invocation cannot cross that boundary a second time.
        if !self.journaled.insert(message) {
            return false;
        }
        writer
            .event(message, Evidence::DurableSubmitIntent)
            .unwrap();
        *self.radio_calls.entry(message).or_default() += 1;
        true
    }

    fn calls(&self, message: Uuid) -> u8 {
        self.radio_calls.get(&message).copied().unwrap_or_default()
    }
}

fn report(name: &str, writer: &Authority, message: Uuid, calls: u8, timeline: Vec<Value>) -> Value {
    json!({
        "scenario": name,
        "timeline": timeline,
        "final_state": writer.state(message).expect("accepted message has a state"),
        "radio_calls_modelled": calls,
    })
}

fn dropped_ack() -> Value {
    let mut writer = Authority::new(1);
    let mut phone = ModelPhone::default();
    let message = writer.accept(id(1), "key", "digest", id(2)).unwrap();
    // Client loses the acceptance ACK and retries with the same identity.
    assert_eq!(writer.accept(id(1), "key", "digest", id(99)), Ok(message));
    let a = writer.connect(id(3), "site-a", "hub-a", 2, 50).unwrap();
    writer.grant(&a, message, id(4), 1, "r", 2, 40).unwrap();
    assert!(phone.submit(&mut writer, message));
    // The result ACK is lost too. Timeout is unknown, never a new send grant.
    assert_eq!(
        writer.event(message, Evidence::SentCallbackTimeout),
        Ok(MessageState::Unknown)
    );
    let b = writer.connect(id(3), "site-b", "hub-b", 41, 50).unwrap();
    assert_eq!(
        writer.grant(&b, message, id(5), 2, "r", 41, 80),
        Err(Rejection::GrantAlreadyIssued)
    );
    assert!(!phone.submit(&mut writer, message));
    report(
        "dropped_ack",
        &writer,
        message,
        phone.calls(message),
        vec![
            json!({"t_ms": 0, "event": "acceptance_ack_dropped"}),
            json!({"t_ms": 1, "event": "accept_replay", "same_message": true}),
            json!({"t_ms": 2, "event": "durable_intent_and_radio_call"}),
            json!({"t_ms": 41, "event": "result_ack_missing_and_reconnect", "retry": "rejected"}),
        ],
    )
}

fn writer_loss() -> Value {
    let mut writer = Authority::new(1);
    let mut phone = ModelPhone::default();
    let message = writer.accept(id(1), "key-1", "digest-1", id(2)).unwrap();
    let other = writer.accept(id(1), "key-2", "digest-2", id(6)).unwrap();
    let a = writer.connect(id(3), "site-a", "hub-a", 0, 50).unwrap();
    writer.grant(&a, message, id(4), 1, "r", 0, 40).unwrap();
    assert!(phone.submit(&mut writer, message));
    writer.writer_available = false;
    assert_eq!(
        writer.event(message, Evidence::SentCallbackOk),
        Err(Rejection::WriterUnavailable)
    );
    assert_eq!(
        writer.connect(id(3), "site-b", "hub-b", 1, 50),
        Err(Rejection::WriterUnavailable)
    );
    assert_eq!(
        writer.grant(&a, other, id(7), 1, "r", 1, 40),
        Err(Rejection::WriterUnavailable)
    );
    assert_eq!(
        writer.accept(id(1), "key-3", "digest-3", id(8)),
        Err(Rejection::WriterUnavailable)
    );

    // Recovery begins dispatch-paused until an ambiguous attempt is reconciled.
    writer.writer_available = true;
    writer.dispatch_enabled = false;
    let b = writer.connect(id(3), "site-b", "hub-b", 2, 50).unwrap();
    assert_eq!(
        writer.grant(&b, other, id(7), 1, "r", 2, 40),
        Err(Rejection::DispatchDisabled)
    );
    assert_eq!(
        writer.event(message, Evidence::CrashWithoutCallback),
        Ok(MessageState::Unknown)
    );
    writer.dispatch_enabled = true;
    assert_eq!(
        writer.grant(&b, message, id(5), 2, "r", 3, 40),
        Err(Rejection::GrantAlreadyIssued)
    );
    assert_eq!(
        writer.grant(&b, other, id(7), 1, "r", 3, 40),
        Err(Rejection::DeviceBusy)
    );
    assert!(!phone.submit(&mut writer, message));
    report(
        "writer_loss",
        &writer,
        message,
        phone.calls(message),
        vec![
            json!({"t_ms": 0, "event": "grant_and_radio_call", "site": "site-a"}),
            json!({"t_ms": 1, "event": "writer_lost", "new_writes": "rejected"}),
            json!({"t_ms": 2, "event": "writer_restored_dispatch_paused", "new_grants": "rejected"}),
            json!({"t_ms": 3, "event": "reconciliation_unknown", "retry": "rejected"}),
        ],
    )
}

fn stale_hub() -> Value {
    let mut writer = Authority::new(1);
    let mut phone = ModelPhone::default();
    let message = writer.accept(id(1), "key", "digest", id(2)).unwrap();
    let a = writer.connect(id(3), "site-a", "hub-a", 0, 50).unwrap();
    let b = writer.connect(id(3), "site-b", "hub-b", 1, 50).unwrap();
    assert_eq!(
        writer.grant(&a, message, id(4), 1, "r", 2, 40),
        Err(Rejection::SessionStale)
    );
    writer.grant(&b, message, id(5), 1, "r", 2, 40).unwrap();
    assert!(phone.submit(&mut writer, message));
    let a_again = writer.connect(id(3), "site-a", "hub-a", 3, 50).unwrap();
    assert_eq!(
        writer.grant(&b, message, id(6), 2, "r", 3, 40),
        Err(Rejection::SessionStale)
    );
    assert_eq!(
        writer.grant(&a_again, message, id(7), 2, "r", 3, 40),
        Err(Rejection::GrantAlreadyIssued)
    );
    assert_eq!(
        writer.event(message, Evidence::SentCallbackOk),
        Ok(MessageState::Submitted)
    );
    report(
        "stale_hub",
        &writer,
        message,
        phone.calls(message),
        vec![
            json!({"t_ms": 2, "event": "hub_b_replaces_a", "stale_a_grant": "rejected"}),
            json!({"t_ms": 3, "event": "hub_a_replaces_b", "stale_b_grant": "rejected", "duplicate_grant": "rejected"}),
        ],
    )
}

fn lease_expiry_reconnect() -> Value {
    let mut writer = Authority::new(1);
    let message = writer.accept(id(1), "key", "digest", id(2)).unwrap();
    let a = writer.connect(id(3), "site-a", "hub-a", 0, 10).unwrap();
    assert_eq!(
        writer.grant(&a, message, id(4), 1, "r", 10, 25),
        Err(Rejection::LeaseExpired)
    );
    let b = writer.connect(id(3), "site-b", "hub-b", 11, 10).unwrap();
    assert_eq!(
        writer.grant(&a, message, id(4), 1, "r", 11, 25),
        Err(Rejection::SessionStale)
    );
    writer.grant(&b, message, id(5), 1, "r", 11, 25).unwrap();
    // Without durable proof of non-submission, expiry remains ambiguous even
    // though this virtual scenario made zero radio calls.
    assert_eq!(
        writer.event(message, Evidence::GrantTimeout),
        Ok(MessageState::Unknown)
    );
    let a_again = writer.connect(id(3), "site-a", "hub-a", 26, 50).unwrap();
    assert_eq!(
        writer.grant(&a_again, message, id(6), 2, "r", 26, 80),
        Err(Rejection::GrantAlreadyIssued)
    );
    report(
        "lease_expiry_reconnect",
        &writer,
        message,
        0,
        vec![
            json!({"t_ms": 10, "event": "lease_expired", "grant": "rejected"}),
            json!({"t_ms": 11, "event": "reconnect_to_b", "stale_a_grant": "rejected"}),
            json!({"t_ms": 26, "event": "grant_timeout_and_reconnect", "retry": "rejected"}),
        ],
    )
}

/// Synthetic agent journey for docs/AGENT-QUICKSTART.md. The "agent" is a
/// scripted fixture: a job-completion notification, a fixture owner reply that
/// grants nothing, and a next action that waits for authenticated approval.
/// Radio calls remain counters; nothing here is device I/O or a model call.
fn agent_journey() -> Value {
    let mut writer = Authority::new(1);
    let mut phone = ModelPhone::default();
    // The agent finishes a fictional job and queues one notification. A lost
    // acceptance ACK replays to the same synthetic message identity.
    let note = writer
        .accept(id(1), "agent-note-1", "note-v1", id(2))
        .unwrap();
    assert_eq!(
        writer.accept(id(1), "agent-note-1", "note-v1", id(99)),
        Ok(note)
    );
    let hub = writer.connect(id(3), "owner-hub", "hub-1", 1, 50).unwrap();
    writer.grant(&hub, note, id(4), 1, "owner", 1, 40).unwrap();
    assert!(phone.submit(&mut writer, note));
    // Submitted is not delivered; the receipt stays a separate honest step.
    assert_eq!(
        writer.event(note, Evidence::SentCallbackOk),
        Ok(MessageState::Submitted)
    );

    // The owner's fixture reply is conversation input. It grants no authority:
    // the next action queues under its own identity and waits for approval.
    let action = writer
        .accept(id(1), "agent-follow-up", "action-v1", id(5))
        .unwrap();
    assert_eq!(writer.state(action), Some(MessageState::Queued));
    assert_eq!(phone.calls(action), 0);
    // Editing the draft after approval invalidates it: the approved identity
    // refuses different content, so approval restarts under a fresh identity.
    assert_eq!(
        writer.accept(id(1), "agent-follow-up", "action-v2", id(50)),
        Err(Rejection::DuplicateKeyDifferentRequest)
    );
    let edited = writer
        .accept(id(1), "agent-follow-up-v2", "action-v2", id(6))
        .unwrap();

    // The owner opts out before approving: the pending action cancels and can
    // never be re-granted. A message already submitted is not recalled.
    assert_eq!(
        writer.event(edited, Evidence::Cancel),
        Ok(MessageState::Cancelled)
    );
    assert_eq!(
        writer.grant(&hub, edited, id(9), 1, "owner", 10, 40),
        Err(Rejection::InvalidState)
    );
    assert_eq!(phone.calls(edited), 0);

    // The owner later approves a renewed follow-up. Its result callback is
    // lost: unknown, never auto-resent, at most one modeled radio call.
    let renewed = writer
        .accept(id(1), "agent-follow-up-v3", "action-v3", id(7))
        .unwrap();
    writer
        .grant(&hub, renewed, id(8), 1, "owner", 11, 40)
        .unwrap();
    assert!(phone.submit(&mut writer, renewed));
    assert_eq!(
        writer.event(renewed, Evidence::SentCallbackTimeout),
        Ok(MessageState::Unknown)
    );
    assert_eq!(
        writer.grant(&hub, renewed, id(10), 2, "owner", 12, 40),
        Err(Rejection::GrantAlreadyIssued)
    );
    assert!(!phone.submit(&mut writer, renewed));

    // The owner revokes the agent connector: reconnecting fences the old hub
    // session and its grant is refused.
    let hub_two = writer.connect(id(3), "owner-hub", "hub-2", 20, 10).unwrap();
    assert_eq!(
        writer.grant(&hub, action, id(11), 2, "owner", 20, 40),
        Err(Rejection::SessionStale)
    );

    // The connector goes offline past its lease: the grant is refused and,
    // without durable proof of non-submission, reconnecting never retries.
    assert_eq!(
        writer.grant(&hub_two, action, id(11), 2, "owner", 30, 40),
        Err(Rejection::LeaseExpired)
    );
    let hub_three = writer.connect(id(3), "owner-hub", "hub-3", 31, 50).unwrap();
    assert_eq!(
        writer.grant(&hub_three, renewed, id(12), 2, "owner", 31, 80),
        Err(Rejection::GrantAlreadyIssued)
    );

    // A fenced writer refuses new requests instead of buffering them, and
    // recovery starts dispatch-paused.
    writer.writer_available = false;
    assert_eq!(
        writer.accept(id(1), "agent-note-2", "note-v2", id(13)),
        Err(Rejection::WriterUnavailable)
    );
    assert_eq!(
        writer.event(note, Evidence::DeliveryCallbackOk),
        Err(Rejection::WriterUnavailable)
    );
    writer.writer_available = true;
    writer.dispatch_enabled = false;
    assert_eq!(
        writer.grant(&hub_three, action, id(14), 2, "owner", 40, 80),
        Err(Rejection::DispatchDisabled)
    );
    report(
        "agent_journey",
        &writer,
        note,
        phone.calls(note),
        vec![
            json!({"t_ms": 1, "event": "job_completed_fixture_and_notification_accepted", "replay": "same_message"}),
            json!({"t_ms": 2, "event": "notification_single_radio_call", "outcome": "submitted_not_delivered"}),
            json!({"t_ms": 3, "event": "owner_fixture_reply", "authority_granted": "none"}),
            json!({"t_ms": 4, "event": "next_action_queued", "awaiting": "authenticated_owner_approval", "radio_calls": 0}),
            json!({"t_ms": 5, "event": "edited_draft_refused", "prior_approval": "invalidated"}),
            json!({"t_ms": 10, "event": "opt_out_cancelled_pending_action", "regrant": "rejected"}),
            json!({"t_ms": 11, "event": "approved_followup_submission_unknown", "resubmit": "rejected", "radio_calls": 1}),
            json!({"t_ms": 20, "event": "agent_access_revoked", "revoked_session_grant": "rejected"}),
            json!({"t_ms": 30, "event": "offline_lease_expired", "grant": "rejected"}),
            json!({"t_ms": 31, "event": "reconnect_after_expiry", "retry": "rejected"}),
            json!({"t_ms": 40, "event": "writer_refusal", "recovery": "dispatch_paused"}),
        ],
    )
}

fn matrix() -> Vec<Value> {
    vec![
        dropped_ack(),
        writer_loss(),
        stale_hub(),
        lease_expiry_reconnect(),
        agent_journey(),
    ]
}

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"scenarios": matrix()})).unwrap()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_attempts_never_get_a_second_modeled_radio_call() {
        for scenario in matrix() {
            assert!(scenario["radio_calls_modelled"].as_u64().unwrap() <= 1);
            if scenario["final_state"] == "unknown" {
                assert_eq!(
                    scenario["timeline"].as_array().unwrap().last().unwrap()["retry"],
                    "rejected"
                );
            }
        }
    }
}
