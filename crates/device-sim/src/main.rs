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

fn matrix() -> Vec<Value> {
    vec![
        dropped_ack(),
        writer_loss(),
        stale_hub(),
        lease_expiry_reconnect(),
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
