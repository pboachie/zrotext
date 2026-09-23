// SPDX-License-Identifier: AGPL-3.0-only
use serde_json::json;
use uuid::Uuid;
use zrotext_domain::{Authority, Evidence, MessageState, Rejection};

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn main() {
    let mut writer = Authority::new(1);
    let message = writer
        .accept(id(1), "request-1", "canonical-digest", id(2))
        .unwrap();
    let a = writer.connect(id(3), "site-a", "hub-a", 0, 90_000).unwrap();
    let grant = writer
        .grant(&a, message, id(4), 1, "recipient-digest", 0, 120_000)
        .unwrap();
    let mut timeline = vec![
        json!({"t_ms": 0, "event": "grant", "site": "site-a", "session_epoch": grant.session_epoch}),
    ];

    // Phone persists intent, calls the radio, then loses the ACK and restarts.
    writer
        .event(message, Evidence::DurableSubmitIntent)
        .unwrap();
    timeline.push(json!({"t_ms": 1, "event": "durable_submit_intent"}));
    writer
        .event(message, Evidence::CrashWithoutCallback)
        .unwrap();
    timeline.push(json!({"t_ms": 2, "event": "crash_without_callback", "state": "unknown"}));

    let b = writer.connect(id(3), "site-b", "hub-b", 3, 90_000).unwrap();
    let retry = writer.grant(&b, message, id(5), 2, "recipient-digest", 3, 120_000);
    assert_eq!(retry, Err(Rejection::GrantAlreadyIssued));
    timeline.push(json!({"t_ms": 3, "event": "hub_move", "site": "site-b", "session_epoch": b.epoch, "retry": "rejected"}));

    writer.writer_available = false;
    let isolated = writer.accept(id(1), "request-2", "canonical-digest", id(6));
    assert_eq!(isolated, Err(Rejection::WriterUnavailable));
    timeline.push(json!({"t_ms": 4, "event": "writer_unreachable", "new_write": "rejected"}));

    assert_eq!(writer.state(message), Some(MessageState::Unknown));
    println!("{}", serde_json::to_string_pretty(&json!({"scenario": "two_hubs_ambiguous_radio_submit", "timeline": timeline, "final_state": "unknown", "radio_calls_modelled": 1})).unwrap());
}
