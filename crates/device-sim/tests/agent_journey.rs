// SPDX-License-Identifier: AGPL-3.0-only
//! Quickstart harness for docs/AGENT-QUICKSTART.md. Runs the real simulator
//! binary (the guided command contributors use) and walks the documented
//! synthetic agent journey against its printed output. Everything here is a
//! fixture: no network, no radio, no AI provider.

use serde_json::Value;
use std::process::Command;

fn printed_scenario(name: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_zrotext-device-sim"))
        .output()
        .expect("simulator binary starts");
    assert!(output.status.success(), "simulator exits cleanly");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("simulator prints JSON");
    parsed["scenarios"]
        .as_array()
        .expect("scenarios form an array")
        .iter()
        .find(|scenario| scenario["scenario"] == name)
        .unwrap_or_else(|| panic!("printed matrix must include the {name} scenario"))
        .clone()
}

fn journey_event<'a>(scenario: &'a Value, event: &str) -> &'a Value {
    scenario["timeline"]
        .as_array()
        .expect("timeline forms an array")
        .iter()
        .find(|entry| entry["event"] == event)
        .unwrap_or_else(|| panic!("journey timeline must include {event}"))
}

#[test]
fn happy_path_finishes_submitted_without_an_unapproved_send() {
    let journey = printed_scenario("agent_journey");
    // The job-completion notification is accepted idempotently and reaches the
    // honest submission state: submitted is not delivered.
    assert_eq!(journey["final_state"], "submitted");
    assert_eq!(journey["radio_calls_modelled"], 1);
    let notification = journey_event(&journey, "notification_single_radio_call");
    assert_eq!(notification["outcome"], "submitted_not_delivered");
    // The owner's fixture reply is conversation input only.
    let reply = journey_event(&journey, "owner_fixture_reply");
    assert_eq!(reply["authority_granted"], "none");
    // The queued next action waits for authenticated owner approval: it never
    // reaches the modeled radio on its own.
    let queued = journey_event(&journey, "next_action_queued");
    assert_eq!(queued["awaiting"], "authenticated_owner_approval");
    assert_eq!(queued["radio_calls"], 0);
}

#[test]
fn adverse_states_refuse_every_documented_retry() {
    let journey = printed_scenario("agent_journey");
    // An edit after approval invalidates it; the same identity refuses
    // different content.
    let edited = journey_event(&journey, "edited_draft_refused");
    assert_eq!(edited["prior_approval"], "invalidated");
    // Opt-out cancels the pending action and a re-grant is refused.
    let opt_out = journey_event(&journey, "opt_out_cancelled_pending_action");
    assert_eq!(opt_out["regrant"], "rejected");
    // Revoked connector access fences the old session.
    let revoked = journey_event(&journey, "agent_access_revoked");
    assert_eq!(revoked["revoked_session_grant"], "rejected");
    // An offline lease expiry refuses the grant, and reconnecting never
    // auto-resends the ambiguous attempt.
    let expired = journey_event(&journey, "offline_lease_expired");
    assert_eq!(expired["grant"], "rejected");
    let reconnect = journey_event(&journey, "reconnect_after_expiry");
    assert_eq!(reconnect["retry"], "rejected");
    // An unknown submission stays unknown with one modeled radio call.
    let unknown = journey_event(&journey, "approved_followup_submission_unknown");
    assert_eq!(unknown["resubmit"], "rejected");
    assert_eq!(unknown["radio_calls"], 1);
    // A fenced writer refuses new requests; recovery starts dispatch-paused.
    let refusal = journey_event(&journey, "writer_refusal");
    assert_eq!(refusal["recovery"], "dispatch_paused");
}
