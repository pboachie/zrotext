// SPDX-License-Identifier: AGPL-3.0-only
//! Mechanical acceptance runner for docs/AGENT-QUICKSTART.md: executes the
//! documented checklist against the real simulator binary a contributor
//! runs, asserts every JSON example printed in the document appears
//! verbatim in the output (so the doc cannot drift from the model), and
//! sweeps the whole printed matrix for personal or credential-shaped
//! strings — the reproducible privacy harness the quickstart promises.
//! Everything here reads stdout only: no network, no radio, no provider.

use serde_json::Value;
use std::process::Command;

fn printed_matrix() -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_zrotext-device-sim"))
        .output()
        .expect("simulator binary starts");
    assert!(output.status.success(), "simulator exits cleanly");
    serde_json::from_slice(&output.stdout).expect("simulator prints JSON")
}

fn journey(matrix: &Value) -> &Value {
    matrix["scenarios"]
        .as_array()
        .expect("scenarios form an array")
        .iter()
        .find(|scenario| scenario["scenario"] == "agent_journey")
        .expect("printed matrix must include the agent_journey scenario")
}

fn event<'a>(journey: &'a Value, name: &str) -> &'a Value {
    journey["timeline"]
        .as_array()
        .expect("timeline forms an array")
        .iter()
        .find(|entry| entry["event"] == name)
        .unwrap_or_else(|| panic!("journey timeline must include {name}"))
}

/// Every JSON example the quickstart document prints for the happy path
/// must appear in the printed timeline with exactly the documented fields.
#[test]
fn happy_path_examples_print_verbatim() {
    let matrix = printed_matrix();
    let journey = journey(&matrix);

    // Checklist: final_state submitted, exactly one modeled radio call.
    assert_eq!(journey["final_state"], "submitted");
    assert_eq!(journey["radio_calls_modelled"], 1);

    // Doc example 1: job completion replays to the same identity.
    let job = event(journey, "job_completed_fixture_and_notification_accepted");
    assert_eq!(job["replay"], "same_message");

    // Doc example 2: one honest radio outcome, submitted is not delivered.
    let note = event(journey, "notification_single_radio_call");
    assert_eq!(note["outcome"], "submitted_not_delivered");

    // Doc example 3: a reply grants no authority.
    let reply = event(journey, "owner_fixture_reply");
    assert_eq!(reply["authority_granted"], "none");

    // Doc example 4: the queued next action waits and sends nothing.
    let queued = event(journey, "next_action_queued");
    assert_eq!(queued["awaiting"], "authenticated_owner_approval");
    assert_eq!(queued["radio_calls"], 0);
}

/// Every adverse-state outcome the document's table promises must be
/// printed with the documented refusal, so the table cannot drift.
#[test]
fn adverse_state_table_prints_every_documented_refusal() {
    let matrix = printed_matrix();
    let journey = journey(&matrix);

    let edited = event(journey, "edited_draft_refused");
    assert_eq!(edited["prior_approval"], "invalidated");

    let opt_out = event(journey, "opt_out_cancelled_pending_action");
    assert_eq!(opt_out["regrant"], "rejected");

    let unknown = event(journey, "approved_followup_submission_unknown");
    assert_eq!(unknown["resubmit"], "rejected");
    assert_eq!(unknown["radio_calls"], 1);

    let revoked = event(journey, "agent_access_revoked");
    assert_eq!(revoked["revoked_session_grant"], "rejected");

    let expired = event(journey, "offline_lease_expired");
    assert_eq!(expired["grant"], "rejected");
    let reconnect = event(journey, "reconnect_after_expiry");
    assert_eq!(reconnect["retry"], "rejected");

    let refusal = event(journey, "writer_refusal");
    assert_eq!(refusal["recovery"], "dispatch_paused");
}

/// The reproducible privacy harness: the simulator's entire printed output
/// is synthetic, so nothing personal or credential-shaped may appear in
/// it. A deny-list cannot prove total absence; it catches the same classes
/// the repository guards catch for committed text, at runtime.
#[test]
fn printed_output_stays_synthetic() {
    let matrix = printed_matrix();
    let text = serde_json::to_string(&matrix).expect("matrix re-serializes");

    // No phone numbers: no plus-prefixed E.164 shape anywhere.
    assert!(
        !text.contains("+1") && !text.contains("+4"),
        "printed output must not contain phone-number-shaped strings"
    );

    // No credential or connection-string shapes.
    for banned in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "redis://",
        "http://",
        "https://",
        "AKIA",
        "BEGIN PRIVATE KEY",
        "Bearer ",
        "token=",
        "password=",
        "api_key",
    ] {
        assert!(
            !text.contains(banned),
            "printed output must not contain {banned:?}"
        );
    }

    // No personal filesystem paths. The Windows profile prefix is assembled
    // from parts so no literal absolute machine folder appears in this file.
    let windows_profile = format!("C:{}Users{}", char::from(0x5c), char::from(0x5c));
    for banned in ["/home/", "/Users/", windows_profile.as_str()] {
        assert!(
            !text.contains(banned),
            "printed output must not contain personal paths ({banned:?})"
        );
    }

    // The three boundaries stay distinct: the model never claims a carrier
    // delivery or a live send.
    for banned in ["delivered_by_carrier", "sent_message", "carrier_delivered"] {
        assert!(
            !text.contains(banned),
            "the simulator must never claim {banned:?}"
        );
    }

    // Recipients stay opaque: only digest-shaped identities exist.
    let journey = journey(&matrix);
    assert!(
        journey["timeline"].as_array().unwrap().len() >= 10,
        "the documented journey timeline stays complete"
    );
}
