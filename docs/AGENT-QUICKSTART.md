# Agent texting quickstart (simulator)

Try the planned agent experience with no Android phone, SIM, gateway deployment, AI-provider account or messaging tool. Everything in this walkthrough is a synthetic fixture: the simulator models delivery decisions as counters and timelines, sends nothing, and contacts nobody.

**Planned; unavailable for real traffic.** This page walks a proposed journey (#614), not a released capability. Real traffic remains behind the existing general-send, sealed-content, line-activation and release gates.

## What exists today

- The deterministic two-hub fault matrix in `crates/device-sim`, including the `agent_journey` scenario this page walks through. It is a pure model: radio calls are counters at the durable-intent boundary, never device I/O.
- The browser [receptionist simulation](RECEPTIONIST-DEMO.md), which explores the same owner-approval interaction design.
- A dormant conversation simulator, loopback-only, behind the `conversation-simulator-tests` feature and `scripts/conversation_simulator.py`. No production route consumes it.

No AI agent, MCP server, tool adapter, guided setup command or reply-event feed exists in this repository today; those are planned in #616, #617, #618, #619 and #620. The "agent" below is a scripted fixture, not a model call. Running this quickstart uses no AI-provider credits, Google Play services, real SMS, personal numbers or production credentials.

## Launch

```sh
cargo run --locked -p zrotext-device-sim
```

The command prints a JSON matrix of scenarios. Find the one named `agent_journey`. Every field in it is synthetic: timestamps are tick counters, the recipient is an opaque digest (no phone number exists in the simulator), and `radio_calls_modelled` counts a modeled boundary crossing, not a radio operation.

## The synthetic journey

The scenario follows one fictional agent serving one fictional owner line.

1. **Job completion.** The agent finishes a scripted job and queues one notification. A lost acceptance ACK replays to the same message identity, so a retry cannot create a second send:

   ```json
   {"t_ms": 1, "event": "job_completed_fixture_and_notification_accepted", "replay": "same_message"}
   ```

2. **Permitted notification.** The owner's modeled hub grants the notification and the model records exactly one radio call. The outcome is honest, not optimistic:

   ```json
   {"t_ms": 2, "event": "notification_single_radio_call", "outcome": "submitted_not_delivered"}
   ```

   Submitted is not delivered; a delivery receipt would be a separate later step.

3. **Owner reply.** A fixture reply arrives. It is conversation input only — an inbound message grants no authority:

   ```json
   {"t_ms": 3, "event": "owner_fixture_reply", "authority_granted": "none"}
   ```

4. **Next action queued for approval.** The agent queues its proposed follow-up and stops. Nothing reaches the modeled radio before an authenticated owner approval:

   ```json
   {"t_ms": 4, "event": "next_action_queued", "awaiting": "authenticated_owner_approval", "radio_calls": 0}
   ```

## Adverse states, also synthetic

The same timeline continues through refusal and unavailable states. Each documented outcome is asserted in code, not just narrated.

| State | Timeline event | Documented outcome |
|---|---|---|
| Edited draft after approval | `edited_draft_refused` | `prior_approval: "invalidated"` — the approved identity refuses different content; approval restarts under a fresh identity |
| Opt-out before approval | `opt_out_cancelled_pending_action` | `regrant: "rejected"` — the pending action cancels; a submitted message is not recalled |
| Unknown submission | `approved_followup_submission_unknown` | `resubmit: "rejected"`, `radio_calls: 1` — an ambiguous result never triggers a second send |
| Revoked agent access | `agent_access_revoked` | `revoked_session_grant: "rejected"` — the fenced old session cannot grant |
| Offline lease expiry | `offline_lease_expired`, `reconnect_after_expiry` | `grant: "rejected"`, `retry: "rejected"` — reconnecting never auto-resends without durable proof of non-submission |
| Fenced writer (refusal) | `writer_refusal` | `recovery: "dispatch_paused"` — new requests are refused, not buffered, and recovery starts paused |

Three boundaries stay distinct throughout: simulated acceptance (queued), modeled radio submission (submitted), and carrier delivery (never claimed here — no carrier exists in the model). `unknown` is not `failed`; it is an honest "cannot know", and the model refuses to guess by retrying.

## Acceptance checklist

Run these from a clean checkout. Every check is offline.

- [ ] `cargo run --locked -p zrotext-device-sim` prints `agent_journey` with `"final_state": "submitted"` and `"radio_calls_modelled": 1`.
- [ ] The queued next action shows `"awaiting": "authenticated_owner_approval"` with `"radio_calls": 0`; nothing sends before approval.
- [ ] Every adverse state above appears in the timeline with its rejected retry.
- [ ] `cargo test --locked -p zrotext-device-sim` passes, including the `agent_journey` harness tests.
- [ ] The run needed no device, SIM, credential, network or provider account; nothing was sent.

## Reproducible privacy and security harness

`crates/device-sim/tests/agent_journey.rs` is the durable harness for this page. It runs the real simulator binary — the same command a contributor uses — parses the printed JSON, and asserts the happy path and every adverse outcome above, so the documentation cannot drift from the model. It is deterministic and runs in CI through normal Cargo test discovery (`cargo test --locked --workspace`).

Safety properties that keep this quickstart safe to publish and rerun:

- The simulator has no live mode at all: no radio API, no send route, no credentials. Accidental live activation is impossible by construction; real sending is gated elsewhere (see [SMS compliance](SMS-COMPLIANCE.md)).
- The simulator contains no phone numbers or message bodies; recipients are opaque digests.
- Repository guards reject non-synthetic numbers, credential-shaped strings and personal paths in committed text: `python scripts/privacy_guard.py` and `python scripts/check_public_tree.py`.
- Screenshots, session logs, scratch output and evidence captures belong in temporary storage or the private operations repository, never in this repository. Public docs carry durable synthetic examples only.

Report suspected vulnerabilities privately as described in [SECURITY.md](../SECURITY.md), never in public issues, pull requests or commit messages.

## What this does not prove, and the pilot handoff

This simulator models decisions, not delivery. It does not prove:

- carrier delivery or delivery receipts from any network;
- behavior on a real Android phone or SIM (reboots, signal, battery, radio firmware);
- any production tool adapter, MCP server or AI integration — none exists yet;
- emergency readiness. Emergency numbers and safety-critical promises are outside the proposed agent workflows.

A later controlled-device pilot (tracked under #614) must verify revocation, suppression, offline expiry, event replay and honest delivery states on a controlled device with the maintainer present before any availability claim. A green simulator run is the entry ticket to that pilot, not a substitute for it.

## Verification

`cargo test --locked -p zrotext-device-sim` runs the scenario's internal assertions plus the `agent_journey` harness tests through standard Cargo test discovery. CI runs the same suite via `cargo test --locked --workspace` and prints the timeline with `target/debug/zrotext-device-sim` after building it. The tests cover the happy path, approval invalidation after an edit, opt-out, revocation, offline expiry, unknown submission, and fenced-writer refusal.
