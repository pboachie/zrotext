// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const scenarios = Object.freeze({
  service: {
    context: "A fictional repair team receives an inquiry. Availability is unverified.",
    sender: "Sample customer", incoming: "Could someone fix a dripping kitchen tap? I'm usually home after 4.",
    intent: "Repair inquiry", details: "Kitchen tap · prefers after 4", next: "Ask for a preferred day; a person checks availability.",
    draft: "Thanks for getting in touch. Which day works best after 4? Our team will check availability before confirming a visit.",
  },
  wedding: {
    context: "A fictional guest replies to an invitation they agreed to receive.",
    sender: "Sample guest", incoming: "We'd love to come! Two of us, with one vegetarian meal please.",
    intent: "Wedding RSVP", details: "Two guests · one vegetarian meal", next: "Confirm the reply; host reviews the guest list.",
    draft: "Thanks! We have your reply as two guests, with one vegetarian meal. The host will review the guest list and confirm the details.",
  },
  assistant: {
    context: "A fictional owner texts their assistant. No calendar is connected.",
    sender: "Sample owner", incoming: "Remind me to bring the library books when I leave tomorrow.",
    intent: "Personal reminder request", details: "Library books · tomorrow · time missing", next: "Ask for a time before proposing a reminder.",
    draft: "What time should I remind you tomorrow? I have not created a reminder yet. I will ask you to confirm the time first.",
  },
});

function initialState(scenario = "service") {
  if (!Object.hasOwn(scenarios, scenario)) throw new Error("Unknown scenario");
  return { scenario, draft: scenarios[scenario].draft, approved: null, outbound: null,
    delivery: "none", blocked: false, handoff: false };
}

function transition(state, action) {
  if (action.type === "reset") return initialState(action.scenario || state.scenario);
  if (action.type === "opt_out") return { ...state, blocked: true, approved: null,
    delivery: state.delivery === "queued" ? "cancelled" : state.delivery };
  if (action.type === "handoff") return { ...state, handoff: true, approved: null,
    delivery: state.delivery === "queued" ? "cancelled" : state.delivery };
  const canDraft = !state.blocked && !state.handoff && state.delivery === "none";
  if (action.type === "edit" && canDraft && typeof action.text === "string") {
    return { ...state, draft: action.text.slice(0, 480), approved: null };
  }
  if (action.type === "approve" && canDraft && state.draft.trim()) return { ...state, approved: state.draft };
  if (action.type === "queue" && canDraft && state.approved === state.draft && state.draft.trim()) {
    return { ...state, delivery: "queued", outbound: state.draft, approved: null };
  }
  if (action.type === "submit" && state.delivery === "queued" && !state.blocked && !state.handoff) {
    return { ...state, delivery: "submitted" };
  }
  if (action.type === "receipt" && ["submitted", "delivery_unknown"].includes(state.delivery)) return { ...state, delivery: "delivered" };
  if (action.type === "unknown" && state.delivery === "submitted") return { ...state, delivery: "delivery_unknown" };
  return state;
}

function statusText(state) {
  const delivery = {
    none: state.approved === state.draft ? "Draft approved. Ready to queue in the simulation." : "Awaiting your review. Nothing has been queued.",
    queued: "Queued in simulation. Waiting for the phone.",
    submitted: "Submitted in simulation. Delivery is not confirmed.",
    delivered: "Delivered in simulation, with a simulated receipt.",
    delivery_unknown: "Delivery unknown in simulation. No automatic resend.",
    cancelled: "Queued reply cancelled in simulation.",
  }[state.delivery];
  return `${state.blocked ? "Recipient blocked. " : ""}${state.handoff ? "A person has taken over. " : ""}${delivery}`;
}

function mount(document) {
  const get = (id) => document.getElementById(id);
  let state = initialState();
  function render() {
    const scenario = scenarios[state.scenario];
    get("scenario").value = state.scenario;
    get("scenario-context").textContent = scenario.context;
    get("intake").replaceChildren();
    for (const [label, value] of [["Intent", scenario.intent], ["Captured", scenario.details], ["Next step", scenario.next]]) {
      const term = document.createElement("dt"); term.textContent = label;
      const detail = document.createElement("dd"); detail.textContent = value;
      get("intake").append(term, detail);
    }
    const incoming = document.createElement("li");
    const sender = document.createElement("strong"); sender.textContent = scenario.sender;
    const text = document.createElement("span"); text.textContent = scenario.incoming;
    incoming.append(sender, text);
    get("conversation").replaceChildren(incoming);
    if (state.outbound !== null) {
      const outgoing = document.createElement("li"); outgoing.className = "outgoing";
      const label = document.createElement("strong"); label.textContent = `Simulated reply · ${state.delivery.replaceAll("_", " ")}`;
      const body = document.createElement("span"); body.textContent = state.outbound;
      outgoing.append(label, body); get("conversation").append(outgoing);
    }
    get("draft").value = state.draft;
    const canDraft = !state.blocked && !state.handoff && state.delivery === "none";
    get("draft").disabled = !canDraft;
    get("approve").disabled = !canDraft || !state.draft.trim() || state.approved === state.draft;
    get("queue").disabled = !canDraft || !state.draft.trim() || state.approved !== state.draft;
    get("advance").disabled = state.delivery !== "queued" || state.blocked || state.handoff;
    get("receipt").disabled = !["submitted", "delivery_unknown"].includes(state.delivery);
    get("unknown").disabled = state.delivery !== "submitted";
    get("opt-out").disabled = state.blocked;
    get("takeover").disabled = state.handoff;
    get("status").textContent = statusText(state);
    get("delivery-detail").textContent = state.blocked && ["submitted", "delivered", "delivery_unknown"].includes(state.delivery)
      ? "An opt-out blocks future replies. It cannot recall a message already submitted. A late receipt may still arrive."
      : "Advance the synthetic phone and receipt separately. Queued or submitted does not mean delivered.";
  }
  const dispatch = (action) => { state = transition(state, action); render(); };
  for (const [id, type] of [["approve", "approve"], ["queue", "queue"], ["advance", "submit"], ["receipt", "receipt"], ["unknown", "unknown"], ["opt-out", "opt_out"], ["takeover", "handoff"], ["reset", "reset"]]) {
    get(id).addEventListener("click", () => dispatch({ type }));
  }
  get("scenario").addEventListener("change", () => dispatch({ type: "reset", scenario: get("scenario").value }));
  get("draft").addEventListener("input", () => {
    // Keep the editor selection stable while updating approval controls.
    state = transition(state, { type: "edit", text: get("draft").value });
    get("approve").disabled = !state.draft.trim();
    get("queue").disabled = true;
    get("status").textContent = statusText(state);
  });
  render();
}

if (typeof module !== "undefined") module.exports = { initialState, transition, statusText, mount };
if (typeof document !== "undefined") mount(document);
