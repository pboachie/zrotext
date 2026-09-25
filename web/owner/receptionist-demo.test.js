// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { initialState, transition: step, statusText, mount } = require("./receptionist-demo.js");

function queued() { return step(step(initialState(), { type: "approve" }), { type: "queue" }); }

test("all scenarios require approval of the exact current draft", () => {
  for (const scenario of ["service", "wedding", "assistant"]) {
    let state = initialState(scenario);
    assert.equal(step(state, { type: "queue" }).delivery, "none");
    state = step(state, { type: "approve" });
    state = step(state, { type: "edit", text: "A revised synthetic reply" });
    assert.equal(step(state, { type: "queue" }).delivery, "none");
    state = step(step(state, { type: "approve" }), { type: "queue" });
    assert.equal(state.outbound, "A revised synthetic reply");
    assert.equal(step(state, { type: "queue" }), state);
  }
});

test("blank drafts cannot be approved or queued", () => {
  const blank = step(initialState(), { type: "edit", text: "   " });
  assert.equal(step(blank, { type: "approve" }).approved, null);
  assert.equal(step(blank, { type: "queue" }).delivery, "none");
});

test("opt-out and human handoff cancel queued work and prevent new automation", () => {
  for (const type of ["opt_out", "handoff"]) {
    const cancelled = step(queued(), { type });
    assert.equal(cancelled.delivery, "cancelled");
    for (const action of ["queue", "approve", "submit", "receipt", "unknown"]) {
      assert.equal(step(cancelled, { type: action }), cancelled);
    }
    const interrupted = step(initialState(), { type });
    assert.equal(step(interrupted, { type: "approve" }).approved, null);
  }
});

test("submission is not delivery and a later opt-out does not claim recall", () => {
  let state = step(queued(), { type: "submit" });
  assert.match(statusText(state), /Delivery is not confirmed/);
  state = step(state, { type: "opt_out" });
  assert.equal(state.delivery, "submitted");
  state = step(state, { type: "unknown" });
  assert.match(statusText(state), /No automatic resend/);
  assert.equal(step(state, { type: "queue" }), state);
  state = step(state, { type: "receipt" });
  assert.equal(state.delivery, "delivered");
  assert.equal(state.blocked, true);
});

test("switching scenarios clears draft, approval, block and previous messages", () => {
  const changed = step(step(queued(), { type: "opt_out" }), { type: "reset", scenario: "wedding" });
  assert.equal(changed.scenario, "wedding");
  assert.equal(changed.delivery, "none");
  assert.equal(changed.blocked, false);
  assert.equal(changed.approved, null);
  assert.equal(changed.outbound, null);
});

test("browser controls render text safely and enforce workflow gates", () => {
  const elements = new Map();
  const element = () => ({ value: "", textContent: "", children: [], listeners: {}, disabled: false,
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const get = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  mount({ getElementById: get, createElement: element });
  assert.equal(get("queue").disabled, true);
  get("approve").listeners.click();
  assert.equal(get("queue").disabled, false);
  get("draft").value = "<img src=x onerror=alert(1)>";
  get("draft").listeners.input();
  assert.equal(get("queue").disabled, true);
  get("approve").listeners.click();
  get("queue").listeners.click();
  assert.equal(get("conversation").children[1].children[1].textContent, "<img src=x onerror=alert(1)>");
  assert.equal(get("receipt").disabled, true);
  get("opt-out").listeners.click();
  assert.equal(get("advance").disabled, true);
  assert.match(get("status").textContent, /Recipient blocked.*cancelled/);
});
