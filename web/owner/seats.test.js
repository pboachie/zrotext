// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

function response(status, body = {}) {
  return {
    status, ok: status >= 200 && status < 300,
    json: async () => {
      if (status === 204) throw new Error("empty response has no JSON body");
      return body;
    },
  };
}

const openInvitation = {
  id: "11111111-1111-4111-8111-111111111111",
  email: "observer@example.test",
  status: "open",
  created_at_ms: 1_000,
  expires_at_ms: 100_000_000,
  accepted_at_ms: null,
  canceled_at_ms: null,
  accepted_user_id: null,
};

const activeSeat = {
  user_id: "22222222-2222-4222-8222-222222222222",
  email: "observer@example.test",
  status: "active",
  email_verified: true,
  created_at_ms: 2_000,
  revoked_at_ms: null,
};

async function seatsPage({
  seats = [activeSeat],
  invitations = [openInvitation],
} = {}) {
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, value: "", children: [], listeners: {},
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  const calls = [];
  const fetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (path === "/v1/auth/seats" && (!options.method || options.method === "GET")) {
      return response(200, { seats, invitations });
    }
    if (path === "/v1/auth/seats/invitations" && options.method === "POST") {
      return response(201, {
        id: "33333333-3333-4333-8333-333333333333",
        email: "new@example.test",
        expires_at_ms: 100_000_000,
        token: "zti_synthetic-invitation-token",
      });
    }
    if (options.method === "DELETE") return response(204);
    throw new Error(`Unexpected request: ${path}`);
  };
  globalThis.document = {
    cookie: "__Host-zrotext_csrf=ztc_synthetic",
    getElementById: element,
    createElement: makeElement,
  };
  globalThis.window = {
    location: { origin: "https://example.test" },
    addEventListener() {},
  };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./seats.js")];
  require("./seats.js");
  await new Promise(setImmediate);
  return { element, calls };
}

async function submit(element) {
  let prevented = false;
  await element.listeners.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
}

test("inviting an observer sends JSON with CSRF and reveals the token once", async () => {
  const { element, calls } = await seatsPage();
  element("invite-email").value = " New@Example.Test ";
  await submit(element("invite-form"));
  const call = calls.find(({ path, options }) => path === "/v1/auth/seats/invitations"
    && options.method === "POST");
  assert.deepEqual(JSON.parse(call.options.body), { email: "new@example.test" });
  assert.equal(call.options.headers["content-type"], "application/json");
  assert.equal(call.options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(call.options.redirect, "error");
  assert.equal(element("invite-token").textContent, "zti_synthetic-invitation-token");
  assert.equal(element("invite-token-panel").hidden, false);
  assert.equal(
    element("invite-accept-url").textContent,
    "https://example.test/owner/observer",
  );
  assert.equal(element("invite-email").value, "");
  // Dismissing clears the one-time token from the page.
  element("dismiss-invite-token").listeners.click();
  assert.equal(element("invite-token").textContent, "");
  assert.equal(element("invite-token-panel").hidden, true);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("seat and invitation lists render with tenant-scoped actions", async () => {
  const { element, calls } = await seatsPage();
  const invitationItems = element("invitation-list").children;
  assert.equal(invitationItems.length, 1);
  assert.match(invitationItems[0].children[0].textContent, /observer@example.test/);
  assert.match(invitationItems[0].children[1].textContent, /Open/);
  const cancel = invitationItems[0].children[2];
  assert.equal(cancel.textContent, "Cancel invitation");
  const seatItems = element("seat-list").children;
  assert.equal(seatItems.length, 1);
  assert.match(seatItems[0].children[1].textContent, /Active/);
  const remove = seatItems[0].children[2];
  assert.equal(remove.textContent, "Remove seat");

  await cancel.listeners.click();
  assert.ok(calls.some(({ path, options }) =>
    path === `/v1/auth/seats/invitations/${openInvitation.id}` && options.method === "DELETE"));
  await remove.listeners.click();
  assert.ok(calls.some(({ path, options }) =>
    path === `/v1/auth/seats/${activeSeat.user_id}` && options.method === "DELETE"));
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("removed seats and unknown statuses render without actions", async () => {
  const { element } = await seatsPage({
    invitations: [{ ...openInvitation, status: "accepted" }],
    seats: [{ ...activeSeat, status: "removed", revoked_at_ms: 5_000 }],
  });
  assert.equal(element("invitation-list").children[0].children.length, 2);
  assert.equal(element("seat-list").children[0].children.length, 2);
  assert.match(element("seat-list").children[0].children[1].textContent, /Removed/);
});

test("conflicts and malformed entries surface without leaking data", async () => {
  const { element } = await seatsPage({
    invitations: [],
    seats: [{ ...activeSeat, user_id: "not-a-uuid" }],
  });
  assert.match(element("seats-status").textContent, /invalid/);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(409);
  element("invite-email").value = "taken@example.test";
  await submit(element("invite-form"));
  globalThis.fetch = originalFetch;
  assert.match(element("invite-status").textContent, /already registered/);
  assert.equal(element("invite-token-panel").hidden, true);
  assert.equal(element("invite-token").textContent, "");
});
