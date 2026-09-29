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
  address_free: false,
};

async function seatsPage({
  seats = [activeSeat],
  invitations = [openInvitation],
  removal = { status: "removed", address_free: true },
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
    if (options.method === "DELETE") {
      return path.startsWith("/v1/auth/seats/invitations/") ? response(204) : response(200, removal);
    }
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
  element("invite-password").value = "synthetic-owner-password";
  element("invite-code").value = " 123456 ";
  await submit(element("invite-form"));
  const call = calls.find(({ path, options }) => path === "/v1/auth/seats/invitations"
    && options.method === "POST");
  assert.deepEqual(JSON.parse(call.options.body), {
    email: "new@example.test",
    current_password: "synthetic-owner-password",
    code: "123456",
  });
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
  // The proof never lingers in the form after a submit.
  assert.equal(element("invite-password").value, "");
  assert.equal(element("invite-code").value, "");
  // Dismissing clears the one-time token from the page.
  element("dismiss-invite-token").listeners.click();
  assert.equal(element("invite-token").textContent, "");
  assert.equal(element("invite-token-panel").hidden, true);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("an invitation needs the password and omits an empty code", async () => {
  const { element, calls } = await seatsPage();
  element("invite-email").value = "new@example.test";
  await submit(element("invite-form"));
  assert.match(element("invite-status").textContent, /password/i);
  assert.ok(!calls.some(({ path, options }) => path === "/v1/auth/seats/invitations"
    && options.method === "POST"));

  element("invite-email").value = "new@example.test";
  element("invite-password").value = "synthetic-owner-password";
  await submit(element("invite-form"));
  const call = calls.find(({ path, options }) => path === "/v1/auth/seats/invitations"
    && options.method === "POST");
  assert.deepEqual(JSON.parse(call.options.body), {
    email: "new@example.test",
    current_password: "synthetic-owner-password",
  });
});

test("a rejected proof shows no token and clears the password", async () => {
  const { element } = await seatsPage();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(400);
  element("invite-email").value = "new@example.test";
  element("invite-password").value = "wrong-password";
  await submit(element("invite-form"));
  globalThis.fetch = originalFetch;
  assert.match(element("invite-status").textContent, /password/);
  assert.equal(element("invite-password").value, "");
  assert.equal(element("invite-token-panel").hidden, true);
  assert.equal(element("invite-token").textContent, "");
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
  assert.match(element("seat-status").textContent, /free and can be invited again/);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("removal says when the address stays occupied", async () => {
  const { element } = await seatsPage({
    removal: { status: "removed", address_free: false },
  });
  await element("seat-list").children[0].children[2].listeners.click();
  assert.match(element("seat-status").textContent, /Seat removed/);
  assert.match(element("seat-status").textContent, /stays occupied/);
  assert.doesNotMatch(element("seat-status").textContent, /free/);
});

test("removed seats and unknown statuses render without actions", async () => {
  const { element } = await seatsPage({
    invitations: [{ ...openInvitation, status: "accepted" }],
    seats: [{
      ...activeSeat, status: "removed", revoked_at_ms: 5_000, user_id: null, address_free: true,
    }],
  });
  assert.equal(element("invitation-list").children[0].children.length, 2);
  const removed = element("seat-list").children[0].children;
  assert.equal(removed.length, 3);
  assert.match(removed[1].textContent, /Removed/);
  assert.match(removed[2].textContent, /address is free/);
  assert.ok(removed.every(({ textContent }) => textContent !== "Remove seat"));
});

test("a removed seat whose address stays occupied says so in the list", async () => {
  const { element } = await seatsPage({
    seats: [{
      ...activeSeat, status: "removed", revoked_at_ms: 5_000, address_free: false,
    }],
  });
  const removed = element("seat-list").children[0].children;
  assert.match(removed[2].textContent, /stays occupied/);
  assert.doesNotMatch(removed[2].textContent, /address is free/);
  assert.ok(removed.every(({ textContent }) => textContent !== "Remove seat"));
});

test("conflicts and malformed entries surface without leaking data", async () => {
  const { element } = await seatsPage({
    invitations: [],
    seats: [{ ...activeSeat, user_id: "not-a-uuid" }],
  });
  assert.match(element("seats-status").textContent, /invalid/);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(409);
  element("invite-email").value = "full@example.test";
  element("invite-password").value = "synthetic-owner-password";
  await submit(element("invite-form"));
  globalThis.fetch = originalFetch;
  // A conflict is only ever about the limits: the page never says whether an
  // address is registered.
  assert.match(element("invite-status").textContent, /limit is reached/);
  assert.doesNotMatch(element("invite-status").textContent, /registered/);
  assert.equal(element("invite-token-panel").hidden, true);
  assert.equal(element("invite-token").textContent, "");
});
