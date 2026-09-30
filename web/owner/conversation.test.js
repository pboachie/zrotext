// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { create } = require("./conversation-core.js");
const selected = () => ({ account: randomUUID(), session: randomUUID(), interval: randomUUID(), device: randomUUID(), line: randomUUID(), generation: "1", peer: "+12", reader: "fixture-reader", manifest: "fixture-manifest" });
function fixture() {
  let time = 0, sent = [], prepared = [], current = selected();
  const adapter = {
    authority: async () => ({ scope: current, phase: "active", validForMs: 60000 }),
    read: async () => "Synthetic inbound <script>literal</script> Ω",
    prepare: async (input) => { prepared.push(input); return { confirm: async (guard) => { guard(); sent.push(input); return { status: "simulator_accepted" }; } }; },
  };
  const c = create(adapter, () => time);
  return { c, adapter, sent, prepared, scope: () => current, tick: (n) => { time += n; }, change: (key) => { current = { ...current, [key]: randomUUID() }; } };
}
const defer = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
test("review never sends and confirmation consumes the exact frozen peer/content/account once", async () => {
  const f = fixture(); await f.c.authorize(); f.c.edit("Synthetic reply Ω\nExact spaces  ");
  const review = await f.c.prepare(); assert.equal(f.sent.length, 0);
  assert.equal(review.body, "Synthetic reply Ω\nExact spaces  "); assert.equal(review.peer, "+12");
  assert.ok(Object.isFrozen(f.prepared[0]) && Object.isFrozen(f.prepared[0].scope));
  await f.c.confirm(); await assert.rejects(f.c.confirm());
  assert.equal(f.sent.length, 1); assert.equal(f.sent[0].scope.account, review.account);
  assert.equal(f.sent[0].body, review.body); assert.equal(f.c.state().draft, "");
});
test("edit, cancellation and expiry each invalidate an already reviewed message", async () => {
  for (const invalidate of [(f) => f.c.edit("changed"), (f) => f.c.clear(), (f) => f.tick(60000)]) {
    const f = fixture(); await f.c.authorize(); f.c.edit("Original"); await f.c.prepare(); invalidate(f);
    await assert.rejects(f.c.confirm()); assert.equal(f.sent.length, 0);
  }
});
test("delayed preparation cannot restore a review after edits or navigation", async () => {
  for (const clear of [false, true]) {
    const f = fixture(), pending = defer(); f.adapter.prepare = () => pending.promise;
    await f.c.authorize(); f.c.edit("Original"); const request = f.c.prepare();
    if (clear) f.c.clear(); else f.c.edit("Changed");
    pending.resolve({ confirm: async () => { throw Error("must not send"); } });
    await assert.rejects(request); assert.equal(f.c.state().canConfirm, false);
  }
});
test("concurrent confirmation never sends twice and does not retry an uncertain result", async () => {
  const f = fixture(), pending = defer(); let calls = 0;
  f.adapter.prepare = async () => ({ confirm: async (guard) => { guard(); calls++; return pending.promise; } });
  await f.c.authorize(); f.c.edit("Original"); await f.c.prepare(); const first = f.c.confirm();
  await assert.rejects(f.c.confirm()); pending.resolve({ status: "unknown" }); await assert.rejects(first);
  await assert.rejects(f.c.confirm()); assert.equal(calls, 1);
});
test("closure while signing prevents transport through the final guard", async () => {
  const f = fixture(), pending = defer();
  f.adapter.prepare = async () => ({ confirm: async (guard) => { await pending.promise; guard(); f.sent.push("forbidden"); return { status: "simulator_accepted" }; } });
  await f.c.authorize(); f.c.edit("Original"); await f.c.prepare(); const first = f.c.confirm();
  f.c.clear(); pending.resolve(); await assert.rejects(first); assert.equal(f.sent.length, 0);
});
test("fresh authorization for every scope field discards previous content and review", async () => {
  for (const key of Object.keys(selected()).filter((key) => !["generation", "peer"].includes(key))) {
    const f = fixture(); await f.c.authorize(); await f.c.read(randomUUID()); f.c.edit("Original"); await f.c.prepare();
    f.change(key); await f.c.authorize(); assert.equal(f.c.state().messages.length, 0);
    assert.equal(f.c.state().draft, ""); await assert.rejects(f.c.confirm());
  }
});
test("inactive, slow or oversized leases cannot activate the composer", async () => {
  for (const value of [{ phase: "pending", validForMs: 1000 }, { phase: "installed", validForMs: 1000 }, { phase: "active", validForMs: 60001 }, { phase: "active", validForMs: 0 }]) {
    const f = fixture(); f.adapter.authority = async () => ({ ...value, scope: f.scope() });
    await assert.rejects(f.c.authorize()); assert.equal(f.c.state().scope, null);
  }
  const f = fixture(); f.adapter.authority = async () => { f.tick(60000); return { phase: "active", validForMs: 60000, scope: f.scope() }; };
  await assert.rejects(f.c.authorize());
});
test("late read cannot display content after closure", async () => {
  const f = fixture(), pending = defer(); f.adapter.read = () => pending.promise;
  await f.c.authorize(); const read = f.c.read(randomUUID()); f.c.clear(); pending.resolve("Synthetic content");
  await assert.rejects(read); assert.equal(f.c.state().messages.length, 0);
});
test("invalid Unicode and oversized content fail before encryption or transport", async () => {
  for (const text of ["", "\0", "\uFEFFtext", "\uD800", "Ω".repeat(16385)]) {
    const f = fixture(); await f.c.authorize(); f.c.edit(text); await assert.rejects(f.c.prepare());
    assert.equal(f.prepared.length, 0); assert.equal(f.sent.length, 0);
  }
});
test("review captures the confirmation function before mutable adapter replacement", async () => {
  const f = fixture(); let original = 0, replacement = 0;
  const candidate = { confirm: async (guard) => { guard(); original++; return {status:"simulator_accepted"}; } };
  f.adapter.prepare = async () => candidate;
  await f.c.authorize(); f.c.edit("Original"); await f.c.prepare();
  candidate.confirm = async () => { replacement++; throw Error("must not replace"); };
  await f.c.confirm(); assert.equal(original,1); assert.equal(replacement,0);
});
