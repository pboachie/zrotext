// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), { fixture } = require("./interval03-test-fixture.cjs");
const factors = () => ({ password: "synthetic-password", factor: "synthetic-factor" });
test("actual retained role05 key and all independent receipt signatures precede verified active consent", async () => {
  const f = await fixture(); try {
    const { c, hc } = await f.create(), choices = await require("./conversation-interval03.js").contentChoices(hc);
    assert.equal(choices.archives[0].keyId, f.choice.archiveReaderKeyId); assert.equal(choices.phones[0].keyId, f.choice.phoneSignerKeyId);
    await c.begin({ durationMs: 1000 }); assert.equal(c.state().phase, "reserved");
    await assert.rejects(c.review()); await c.review({ disclosure: true }); assert.equal(c.state().originalSaved, true);
    const original = (await f.read()).original; await c.request(factors()); assert.equal(c.state().phase, "requested");
    await f.activate(); await c.check(); assert.equal(c.state().verifiedActive, true);
    assert.deepEqual((await f.read()).original, original); await c.stop(); assert.equal(c.state().verifiedActive, false);
    await c.check(); assert.equal(c.state().phase, "stopped");
    assert.equal(JSON.stringify(await f.read()).includes("synthetic-password"), false);
  } finally { f.close(); }
});
test("lost first reservation response recovers by original opening without creating or signing another", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); f.loseReserve = true; await assert.rejects(c.begin({ durationMs: 1000 }));
    const before = await f.read(); assert.equal(before.receipt, null); assert.equal(before.reserve_submitted, true);
    await assert.rejects(c.begin({ durationMs: 1000 })); await c.check();
    assert.equal(c.state().openingId, before.command.opening_id); assert.equal(f.calls.filter(x => x.route.endsWith("/challenges")).length, 1);
    assert.equal(f.calls.filter(x => x.route.endsWith("/openings/status")).length, 1); assert.equal((await f.read()).original, null);
  } finally { f.close(); }
});
test("unknown request survives reload with exact original signature and no automatic repeat", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); await c.begin({ durationMs: 1000 }); await c.review({ disclosure: true }); f.loseRequest = true;
    await assert.rejects(c.request(factors())); const before = await f.read(); c.close();
    const again = (await f.create()).c; await assert.rejects(again.review({ disclosure: true })); await assert.rejects(again.request(factors()));
    await again.check(); assert.equal(again.state().phase, "requested"); assert.deepEqual((await f.read()).original, before.original);
    assert.equal(f.calls.filter(x => x.route.endsWith("/requests")).length, 1);
  } finally { f.close(); }
});
test("failed recovery commit prevents reservation HTTP and preserves a resumable original command", async () => {
  const f = await fixture(); try {
    let fail = true;
    const { c } = await f.create({ openRecovery: async o => { const j = await f.openAttempts(o); return { ...j, compareAndSet: (a, b) => {
      if (fail && b.reserve_submitted) return Promise.reject(Error("Synthetic commit failure")); return j.compareAndSet(a, b);
    } }; } });
    await assert.rejects(c.begin({ durationMs: 1000 })); const before = await f.read(); assert.equal(before.reserve_submitted, false);
    assert.equal(f.calls.filter(x => x.route.endsWith("/challenges")).length, 0); fail = false; await c.resumeReservation();
    assert.equal(c.state().openingId, before.command.opening_id); assert.equal(f.calls.filter(x => x.route.endsWith("/challenges")).length, 1);
  } finally { f.close(); }
});
test("fresh same-user session may observe original consent but cannot sign or adopt it", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); await c.begin({ durationMs: 1000 }); const before = await f.read(); c.close(); f.sessionId = crypto.randomUUID();
    const again = (await f.create()).c; await again.check(); assert.equal(again.state().phase, "historical_only");
    await assert.rejects(again.review({ disclosure: true })); await assert.rejects(again.begin({ durationMs: 1000 }));
    assert.equal((await f.read()).owner_session_id, before.owner_session_id);
  } finally { f.close(); }
});
test("changed current physical commitment or absent retained key never yields a signed request", async () => {
  for (const mode of ["physical", "key"]) {
    const f = await fixture(); try {
      const { c } = await f.create(); await c.begin({ durationMs: 1000 });
      if (mode === "physical") f.mutateContext = v => ({ ...v, physical_selection_digest: f.helpers.b64(new Uint8Array(32).fill(8)) });
      else await f.removeKey();
      await assert.rejects(c.review({ disclosure: true })); assert.equal((await f.read()).original, null);
      assert.equal(f.calls.filter(x => x.route.endsWith("/requests")).length, 0);
    } finally { f.close(); }
  }
});
test("visibility, selected peer, clock and parent checkpoint withdrawal stop all later actions", async () => {
  for (const change of [f => { f.document.hidden = true; }, f => { f.choice.peer = "+13"; }, f => { f.mono = -1; }]) {
    const f = await fixture(); try { const { c } = await f.create(); await c.begin({ durationMs: 1000 }); const before = f.calls.length;
      change(f); await assert.rejects(c.review({ disclosure: true })); assert.equal(c.state().closed, true); assert.equal(f.calls.length, before);
    } finally { f.close(); }
  }
  const f = await fixture(); try { const { c, hc } = await f.create(); await c.begin({ durationMs: 1000 }); await hc.restart();
    await assert.rejects(c.review({ disclosure: true })); assert.equal(c.state().closed, true);
  } finally { f.close(); }
});
test("local Stop withdraws immediately during real signing and late crypto cannot publish a request", async () => {
  const f = await fixture(), sign = crypto.subtle.sign; let release, entered;
  const blocked = new Promise(resolve => { entered = resolve; });
  try {
    const { c } = await f.create(); await c.begin({ durationMs: 1000 });
    crypto.subtle.sign = async (...args) => {
      const result = await Reflect.apply(sign, crypto.subtle, args);
      if (Buffer.from(args[2]).subarray(0, 33).toString().startsWith("zrotext/conversation/request03/v1")) { entered(); await new Promise(resolve => { release = resolve; }); }
      return result;
    };
    const signing = c.review({ disclosure: true }); await blocked;
    const stopped = c.stop(); assert.equal(c.state().phase, "stopping"); assert.equal(c.state().verifiedActive, false);
    release(); await assert.rejects(signing); await stopped;
    assert.equal((await f.read()).original, null); assert.equal((await f.read()).stop_submitted, true);
    assert.equal(f.calls.filter(x => x.route.endsWith("/requests")).length, 0); await c.check(); assert.equal(c.state().phase, "stopped");
  } finally { crypto.subtle.sign = sign; release?.(); f.close(); }
});
test("verified active display expires with actual current permission and does not become persistent authority", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); await c.begin({ durationMs: 1000 }); await c.review({ disclosure: true }); await c.request(factors()); await f.activate(); await c.check();
    assert.equal(c.state().verifiedActive, true); f.mono += 1000; assert.equal(c.state().verifiedActive, false); assert.equal(c.state().phase, "permission_expired");
    assert.equal(f.calls.filter(x => x.route.endsWith("/requests")).length, 1);
  } finally { f.close(); }
});
test("fresh anchored time permits explicit replacement only of a proven expired never-submitted command", async () => {
  const f = await fixture(); try {
    let refuse = true;
    const { c } = await f.create({ openRecovery: async o => { const j = await f.openAttempts(o); return { ...j, compareAndSet: (a, b) => {
      if (refuse && b.reserve_submitted) return Promise.reject(Error("Synthetic pre-HTTP commit refusal")); return j.compareAndSet(a, b);
    } }; } });
    await assert.rejects(c.begin({ durationMs: 1000 })); const original = await f.read();
    assert.equal(original.reserve_submitted, false); assert.equal(original.original, null); assert.equal(original.receipt, null);
    await assert.rejects(c.begin({ durationMs: 1000 })); f.mono += 2000;
    await assert.rejects(c.resumeReservation()); assert.equal(f.calls.filter(v => v.route.endsWith("/challenges")).length, 0);
    // Actual primary comparison may trail the parent's conservative local
    // upper clock slightly; retain separate floors without relaxing expiry.
    f.mutateContext = v => { v.compared_ms = String(BigInt(v.compared_ms) + 1999n); v.selection.compared_ms = v.compared_ms; return v; };
    refuse = false; await c.begin({ durationMs: 1000 }); const fresh = await f.read();
    assert.notEqual(fresh.command.opening_id, original.command.opening_id); assert.equal(fresh.original, null);
    const journal = await f.openAttempts({ scope: { ...f.scope, peer: f.choice.peer }, currentOrigin: () => f.origin });
    try { const page = await journal.page(); assert.equal(page.attempts.length, 2); assert.deepEqual(page.attempts.find(v => v.command.opening_id === original.command.opening_id), original); }
    finally { journal.close(); }
  } finally { f.close(); }
});
test("a primary comparison below the preceding genuine successful comparison still refuses", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); await c.begin({ durationMs: 1000 });
    f.mutateContext = v => { v.compared_ms = String(BigInt(v.compared_ms) - 1n); v.selection.compared_ms = v.compared_ms; return v; };
    await assert.rejects(c.review({ disclosure: true })); assert.equal((await f.read()).original, null);
    assert.equal(f.calls.filter(v => v.route.endsWith("/requests")).length, 0);
  } finally { f.close(); }
});
test("expiry of a submitted UNKNOWN never permits an explicit replacement or signature reset", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(); f.loseReserve = true; await assert.rejects(c.begin({ durationMs: 1000 })); const original = await f.read();
    f.mono += 2000; assert.equal(c.state().canPrepareFresh, false); await assert.rejects(c.begin({ durationMs: 1000 }));
    await assert.rejects(c.resumeReservation()); assert.deepEqual(await f.read(), original);
    assert.equal(f.calls.filter(v => v.route.endsWith("/challenges")).length, 1);
  } finally { f.close(); }
});
