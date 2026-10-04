// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { openOriginalReply02 } from "../dist/original-reply-reader.js";
import { verifyOriginalReplySelection02, verifyArchiveReplySelection02 } from "../dist/original-reply-selection.js";
import { originalReplyFixture } from "./original-reply-fixture.mjs";
import { openConversationInbound02 } from "../dist/conversation-reader.js";
const options = (f, readCurrent = async () => f.authority) => ({ scope: f.scope, event: f.event, privateKey: f.privateKey, historical: f.manifest, selection: f.selection, readCurrent });
test("original role3 reader opens signed phone ciphertext with independently accepted history", async () => {
  const f = await originalReplyFixture(); let reads = 0;
  assert.equal(await openOriginalReply02(f.envelope, options(f, async () => { reads++; return f.authority; })), "synthetic original reply");
  assert.equal(reads, 2); assert.equal(f.privateKey.extractable, false);
});
test("original reader opens accepted past history under an independently ratcheted current manifest", async () => {
  const f = await originalReplyFixture();
  assert.equal(await openOriginalReply02(f.envelope, options(f, async () => ({ ...f.authority, manifest: f.successor }))), "synthetic original reply");
});
test("original reader refuses forged signature, unaccepted history and wrong selected scope", async () => {
  const f = await originalReplyFixture(), corrupt = f.envelope.slice(); corrupt[corrupt.length - 1] ^= 1;
  await assert.rejects(openOriginalReply02(corrupt, options(f)));
  await assert.rejects(openOriginalReply02(f.envelope, { ...options(f), historical: { ...f.manifest } }));
  await assert.rejects(openOriginalReply02(f.envelope, { ...options(f), scope: { ...f.scope, readGrant: new Uint8Array(16).fill(20) } }));
  await assert.rejects(verifyOriginalReplySelection02(f.statement, f.installation, f.approval, f.manifest, 2000n, f.scope));
});
test("original reader rechecks withdrawal, revision and deadline after asynchronous opening", async () => {
  for (const final of [null, { revision: "changed" }, { nowMs: 90000n }, { reader: new Uint8Array(32).fill(20) }]) {
    const f = await originalReplyFixture(); let reads = 0;
    await assert.rejects(openOriginalReply02(f.envelope, options(f, async () => {
      if (++reads === 1) return f.authority;
      if (final === null) throw Error("revoked");
      return { ...f.authority, ...final };
    })));
    assert.equal(reads, 2);
  }
});
test("original reader ignores mutation of the verified selection record", async () => {
  const f = await originalReplyFixture(); f.selection.readers[0].reader.fill(0);
  assert.equal(await openOriginalReply02(f.envelope, options(f)), "synthetic original reply");
});
test("archive opening requires exact verified phone selection for additional role3 wraps", async () => {
  const f = await originalReplyFixture();
  const context = { ...f.scope, archiveReader: f.selection.archiveReader, archivePrivateKey: f.archivePrivateKey, historical: f.manifest, current: f.manifest, nowMs: 2000n };
  const ownerSelection = await verifyArchiveReplySelection02(f.statement, f.approval, f.installation, f.manifest, 2000n, context);
  await assert.rejects(openConversationInbound02(f.envelope, context), /archive-only wraps/);
  assert.equal(await openConversationInbound02(f.envelope, { ...context, selection: ownerSelection }), "synthetic original reply");
  await assert.rejects(openConversationInbound02(f.envelope, { ...context, selection: { ...f.selection } }));
  await assert.rejects(openConversationInbound02(f.envelope, { ...context, selection: f.selection, interval: new Uint8Array(16).fill(25) }));
});
test("phone-signed selection still refuses duplicate tuples, zero readers and trailing fields", async () => {
  const f = await originalReplyFixture(), countAt = f.statement.length - 65;
  const duplicate = new Uint8Array(f.statement.length + 64); duplicate.set(f.statement); duplicate[countAt] = 2; duplicate.set(f.statement.subarray(countAt + 1), f.statement.length);
  const empty = f.statement.slice(0, countAt + 1); empty[countAt] = 0;
  const trailing = new Uint8Array(f.statement.length + 1); trailing.set(f.statement);
  for (const malformed of [duplicate, empty, trailing]) {
    const signed = await f.signSelection(malformed);
    await assert.rejects(verifyOriginalReplySelection02(malformed, signed.approval, signed.installation, f.manifest, 2000n, f.scope));
  }
});
