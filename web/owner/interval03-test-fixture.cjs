// SPDX-License-Identifier: AGPL-3.0-only
// Genuine ephemeral crypto/retained IndexedDB keys. Synthetic HTTP is not a live server.
const path = require("node:path"), { createRequire } = require("node:module"), { pathToFileURL } = require("node:url");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const history = require("./conversation-manifest03-history.js"), highwater = require("./conversation-manifest03-recovery.js");
const controller = require("./conversation-interval03.js"), recovery = require("./conversation-interval03-recovery.js");
const load = n => import(pathToFileURL(path.join(__dirname, "../../sdk/typescript/dist", n + ".js")).href);
const hex = b => Buffer.from(b).toString("hex"), un64 = b => Uint8Array.from(Buffer.from(b, "base64url"));
async function fixture() {
  const h = await import("../../sdk/typescript/test/manifest-history03-fixture.mjs"), f = await h.fixture({ originalProofs: true });
  const [custody, consent] = await Promise.all([load("browser-message-signer-store03"), load("conversation-interval03")]);
  const prefix = "interval-controller-test-" + crypto.randomUUID(), instances = [];
  const scope = { origin: f.origin, accountId: h.text(f.account), originalUserId: h.text(f.user), deviceId: h.text(f.device), lineId: h.text(f.line), rootFingerprint: hex(f.fingerprint) };
  f.openKeys = o => custody.BrowserMessageSigner03KeyStore.open({ ...o, name: prefix + "-keys" });
  f.removeKey = async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open(prefix + "-keys"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    try { await new Promise((resolve, reject) => { const tx = db.transaction("browser-message-signing03-v1", "readwrite"); tx.objectStore("browser-message-signing03-v1").clear(); tx.oncomplete = resolve; tx.onabort = tx.onerror = () => reject(Error("Synthetic key removal failed")); }); }
    finally { db.close(); }
  };
  const initial = await f.openKeys({ currentOrigin: () => f.origin }), metadata = await initial.create(scope, { retain: true, newEnrollment: true });
  const retained = await initial.load(scope, metadata.keyId);
  await retained.withKey(scope, metadata.keyId, privateKey => f.step({ point: Uint8Array.from(Buffer.from(metadata.publicPoint, "hex")), pair: { privateKey } }));
  retained.close(); initial.close(); f.keyId = metadata.keyId;
  const roles = new Map(Array.from({ length: f.signed[152] }, (_, i) => { const r = f.signed.slice(153 + i * 149, 153 + (i + 1) * 149); return [r[0], r.slice(1, 33)]; }));
  f.mono = 0; f.sessionId = h.text(f.session); f.calls = []; f.loseReserve = f.loseRequest = false;
  f.document = { hidden: false, cookie: "__Host-zrotext_csrf=ztc_" + h.b64(new Uint8Array(32).fill(11)), addEventListener() {}, removeEventListener() {} };
  f.window = { location: { origin: f.origin }, addEventListener() {}, removeEventListener() {} };
  f.choice = { peer: "+12", archiveReaderKeyId: hex(roles.get(2)), phoneSignerKeyId: hex(roles.get(4)), integrationReaders: [], retentionConsent: true };
  f.selection = { enabled: true, retentionConsent: true, compared: true, origin: f.origin, account_id: h.text(f.account), device_id: h.text(f.device), line_id: h.text(f.line),
    rootFingerprint: hex(f.fingerprint), pairedFingerprint: hex(await h.sha(f.phone.point)), manifestVersion: "1", manifestDigest: hex(f.compared.priorDigest) };
  const current = await f.wireCurrent(), now = BigInt(current.compared_ms);
  const physical = await h.hash("ZTSE/line/payload-profile/physical-selection/v1", Uint8Array.of(1), f.account, f.device, f.line, f.binding,
    f.accepted.electionCommitment, un64(current.device_session_digest), f.oldBinding, await h.sha(un64(f.evidence.activation_evidence)));
  f.reserve = async body => {
    if (f.receipt) return f.receipt;
    const interval = crypto.randomUUID(), receipt = crypto.randomUUID(), uuid = s => Uint8Array.from(Buffer.from(s.replaceAll("-", ""), "hex"));
    const fields = { accountId: f.account, deviceId: f.device, lineId: f.line, bindingId: f.binding, intervalId: uuid(interval), receiptId: uuid(receipt),
      ownerUserId: f.user, ownerSessionId: f.session, openingId: uuid(body.opening_id), bindingGeneration: 7n, vaultGeneration: 1n, manifestVersion: f.version, selectionEpoch: 1n,
      issuedMs: now, setupExpiresMs: BigInt(body.interval_expires_ms), intervalFromMs: now, intervalUntilMs: BigInt(body.interval_expires_ms), selectedReaderKeyId: f.reader,
      archiveReaderKeyId: roles.get(2), phoneSignerKeyId: roles.get(4), browserSignerKeyId: roles.get(5), rootFingerprint: f.fingerprint, manifestDigest: f.digest,
      electionCommitment: f.accepted.electionCommitment, electionBundleSha256: f.accepted.electionBundleSha256, ownerSessionDigest: un64(current.owner_session_digest),
      originDigest: un64(current.origin_digest), deviceSessionDigest: un64(current.device_session_digest), physicalSelectionDigest: physical, nonce: new Uint8Array(32).fill(4), peer: h.enc.encode(body.peer), integrationReaders: [] };
    const statement = await consent.encodeConversationStatement03(fields);
    f.receipt = { v: 1, opening_id: body.opening_id, interval_id: interval, receipt_id: receipt, statement: h.b64(statement), owner_signature: null,
      phone_signature: null, installed_signature: null, requested_ms: null, approved_ms: null, installed_ms: null, phase: "reserved" }; return f.receipt;
  };
  f.activate = async () => {
    const r = f.receipt, raw = un64(r.statement), requested = un64(r.owner_signature);
    const approval = await h.sign(f.phone, h.frame("zrotext/conversation/approve03/v1", h.join(raw, await h.sha(requested))));
    const installed = await h.sign(f.phone, h.frame("zrotext/conversation/install03/v1", h.join(raw, await h.sha(requested), await h.sha(approval))));
    f.receipt = { ...r, phone_signature: h.b64(approval), installed_signature: h.b64(installed), approved_ms: String(now), installed_ms: String(now), phase: "active" };
  };
  f.fetch = async (url, options = {}) => {
    const route = new URL(url, f.origin).pathname, body = options.body && JSON.parse(options.body); f.calls.push({ route, body }); let value;
    if (f.beforeFetch) await f.beforeFetch(route, options);
    if (route === "/v1/auth/session") value = { role: "owner", account_id: h.text(f.account), user_id: h.text(f.user), session_id: f.sessionId };
    else if (route.endsWith("/original")) value = { v: 1, kind: "manifest_original03", line_id: h.text(f.line), binding_id: h.text(f.binding), evidence: f.evidence };
    else if (route.endsWith("/history")) value = f.page();
    else if (route.endsWith("/challenges")) { value = await f.reserve(body); if (f.loseReserve) throw Error("Synthetic lost reservation response"); }
    else if (route.endsWith("/requests")) {
      f.receipt = { ...f.receipt, owner_signature: body.owner_signature, requested_ms: String(now), phase: "requested" }; value = f.receipt;
      if (f.loseRequest) throw Error("Synthetic lost request response");
    } else if (route.endsWith("/status")) value = f.receipt;
    else if (route.endsWith("/stop")) { f.receipt = { ...f.receipt, phase: "stopped" }; return new Response(null, { status: 204 }); }
    else if (route.endsWith("/context")) {
      value = { v: 1, kind: "owner_conversation_context03", request_id: body.request_id, opening_id: body.opening_id, interval_id: body.interval_id,
        statement_sha256: h.b64(await h.sha(un64(f.receipt.statement))), selection: { ...current, permission_expires_ms: f.receipt ? String((await consent.decodeConversationStatement03(un64(f.receipt.statement))).intervalUntilMs) : current.permission_expires_ms },
        owner_session_expires_ms: "1000000", physical_selection_digest: h.b64(physical), compared_ms: current.compared_ms,
        permission_expires_ms: String((await consent.decodeConversationStatement03(un64(f.receipt.statement))).intervalUntilMs), readers: [] };
      if (f.mutateContext) value = f.mutateContext(value);
    } else throw Error("Unexpected synthetic interval route");
    return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
  };
  f.openAttempts = o => recovery.open({ ...o, name: prefix + "-attempts" });
  f.create = async (extra = {}) => {
    const hc = history.create({ enabled: true, readSelection: () => f.selection, document: f.document, window: f.window, fetch: f.fetch, monotonic: () => f.mono,
      importSdk: load, openRecovery: o => highwater.open({ ...o, name: prefix + "-history" }) }); instances.push(hc);
    await hc.open({ size: 65, arrayBuffer: async () => f.phone.point.slice().buffer }); await hc.next();
    const c = controller.create({ enabled: true, history: hc, readSelection: () => f.choice, document: f.document, window: f.window, fetch: f.fetch,
      monotonic: () => f.mono, importSdk: load, openKeyStore: f.openKeys, openRecovery: f.openAttempts, ...extra }); instances.push(c); await c.open(); return { c, hc };
  };
  f.read = async () => { const j = await f.openAttempts({ scope: { ...scope, peer: f.choice.peer }, currentOrigin: () => f.origin }); try { return await j.read(); } finally { j.close(); } };
  f.close = () => instances.forEach(c => c.close()); f.scope = scope; f.helpers = h; return f;
}
module.exports = { fixture };
