// SPDX-License-Identifier: AGPL-3.0-only
// Actual ephemeral crypto and IndexedDB; HTTP replies are synthetic service fixtures.
const path = require("node:path"), { createRequire } = require("node:module"), { pathToFileURL } = require("node:url");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const history = require("./conversation-manifest03-history.js"), recovery = require("./conversation-manifest03-recovery.js");
const enrollment = require("./conversation-message-key03.js"), attempts = require("./conversation-message-key03-recovery.js");
const load = n => import(pathToFileURL(path.join(__dirname, "../../sdk/typescript/dist", n + ".js")).href);
const hex = b => Buffer.from(b).toString("hex"), un64 = b => Uint8Array.from(Buffer.from(b, "base64url"));
async function fixture() {
  const h = await import("../../sdk/typescript/test/manifest-history03-fixture.mjs"), f = await h.fixture({ originalProofs: true });
  const [install, manifest, custody] = await Promise.all([load("manifest-install03"), load("draft03-manifest"), load("browser-message-signer-store03")]);
  const prefix = "message-key-test-" + crypto.randomUUID(), instances = [];
  f.sessionId = h.text(f.session); f.mono = 0; f.calls = []; f.installCount = 0;
  f.document = { hidden: false, cookie: "__Host-zrotext_csrf=ztc_" + h.b64(new Uint8Array(32).fill(11)), addEventListener() {}, removeEventListener() {} };
  f.window = { location: { origin: f.origin }, addEventListener() {}, removeEventListener() {} };
  f.selection = { enabled: true, retentionConsent: true, compared: true, origin: f.origin, account_id: h.text(f.account), device_id: h.text(f.device), line_id: h.text(f.line),
    rootFingerprint: hex(f.fingerprint), pairedFingerprint: hex(await h.sha(f.phone.point)), manifestVersion: "1", manifestDigest: hex(f.compared.priorDigest) };
  f.phoneFile = { size: 65, arrayBuffer: async () => f.phone.point.slice().buffer };
  f.accept = async body => {
    const bytes = un64(body.statement), signature = un64(body.signature), signed = un64(body.successor_manifest03);
    const statement = await install.verifyManifestInstallPossession03(bytes, signature), accepted = statement.issuedMs + 2n;
    const previous = f.signed, predecessor = f.version, before = f.prefix;
    const active = Array.from({ length: previous[152] }, (_, i) => previous.slice(153 + i * 149, 153 + (i + 1) * 149)).find(r => r[0] === 5 && r[148] === 1);
    const operation = !active ? "enroll" : h.b64(active.slice(1, 33)) === h.b64(statement.signerKeyId) ? "renew" : "replace";
    f.current = await manifest.verifyManifest03Successor(signed, f.current, accepted);
    f.signed = signed; f.version++; f.digest = await h.sha(signed.slice(0, -64)); f.acceptedMs = accepted;
    f.prefix = await h.hash("ZTSE/line/payload-profile/manifest-ancestry-step03/v1", before, statement.openingId, await h.sha(bytes), await h.sha(signature), await h.sha(signed), h.num(accepted));
    const row = { opening_id: body.opening_id, statement: body.statement, signature: body.signature, successor_manifest03: body.successor_manifest03, accepted_ms: String(accepted) };
    f.rows.push({ row, position: { version: f.version, digest: f.digest, ancestry: f.prefix }, acceptedMs: accepted });
    f.receipt = { v: 1, ...row, line_id: h.text(f.line), binding_id: h.text(f.binding), election_digest: h.b64(f.accepted.electionCommitment),
      predecessor_version: String(predecessor), predecessor_digest: h.b64(statement.predecessorDigest), successor_version: String(f.version), successor_digest: h.b64(f.digest),
      operation, predecessor_ancestry_sha256: h.b64(before), ancestry_sha256: h.b64(f.prefix) };
    return f.receipt;
  };
  f.fetch = async (url, options = {}) => {
    const route = new URL(url, f.origin).pathname, body = options.body && JSON.parse(options.body); f.calls.push({ route, body }); let value;
    if (route === "/v1/auth/session") value = { role: "owner", account_id: h.text(f.account), user_id: h.text(f.user), session_id: f.sessionId };
    else if (route.endsWith("/original")) value = { v: 1, kind: "manifest_original03", line_id: h.text(f.line), binding_id: h.text(f.binding), evidence: f.evidence };
    else if (route.endsWith("/history")) { const start = Number(BigInt(body.after_version) - 2n); value = f.page(start, Math.min(start + 8, f.rows.length)); }
    else if (route.endsWith("/manifests/status")) { if (!f.receipt) throw Error("No synthetic accepted receipt"); value = f.receipt; }
    else if (route.endsWith("/manifests")) { f.installCount++; value = await f.accept(body); if (f.loseResponse) throw Error("Synthetic response lost after acceptance"); }
    else throw Error("Unexpected synthetic route");
    return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
  };
  f.openKeys = options => custody.BrowserMessageSigner03KeyStore.open({ ...options, name: prefix + "-keys" });
  f.openAttempts = options => attempts.open({ ...options, name: prefix + "-attempts" });
  f.create = async (extra = {}) => {
    const hc = history.create({ enabled: true, readSelection: () => f.selection, document: f.document, window: f.window, fetch: f.fetch, monotonic: () => f.mono,
      importSdk: load, openRecovery: o => recovery.open({ ...o, name: prefix + "-history" }) }); instances.push(hc);
    await hc.open(f.phoneFile); await hc.next();
    const c = enrollment.create({ enabled: true, history: hc, document: f.document, window: f.window, fetch: f.fetch, monotonic: () => f.mono,
      importSdk: load, openKeyStore: f.openKeys, openRecovery: f.openAttempts, ...extra }); instances.push(c); await c.open(); return { c, hc };
  };
  f.signedOutput = async packet => {
    // The public saved proposal must already exist before offline handoff.
    if (!(packet instanceof Uint8Array)) throw Error("Saved public proposal required");
    const keyScope = { origin: f.origin, accountId: h.text(f.account), originalUserId: h.text(f.user), deviceId: h.text(f.device), lineId: h.text(f.line), rootFingerprint: hex(f.fingerprint) };
    const journal = await f.openAttempts({ scope: keyScope, currentOrigin: () => f.origin }); const saved = await journal.read(); journal.close();
    const unsigned = un64(saved.proposal.unsigned), signed = h.join(unsigned, await h.sign(f.root, h.frame("ZTSE/manifest/v3", unsigned)));
    return { size: signed.length, arrayBuffer: async () => signed.slice().buffer };
  };
  f.close = () => instances.forEach(c => c.close()); f.helpers = h; return f;
}
module.exports = { fixture, load, un64 };
