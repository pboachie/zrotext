// SPDX-License-Identifier: AGPL-3.0-only
// Genuine ephemeral encryption/signatures; HTTP and IndexedDB are test fixtures.
const path = require("node:path"), { createRequire } = require("node:module"), { pathToFileURL } = require("node:url");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const load = n => import(pathToFileURL(path.join(__dirname, "../../sdk/typescript/dist", n + ".js")).href);
const b64 = b => Buffer.from(b).toString("base64url");
const id = b => Buffer.from(b).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
async function fixture() {
  const h = await import("../../sdk/typescript/test/fixtures/profile03-outbound-fixture.mjs"), f = await h.fixture();
  const sdk = Object.assign({}, ...await Promise.all(["sealed-envelope03", "reviewed-intent03", "owner-reviewed-send03"].map(load)));
  const scope = { origin: "https://example.test", accountId: id(f.authority.accountId), originalUserId: id(h.uuid(140)), deviceId: id(f.authority.deviceId),
    lineId: id(f.authority.lineId), rootFingerprint: Buffer.from(f.fingerprint).toString("hex"), peer: "+12" };
  const context = await sdk.captureTrustedReviewContext03({ currentAuthority: h.clone(f.authority), manifest: f.currentManifest, acceptedElection: f.proof,
    accountSelectionEpoch: 1n, ownerUserId: h.uuid(140), ownerSessionId: h.uuid(160), canonicalOrigin: scope.origin, intervalId: h.uuid(180),
    intervalFromMs: 20000n, intervalUntilMs: 60000n, peer: h.enc.encode(scope.peer), signerKeyId: f.records[4].id.slice(),
    recipients: f.records.slice(0, 3).map(r => ({ role: r.role, keyId: r.id.slice() })), nowMs: h.present });
  const sign = async bytes => h.canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.privateKey, bytes)));
  async function make() {
    const composition = { ...h.inputFor(f), messageId: Uint8Array.from(Buffer.from(crypto.randomUUID().replaceAll("-", ""), "hex")) };
    const { signerPrivateKey: _key, ...unsignedInput } = composition, prepared = await sdk.prepareSealedOutboundEnvelope03(unsignedInput);
    const snapshot = sdk.preparedOutboundEnvelopeSnapshot03(prepared), signature = await sign(snapshot.transcript);
    const out = await sdk.completeSealedOutboundEnvelope03({ prepared, signature, nowMs: h.present });
    const intent = await sdk.prepareReviewedIntent03V2({ context, envelope: out.envelope, reviewIssuedMs: h.present, reviewExpiresMs: 35000n, smsCeiling: 2, nowMs: h.present });
    const reviewedSignature = await sign(sdk.reviewedIntentTranscript03V2(intent));
    const proof = await sdk.verifyReviewedIntent03V2({ context, envelope: out.envelope, intent, signature: reviewedSignature, nowMs: h.present });
    const first = { v: 1, message_id: id(composition.messageId), interval_id: id(h.uuid(180)), owner_session_id: id(h.uuid(160)), unsigned_envelope: b64(snapshot.unsignedEnvelope),
      envelope: null, reviewed_intent: null, reviewed_signature: null, stage: "envelope_sign_reserved", closed: false, receipt: null };
    const signed = { ...first, envelope: b64(out.envelope), stage: "envelope_signed" };
    const intentReserved = { ...signed, reviewed_intent: b64(intent), stage: "intent_sign_reserved" };
    const complete = { ...intentReserved, reviewed_signature: b64(reviewedSignature), stage: "intent_signed" };
    const submitted = { ...complete, stage: "submit_reserved" };
    const receipt = { v: 1, message_id: first.message_id, interval_id: first.interval_id, accepted_ms: "30000", expires_ms: "40000", selection_epoch: "1",
      envelope_sha256: b64(await h.sha(out.envelope)), reviewed_intent_sha256: b64(await h.sha(intent)), reviewed_signature_sha256: b64(await h.sha(reviewedSignature)), sms_ceiling: 2 };
    const accepted = { ...submitted, stage: "accepted", receipt };
    return { first, signed, intentReserved, complete, submitted, accepted, proof, content: composition.content };
  }
  return { scope, make, sdk, load, b64, present: h.present };
}
module.exports = { fixture, load };
