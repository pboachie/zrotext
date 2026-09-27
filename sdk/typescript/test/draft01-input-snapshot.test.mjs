import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { keyId, openDraftEnvelope, parseDraftEnvelope, signatureInput, wrapInfo } from "../dist/draft01.js";

const fixture = JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const envelope = () => bytes(fixture.outbound.envelopeHex);
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
async function context() {
  const pair = await suite.kem.deriveKeyPair(bytes(fixture.deviceIkmHex));
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { accountId: bytes(fixture.accountIdHex), deviceId: bytes(fixture.deviceIdHex),
    lineId: bytes(fixture.lineIdHex), peer: fixture.peer, manifestDigest: bytes(fixture.manifestDigestHex),
    signerPublicPoint: bytes(fixture.signerPublicPointHex), recipientRole: 1,
    recipientKeyId: await keyId(0x0010, point), recipientPrivateKey: pair.privateKey };
}

test("draft reader checks the signer point supplied at invocation", async () => {
  const replacement = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const changed = envelope();
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    replacement.privateKey, signatureInput(parseDraftEnvelope(changed))));
  changed.set(signature, changed.length - 64);
  const expected = await context();
  const replacementPoint = new Uint8Array(await crypto.subtle.exportKey("raw", replacement.publicKey));
  const pending = openDraftEnvelope(changed, expected);
  expected.signerPublicPoint.set(replacementPoint);
  await assert.rejects(pending, /origin signature/);
});

test("draft reader uses the recipient key ID supplied at invocation", async () => {
  const expected = await context();
  const correct = Uint8Array.from(expected.recipientKeyId);
  expected.recipientKeyId.fill(0);
  const pending = openDraftEnvelope(envelope(), expected);
  expected.recipientKeyId.set(correct);
  await assert.rejects(pending, /authorized recipient wrap missing/);
});

test("draft reader is unaffected by later changes to its input buffers", async () => {
  const expected = await context();
  const input = envelope();
  const pending = openDraftEnvelope(input, expected);
  input.fill(0);
  expected.signerPublicPoint.fill(0);
  expected.recipientKeyId.fill(0);
  expected.accountId.fill(0);
  expected.recipientRole = 3;
  expected.recipientPrivateKey = null;
  assert.equal(await pending, fixture.outbound.plaintext);
});

test("draft wrap info uses the recipient identity supplied at invocation", async () => {
  const parsed = parseDraftEnvelope(envelope());
  const wrap = parsed.wraps[0];
  const original = await wrapInfo(parsed, wrap);
  const pending = wrapInfo(parsed, wrap);
  parsed.protected.fill(0);
  wrap.keyId.fill(0);
  wrap.role = 3;
  assert.deepEqual(await pending, original);
});
