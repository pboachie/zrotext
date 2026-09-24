import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { bodyAad, keyId, openDraftEnvelope, parseDraftEnvelope, signatureInput, wrapAad, wrapInfo } from "../dist/draft01.js";

globalThis.crypto ??= webcrypto;
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const fixture = JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
const envelope = (which) => bytes(fixture[which].envelopeHex);

async function context(role) {
  const ikm = bytes(role === 1 ? fixture.deviceIkmHex : fixture.archiveIkmHex);
  const pair = await suite.kem.deriveKeyPair(ikm);
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return {
    accountId: bytes(fixture.accountIdHex), deviceId: bytes(fixture.deviceIdHex),
    lineId: bytes(fixture.lineIdHex), peer: fixture.peer,
    manifestDigest: bytes(fixture.manifestDigestHex), signerPublicPoint: bytes(fixture.signerPublicPointHex),
    recipientRole: role, recipientKeyId: await keyId(0x0010, point), recipientPrivateKey: pair.privateKey,
  };
}

test("RFC 9180 A.3.1 P-256 base-mode known answer", async () => {
  // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1
  const rfc = {
    ikmR: "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550",
    ikmE: "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
    enc: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
    info: "4f6465206f6e2061204772656369616e2055726e",
    pt: "4265617574792069732074727574682c20747275746820626561757479",
    aad: "436f756e742d30",
    ct: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
  };
  const recipientKey = await suite.kem.deriveKeyPair(bytes(rfc.ikmR));
  const sender = await suite.createSenderContext({ recipientPublicKey: recipientKey.publicKey, info: bytes(rfc.info), ekm: bytes(rfc.ikmE) });
  assert.equal(hex(sender.enc), rfc.enc);
  assert.equal(hex(await sender.seal(bytes(rfc.pt), bytes(rfc.aad))), rfc.ct);
  const recipient = await suite.createRecipientContext({ recipientKey: recipientKey.privateKey, enc: bytes(rfc.enc), info: bytes(rfc.info) });
  assert.equal(hex(await recipient.open(bytes(rfc.ct), bytes(rfc.aad))), rfc.pt);
  const wrong = await suite.createRecipientContext({ recipientKey: recipientKey.privateKey, enc: bytes(rfc.enc), info: bytes(rfc.info) });
  await assert.rejects(wrong.open(bytes(rfc.ct), bytes("00")));
});

for (const [which, role] of [["outbound", 1], ["inbound", 2]]) {
  test(`${which}: exact draft bytes and independent Web Crypto / HPKE open`, async () => {
    const vector = fixture[which];
    const parsed = parseDraftEnvelope(envelope(which));
    assert.equal(parsed.kind, vector.kind);
    assert.equal(hex(parsed.protected), vector.protectedHex);
    assert.equal(hex(parsed.unsigned), vector.unsignedHex);
    assert.equal(hex(parsed.signature), vector.signatureHex);
    assert.equal(hex(createHash("sha256").update(parsed.unsigned).digest()), vector.unsignedSha256);
    assert.equal(hex(bodyAad(parsed)), vector.bodyAadHex);
    assert.equal(signatureInput(parsed).length, parsed.unsigned.length + "ZTSE/sign/v1\0".length + 4);
    for (const [index, wrap] of parsed.wraps.entries()) {
      const transcript = vector.wrapTranscripts[index];
      assert.equal(wrap.role, transcript.role);
      assert.equal(hex(wrap.keyId), transcript.keyIdHex);
      assert.equal(hex(await wrapInfo(parsed, wrap)), transcript.infoHex);
      assert.equal(hex(wrapAad(parsed, wrap)), transcript.aadHex);
    }
    assert.equal(await openDraftEnvelope(envelope(which), await context(role)), vector.plaintext);
  });
}

test("shape and parse failures reject ambiguous bytes before opening", () => {
  const good = envelope("outbound");
  const variants = [good.subarray(0, good.length - 1), Uint8Array.from([...good, 0]),
    patch(good, 4, 2), patch(good, 5, 2), patch(good, 6, 1), patch(good, 9, good[9] + 1),
    patch(good, 10 + 152, 2), patch(good, 10 + 153, 2), patch(good, 10 + 144, 0xff),
    patch(good, 10 + 64, 0x80), patch(good, 10 + 136, 0x80)];
  for (const variant of variants) assert.throws(() => parseDraftEnvelope(variant));
  const parsed = parseDraftEnvelope(good);
  const countAt = parsed.unsigned.length - 1 - parsed.wraps.length * 146;
  const firstWrapAt = countAt + 1;
  for (const variant of [patch(good, countAt, 9), patch(good, firstWrapAt, 3), patch(good, firstWrapAt + 33, 2)]) {
    assert.throws(() => parseDraftEnvelope(variant));
  }
  const inbound = envelope("inbound");
  assert.throws(() => parseDraftEnvelope(patch(inbound, 10 + 144, 0)));
  assert.throws(() => parseDraftEnvelope(patch(inbound, 10 + 160, 0x80)));
});

test("signed field tampering and routing substitutions fail closed", async () => {
  const good = envelope("outbound");
  const expected = await context(1);
  const parsed = parseDraftEnvelope(good);
  const countAt = parsed.unsigned.length - 1 - parsed.wraps.length * 146;
  const changes = [10, 26, 42, 58, 82, 114, 146, 163, 167, 180, countAt + 2,
    countAt + 34, countAt + 99, good.length - 1];
  for (const at of changes) await assert.rejects(openDraftEnvelope(patch(good, at, good[at] ^ 1), expected));
  for (const changed of [
    { ...expected, accountId: new Uint8Array(16) },
    { ...expected, deviceId: new Uint8Array(16) },
    { ...expected, lineId: new Uint8Array(16) },
    { ...expected, peer: "+13" },
    { ...expected, manifestDigest: new Uint8Array(32) },
    { ...expected, recipientRole: 3 },
  ]) await assert.rejects(openDraftEnvelope(good, changed));
});

test("valid re-signatures cannot relocate existing ciphertext to new protected bytes or nonce", async () => {
  const good = envelope("outbound");
  const expected = await context(1);
  for (const at of [26, 58, 166, 10 + parseDraftEnvelope(good).protected.length]) {
    const changed = patch(good, at, good[at] ^ 1);
    const resigned = await resign(changed);
    const signer = await crypto.subtle.importKey("raw", bytes(fixture.signerPublicPointHex),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const parsed = parseDraftEnvelope(resigned);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signer,
      parsed.signature, signatureInput(parsed)), true);
    const adjusted = at === 58 ? { ...expected, lineId: parsed.lineId }
      : at === 166 ? { ...expected, peer: parsed.peer } : expected;
    await assert.rejects(openDraftEnvelope(resigned, adjusted));
  }
});

test("re-signed invalid encapsulated point still fails cryptographic validation", async () => {
  const good = envelope("outbound");
  const parsed = parseDraftEnvelope(good);
  const firstWrapAt = parsed.unsigned.length - parsed.wraps.length * 146;
  const changed = patch(good, firstWrapAt + 34, 0xff);
  await assert.rejects(openDraftEnvelope(await resign(changed), await context(1)));
});

async function resign(envelopeBytes) {
  const point = bytes(fixture.signerPublicPointHex);
  const scalar = new Uint8Array(32); scalar[31] = 5;
  const signer = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: Buffer.from(point.subarray(1, 33)).toString("base64url"),
    y: Buffer.from(point.subarray(33)).toString("base64url"), d: Buffer.from(scalar).toString("base64url"),
    ext: true, key_ops: ["sign"],
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const parsed = parseDraftEnvelope(envelopeBytes);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer, signatureInput(parsed));
  const output = Uint8Array.from(envelopeBytes);
  output.set(new Uint8Array(signature), parsed.unsigned.length);
  return output;
}

function patch(source, at, value) {
  const result = Uint8Array.from(source);
  result[at] = value;
  return result;
}
