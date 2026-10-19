// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verifyOriginalRegistrationSignatures03 as registration, verifyOriginalActivationSignatures03 as activation } from '../dist/original-line-evidence03.js';

const enc = new TextEncoder(), N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const regLabel = 'ZTSE/line/payload-profile/registration-evidence/v1';
const actLabel = 'ZTSE/line/payload-profile/activation-evidence/v1';
const cat = (...xs) => Uint8Array.from(Buffer.concat(xs));
const fill = (n, v) => new Uint8Array(n).fill(v);
const num = (n, size = 8) => { const b = new Uint8Array(size), v = new DataView(b.buffer); if (size === 8) v.setBigUint64(0, BigInt(n)); else if (size === 4) v.setUint32(0, Number(n)); else v.setUint16(0, Number(n)); return b; };
const text = s => cat(num(enc.encode(s).length, 2), enc.encode(s));
const framed = (domain, body) => cat(enc.encode(domain + '\0'), num(body.length, 4), body);
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const hex = b => Buffer.from(b).toString('hex');
const scalar = b => BigInt('0x' + hex(b));
const fixed = n => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
function half(raw, high = false) {
  const s = scalar(raw.subarray(32)), low = s > N / 2n ? N - s : s;
  return cat(raw.subarray(0, 32), fixed(high ? N - low : low));
}
function der(raw) {
  const integer = original => {
    let at = 0; while (at < original.length - 1 && original[at] === 0) at++;
    const b = original.slice(at), value = b[0] & 128 ? cat(Uint8Array.of(0), b) : b;
    return cat(Uint8Array.of(2, value.length), value);
  };
  const body = cat(integer(raw.subarray(0, 32)), integer(raw.subarray(32)));
  return cat(Uint8Array.of(48, body.length), body);
}
async function key() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  return { pair, point: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
}
async function sign(k, message, high = false) {
  return half(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.pair.privateKey, message)), high);
}
function regBytes(f) {
  return framed(regLabel, cat(num(f.transcript.length, 4), f.transcript, f.rootSignature, f.approvalSignature,
    f.approval.point, f.approvalFingerprint, f.pairedFingerprint, num(f.issued), num(f.expires), num(f.completed)));
}
function actBytes(f) {
  return framed(actLabel, cat(f.registrationId, f.binding, f.phone.point, f.approval.point, f.deviceStatement,
    num(f.deviceDer.length, 2), f.deviceDer, f.ownerStatement, num(f.ownerDer.length, 2), f.ownerDer, num(f.accepted)));
}
async function fixture({ highDevice = false, highOwner = false } = {}) {
  const f = { root: await key(), approval: await key(), phone: await key(), account: fill(16, 1), user: fill(16, 2), session: fill(16, 3),
    device: fill(16, 4), line: fill(16, 5), registrationId: fill(16, 6), challenge: fill(16, 8), binding: fill(16, 9),
    reader: fill(32, 14), generation: 7n, issued: 2000n, expires: 62000n, completed: 3000n, accepted: 4000n, now: 100000n };
  f.pin = cat(enc.encode('ZTRP\x02'), f.account, num(1), f.root.point);
  f.rootFingerprint = await sha(cat(enc.encode('ZTSE/root-pin/v2\0'), f.pin));
  f.approvalFingerprint = await sha(f.approval.point); f.pairedFingerprint = await sha(f.phone.point);
  // Independently frame the original Rust RootLineRegister order; no SDK encoder.
  f.transcript = cat(enc.encode('ZTSE/line/owner-key/register/v1\0'), f.account, f.user, f.session, f.device, f.line,
    num(f.generation), f.registrationId, fill(32, 7), num(f.issued), num(f.expires), f.pin, f.rootFingerprint,
    f.approval.point, f.approvalFingerprint, f.pairedFingerprint, num(8), num(9), text('site-fixture'), text('instance-fixture'), text('https://owner.invalid'));
  f.rootSignature = await sign(f.root, f.transcript); f.approvalSignature = await sign(f.approval, f.transcript);
  f.observation = cat(num(35, 2), num(2, 2), num(1, 4), Uint8Array.of(2), fill(16, 10), fill(16, 11), num(0, 4), num(1, 4),
    fill(16, 12), num(5), fill(16, 13), fill(32, 15));
  f.deviceStatement = cat(enc.encode('ZTSE/line/device-confirm/v2\0'), Uint8Array.of(2, 2), f.account, f.line, f.device,
    num(f.generation), f.challenge, fill(32, 7), f.observation);
  assert.equal(f.deviceStatement.length, 255);
  f.deviceDer = der(await sign(f.phone, f.deviceStatement, highDevice));
  f.ownerStatement = cat(enc.encode('ZTSE/line/owner-approve/v2\0'), f.deviceStatement, await sha(f.deviceDer));
  assert.equal(f.ownerStatement.length, 314);
  f.ownerDer = der(await sign(f.approval, f.ownerStatement, highOwner));
  f.selected = { accountId: f.account, deviceId: f.device, lineId: f.line, generation: f.generation,
    comparedRootFingerprint: f.rootFingerprint, pairedSigningPoint: f.phone.point, origin: 'https://owner.invalid', trustedNowMs: f.now };
  f.activationSelection = { oldBindingId: f.binding, selectedReaderKeyId: f.reader, trustedNowMs: f.now };
  return f;
}

test('genuine original registration verifies after its window closes without rewriting the historical owner session', async () => {
  const f = await fixture(), bytes = regBytes(f), result = await registration(bytes, f.selected);
  assert.equal(result.accountHex, hex(f.account)); assert.equal(result.originalSessionHex, hex(f.session));
  assert.equal(result.originalUserHex, hex(f.user)); assert.equal(result.generation, f.generation);
  assert.equal(result.evidenceSha256Hex, hex(await sha(bytes))); assert.equal(result.completedMs, f.completed);
  assert.ok(Object.isFrozen(result)); assert.equal('current' in result, false); assert.equal('accepted' in result, false);
});

test('original canonical evidence and old binding digest match independent framing', async () => {
  const f = await fixture(), receipt = await registration(regBytes(f), f.selected), blob = actBytes(f);
  const result = await activation(blob, receipt, f.activationSelection);
  const deviceDigest = await sha(cat(f.deviceStatement, f.deviceDer)), ownerDigest = await sha(cat(f.ownerStatement, f.ownerDer));
  const expected = framed('ZTSE/line/payload-profile/old-binding/v1', cat(Uint8Array.of(2, 2), f.binding, f.account, f.device, f.line,
    num(f.generation), f.challenge, f.registrationId, await sha(regBytes(f)), ownerDigest, deviceDigest, f.reader));
  assert.equal(result.oldBindingDigestHex, hex(await sha(expected))); assert.equal(result.evidenceSha256Hex, hex(await sha(blob)));
  assert.equal(result.deviceConfirmationDigestHex, hex(deviceDigest)); assert.equal(result.ownerApprovalDigestHex, hex(ownerDigest));
  assert.equal(result.acceptedMs, f.accepted); assert.ok(Object.isFrozen(result));
});

test('legacy v2 high-S DER remains valid and its exact bytes stay in owner statement and commitments', async () => {
  for (const options of [{ highDevice: true }, { highOwner: true }, { highDevice: true, highOwner: true }]) {
    const f = await fixture(options), r = await registration(regBytes(f), f.selected), result = await activation(actBytes(f), r, f.activationSelection);
    assert.equal(result.deviceConfirmationDigestHex, hex(await sha(cat(f.deviceStatement, f.deviceDer))));
    assert.equal(result.ownerApprovalDigestHex, hex(await sha(cat(f.ownerStatement, f.ownerDer))));
  }
});

test('registration original raw signatures retain their low-S policy', async () => {
  const f = await fixture();
  for (const field of ['rootSignature', 'approvalSignature']) {
    const changed = { ...f, [field]: half(f[field], true) };
    await assert.rejects(registration(regBytes(changed), f.selected));
  }
});

test('registration rejects wrong independent account, device, line, generation, root, point, origin and time', async () => {
  const f = await fixture();
  for (const change of [{ accountId: fill(16, 20) }, { deviceId: fill(16, 20) }, { lineId: fill(16, 20) }, { generation: 8n },
    { comparedRootFingerprint: fill(32, 20) }, { pairedSigningPoint: (await key()).point }, { origin: 'https://other.invalid' },
    { origin: 'http://owner.invalid' }, { origin: 'https://owner.invalid/' }, { trustedNowMs: f.completed - 1n }, { trustedNowMs: 0n }]) {
    await assert.rejects(registration(regBytes(f), { ...f.selected, ...change }));
  }
});

test('registration detects changed transcript, both signatures, duplicated fingerprints and forged checkpoint', async () => {
  const f = await fixture();
  for (const field of ['transcript', 'rootSignature', 'approvalSignature', 'approvalFingerprint', 'pairedFingerprint']) {
    const copy = Uint8Array.from(f[field]); copy[copy.length - 1] ^= 1;
    await assert.rejects(registration(regBytes({ ...f, [field]: copy }), f.selected));
  }
  for (const change of [{ completed: f.issued - 1n }, { completed: f.expires }, { issued: 1n }, { expires: f.expires + 1n },
    { approvalFingerprint: f.pairedFingerprint }]) await assert.rejects(registration(regBytes({ ...f, ...change }), f.selected));
});

test('all binary frames require exact purpose, length, EOF and bounded ordinary byte storage', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  for (const [blob, run] of [[regBytes(f), b => registration(b, f.selected)], [actBytes(f), b => activation(b, r, f.activationSelection)]]) {
    for (const input of [blob.slice(0, -1), cat(blob, Uint8Array.of(0)), fill(4096, 1), new Uint8Array(new SharedArrayBuffer(blob.length))]) {
      await assert.rejects(run(input));
    }
    for (const at of [0, blob.indexOf(0) + 1]) { const changed = Uint8Array.from(blob); changed[at] ^= 1; await assert.rejects(run(changed)); }
  }
});

test('synthetic opaque canonical vector is not a signature or original receipt', async () => {
  const f = await fixture();
  const v = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/profile03-authority-adapter-canonical.json', import.meta.url), 'utf8'));
  await assert.rejects(registration(Uint8Array.from(Buffer.from(v.registration_evidence.canonical_hex, 'hex')), f.selected));
});

test('shared independently signed original vector preserves legacy high-S and exact old binding commitment', async () => {
  const v = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/sealed-profile03-activation-evidence-01.json', import.meta.url), 'utf8'));
  const decode = value => Uint8Array.from(Buffer.from(value, 'hex'));
  const original = decode(v.activation_evidence), at = enc.encode(actLabel + '\0').length + 4 + 32;
  const pairedPoint = original.slice(at, at + 65);
  // Match the separately recorded producer's signing-key identity, not an echo field.
  assert.equal(hex(await sha(cat(enc.encode('ZTSE/key/v1\0'), Uint8Array.of(4), pairedPoint))), v.paired_signing_key_id);
  const r = await registration(decode(v.registration_evidence), {
    accountId: decode(v.account_id), deviceId: decode(v.device_id), lineId: decode(v.line_id), generation: BigInt(v.generation),
    comparedRootFingerprint: decode(v.root_fingerprint), pairedSigningPoint: pairedPoint, origin: v.origin, trustedNowMs: 100000n,
  });
  const checked = await activation(original, r, { oldBindingId: decode(v.old_binding_id),
    selectedReaderKeyId: decode(v.selected_reader_key_id), trustedNowMs: 100000n });
  assert.equal(checked.oldBindingDigestHex, v.old_binding_proof_digest);
  assert.equal(checked.activationChallengeHex, v.activation_challenge_id);
  assert.equal(checked.registrationHex, v.registration_id); assert.equal(checked.acceptedMs, BigInt(v.accepted_ms));
});

test('original activation rejects unverified or copied registration objects', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  for (const candidate of [{ ...r }, Object.freeze({ ...r }), {}, null]) await assert.rejects(activation(actBytes(f), candidate, f.activationSelection));
});

test('activation refuses substituted original points, identities, generation and signature hashes', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  for (const change of [{ registrationId: fill(16, 20) }, { binding: fill(16, 20) }, { phone: await key() }, { approval: await key() },
    { accepted: f.completed - 1n }, { accepted: f.now + 1n }, { ownerStatement: fill(314, 1) }]) {
    await assert.rejects(activation(actBytes({ ...f, ...change }), r, f.activationSelection));
  }
  for (const at of [28, 29, 30, 46, 62, 78, 86, 102, 134]) {
    const changed = Uint8Array.from(f.deviceStatement); changed[at] ^= 1;
    await assert.rejects(activation(actBytes({ ...f, deviceStatement: changed }), r, f.activationSelection));
  }
  const other = await fixture({ highDevice: true });
  await assert.rejects(activation(actBytes({ ...f, deviceDer: other.deviceDer }), r, f.activationSelection));
});

test('canonical DER rejects zero, negative, padded, oversized, trailing and changed original signatures', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  const bad = [Uint8Array.of(48, 6, 2, 1, 0, 2, 1, 1), Uint8Array.of(48, 6, 2, 1, 128, 2, 1, 1),
    Uint8Array.of(48, 7, 2, 2, 0, 1, 2, 1, 1), fill(81, 1), cat(f.deviceDer, Uint8Array.of(0))];
  for (const field of ['deviceDer', 'ownerDer']) for (const changed of bad) await assert.rejects(activation(actBytes({ ...f, [field]: changed }), r, f.activationSelection));
  const changed = Uint8Array.from(f.ownerDer); changed[changed.length - 1] ^= 1;
  await assert.rejects(activation(actBytes({ ...f, ownerDer: changed }), r, f.activationSelection));
});

test('valid signatures cannot replace wrong sealed purpose, observation ranges or binding identity', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  for (const [at, value] of [[29, 1], [135, 32], [136, 2], [137, 0], [142, 3], [175, 255]]) {
    const deviceStatement = Uint8Array.from(f.deviceStatement); deviceStatement[at] = value;
    const deviceDer = der(await sign(f.phone, deviceStatement));
    const ownerStatement = cat(enc.encode('ZTSE/line/owner-approve/v2\0'), deviceStatement, await sha(deviceDer));
    const ownerDer = der(await sign(f.approval, ownerStatement));
    // Changing a high byte to its existing zero would not change an observation.
    if (hex(deviceStatement) === hex(f.deviceStatement)) continue;
    await assert.rejects(activation(actBytes({ ...f, deviceStatement, deviceDer, ownerStatement, ownerDer }), r, f.activationSelection));
  }
  await assert.rejects(activation(actBytes({ ...f, binding: f.challenge }), r, { ...f.activationSelection, oldBindingId: f.challenge }));
});

test('selection records reject accessors, extras and unsupported byte kinds without invoking a getter', async () => {
  const f = await fixture(); let invoked = false;
  const getter = { ...f.selected }; Object.defineProperty(getter, 'origin', { get() { invoked = true; return 'https://owner.invalid'; } });
  await assert.rejects(registration(regBytes(f), getter)); assert.equal(invoked, false);
  await assert.rejects(registration(regBytes(f), { ...f.selected, password: 'example' }));
  await assert.rejects(registration(regBytes(f), { ...f.selected, accountId: new Uint16Array(8) }));
  const r = await registration(regBytes(f), f.selected);
  await assert.rejects(activation(actBytes(f), r, { ...f.activationSelection, current: true }));
  await assert.rejects(activation(actBytes(f), r, { ...f.activationSelection, selectedReaderKeyId: fill(32, 0) }));
});

test('input and selection buffers are captured before the first asynchronous validation', async () => {
  const f = await fixture(), input = regBytes(f), expected = { ...f.selected, accountId: Uint8Array.from(f.account), pairedSigningPoint: Uint8Array.from(f.phone.point) };
  const pending = registration(input, expected); input.fill(0); expected.accountId.fill(0); expected.pairedSigningPoint.fill(0); expected.origin = 'https://other.invalid';
  const r = await pending; assert.equal(r.accountHex, hex(f.account));
  const blob = actBytes(f), selected = { ...f.activationSelection, oldBindingId: Uint8Array.from(f.binding), selectedReaderKeyId: Uint8Array.from(f.reader) };
  const next = activation(blob, r, selected); blob.fill(0); selected.oldBindingId.fill(0); selected.selectedReaderKeyId.fill(0);
  const result = await next; assert.equal(result.oldBindingHex, hex(f.binding));
});

test('later verifier calls refuse a regressing trusted observation instead of renewing historical evidence', async () => {
  const f = await fixture(), r = await registration(regBytes(f), f.selected);
  await assert.rejects(activation(actBytes(f), r, { ...f.activationSelection, trustedNowMs: f.now - 1n }));
  const old = await activation(actBytes(f), r, { ...f.activationSelection, trustedNowMs: f.now + 1000n });
  assert.equal(old.acceptedMs, f.accepted);
});
