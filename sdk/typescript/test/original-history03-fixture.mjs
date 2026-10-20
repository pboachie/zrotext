// SPDX-License-Identifier: AGPL-3.0-only
// Genuine ephemeral signature fixtures; no hardware, hosted acceptance or owner roots.
import { canonicalP256Signature } from '../dist/draft01.js';
import { verifyOriginalRegistrationSignatures03, verifyOriginalActivationSignatures03 } from '../dist/original-line-evidence03.js';
const enc = new TextEncoder(), fill = (n, v) => new Uint8Array(n).fill(v);
const cat = (...parts) => Uint8Array.from(Buffer.concat(parts));
const num = (n, width = 8) => { const out = new Uint8Array(width), v = new DataView(out.buffer); if (width === 8) v.setBigUint64(0, BigInt(n)); else if (width === 4) v.setUint32(0, Number(n)); else v.setUint16(0, Number(n)); return out; };
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const frame = (s, b) => cat(enc.encode(s + '\0'), num(b.length, 4), b);
const text = s => cat(num(enc.encode(s).length, 2), enc.encode(s));
const sign = async (k, b) => canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.pair.privateKey, b)));
function der(raw) {
  const integer = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 128) b = cat(Uint8Array.of(0), b); return cat(Uint8Array.of(2, b.length), b); };
  const b = cat(integer(raw.slice(0, 32)), integer(raw.slice(32))); return cat(Uint8Array.of(48, b.length), b);
}
export async function originals(f) {
  const registrationId = fill(16, 201), activationId = fill(16, 202);
  const transcript = cat(enc.encode('ZTSE/line/owner-key/register/v1\0'), f.account, f.user, f.session, f.device, f.line,
    num(4), registrationId, fill(32, 203), num(9000), num(20000), f.pin, f.fingerprint,
    f.approval.point, await sha(f.approval.point), await sha(f.phone.point), num(1), num(1), text('fixture-site'), text('fixture-instance'), text(f.origin));
  const registration = frame('ZTSE/line/payload-profile/registration-evidence/v1', cat(num(transcript.length, 4), transcript,
    await sign(f.root, transcript), await sign(f.approval, transcript), f.approval.point, await sha(f.approval.point), await sha(f.phone.point), num(9000), num(20000), num(9200)));
  const observation = cat(num(35, 2), num(2, 2), num(1, 4), Uint8Array.of(2), fill(16, 10), fill(16, 11), num(0, 4), num(1, 4), fill(16, 12), num(5), fill(16, 13), fill(32, 15));
  const ds = cat(enc.encode('ZTSE/line/device-confirm/v2\0'), Uint8Array.of(2, 2), f.account, f.line, f.device, num(4), activationId, fill(32, 204), observation);
  const dsig = der(await sign(f.phone, ds)), os = cat(enc.encode('ZTSE/line/owner-approve/v2\0'), ds, await sha(dsig)), osig = der(await sign(f.approval, os));
  const activation = frame('ZTSE/line/payload-profile/activation-evidence/v1', cat(registrationId, f.oldBinding, f.phone.point, f.approval.point, ds, num(dsig.length, 2), dsig, os, num(osig.length, 2), osig, num(9300)));
  const r = await verifyOriginalRegistrationSignatures03(registration, { accountId: f.account, deviceId: f.device, lineId: f.line, generation: 4n,
    comparedRootFingerprint: f.fingerprint, pairedSigningPoint: f.phone.point, origin: f.origin, trustedNowMs: f.acceptedMs });
  const a = await verifyOriginalActivationSignatures03(activation, r, { oldBindingId: f.oldBinding, selectedReaderKeyId: f.reader, trustedNowMs: f.acceptedMs });
  return { registration, activation, oldProof: Uint8Array.from(Buffer.from(a.oldBindingDigestHex, 'hex')) };
}
