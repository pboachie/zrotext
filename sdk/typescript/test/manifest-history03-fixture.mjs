// SPDX-License-Identifier: AGPL-3.0-only
// Generated synthetic P-256 fixtures only; no owner custody or acceptance claim.
import { canonicalP256Signature, keyId } from '../dist/draft01.js';
import { enrollRootPin02, verifyManifest02 } from '../dist/draft02-manifest.js';
import { verifyManifest03From02 } from '../dist/draft03-manifest.js';
import { verifyAcceptedPayloadProfileElection03 } from '../dist/payload-profile-election03.js';
import { encodeProfile03ManifestProposal, verifyProfile03ManifestOutput } from '../dist/profile03-manifest-proposal.js';
import { encodeManifestInstall03, manifestInstallSigningBytes03 } from '../dist/manifest-install03.js';
export const enc = new TextEncoder(), zero16 = new Uint8Array(16), zero32 = new Uint8Array(32);
export const uuid = n => Uint8Array.from({ length: 16 }, (_, i) => n + i);
export const b64 = b => Buffer.from(b).toString('base64url');
export const text = b => Buffer.from(b).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
export function join(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; }
export function num(n, width = 8) { const b = new Uint8Array(width), v = new DataView(b.buffer); if (width === 8) v.setBigUint64(0, n); else if (width === 4) v.setUint32(0, Number(n)); else v.setUint16(0, Number(n)); return b; }
export const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
export const frame = (label, bytes) => join(enc.encode(label + '\0'), num(BigInt(bytes.length), 4), bytes);
export const hash = async (label, ...parts) => sha(frame(label, join(...parts)));
export async function key() { const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']); return { pair, point: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) }; }
export const sign = async (k, bytes) => canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.pair.privateKey, bytes)));
export async function fixture() {
  const f = { root: await key(), phone: await key(), approval: await key(), origin: 'https://owner.invalid', account: uuid(1), device: uuid(20), line: uuid(40),
    challenge: uuid(60), oldBinding: uuid(80), binding: uuid(100), user: uuid(140), session: uuid(160), acceptedMs: 10000n };
  const records = [];
  for (const role of [1, 2, 4, 6]) {
    const k = role === 6 ? f.root : role === 4 ? f.phone : await key();
    records.push(join(Uint8Array.of(role), await keyId(role <= 3 ? 0x10 : 0x101, k.point), k.point,
      [1, 4].includes(role) ? f.device : zero16, [1, 4].includes(role) ? f.line : zero16,
      num(BigInt({ 1: 4, 2: 12, 4: 2, 6: 0 }[role]), 2), num(9000n), num(2000000n), Uint8Array.of(1)));
  }
  f.reader = records[0].slice(1, 33);
  const manifest = async (profile, version, previous) => {
    const body = join(enc.encode('ZTMA'), Uint8Array.of(profile), ...(profile === 3 ? [Uint8Array.of(3, 2)] : []),
      f.account, num(1n), num(version), num(9000n), num(2000000n), previous, f.root.point, Uint8Array.of(records.length), ...records);
    return { signed: join(body, await sign(f.root, frame(`ZTSE/manifest/v${profile}`, body))), digest: await sha(body) };
  };
  f.pin = join(enc.encode('ZTRP'), Uint8Array.of(2), f.account, num(1n), f.root.point);
  f.fingerprint = await sha(join(enc.encode('ZTSE/root-pin/v2\0'), f.pin));
  const trust = await enrollRootPin02(f.pin, f.fingerprint), old = await manifest(2, 1n, zero32);
  const prior = await verifyManifest02(old.signed, trust, f.acceptedMs), first = await manifest(3, 2n, old.digest);
  f.first = await verifyManifest03From02(first.signed, prior, old.signed, f.acceptedMs);
  const digest = n => new Uint8Array(32).fill(n);
  f.core = join(enc.encode('ZTPE'), Uint8Array.of(3, 1, 2, 3), f.account, f.device, f.line, f.challenge, f.oldBinding, num(4n), num(7n), digest(1),
    f.fingerprint, num(1n), num(1n), old.digest, num(2n), first.digest, f.reader,
    await keyId(0x101, f.phone.point), await keyId(0x101, f.approval.point), digest(2), num(9000n), num(20000n), digest(3), digest(4), digest(5), new Uint8Array(4));
  const ds = await sign(f.phone, frame('ZTSE/line/payload-profile/device/v1', f.core));
  f.bundle = join(f.core, ds, await sign(f.approval, frame('ZTSE/line/payload-profile/owner/v1', join(f.core, await sha(ds)))));
  f.accepted = { accountId: f.account, deviceId: f.device, lineId: f.line, rootFingerprint: f.fingerprint, vaultGeneration: 1n,
    oldBindingId: f.oldBinding, oldBindingGeneration: 4n, oldBindingProofDigest: digest(1), newBindingId: f.binding, newBindingGeneration: 7n,
    selectedReaderKeyId: f.reader, priorManifestVersion: 1n, priorManifestDigest: old.digest, priorSignedManifestSha256: await sha(old.signed),
    acceptedManifestVersion: 2n, acceptedManifestDigest: first.digest, acceptedSignedManifestSha256: await sha(first.signed), electionCoreSha256: await sha(f.core),
    electionCommitment: await hash('ZTSE/line/payload-profile/commitment/v1', f.core), electionBundleSha256: await sha(f.bundle), acceptedAtMs: f.acceptedMs };
  f.proof = await verifyAcceptedPayloadProfileElection03({ bundle: f.bundle, expectedCore: f.core, acceptedRecord: f.accepted,
    predecessor02: prior, priorSignedManifest02: old.signed, acceptedSignedManifest03: first.signed,
    deviceSigningPointAtAcceptance: f.phone.point, ownerApprovalPointAtAcceptance: f.approval.point });
  f.evidence = { root_pin: b64(f.pin), prior_manifest02: b64(old.signed), prior_accepted_ms: '10000', accepted_manifest03: b64(first.signed),
    accepted_ms: '10000', bundle: b64(f.bundle), device_signing_point: b64(f.phone.point), owner_approval_point: b64(f.approval.point),
    registration_evidence: 'AQ', activation_evidence: 'AQ' };
  f.seed = { acceptedElection: f.proof, firstManifest: f.first, originalEvidence: f.evidence, origin: f.origin };
  f.signed = first.signed; f.current = f.first; f.version = 2n; f.digest = first.digest;
  f.prefix = await hash('ZTSE/line/payload-profile/manifest-ancestry-base03/v1', f.account, f.challenge, f.binding, await sha(first.signed), num(f.acceptedMs), f.accepted.electionBundleSha256);
  f.firstPosition = { version: f.version, digest: f.digest, ancestry: f.prefix }; f.rows = [];
  f.step = async (browser, issuedMs = f.acceptedMs + 1000n) => {
    const active = Array.from({ length: f.signed[152] }, (_, i) => f.signed.slice(153 + i * 149, 153 + (i + 1) * 149)).find(r => r[0] === 5 && r[148] === 1);
    const browserId = await keyId(0x101, browser.point), operation = !active ? 'enroll' : b64(active.slice(1, 33)) === b64(browserId) ? 'renew' : 'replace';
    const scope = { operation, accountId: f.account, deviceId: f.device, lineId: f.line, origin: f.origin, rootFingerprint: f.fingerprint,
      predecessorVersion: f.version, predecessorDigest: f.digest, predecessorAcceptedMs: f.acceptedMs, phoneReaderKeyId: f.reader,
      browserPoint: browser.point, browserKeyId: browserId, issuedMs, expiresMs: 2000000n + BigInt(f.rows.length + 1) * 100000n };
    const input = { scope, predecessor: f.current, originalSigned03: f.signed, nowMs: issuedMs + 5n };
    const proposal = await encodeProfile03ManifestProposal(input), signed = join(proposal.unsigned, await sign(f.root, frame('ZTSE/manifest/v3', proposal.unsigned)));
    const opening = uuid(180 + f.rows.length), statement = await encodeManifestInstall03({ accountId: f.account, ownerUserId: f.user, ownerSessionId: f.session,
      deviceId: f.device, lineId: f.line, bindingId: f.binding, electionChallengeId: f.challenge, openingId: opening,
      bindingGeneration: 7n, vaultGeneration: 1n, selectionEpoch: 1n, predecessorVersion: f.version, successorVersion: f.version + 1n,
      issuedMs, expiresMs: issuedMs + 300000n, rootFingerprint: f.fingerprint, electionCommitment: f.accepted.electionCommitment,
      electionBundleSha256: f.accepted.electionBundleSha256, originDigest: await sha(enc.encode(f.origin)),
      ownerSessionDigest: await hash('ZTSE/line/payload-profile/owner-session/v1', f.account, f.user, f.session), predecessorDigest: f.digest,
      signedSuccessorSha256: await sha(signed), signerKeyId: browserId, signerPoint: browser.point });
    const signature = await sign(browser, await manifestInstallSigningBytes03(statement)), acceptedMs = issuedMs + 5n;
    const prefix = await hash('ZTSE/line/payload-profile/manifest-ancestry-step03/v1', f.prefix, opening, await sha(statement), await sha(signature), await sha(signed), num(acceptedMs));
    const row = { opening_id: text(opening), statement: b64(statement), signature: b64(signature), successor_manifest03: b64(signed), accepted_ms: String(acceptedMs) };
    f.current = await verifyProfile03ManifestOutput({ ...input, signed03: signed }); f.signed = signed; f.version++; f.digest = await sha(signed.slice(0, -64)); f.prefix = prefix; f.acceptedMs = acceptedMs;
    f.rows.push({ row, position: { version: f.version, digest: f.digest, ancestry: f.prefix }, acceptedMs }); return row;
  };
  f.page = (start = 0, end = f.rows.length) => {
    const after = start ? f.rows[start - 1].position : f.firstPosition, next = end ? f.rows[end - 1].position : f.firstPosition;
    return { v: 1, kind: 'manifest_ancestry03', account_id: text(f.account), device_id: text(f.device), line_id: text(f.line), binding_id: text(f.binding),
      binding_generation: '7', selection_epoch: '1', election_digest: b64(f.accepted.electionCommitment), election_bundle_sha256: b64(f.accepted.electionBundleSha256),
      root_fingerprint: b64(f.fingerprint), after_version: String(after.version), after_digest: b64(after.digest), after_ancestry_sha256: b64(after.ancestry),
      tip_version: String(f.version), tip_digest: b64(f.digest), tip_ancestry_sha256: b64(f.prefix), tip_accepted_ms: String(f.acceptedMs), compared_ms: String(f.acceptedMs + 100n),
      entries: f.rows.slice(start, end).map(v => structuredClone(v.row)), next_version: String(next.version), next_digest: b64(next.digest), next_ancestry_sha256: b64(next.ancestry),
      complete: end === f.rows.length, evidence: { ...f.evidence } };
  };
  f.authority = () => ({ profile: 3, manifestProfile: 3, accountId: f.account, deviceId: f.device, lineId: f.line, bindingId: f.binding, bindingGeneration: 7n,
    selectedReaderKeyId: f.reader, rootFingerprint: f.fingerprint, vaultGeneration: 1n, manifestVersion: f.version, manifestDigest: f.digest,
    electionCommitment: f.accepted.electionCommitment, electionBundleSha256: f.accepted.electionBundleSha256, comparedAtMs: f.acceptedMs + 100n, permissionExpiresAtMs: f.acceptedMs + 10000n });
  f.wireCurrent = async () => ({ v: 1, kind: 'owner_manifest_selection03', envelope_profile: 3, manifest_profile: 3,
    account_id: text(f.account), user_id: text(f.user), owner_session_id: text(f.session), device_id: text(f.device), line_id: text(f.line), selection_epoch: '1',
    origin_digest: b64(await sha(enc.encode(f.origin))), owner_session_digest: b64(await hash('ZTSE/line/payload-profile/owner-session/v1', f.account, f.user, f.session)),
    device_session_digest: b64(new Uint8Array(32).fill(1)), site_id: 'synthetic-site', instance_id: 'synthetic-instance', connection_epoch: '1', deployment_epoch: '1',
    old_binding_id: text(f.oldBinding), old_binding_generation: '4', old_binding_proof_digest: b64(f.accepted.oldBindingProofDigest), binding_id: text(f.binding), binding_generation: '7',
    reader_key_id: b64(f.reader), device_signing_key_id: b64(await keyId(0x101, f.phone.point)), approval_key_id: b64(await keyId(0x101, f.approval.point)),
    root_fingerprint: b64(f.fingerprint), trust_generation: '1', manifest_version: String(f.version), manifest_digest: b64(f.digest),
    election_digest: b64(f.accepted.electionCommitment), election_bundle_sha256: b64(f.accepted.electionBundleSha256), compared_ms: String(f.acceptedMs + 100n),
    permission_expires_ms: String(f.acceptedMs + 10000n), physical_selection: { kind: 'original_v2' }, current_manifest03: b64(f.signed), manifest_ancestry_sha256: b64(f.prefix), evidence: { ...f.evidence } });
  return f;
}
