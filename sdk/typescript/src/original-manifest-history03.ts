// SPDX-License-Identifier: AGPL-3.0-only
/** Historical cryptography relative to actual authenticated immutable service
 * records. This does not prove their database provenance or present permission.
 * The browser controller obtains originals through the fixed owner transport;
 * its independent compared root/phone/checkpoint never comes from that reply. */
import { captureElectionBytes03, electionTime03, verifyAcceptedPayloadProfileElection03, type VerifiedAcceptedElection03 } from './payload-profile-election03.js';
import { enrollRootPin02, verifyManifest02 } from './draft02-manifest.js';
import { verifyManifest03From02, type VerifiedManifest03 } from './draft03-manifest.js';
import { verifyOriginalRegistrationSignatures03, originalRegistrationPublicKeys03, verifyOriginalActivationSignatures03 } from './original-line-evidence03.js';
import { manifestHistoryBinary03 as binary, manifestHistoryDecimal03 as decimal, manifestEvidenceFields03,
  type OriginalManifestBootstrapCandidate03, type OriginalManifestEvidence03 } from './accepted-manifest-history03.js';

export type ComparedOriginalManifest03 = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array; rootFingerprint: Uint8Array;
  pairedSigningPoint: Uint8Array; origin: string; priorVersion: bigint; priorDigest: Uint8Array;
}>;
const enc = new TextEncoder();
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function fail(): never { throw Error('Original manifest checkpoint03 refused'); }
function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const d = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(d).length !== fields.length || fields.some(k => !d[k] || !('value' in d[k]) || !d[k].enumerable)) fail();
  return Object.fromEntries(fields.map(k => [k, d[k].value]));
}
function uuid(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) fail();
  const out = Uint8Array.from(value.replaceAll('-', '').match(/../g)!, v => parseInt(v, 16));
  if (!out.some(v => v !== 0)) fail(); return out;
}
const hex = (a: Uint8Array) => [...a].map(v => v.toString(16).padStart(2, '0')).join('');
async function sha(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(bytes).buffer));
}
function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, v) => n + v.length, 0)); let at = 0;
  for (const v of parts) { out.set(v, at); at += v.length; } return out;
}
async function commitment(label: string, bytes: Uint8Array): Promise<Uint8Array> {
  const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, bytes.length);
  return sha(join(enc.encode(label + '\0'), n, bytes));
}
/** Genuine registration/activation/E500/02-to03 proofs at ORIGINAL accepted
 * times, including when those windows have since elapsed. binding_id and the
 * timestamps remain service-attributed immutable facts, not signed attestations. */
export async function verifyOriginalManifestHistory03(candidate: OriginalManifestBootstrapCandidate03,
  compared: ComparedOriginalManifest03): Promise<Readonly<{
    seed: Readonly<{ acceptedElection: VerifiedAcceptedElection03; firstManifest: VerifiedManifest03;
      originalEvidence: OriginalManifestEvidence03; origin: string }>;
    originalUserHex: string; originalIdentity: string;
  }>> {
  // Capture all caller-owned fields and bytes before the first asynchronous wait.
  const c = record(candidate, ['v', 'kind', 'line_id', 'binding_id', 'evidence']);
  const selected = record(compared, ['accountId', 'deviceId', 'lineId', 'rootFingerprint', 'pairedSigningPoint', 'origin', 'priorVersion', 'priorDigest']);
  const account = captureElectionBytes03(selected.accountId as Uint8Array, 16), device = captureElectionBytes03(selected.deviceId as Uint8Array, 16);
  const line = captureElectionBytes03(selected.lineId as Uint8Array, 16), root = captureElectionBytes03(selected.rootFingerprint as Uint8Array, 32);
  const paired = captureElectionBytes03(selected.pairedSigningPoint as Uint8Array, 65), priorDigest = captureElectionBytes03(selected.priorDigest as Uint8Array, 32);
  for (const b of [account, device, line, root, priorDigest]) if (!b.some(v => v !== 0)) fail();
  const priorVersion = selected.priorVersion as bigint; electionTime03(priorVersion);
  const origin = selected.origin;
  if (typeof origin !== 'string' || origin.length > 255 || new URL(origin).origin !== origin || new URL(origin).protocol !== 'https:') fail();
  if (c.v !== 1 || c.kind !== 'manifest_original03' || !same(uuid(c.line_id), line)) fail();
  const binding = uuid(c.binding_id), raw = record(c.evidence, manifestEvidenceFields03);
  if (manifestEvidenceFields03.some(k => typeof raw[k] !== 'string')) fail();
  const evidence = Object.freeze({ ...raw }) as OriginalManifestEvidence03;
  const pin = binary(evidence.root_pin, 94), old = binary(evidence.prior_manifest02, 364, 9751);
  const signed = binary(evidence.accepted_manifest03, 366, 9753), bundle = binary(evidence.bundle, 628), core = bundle.slice(0, 500), view = new DataView(core.buffer);
  const accepted = decimal(evidence.accepted_ms), priorAccepted = decimal(evidence.prior_accepted_ms);
  const enrollment = binary(evidence.device_signing_point, 65), approval = binary(evidence.owner_approval_point, 65);
  const registrationBytes = binary(evidence.registration_evidence, 1, 98304), activationBytes = binary(evidence.activation_evidence, 1, 98304);
  if (priorAccepted > accepted || !same(enrollment, paired) || !same(core.subarray(8, 24), account)
      || !same(core.subarray(24, 40), device) || !same(core.subarray(40, 56), line)
      || !same(core.subarray(136, 168), root) || view.getBigUint64(176) !== priorVersion
      || !same(core.subarray(184, 216), priorDigest)) fail();
  const trust = await enrollRootPin02(pin, root);
  if (!same(trust.accountId, account) || !same(await sha(enc.encode(origin)), core.subarray(400, 432))) fail();
  const selectedTrust = { ...trust, version: priorVersion, digest: priorDigest };
  await verifyManifest02(old, selectedTrust, priorAccepted);
  const predecessor = await verifyManifest02(old, selectedTrust, accepted);
  const registration = await verifyOriginalRegistrationSignatures03(registrationBytes, {
    accountId: account, deviceId: device, lineId: line, generation: view.getBigUint64(88),
    comparedRootFingerprint: root, pairedSigningPoint: paired, origin, trustedNowMs: accepted });
  if (!same(originalRegistrationPublicKeys03(registration).approvalPoint, approval)) fail();
  const activated = await verifyOriginalActivationSignatures03(activationBytes, registration, {
    oldBindingId: core.slice(72, 88), selectedReaderKeyId: core.slice(256, 288), trustedNowMs: accepted });
  if (activated.oldBindingDigestHex !== hex(core.subarray(104, 136))) fail();
  const record03 = { accountId: account, deviceId: device, lineId: line, rootFingerprint: root, vaultGeneration: 1n,
    oldBindingId: core.slice(72, 88), oldBindingGeneration: view.getBigUint64(88), oldBindingProofDigest: core.slice(104, 136),
    newBindingId: binding, newBindingGeneration: view.getBigUint64(96), selectedReaderKeyId: core.slice(256, 288),
    priorManifestVersion: priorVersion, priorManifestDigest: priorDigest, priorSignedManifestSha256: await sha(old),
    acceptedManifestVersion: view.getBigUint64(216), acceptedManifestDigest: core.slice(224, 256), acceptedSignedManifestSha256: await sha(signed),
    electionCoreSha256: await sha(core), electionCommitment: await commitment('ZTSE/line/payload-profile/commitment/v1', core),
    electionBundleSha256: await sha(bundle), acceptedAtMs: accepted };
  const acceptedElection = await verifyAcceptedPayloadProfileElection03({ bundle, expectedCore: core, acceptedRecord: record03,
    predecessor02: predecessor, priorSignedManifest02: old, acceptedSignedManifest03: signed,
    deviceSigningPointAtAcceptance: paired, ownerApprovalPointAtAcceptance: approval });
  const firstManifest = await verifyManifest03From02(signed, predecessor, old, accepted);
  return Object.freeze({ seed: Object.freeze({ acceptedElection, firstManifest, originalEvidence: evidence, origin }),
    originalUserHex: registration.originalUserHex,
    // Exact immutable public bytes and retained binding, for the local scope CAS.
    originalIdentity: hex(await sha(enc.encode(JSON.stringify([c.binding_id, ...manifestEvidenceFields03.map(k => evidence[k])])))) });
}
