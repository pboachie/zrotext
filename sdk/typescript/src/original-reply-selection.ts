// SPDX-License-Identifier: AGPL-3.0-only
/** Phone-approved selected original-event readers. No server-created root pin. */
import { canonicalSignature02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02 } from "./draft02-manifest.js";
import { type OriginalReplyScope } from "./original-reply-reader.js";

const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);
const copy = (b: Uint8Array): Uint8Array => Uint8Array.from(b);
const ab = (b: Uint8Array): ArrayBuffer => Uint8Array.from(b).buffer;
function refuse(): never { throw Error("Original reply selection unavailable"); }
const disclosure = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
export type OriginalReplySelection = Readonly<{
  account: Uint8Array; device: Uint8Array; line: Uint8Array; generation: bigint;
  interval: Uint8Array; receipt: Uint8Array; originatingSession: Uint8Array; nonce: Uint8Array;
  expiresMs: bigint; peer: string; archiveReader: Uint8Array; signer: Uint8Array;
  rootGeneration: bigint; predecessorVersion: bigint; predecessorDigest: Uint8Array;
  activationVersion: bigint; activationDigest: Uint8Array; connectionEpoch: bigint; deploymentEpoch: bigint;
  site: string; instance: string;
  readers: readonly Readonly<{ connector: Uint8Array; readGrant: Uint8Array; reader: Uint8Array }>[];
}>;
export type OriginalArchiveReplyScope = Readonly<Pick<OriginalReplyScope, "account" | "device" | "line" | "interval" | "peer"> & { archiveReader: Uint8Array }>;
function parse(input: Uint8Array): { bytes: Uint8Array; value: OriginalReplySelection; disclosureDigest: Uint8Array } {
  const bytes = copy(input); let at = 0;
  if (bytes.length < 380 || bytes.length > 1536) refuse();
  const take = (n: number): Uint8Array => { if (at + n > bytes.length) refuse(); const value = bytes.slice(at, at + n); at += n; return value; };
  const fixed = (n: number): Uint8Array => { const value = take(n); if (!value.some(v => v !== 0)) refuse(); return value; };
  const number = (): bigint => { const value = new DataView(take(8).buffer).getBigUint64(0); if (value === 0n || value > (1n << 63n) - 1n) refuse(); return value; };
  const text = (): string => decoder.decode(take(take(1)[0]));
  if (!same(take(5), Uint8Array.of(90, 84, 67, 65, 2))) refuse();
  const account = fixed(16), device = fixed(16), line = fixed(16), generation = number();
  const interval = fixed(16), receipt = fixed(16), originatingSession = fixed(16), nonce = fixed(32), expiresMs = number(), peer = text();
  if (!/^\+[1-9][0-9]{1,14}$/.test(peer) || text() !== "conversation-content-v1") refuse();
  const disclosureDigest = take(32), archiveReader = fixed(32), signer = fixed(32), rootGeneration = number(), predecessorVersion = number();
  const predecessorDigest = fixed(32), activationVersion = number(), activationDigest = fixed(32), connectionEpoch = number(), deploymentEpoch = number();
  const site = text(), instance = text();
  if (activationVersion !== predecessorVersion + 1n || !/^[\x21-\x7e]{1,64}$/.test(site) || !/^[\x21-\x7e]{1,64}$/.test(instance)) refuse();
  const count = take(1)[0]; if (count < 1 || count > 6) refuse();
  const readers: { connector: Uint8Array; readGrant: Uint8Array; reader: Uint8Array }[] = []; const previous: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const connector = fixed(16), readGrant = fixed(16), reader = fixed(32);
    if (previous.length) {
      const last = previous[previous.length - 1]; let order = 0;
      for (let j = 0; j < reader.length && order === 0; j++) order = reader[j] - last[j];
      if (order <= 0) refuse();
    }
    if (readers.some(r => same(r.connector, connector) || same(r.readGrant, readGrant) || same(r.reader, reader))) refuse();
    readers.push({ connector, readGrant, reader }); previous.push(reader);
  }
  if (at !== bytes.length) refuse();
  return { bytes, disclosureDigest, value: { account, device, line, generation, interval, receipt, originatingSession, nonce, expiresMs,
    peer, archiveReader, signer, rootGeneration, predecessorVersion, predecessorDigest, activationVersion, activationDigest,
    connectionEpoch, deploymentEpoch, site, instance, readers } };
}
const accepted = new WeakMap<OriginalReplySelection, OriginalReplySelection>();
/** Validates BOTH phone approval and installation on an independently accepted activation manifest. */
export async function verifyOriginalReplySelection02(input: Uint8Array, approval: Uint8Array, installation: Uint8Array,
  activation: Manifest02, acceptedMs: bigint, selected: OriginalReplyScope): Promise<OriginalReplySelection> {
  return verifySelection(input, approval, installation, activation, acceptedMs, selected);
}
/** Owner archive opening verifies the whole signed selection without acquiring a role-3 capability. */
export async function verifyArchiveReplySelection02(input: Uint8Array, approval: Uint8Array, installation: Uint8Array,
  activation: Manifest02, acceptedMs: bigint, selected: OriginalArchiveReplyScope): Promise<OriginalReplySelection> {
  return verifySelection(input, approval, installation, activation, acceptedMs, selected);
}
async function verifySelection(input: Uint8Array, approval: Uint8Array, installation: Uint8Array,
  activation: Manifest02, acceptedMs: bigint, selected: OriginalReplyScope | OriginalArchiveReplyScope): Promise<OriginalReplySelection> {
  const { bytes, value, disclosureDigest } = parse(input), approvalBytes = copy(approval), installationBytes = copy(installation);
  const scope = { account: copy(selected.account), device: copy(selected.device), line: copy(selected.line), interval: copy(selected.interval), peer: selected.peer };
  const chosen = "reader" in selected ? { connector: copy(selected.connector), readGrant: copy(selected.readGrant), reader: copy(selected.reader) } : null;
  const archive = "archiveReader" in selected ? copy(selected.archiveReader) : null;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(disclosure)));
  if (!same(digest, disclosureDigest) || acceptedMs <= 0n || acceptedMs >= value.expiresMs || value.peer !== scope.peer ||
      !same(value.account, scope.account) || !same(value.device, scope.device) || !same(value.line, scope.line) || !same(value.interval, scope.interval) ||
      (chosen && !value.readers.some(r => same(r.connector, chosen.connector) && same(r.readGrant, chosen.readGrant) && same(r.reader, chosen.reader))) ||
      (archive && !same(archive, value.archiveReader))) refuse();
  const manifest = await verifyManifest02(copy(activation.bytes), verifiedManifestTrust02(activation, acceptedMs), acceptedMs);
  const identity = verifiedManifestIdentity02(manifest, acceptedMs);
  if (!same(identity.accountId, scope.account) || identity.generation !== value.rootGeneration || identity.version !== value.activationVersion || !same(identity.digest, value.activationDigest)) refuse();
  const signer = manifest.keys.find(k => k.role === 4 && same(k.keyId, value.signer));
  if (!signer || signer.state !== 1 || !(signer.scope & 2) || !same(signer.deviceId, scope.device) || !same(signer.lineId, scope.line) || signer.fromMs > acceptedMs || acceptedMs >= signer.untilMs) refuse();
  const key = await crypto.subtle.importKey("raw", ab(signer.point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  for (const [name, signature] of [["approve", approvalBytes], ["install", installationBytes]] as const) {
    if (signature.length !== 64 || !same(signature, canonicalSignature02(signature))) refuse();
    const domain = encoder.encode(`zrotext/conversation/${name}/v2\0`), transcript = new Uint8Array(domain.length + 4 + bytes.length);
    transcript.set(domain); new DataView(transcript.buffer).setUint32(domain.length, bytes.length); transcript.set(bytes, domain.length + 4);
    if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ab(signature), transcript.buffer)) refuse();
  }
  accepted.set(value, parse(bytes).value); return value;
}
/** Reads immutable verified selection provenance; caller-mutated records never authorize decryption. */
export function acceptedOriginalReplySelection(value: OriginalReplySelection): OriginalReplySelection {
  const stored = accepted.get(value); if (!stored) refuse();
  return { ...stored, account: copy(stored.account), device: copy(stored.device), line: copy(stored.line), interval: copy(stored.interval),
    receipt: copy(stored.receipt), originatingSession: copy(stored.originatingSession), nonce: copy(stored.nonce), archiveReader: copy(stored.archiveReader),
    signer: copy(stored.signer), predecessorDigest: copy(stored.predecessorDigest), activationDigest: copy(stored.activationDigest),
    readers: stored.readers.map(r => ({ connector: copy(r.connector), readGrant: copy(r.readGrant), reader: copy(r.reader) })) };
}
