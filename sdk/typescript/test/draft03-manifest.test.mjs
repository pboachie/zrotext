import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { test } from "node:test";
import { canonicalSignature02, enrollRootPin02, verifyManifest02 } from "../dist/draft02-manifest.js";
import {
  verifyManifest03From02, verifyManifest03Successor, verifyManifest03Current,
  verifiedManifestIdentity03,
} from "../dist/draft03-manifest.js";

const vector = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/sealed-profile03-contract-01.json", import.meta.url)));
const now = BigInt(vector.nowMs), max = (1n << 63n) - 1n;
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const enc = new TextEncoder(), z16 = new Uint8Array(16), z32 = new Uint8Array(32);
const account = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const device = Uint8Array.from({ length: 16 }, (_, i) => i + 17);
const line = Uint8Array.from({ length: 16 }, (_, i) => i + 33);
const hex = value => Uint8Array.from(Buffer.from(value, "hex"));
const copy = value => Uint8Array.from(value);
function join(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n); return b; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; }
async function sha(b) { return new Uint8Array(await crypto.subtle.digest("SHA-256", b)); }
async function key() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function id(role, point) { return sha(join(enc.encode("ZTSE/key/v1\0"), u16(role <= 3 ? 0x10 : 0x101), point)); }
async function sign(root, label, unsigned) {
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    root.privateKey, join(enc.encode(`${label}\0`), u32(unsigned.length), unsigned))));
}
function highS(bytes) {
  const b = copy(bytes), at = b.length - 32;
  let n = order - b.subarray(at).reduce((v, x) => v * 256n + BigInt(x), 0n);
  for (let i = b.length - 1; i >= at; i--) { b[i] = Number(n & 255n); n >>= 8n; } return b;
}
async function fixture() {
  const root = await key(), records = [];
  for (let role = 1; role <= 6; role++) {
    const k = role === 6 ? root : await key();
    records.push({ role, point: k.point, keyId: await id(role, k.point),
      device: role === 1 || role === 4 ? device : z16,
      line: [1, 4, 5].includes(role) ? line : z16,
      scope: [0, 4, 12, 12, 2, 1, 0][role], state: 1 });
  }
  const pinBytes = join(enc.encode("ZTRP"), Uint8Array.of(2), account, u64(1n), root.point);
  const pin = await enrollRootPin02(pinBytes, await sha(join(enc.encode("ZTSE/root-pin/v2\0"), pinBytes)));
  return { root, records, pin };
}
async function manifest(f, options = {}) {
  const profile = options.profile ?? 3, issued = options.issued ?? now - 1_000n;
  const expires = options.expires ?? now + 60_000n;
  const records = [...(options.records ?? f.records)];
  if (options.sort !== false) records.sort((a, b) => a.role - b.role || Buffer.compare(a.keyId, b.keyId));
  const encoded = records.map(r => join(Uint8Array.of(r.role), r.keyId, r.point, r.device, r.line,
    u16(r.scope), u64(r.from ?? issued), u64(r.until ?? expires), Uint8Array.of(r.state)));
  const unsigned = join(enc.encode("ZTMA"), Uint8Array.of(profile),
    ...(profile === 3 ? [Uint8Array.of(options.envelope ?? 3, options.predecessor ?? 2)] : []),
    options.account ?? account, u64(options.generation ?? 1n), u64(options.version ?? (profile === 2 ? 1n : 2n)),
    u64(issued), u64(expires), options.previous ?? z32, options.rootPoint ?? f.root.point,
    Uint8Array.of(records.length), ...encoded);
  return { bytes: join(unsigned, await sign(options.signer ?? f.root, options.label ?? `ZTSE/manifest/v${profile}`, unsigned)),
    digest: await sha(unsigned), unsigned };
}
async function setup(f) {
  f ??= await fixture();
  const old = await manifest(f, { profile: 2 }), prior = await verifyManifest02(old.bytes, f.pin, now);
  const first = await manifest(f, { previous: old.digest });
  const handle = await verifyManifest03From02(first.bytes, prior, old.bytes, now);
  return { f, old, prior, first, handle };
}
const identity = (handle, time = now) => verifiedManifestIdentity03(handle, time);

test("public signed vectors enter through genuine02 provenance and bounded03 chain APIs", async () => {
  const pin = await enrollRootPin02(hex(vector.rootPinHex), hex(vector.rootFingerprintHex));
  const old = hex(vector.manifests.prior02.signedHex), prior = await verifyManifest02(old, pin, now);
  const first = hex(vector.manifests.successor03.signedHex);
  const handle = await verifyManifest03From02(first, prior, old, now);
  assert.deepEqual(identity(handle).digest, hex(vector.manifests.successor03.semanticDigestHex));
  assert.equal(identity(handle).predecessorProfile, 2);
  const next = await verifyManifest03Successor(hex(vector.manifests.after03.signedHex), handle, now);
  assert.deepEqual(identity(next).digest, hex(vector.manifests.after03.semanticDigestHex));
  await verifyManifest03Current(first, handle, now);
  for (const name of ["genesis03ContractOnly", "sameVersionFork03"]) {
    await assert.rejects(verifyManifest03Current(hex(vector.manifests[name].signedHex), handle, now));
  }
});

test("current semantic signatures are verified without replacing the original handle", async () => {
  const { f, old, prior, first, handle } = await setup();
  const alternate = await manifest(f, { previous: old.digest });
  assert.deepEqual(alternate.unsigned, first.unsigned);
  assert.notDeepEqual(alternate.bytes, first.bytes);
  const later = await verifyManifest03Current(alternate.bytes, handle, now + 1n);
  assert.deepEqual(identity(handle).digest, identity(later, now + 1n).digest);
  assert.equal(verifiedManifestIdentity03(handle, now + 2n).comparisonMs, now);
  assert.equal(verifiedManifestIdentity03(later, now + 2n).comparisonMs, now + 1n);
  const bad = copy(first.bytes); bad[bad.length - 2] ^= 1;
  await assert.rejects(verifyManifest03Current(bad, handle, now), /signature/);
  await assert.rejects(verifyManifest03Current(highS(first.bytes), handle, now), /high-s/);
  const zero = copy(first.bytes); zero.fill(0, zero.length - 64);
  await assert.rejects(verifyManifest03Current(zero, handle, now), /scalar/);
  const wrongDomain = await manifest(f, { previous: old.digest, label: "ZTSE/manifest/v2" });
  await assert.rejects(verifyManifest03From02(wrongDomain.bytes, prior, old.bytes, now), /signature/);
  const wrongSigner = await manifest(f, { previous: old.digest, signer: await key() });
  await assert.rejects(verifyManifest03Current(wrongSigner.bytes, handle, now), /signature/);
});

test("valid signatures cannot authorize wrong profile identity or chain", async () => {
  const { f, old, prior, first, handle } = await setup();
  for (const options of [
    { account: device }, { generation: 2n }, { generation: 0n }, { version: 0n }, { account: z16 },
    { envelope: 2 }, { predecessor: 0 }, { predecessor: 1 }, { predecessor: 3 },
    { version: 1n }, { version: 3n }, { previous: z32 },
  ]) {
    const bad = await manifest(f, { previous: old.digest, ...options });
    await assert.rejects(verifyManifest03From02(bad.bytes, prior, old.bytes, now));
  }
  const other = await fixture();
  await assert.rejects(verifyManifest03From02((await manifest(other, { previous: old.digest })).bytes, prior, old.bytes, now), /identity mismatch/);
  await assert.rejects(verifyManifest03Successor(first.bytes, handle, now), /chain/);
  const valid = await manifest(f, { predecessor: 3, version: 3n, previous: first.digest });
  const next = await verifyManifest03Successor(valid.bytes, handle, now);
  await assert.rejects(verifyManifest03Current(first.bytes, next, now), /fork\/rollback/);
  const fork = await manifest(f, { previous: old.digest, issued: now - 999n });
  await assert.rejects(verifyManifest03Current(fork.bytes, handle, now), /fork/);
  const wrongPrior = await manifest(f, { predecessor: 3, version: 3n, previous: old.digest });
  await assert.rejects(verifyManifest03Successor(wrongPrior.bytes, handle, now), /chain/);
});

test("strict role grammar rejects signed invalid metadata while retaining syntactic positives", async () => {
  const { f, old, prior } = await setup();
  const rejectRecords = async records => assert.rejects(verifyManifest03From02(
    (await manifest(f, { previous: old.digest, records })).bytes, prior, old.bytes, now));
  for (const [at, replacement] of [
    [0, { scope: 1 }], [0, { device: z16 }], [0, { line: z16 }],
    [1, { device }], [1, { line }], [1, { scope: 4 }],
    [2, { scope: 2 }], [2, { device }], [2, { line }],
    [3, { scope: 1 }], [3, { device: z16 }], [3, { line: z16 }],
    [4, { device }], [4, { line: z16 }], [4, { scope: 2 }],
    [5, { scope: 1 }], [5, { device }], [5, { line }], [5, { state: 2 }],
    [5, { from: now }], [5, { until: now }], [0, { state: 0 }], [0, { state: 3 }],
    [0, { from: now + 2n, until: now + 1n }], [0, { keyId: z32 }],
    [0, { point: new Uint8Array(65) }], [0, { point: join(Uint8Array.of(4), new Uint8Array(64)) }],
    [0, { role: 0 }], [0, { role: 7 }],
  ]) await rejectRecords(f.records.map((r, i) => i === at ? { ...r, ...replacement } : r));
  const repeated = f.records.map((r, i) => i === 4 ? { ...r, point: f.root.point } : r);
  repeated[4].keyId = await id(5, f.root.point); await rejectRecords(repeated);
  const aliasedRoot = f.records.map((r, i) => i === 5 ? { ...r, point: f.records[4].point } : r);
  aliasedRoot[5].keyId = await id(6, aliasedRoot[5].point); await rejectRecords(aliasedRoot);
  await rejectRecords(f.records.filter(r => r.role !== 2));
  await rejectRecords(f.records.filter(r => r.role !== 6));
  await rejectRecords(f.records.map(r => r.role === 2 ? { ...r, state: 2 } : r));
  const secondArchive = await key();
  await rejectRecords([...f.records, { ...f.records[1], point: secondArchive.point, keyId: await id(2, secondArchive.point) }]);
  const duplicate = await manifest(f, { previous: old.digest, records: [...f.records, f.records[0]] });
  await assert.rejects(verifyManifest03From02(duplicate.bytes, prior, old.bytes, now), /order/);
  const unsorted = await manifest(f, { previous: old.digest, records: [...f.records].reverse(), sort: false });
  await assert.rejects(verifyManifest03From02(unsorted.bytes, prior, old.bytes, now), /order/);
  // Equal windows/revoked optional records are grammar, not live permission.
  const allowed = f.records.map(r => r.role === 3 ? { ...r, state: 2, from: now, until: now } : r);
  await verifyManifest03From02((await manifest(f, { previous: old.digest, records: allowed })).bytes, prior, old.bytes, now);
  for (const scope of [4, 8, 12]) await verifyManifest03From02((await manifest(f, {
    previous: old.digest, records: f.records.map(r => r.role === 3 ? { ...r, scope } : r),
  })).bytes, prior, old.bytes, now);
  // Owner+archive alone is a valid manifest parser result, not dispatch authority.
  await verifyManifest03From02((await manifest(f, { previous: old.digest,
    records: f.records.filter(r => [2, 6].includes(r.role)) })).bytes, prior, old.bytes, now);
});

test("bounds clocks and exact bigint inputs are enforced before02 provenance", async () => {
  const { f, old, prior, first, handle } = await setup();
  for (const time of [0n, -1n, max + 1n, 1, Number(max), "1", true, Object(1n), undefined]) {
    await assert.rejects(verifyManifest03From02(first.bytes, {}, old.bytes, time), /comparison range\/type/);
    await assert.rejects(verifyManifest03Successor(first.bytes, handle, time), /comparison range\/type/);
    await assert.rejects(verifyManifest03Current(first.bytes, handle, time), /comparison range\/type/);
    assert.throws(() => verifiedManifestIdentity03(handle, time), /comparison range\/type/);
  }
  for (const options of [
    { issued: 0n }, { issued: now, expires: now }, { issued: now + 1n, expires: now },
    { issued: now - 1n, expires: now + 86_400_000n }, { expires: now },
    { issued: now + 300_001n, expires: now + 400_000n },
    { generation: max + 1n }, { version: max + 1n }, { issued: max + 1n }, { expires: max + 1n },
    { records: f.records.map((r, i) => i === 0 ? { ...r, from: max + 1n } : r) },
    { records: f.records.map((r, i) => i === 0 ? { ...r, until: max + 1n } : r) },
  ]) await assert.rejects(verifyManifest03From02((await manifest(f, { previous: old.digest, ...options })).bytes, prior, old.bytes, now));
  const boundary = await manifest(f, { predecessor: 3, version: 3n, previous: first.digest,
    issued: max - 1_000n, expires: max });
  const latest = await verifyManifest03Successor(boundary.bytes, handle, max - 1n);
  assert.equal(verifiedManifestIdentity03(latest, max - 1n).expiresMs, max);
  assert.throws(() => verifiedManifestIdentity03(latest, max), /stale/);
  await assert.rejects(verifyManifest03Current(first.bytes, handle, now - 1n), /regression/);
  await assert.rejects(verifyManifest03Successor(boundary.bytes, handle, now - 1n), /regression/);
  assert.throws(() => verifiedManifestIdentity03(handle, now - 1n), /regression/);
  for (const bytes of [new Uint8Array(365), new Uint8Array(9754), first.bytes.subarray(0, first.bytes.length - 1),
    join(first.bytes, Uint8Array.of(0))]) await assert.rejects(verifyManifest03Current(bytes, handle, now), /bounds|size/);
  for (const count of [0, 65, 1]) { const b = copy(first.bytes); b[152] = count;
    await assert.rejects(verifyManifest03Current(b, handle, now), /count/); }
  const downgraded = copy(first.bytes); downgraded[4] = 2;
  await assert.rejects(verifyManifest03Current(downgraded, handle, now), /profile/);
  for (const options of [{ issued: now + 300_000n, expires: now + 400_000n },
    { issued: now - 1_000n, expires: now + 86_399_000n }]) {
    await verifyManifest03From02((await manifest(f, { previous: old.digest, ...options })).bytes, prior, old.bytes, now);
  }
  const maximumRecords = [...f.records];
  while (maximumRecords.length < 64) {
    const extra = await key();
    maximumRecords.push({ ...f.records[2], point: extra.point, keyId: await id(3, extra.point) });
  }
  const maximumBytes = await manifest(f, { previous: old.digest, records: maximumRecords });
  assert.equal(maximumBytes.bytes.length, 9753);
  await verifyManifest03From02(maximumBytes.bytes, prior, old.bytes, now);
});

test("first upgrade refuses unsupported anchors generations expired02 and version overflow", async () => {
  const { f, old, prior, first } = await setup();
  await assert.rejects(verifyManifest03From02(first.bytes, prior, old.bytes, now + 60_000n), /stale/);
  for (const generation of [1n, 2n]) {
    const anchor = generation === 1n ? Uint8Array.from({ length: 32 }, () => 7) : z32;
    const bytes = await manifest(f, { profile: 2, generation, previous: anchor });
    // A genuine02 verifier handle can originate from structural trust. New03
    // explicitly checks this captured metadata; it cannot attest its lineage.
    const accepted = await verifyManifest02(bytes.bytes, { ...f.pin, generation, anchorDigest: anchor }, now);
    await assert.rejects(verifyManifest03From02(first.bytes, accepted, bytes.bytes, now), /unsupported02/);
  }
  for (const version of [max - 1n, max]) {
    const encoded = await manifest(f, { profile: 2, version });
    const accepted = await verifyManifest02(encoded.bytes, { ...f.pin, version, digest: encoded.digest }, now);
    const candidate = await manifest(f, { previous: encoded.digest, version: max });
    if (version === max - 1n) assert.equal(identity(await verifyManifest03From02(candidate.bytes, accepted, encoded.bytes, now)).version, max);
    else await assert.rejects(verifyManifest03From02(candidate.bytes, accepted, encoded.bytes, now), /overflow/);
  }
});

test("supplied02 evidence must match genuine private semantics and need not be original signature", async () => {
  const { f, old, prior, first } = await setup();
  const alternate = await manifest(f, { profile: 2 });
  assert.deepEqual(old.unsigned, alternate.unsigned); assert.notDeepEqual(old.bytes, alternate.bytes);
  await verifyManifest03From02(first.bytes, prior, alternate.bytes, now);
  const next = await manifest(f, { profile: 2, version: 2n, previous: old.digest });
  await assert.rejects(verifyManifest03From02(first.bytes, prior, next.bytes, now), /semantic mismatch/);
  const corrupted = copy(old.bytes); corrupted[corrupted.length - 2] ^= 1;
  await assert.rejects(verifyManifest03From02(first.bytes, prior, corrupted, now), /signature/);
  for (const fake of [{ ...prior }, Object.create(prior), {}, JSON.parse(JSON.stringify({}))]) {
    await assert.rejects(verifyManifest03From02(first.bytes, fake, old.bytes, now), /just-verified/);
  }
});

test("opaque snapshots and synchronous capture survive immediate caller mutation", async () => {
  const { f, old, prior, first, handle } = await setup();
  const bytes = copy(first.bytes), supplied = copy(old.bytes);
  const pending = verifyManifest03From02(bytes, prior, supplied, now);
  bytes.fill(0); supplied.fill(0); prior.bytes.fill(0); prior.digest.fill(0);
  prior.rootPoint.fill(0); prior.accountId.fill(0); prior.version = 99n;
  prior.keys.forEach(k => { k.point.fill(0); k.state = 2; });
  const accepted = await pending;
  assert.deepEqual(identity(accepted).digest, first.digest);
  // Visible02 corruption cannot redefine the actual private predecessor.
  await verifyManifest03From02(first.bytes, prior, old.bytes, now);
  const projected = identity(accepted); projected.digest.fill(0); projected.rootPoint.fill(0); projected.accountId.fill(0);
  projected.version = 99n;
  assert.deepEqual(identity(accepted).digest, first.digest);
  assert.equal(identity(accepted).version, 2n);
  assert.ok(Object.isFrozen(accepted)); assert.deepEqual(Object.getOwnPropertySymbols(accepted), []);
  const next = await manifest(f, { predecessor: 3, version: 3n, previous: first.digest });
  const incoming = copy(next.bytes), continuation = verifyManifest03Successor(incoming, handle, now);
  incoming.fill(0); assert.deepEqual(identity(await continuation).digest, next.digest);
  const current = copy(first.bytes), check = verifyManifest03Current(current, handle, now);
  current.fill(0); assert.deepEqual(identity(await check).digest, first.digest);
  for (const fake of [{}, { ...accepted }, Object.create(accepted), JSON.parse(JSON.stringify(accepted))]) {
    await assert.rejects(verifyManifest03Successor(next.bytes, fake, now), /exact verified03/);
    await assert.rejects(verifyManifest03Current(first.bytes, fake, now), /exact verified03/);
    assert.throws(() => verifiedManifestIdentity03(fake, now), /exact verified03/);
  }
  assert.equal(identity(handle).comparisonMs, now);
});

test("ordinary byte views ignore shadow hooks and unsupported storage refuses", async () => {
  const { f, old, prior, first, handle } = await setup();
  const shadow = copy(first.bytes), shadow02 = copy(old.bytes);
  for (const bytes of [shadow, shadow02]) for (const key of ["buffer", "byteLength", "constructor", Symbol.iterator, Symbol.toStringTag]) {
    Object.defineProperty(bytes, key, { get() { throw Error("caller hook invoked"); } });
  }
  await verifyManifest03From02(shadow, prior, shadow02, now);
  const backing = new Uint8Array(first.bytes.length + 10); backing.set(first.bytes, 5);
  await verifyManifest03Current(backing.subarray(5, 5 + first.bytes.length), handle, now);
  const shared = new Uint8Array(new SharedArrayBuffer(first.bytes.length)); shared.set(first.bytes);
  const disguisedShared = bytes => {
    const backing = new SharedArrayBuffer(bytes.length), view = new Uint8Array(backing);
    view.set(bytes);
    Object.setPrototypeOf(backing, ArrayBuffer.prototype);
    assert.equal(Object.getPrototypeOf(backing), ArrayBuffer.prototype);
    assert.equal(Reflect.apply(Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, "byteLength").get,
      backing, []), bytes.length); // Still shared despite its ordinary prototype.
    return view;
  };
  await assert.rejects(verifyManifest03From02(disguisedShared(first.bytes), prior, old.bytes, now), /byte/);
  await assert.rejects(verifyManifest03From02(first.bytes, prior, disguisedShared(old.bytes), now), /byte/);
  await assert.rejects(verifyManifest03Current(disguisedShared(first.bytes), handle, now), /byte/);
  const next = await manifest(f, { predecessor: 3, version: 3n, previous: first.digest });
  await assert.rejects(verifyManifest03Successor(disguisedShared(next.bytes), handle, now), /byte/);
  for (const Type of [Uint8ClampedArray, Int8Array]) {
    const view = new Type(first.bytes.length);
    new Uint8Array(view.buffer).set(first.bytes);
    Object.setPrototypeOf(view, Uint8Array.prototype);
    assert.equal(Object.getPrototypeOf(view), Uint8Array.prototype);
    const intrinsicTag = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag).get;
    assert.equal(Reflect.apply(intrinsicTag, view, []), Type.name);
    await assert.rejects(verifyManifest03Current(view, handle, now), /byte/);
    await assert.rejects(verifyManifest03From02(view, prior, old.bytes, now), /byte/);
    const successorView = new Type(next.bytes.length); new Uint8Array(successorView.buffer).set(next.bytes);
    Object.setPrototypeOf(successorView, Uint8Array.prototype);
    await assert.rejects(verifyManifest03Successor(successorView, handle, now), /byte/);
    const priorView = new Type(old.bytes.length); new Uint8Array(priorView.buffer).set(old.bytes);
    Object.setPrototypeOf(priorView, Uint8Array.prototype);
    await assert.rejects(verifyManifest03From02(first.bytes, prior, priorView, now), /byte/);
  }
  const detached = copy(first.bytes); structuredClone(detached.buffer, { transfer: [detached.buffer] });
  for (const bytes of [Buffer.from(first.bytes), new Proxy(copy(first.bytes), {}), Object.create(Uint8Array.prototype),
    shared, detached, vm.runInNewContext("new Uint8Array(1000)"), new (class extends Uint8Array {})(first.bytes),
    new Uint16Array(1000), [], null]) {
    await assert.rejects(verifyManifest03Current(bytes, handle, now), /byte/);
    await assert.rejects(verifyManifest03From02(first.bytes, prior, bytes, now), /byte/);
  }
});

test("expired03 is chain history only and concurrent forks require external atomic selection", async () => {
  const { f, first, handle } = await setup();
  const later = now + 70_000n;
  assert.throws(() => verifiedManifestIdentity03(handle, later), /stale/);
  await assert.rejects(verifyManifest03Current(first.bytes, handle, later), /stale/);
  const options = { predecessor: 3, version: 3n, previous: first.digest, issued: later, expires: later + 1_000n };
  const a = await manifest(f, options), b = await manifest(f, { ...options, expires: later + 2_000n });
  const [left, right] = await Promise.all([verifyManifest03Successor(a.bytes, handle, later), verifyManifest03Successor(b.bytes, handle, later)]);
  assert.notDeepEqual(verifiedManifestIdentity03(left, later).digest, verifiedManifestIdentity03(right, later).digest);
  assert.deepEqual(identity(handle).digest, first.digest);
  assert.equal(verifiedManifestIdentity03(left, later + 1n).comparisonMs, later);
  await assert.rejects(verifyManifest03Current(b.bytes, left, later), /fork/);
  await assert.rejects(verifyManifest03Current(a.bytes, right, later), /fork/);
});
