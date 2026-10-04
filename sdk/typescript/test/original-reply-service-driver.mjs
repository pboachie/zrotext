// SPDX-License-Identifier: AGPL-3.0-only
// Invoked by the real Rust/router/PostgreSQL fixture with private stdin and cwd.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { request } from 'node:https';
import { join, parse } from 'node:path';
import { enrollRootPin02, verifyManifest02, verifiedManifestTrust02 } from '../dist/draft02-manifest.js';
import { prepareInboundEnvelope02 } from '../dist/draft02-envelope-prep.js';
import { OriginalReplyClient } from '../dist/original-reply-client.js';
import { createOriginalReplyReceiver } from '../../replies/original-reply-events.mjs';
globalThis.crypto ??= webcrypto;
const bytes = text => Uint8Array.from(Buffer.from(text, 'base64'));
const hex = text => Uint8Array.from(Buffer.from(text, 'hex'));
const uuid = text => { assert.match(text, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/); return hex(text.replaceAll('-', '')); };
const scope = input => ({ account: uuid(input.account_id), device: uuid(input.device_id), line: uuid(input.line_id),
  interval: uuid(input.interval_id), connector: uuid(input.connector_id), readGrant: uuid(input.read_grant_id), reader: hex(input.reader_id), peer: input.peer });
async function manifests(f) {
  let trust = await enrollRootPin02(bytes(f.root_anchor.pin_b64), hex(f.root_anchor.fingerprint_hex));
  // This baseline is supplied by the fixture's independent local trust setup,
  // never taken from the service response being tested.
  if (f.root_anchor.highwater_version !== undefined) {
    assert.equal(typeof f.root_anchor.highwater_digest, 'string');
    trust = { ...trust, version: BigInt(f.root_anchor.highwater_version), digest: hex(f.root_anchor.highwater_digest) };
  }
  assert.ok(Array.isArray(f.accepted_manifests) && f.accepted_manifests.length > 0 && f.accepted_manifests.length <= 32);
  const result = [];
  for (const snapshot of f.accepted_manifests) {
    const at = BigInt(snapshot.accepted_at_ms), manifest = await verifyManifest02(bytes(snapshot.manifest_b64), trust, at);
    result.push(manifest); trust = verifiedManifestTrust02(manifest, at);
  }
  return result;
}
async function key(jwk, name, usage) {
  return crypto.subtle.importKey('jwk', { ...jwk, ext: false }, { name, namedCurve: 'P-256' }, false, [usage]);
}
let input = '', adapter;
try {
  for await (const chunk of process.stdin) { input += chunk; if (Buffer.byteLength(input) > 262144) throw new Error(); }
  const f = JSON.parse(input); input = '';
  assert.ok(['seed', 'exercise', 'recover'].includes(f.phase));
  const accepted = await manifests(f), selected = scope(f.scope), event = uuid(f.event_id);
  if (f.phase === 'seed') {
    const jwk = f.phone_private_jwk;
    const point = Uint8Array.from(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
    const prepared = await prepareInboundEnvelope02({ kind: 2, manifest: accepted.at(-1), nowMs: BigInt(f.observed_at_ms),
      messageId: event, eventId: event, deviceId: selected.device, lineId: selected.line, peer: new TextEncoder().encode(selected.peer),
      observedMs: BigInt(f.observed_at_ms), localSequence: BigInt(f.local_sequence), content: 'synthetic original reply',
      cek: bytes(f.cek_b64), nonce: bytes(f.nonce_b64), signer: { privateKey: await key(jwk, 'ECDSA', 'sign'), publicPoint: point },
      recipients: f.recipients.map(r => ({ role: r.role, keyId: hex(r.key_id), point: bytes(r.point_b64), ekm: bytes(r.ekm_b64) })) });
    process.stdout.write(JSON.stringify({ envelope_b64: Buffer.from(prepared.envelope).toString('base64') }));
  } else {
    const origin = new URL(f.origin), port = Number(origin.port);
    assert.equal(origin.protocol, 'https:'); assert.ok(['localhost', '127.0.0.1'].includes(origin.hostname));
    assert.equal(origin.pathname, '/'); assert.equal(origin.search, ''); assert.equal(origin.hash, '');
    assert.equal(origin.username, ''); assert.equal(origin.password, ''); assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
    assert.ok(typeof f.ca_pem === 'string' && f.ca_pem.length < 8192);
    const methods = [];
    // Pin both destination and path; a malicious absolute request target cannot
    // nominate a different upstream. TLS hostname/CA verification remains on.
    const fetch = (url, init) => new Promise((resolve, reject) => {
      if (url !== origin.origin + '/v1/reply-events' || init.method !== 'POST') { reject(new Error()); return; }
      methods.push(JSON.parse(init.body).method);
      const req = request({ hostname: origin.hostname, port, path: '/v1/reply-events', method: 'POST', ca: f.ca_pem,
        headers: init.headers, signal: init.signal, rejectUnauthorized: true }, res => {
        const chunks = []; let size = 0;
        res.on('error', reject); res.on('data', chunk => { size += chunk.length; if (size > 524288) { req.destroy(); reject(new Error()); } else chunks.push(chunk); });
        res.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: res.headers })));
      }); req.on('error', reject); req.end(init.body);
    });
    const client = new OriginalReplyClient({ origin: origin.origin, credential: f.read_credential, scope: selected,
      privateKey: await key(f.role3_private_jwk, 'ECDH', 'deriveBits'), acceptedHistory: accepted, clock: () => BigInt(Date.now()), fetch,
      ...(f.output_credential ? { outputCredential: async () => f.output_credential } : {}) });
    const cwd = process.cwd(); assert.notEqual(cwd, parse(cwd).root);
    adapter = await createOriginalReplyReceiver({ client, journalPath: join(cwd, 'journal.sqlite'), receiverPath: join(cwd, 'receiver.sqlite'),
      webhookSecret: new Uint8Array(32).fill(9), cursorSecret: new Uint8Array(32).fill(10) });
    if (f.phase === 'exercise') {
      const page = await adapter.page(); assert.ok(page.events.some(e => e.event_id === f.event_id));
      // Unassociated events intentionally skip the adapter callback. Prove the
      // independently authorized original reader anyway, rather than counting
      // owner-review metadata as a successful cryptographic open.
      assert.equal(await client.read(event), 'synthetic original reply');
      const result = await adapter.process(f.event_id, f.consume_request.active_request_id, text => {
        assert.equal(text, 'synthetic original reply'); return f.consume_request.descriptor;
      });
      assert.equal(result.replay, false); assert.equal(methods.filter(m => m === 'consume').length, 1);
      assert.equal(methods.filter(m => m === 'read').length, f.consume_request.active_request_id === null ? 1 : 2);
      process.stdout.write(JSON.stringify(result));
    } else {
      const result = await adapter.process(f.event_id, f.consume_request.active_request_id, () => { throw new Error('callback must not run'); });
      assert.equal(result.replay, true); assert.equal(methods.filter(m => m === 'consume').length, 0);
      assert.equal(methods.filter(m => m === 'read').length, 0); assert.equal(methods.filter(m => m === 'status').length, 1);
      process.stdout.write(JSON.stringify(result));
    }
  }
} catch {
  // Stdin includes fixture-only secrets and keys. Never print input, exceptions,
  // plaintext, paths, response bodies or provider diagnostics.
  process.stderr.write('original reply fixture refused\n'); process.exitCode = 1;
} finally { adapter?.close(); }
