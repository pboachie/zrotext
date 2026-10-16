// SPDX-License-Identifier: AGPL-3.0-only
// Browser protocol/crypto controls; the fake HTTPS peer is not DB acceptance.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto, createHash, createECDH } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const material = import('../review/root-material.mjs'), clients = import('../review/root.mjs');
const vector = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, '../../protocol/v1/vectors', name), 'utf8'));
const backup = vector('root-backup-01.json'), card = vector('recovery-kit-01.json'), custody = vector('root-custody-01.json');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const asId = (s) => s.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
const id = (n) => '10000000-0000-4000-8000-' + n.toString(16).padStart(12, '0');
const file = (s) => ({ size: s.length / 2, arrayBuffer: async () => fromHex(s).buffer });
const b64 = (n) => Buffer.alloc(32, n).toString('base64');
const token = (n) => Buffer.alloc(32, n).toString('base64url');
const sha = (bytes) => createHash('sha256').update(bytes).digest('base64');

async function fixture({ loseIssue = false, loseComplete = false, wrongActor = false } = {}) {
  const m = await material, { ReviewRootClient } = await clients;
  let next = 0, generation = 0, cookies = '', root = { kind: 'no_root_history' }, prepared, issue, enrolled = false;
  const requests = [];
  const broker = '__Host-ztrw-broker-csrf=' + token(2), owner = '__Host-ztrw-owner-csrf=' + token(3);
  const response = (body) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  const op = (body, state) => ({ version: 1, request_id: body.request_id, preparation_id: prepared.preparation_id, generation: String(generation), state, create_deadline_ms: '1300000', delivery_deadline_ms: '1600000', server_now_ms: enrolled ? '1000002' : '1000000' });
  const client = new ReviewRootClient({ origin: card.origin, newId: () => id(++next), cookies: () => cookies, fetch: async (url, options) => {
    const route = new URL(url).pathname.replace('/v1/review/', ''), body = JSON.parse(options.body); requests.push({ route, body });
    switch (route) {
      case 'browser/prepare': case 'browser/confirm': return response({ version: 1, request_id: body.request_id, browser_context_commitment_b64: b64(4), issued_ms: '900000', expires_ms: '1600000', server_now_ms: '1000000', outstanding: null, owner_session_issued: false });
      case 'preparations':
        ++generation; prepared = { request_id: body.request_id, preparation_id: id(200 + generation), generation: String(generation) };
        cookies = '__Host-ztrw-c-' + prepared.preparation_id.replaceAll('-', '') + '=' + token(1) + (generation > 1 ? '; ' + broker + '; ' + owner : '');
        return response(op(body, 'prepared'));
      case 'preparations/confirm': return response(op(body, 'confirmed'));
      case 'login/bootstrap': return response(op(body, 'committed_known'));
      case 'login/status': cookies += '; ' + broker; return response(op(body, 'committed_known'));
      case 'workspace/status': cookies += '; ' + owner; return response(op(body, 'committed_known'));
      case 'session/confirm': cookies = broker + '; ' + owner; return response(op(body, 'committed_known'));
      case 'session/context': return response({ version: 1, request_id: body.request_id, realm: id(30), database_commitment_b64: b64(5), config_digest_b64: b64(6), config_revision: '1', origin: card.origin,
        account: asId(card.accountIdHex), owner_user: asId('02'.repeat(16)), review_owner_session: asId('03'.repeat(16)), broker_principal: id(5), credential_id: id(6), credential_revision: '1', broker_session: id(7), auth_event: id(8),
        issued_ms: '900000', absolute_expiry_ms: '1600000', idle_deadline_ms: '1500000', server_now_ms: enrolled ? '1000002' : '1000000', capabilities: ['bootstrap_session', 'root_issue', 'root_complete', 'root_receipt', 'root_custody_export'], locator_retained: true, root_state: root });
      case 'root/issue': {
        issue = { version: 1, ...prepared, root_challenge_id: asId('04'.repeat(16)), reauth_challenge_id: id(50), reauth_nonce_b64: b64(7), unsigned_enrollment_b64: m.base64(fromHex(custody.unsignedHex)), custody_statement_b64: m.base64(fromHex(custody.transcriptHex)), root_pin_b64: m.base64(fromHex(card.rootPinHex)), request_commitment_b64: b64(8), expires_ms: '1300000', server_now_ms: '1000000' };
        root = { kind: 'pending_enrollment', challenge_id: issue.root_challenge_id, root_pin_b64: issue.root_pin_b64, root_fingerprint_b64: m.base64(fromHex(card.fingerprintHex)),
          encrypted_backup_sha256_b64: sha(fromHex(backup.ciphertextHex)), public_card_sha256_b64: sha(fromHex(card.cardHex)), unsigned_enrollment_sha256_b64: sha(fromHex(custody.unsignedHex)), custody_statement_sha256_b64: custody.transcriptSha256Hex ? m.base64(fromHex(custody.transcriptSha256Hex)) : '', expires_ms: issue.expires_ms };
        if (loseIssue) { loseIssue = false; throw Error('Synthetic issue response lost after commit'); }
        return response(issue);
      }
      case 'root/issue-status': assert.equal(body.request_id, issue.request_id); return response(issue);
      case 'root/complete':
        assert.equal(body.root_challenge_id, issue.root_challenge_id); assert.equal(body.reauth_challenge_id, issue.reauth_challenge_id);
        enrolled = true; root = { kind: 'enrolled', root_pin_b64: issue.root_pin_b64, root_fingerprint_b64: m.base64(fromHex(card.fingerprintHex)), generation: '1' };
        if (loseComplete) { loseComplete = false; throw Error('Synthetic completion response lost after commit'); }
        return response(op(body, 'committed_known'));
      case 'root/result': return response({ version: 1, request_id: body.request_id, account: asId(card.accountIdHex), actor_owner_user: wrongActor ? id(999) : asId('02'.repeat(16)), actor_review_owner_session: asId('03'.repeat(16)),
        root_challenge_id: issue.root_challenge_id, root_pin_b64: issue.root_pin_b64, root_fingerprint_b64: m.base64(fromHex(card.fingerprintHex)), completed_ms: '1000001', server_now_ms: '1000002' });
      default: throw Error('Unexpected route ' + route);
    }
  } });
  await client.initialize(); await client.login('pilot', () => 'synthetic-review-password');
  const begin = () => client.issue(file(backup.ciphertextHex), file(card.cardHex), { bundle: asId(card.backupIdHex), fingerprint: card.fingerprintHex });
  async function publicSignatures() {
    // Same derivable public synthetic vector scalar used by root_backup/tests.rs.
    const scalar = createHash('sha256').update('ZROtext synthetic root-backup test root').digest();
    const point = fromHex(card.rootPinHex).subarray(29), curve = createECDH('prime256v1'); curve.setPrivateKey(scalar);
    assert.deepEqual(Uint8Array.from(curve.getPublicKey()), point);
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: Buffer.from(point.subarray(1, 33)).toString('base64url'), y: Buffer.from(point.subarray(33)).toString('base64url'), d: scalar.toString('base64url'), ext: false }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    scalar.fill(0);
    const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    async function sign(bytes) {
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes));
      const s = BigInt('0x' + m.hex(raw.subarray(32)));
      if (s > order / 2n) raw.set(fromHex((order - s).toString(16).padStart(64, '0')), 32);
      return m.hex(raw);
    }
    const unsigned = fromHex(custody.unsignedHex), length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, unsigned.length);
    return 'Enrollment signature: ' + await sign(m.concat(new TextEncoder().encode('ZTSE/root-enroll/v1\0'), length, unsigned)) + '\nCustody signature: ' + await sign(fromHex(custody.transcriptHex)) + '\n';
  }
  return { client, requests, begin, publicSignatures };
}

test('browser first-root journey verifies genuine public signatures and original receipt before delivery acknowledgement', async () => {
  const f = await fixture(); await f.begin();
  assert.equal(f.client.snapshot().pending, null);
  await f.client.complete(await f.publicSignatures(), () => 'synthetic-review-password');
  assert.equal(f.client.snapshot().context.root_state.kind, 'enrolled');
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.requests.filter((r) => r.route === 'root/issue').length, 1);
  assert.equal(f.requests.filter((r) => r.route === 'root/complete').length, 1);
  assert.deepEqual(f.requests.filter((r) => Object.hasOwn(r.body, 'password')).map((r) => r.route), ['login/bootstrap', 'root/complete']);
});

test('lost root issue response recovers original public challenge without issuing another', async () => {
  const f = await fixture({ loseIssue: true }); await assert.rejects(f.begin());
  const original = f.client.snapshot().pending; assert.equal(original.kind, 'root_issue');
  await f.client.reconcile();
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.requests.filter((r) => r.route === 'root/issue').length, 1);
  assert.equal(f.requests.find((r) => r.route === 'root/issue-status').body.request_id, original.request_id);
  assert.ok(f.client.snapshot().challenge);
});

test('lost root completion response reads the original positive receipt without resubmitting signatures or password', async () => {
  const f = await fixture({ loseComplete: true }); await f.begin();
  await assert.rejects(f.client.complete(await f.publicSignatures(), () => 'synthetic-review-password'));
  const original = f.client.snapshot().pending; assert.equal(original.kind, 'root_complete');
  await f.client.reconcile();
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.client.snapshot().context.root_state.kind, 'enrolled');
  assert.equal(f.requests.filter((r) => r.route === 'root/complete').length, 1);
  assert.equal(f.requests.at(-2).body.request_id, original.request_id);
});

test('different completion actor refuses the receipt and never acknowledges publication', async () => {
  const f = await fixture({ wrongActor: true }); await f.begin();
  await assert.rejects(f.client.complete(await f.publicSignatures(), () => 'synthetic-review-password'));
  assert.equal(f.client.snapshot().pending.kind, 'root_complete');
  assert.equal(f.requests.filter((r) => r.route === 'session/confirm').length, 2);
  assert.equal(f.requests.filter((r) => r.route === 'root/complete').length, 1);
});
