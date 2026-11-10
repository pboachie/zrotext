import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeOwnerProfileJson03 } from '../dist/accepted-manifest-history03.js';

const encode = raw => new TextEncoder().encode(raw);

test('string scanning preserves odd and even backslash runs before quotes', () => {
  for (let count = 0; count <= 32; count++) {
    for (const ending of ['', '"', '"tail', '\\', '\\"']) {
      const value = 'prefix' + '\\'.repeat(count) + ending;
      const raw = JSON.stringify(value);
      assert.equal(decodeOwnerProfileJson03(encode(raw)), value);
      const key = value + 'key';
      const object = decodeOwnerProfileJson03(encode(JSON.stringify({ [key]: value })));
      assert.equal(object[key], value);
    }
  }
});

test('string scanning preserves JSON escapes Unicode and long strings', () => {
  for (const value of ['', '\b\f\n\r\t', '\u0000\u001f', '\u2028\u2029', '\ud800', '\udfff', String.fromCodePoint(0x1f600), 'text'.repeat(30000)]) {
    assert.equal(decodeOwnerProfileJson03(encode(JSON.stringify(value))), value);
  }
  assert.equal(decodeOwnerProfileJson03(encode('"\\u2028"')), '\u2028');
});

test('string scanning rejects malformed escapes control characters and decoded duplicate keys', () => {
  const malformed = ['"unterminated', '"trailing\\', '"\\"', '"\\x20"', '"\\u123"', '"\\uZZZZ"', '"ok"tail'];
  for (let code = 0; code < 32; code++) malformed.push('"before' + String.fromCharCode(code) + 'after"');
  for (const raw of malformed) assert.throws(() => decodeOwnerProfileJson03(encode(raw)));
  for (let count = 0; count <= 16; count++) {
    const key = '\\'.repeat(count) + '"key', literal = JSON.stringify(key);
    const escaped = literal.replace('key', '\\u006bey');
    assert.throws(() => decodeOwnerProfileJson03(encode('{' + literal + ':1,' + escaped + ':1}')));
  }
});

test('long unescaped strings use one native quote search', context => {
  const value = 'text'.repeat(30000), raw = JSON.stringify(value);
  const indexOf = String.prototype.indexOf;
  let searches = 0;
  context.mock.method(String.prototype, 'indexOf', function (needle, from) {
    if (String(this) === raw && needle === '"') searches++;
    return indexOf.call(this, needle, from);
  });
  try {
    assert.equal(decodeOwnerProfileJson03(encode(raw)), value);
  } finally {
    context.mock.restoreAll();
  }
  assert.equal(searches, 1);
});
