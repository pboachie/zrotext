// SPDX-License-Identifier: AGPL-3.0-only
// Exact v1 transcripts for the SMS owner approval key and SMS line activation
// (protocol/v1/sms-line-activation-contract.md). The browser rebuilds every
// byte it signs; it never signs a statement supplied by the server.
"use strict";

(function (root) {
  const REGISTER_DOMAIN = "ZTSMS/owner-key/register/v1\0";
  const DEVICE_DOMAIN = "ZTSMS/line/device-confirm/v1\0";
  const OWNER_DOMAIN = "ZTSMS/line/owner-approve/v1\0";
  const DEVICE_FIELDS = 16 * 4 + 8 + 32 + 2 + 1 + 4;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  const ascii = (text) => Uint8Array.from(text, (character) => character.charCodeAt(0));

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  function uuidBytes(value) {
    if (typeof value !== "string" || !UUID.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value))
      throw new Error("invalid UUID");
    const hex = value.replaceAll("-", "");
    return Uint8Array.from({ length: 16 }, (_, index) => parseInt(hex.slice(index * 2, index * 2 + 2), 16));
  }

  function uuidString(bytes) {
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function equalBytes(left, right) {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
    return difference === 0;
  }

  function base64(bytes) {
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text);
  }

  function fromBase64(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0)
      throw new Error("invalid base64");
    const bytes = Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
    if (base64(bytes) !== text) throw new Error("non-canonical base64");
    return bytes;
  }

  function base64url(bytes) {
    return base64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  async function sha256(bytes) {
    return new Uint8Array(await root.crypto.subtle.digest("SHA-256", bytes));
  }

  // ASN.1 DER INTEGER for an unsigned big-endian scalar: minimal length, with
  // a leading zero only when the high bit is set.
  function derInteger(scalar) {
    let start = 0;
    while (start < scalar.length - 1 && scalar[start] === 0) start += 1;
    let value = scalar.slice(start);
    if (value[0] & 0x80) value = concat(Uint8Array.of(0), value);
    return concat(Uint8Array.of(0x02, value.length), value);
  }

  /** WebCrypto returns ECDSA as r||s (IEEE P1363); the server requires canonical DER. */
  function p1363ToDer(signature) {
    if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new Error("invalid P-256 signature");
    const body = concat(derInteger(signature.slice(0, 32)), derInteger(signature.slice(32)));
    return concat(Uint8Array.of(0x30, body.length), body);
  }

  async function registrationStatement({ accountId, userId, sessionId, challengeId, nonce, publicKeySec1 }) {
    if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new Error("invalid nonce");
    if (!(publicKeySec1 instanceof Uint8Array) || publicKeySec1.length !== 65 || publicKeySec1[0] !== 4)
      throw new Error("invalid public key");
    return concat(ascii(REGISTER_DOMAIN), uuidBytes(accountId), uuidBytes(userId),
      uuidBytes(sessionId), uuidBytes(challengeId), nonce, await sha256(publicKeySec1));
  }

  /** Parses sms_device_statement so the owner can compare it with what was opened. */
  function parseDeviceStatement(bytes) {
    const domain = ascii(DEVICE_DOMAIN);
    if (!(bytes instanceof Uint8Array) || bytes.length !== domain.length + DEVICE_FIELDS ||
        !equalBytes(bytes.slice(0, domain.length), domain)) throw new Error("not an SMS device statement");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = domain.length;
    const take = (length) => {
      const part = bytes.slice(offset, offset + length);
      offset += length;
      return part;
    };
    const accountId = uuidString(take(16));
    const lineId = uuidString(take(16));
    const deviceId = uuidString(take(16));
    const generation = view.getBigInt64(offset);
    offset += 8;
    const challengeId = uuidString(take(16));
    const nonce = take(32);
    const androidApiLevel = view.getUint16(offset);
    const activeSubscriptionCount = view.getUint8(offset + 2);
    const selectedSubscriptionId = view.getInt32(offset + 3);
    return { accountId, lineId, deviceId, generation, challengeId, nonce,
      androidApiLevel, activeSubscriptionCount, selectedSubscriptionId };
  }

  async function ownerApprovalStatement(deviceStatement, deviceSignatureDer) {
    parseDeviceStatement(deviceStatement);
    if (!(deviceSignatureDer instanceof Uint8Array) || deviceSignatureDer.length < 8 || deviceSignatureDer.length > 80)
      throw new Error("invalid device signature");
    return concat(ascii(OWNER_DOMAIN), deviceStatement, await sha256(deviceSignatureDer));
  }

  const I64_MAX = (1n << 63n) - 1n;
  const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const V2_DEVICE = ascii("ZTSMS/line/device-confirm/v2\0");
  const V2_OWNER = ascii("ZTSMS/line/owner-approve/v2\0");

  function positiveI64(text) {
    if (typeof text !== "string" || text.length > 19 || !/^[1-9][0-9]*$/.test(text) ||
        [...text].some((c) => c < "0" || c > "9")) throw new Error("invalid generation");
    const value = BigInt(text);
    if (value > I64_MAX) throw new Error("invalid generation");
    return value;
  }

  function fromBase64url(text, length = null) {
    if (typeof text !== "string" || !text.length || text.length > 1024 ||
        [...text].some((c) => !/[A-Za-z0-9_-]/.test(c))) throw new Error("invalid base64url");
    const padded = text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - text.length % 4) % 4);
    const bytes = fromBase64(padded);
    if (base64url(bytes) !== text || (length !== null && bytes.length !== length))
      throw new Error("invalid base64url");
    return bytes;
  }

  /** Canonical, nonzero, in-range P-256 DER; no low-s-only policy. */
  function canonicalDer(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 8 || bytes.length > 80 ||
        bytes[0] !== 0x30 || bytes[1] !== bytes.length - 2) throw new Error("invalid signature");
    let at = 2;
    for (let part = 0; part < 2; part += 1) {
      if (bytes[at++] !== 2) throw new Error("invalid signature");
      const size = bytes[at++];
      if (!size || size > 33 || at + size > bytes.length || (bytes[at] & 0x80) ||
          (size > 1 && bytes[at] === 0 && !(bytes[at + 1] & 0x80))) throw new Error("invalid signature");
      let scalar = 0n;
      for (const byte of bytes.slice(at, at + size)) scalar = (scalar << 8n) | BigInt(byte);
      if (scalar === 0n || scalar >= P256_ORDER) throw new Error("invalid signature");
      at += size;
    }
    if (at !== bytes.length) throw new Error("invalid signature");
    return bytes;
  }

  function observationV2(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 121) throw new Error("invalid observation");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const out = {
      androidApiLevel: view.getUint16(0), activeSubscriptionCount: view.getUint16(2),
      selectedSubscriptionId: view.getInt32(4), selectedKind: bytes[8],
      selectedPortIndex: view.getInt32(41), selectedSlotIndex: view.getInt32(45),
      observerEpoch: view.getBigInt64(65),
    };
    if (out.androidApiLevel < 33 || out.activeSubscriptionCount < 1 || out.activeSubscriptionCount > 256 ||
        out.selectedSubscriptionId < 0 || ![1, 2].includes(out.selectedKind) ||
        out.selectedPortIndex < 0 || out.selectedSlotIndex < 0 || out.observerEpoch <= 0n)
      throw new Error("invalid observation");
    for (const [name, offset] of [["cardToken", 9], ["profileToken", 25], ["monitorId", 49], ["leaseId", 73]]) {
      out[name] = uuidString(bytes.slice(offset, offset + 16));
      uuidBytes(out[name]);
    }
    return out;
  }

  function parseDeviceStatementV2(bytes) {
    const start = V2_DEVICE.length + 2;
    if (!(bytes instanceof Uint8Array) || bytes.length !== start + 104 + 121 ||
        !equalBytes(bytes.slice(0, V2_DEVICE.length), V2_DEVICE) ||
        bytes[V2_DEVICE.length] !== 2 || bytes[V2_DEVICE.length + 1] !== 1)
      throw new Error("not an SMS v2 device statement");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const out = {};
    for (const [name, offset] of [["accountId", 0], ["lineId", 16], ["deviceId", 32], ["challengeId", 56]]) {
      out[name] = uuidString(bytes.slice(start + offset, start + offset + 16));
      uuidBytes(out[name]);
    }
    out.generation = view.getBigInt64(start + 48);
    if (out.generation <= 0n) throw new Error("invalid generation");
    out.nonce = bytes.slice(start + 72, start + 104);
    out.observation = bytes.slice(start + 104);
    return Object.assign(out, observationV2(out.observation));
  }

  function deviceStatementV2({ accountId, lineId, deviceId, challengeId, generation, nonce, observation }) {
    const integer = positiveI64(generation);
    for (const id of [accountId, lineId, deviceId, challengeId]) {
      if (typeof id !== "string" || id.length !== 36) throw new Error("invalid UUID");
      uuidBytes(id);
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new Error("invalid nonce");
    observationV2(observation);
    const encoded = new Uint8Array(8);
    new DataView(encoded.buffer).setBigInt64(0, integer);
    return concat(V2_DEVICE, Uint8Array.of(2, 1), uuidBytes(accountId), uuidBytes(lineId), uuidBytes(deviceId),
      encoded, uuidBytes(challengeId), nonce, observation);
  }

  async function ownerApprovalStatementV2(statement, der) {
    parseDeviceStatementV2(statement);
    canonicalDer(der);
    return concat(V2_OWNER, statement, await sha256(der));
  }

  /** Flat closed-response grammar: keep numeric tokens exact before conversion. */
  function flatV2Response(text, keys = null) {
    if (typeof text !== "string" || new TextEncoder().encode(text).length > 4096)
      throw new Error("invalid activation response");
    let at = 0;
    const whitespace = () => { while (at < text.length && " \t\r\n".includes(text[at])) at += 1; };
    const token = /"([^"\u005c\u0000-\u001f]*)"|(true|false|null)|(-?(?:0|[1-9][0-9]*))/y;
    const read = () => {
      token.lastIndex = at;
      const match = token.exec(text);
      if (!match) throw new Error("invalid activation response");
      at = token.lastIndex;
      return match[1] !== undefined ? match[1] : match[2] ? JSON.parse(match[2]) : BigInt(match[3]);
    };
    whitespace();
    if (text[at++] !== "{") throw new Error("invalid activation response");
    const out = Object.create(null);
    whitespace();
    if (text[at] !== "}") while (true) {
      const key = read();
      if (typeof key !== "string" || Object.hasOwn(out, key)) throw new Error("invalid activation response");
      whitespace();
      if (text[at++] !== ":") throw new Error("invalid activation response");
      whitespace(); out[key] = read(); whitespace();
      if (text[at] === "}") break;
      if (text[at++] !== ",") throw new Error("invalid activation response");
      whitespace();
    }
    at += 1; whitespace();
    if (at !== text.length || (keys && (Object.keys(out).length !== keys.length || keys.some((k) => !Object.hasOwn(out, k)))))
      throw new Error("invalid activation response");
    return out;
  }

  const api = { base64, base64url, fromBase64, sha256, p1363ToDer, registrationStatement,
    parseDeviceStatement, ownerApprovalStatement, equalBytes, uuidBytes,
    positiveI64, fromBase64url, canonicalDer, observationV2, parseDeviceStatementV2,
    deviceStatementV2, ownerApprovalStatementV2, flatV2Response };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZtSmsLineSigning = api;
})(typeof globalThis === "object" ? globalThis : this);
