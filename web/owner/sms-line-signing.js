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

  const api = { base64, base64url, fromBase64, sha256, p1363ToDer, registrationStatement,
    parseDeviceStatement, ownerApprovalStatement, equalBytes, uuidBytes };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZtSmsLineSigning = api;
})(typeof globalThis === "object" ? globalThis : this);
