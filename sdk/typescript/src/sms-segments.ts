// SPDX-License-Identifier: AGPL-3.0-only
// Bounded SMS segment estimates per protocol/v1/sms-segment-estimate.md.
// Pure text accounting only: nothing here sends, approves, schedules, or
// claims a carrier or billing guarantee. The device re-checks the real
// bounds with SmsManager.divideMessage before dispatch.

/** GSM 03.38 default alphabet: characters that fit one septet each. */
const GSM_DEFAULT = new Set([
  "@", "\u00a3", "$", "\u00a5", "\u00e8", "\u00e9", "\u00f9", "\u00ec", "\u00f2", "\u00c7",
  "\n", "\u00d8", "\u00f8", "\r", "\u00c5", "\u00e5", "\u0394", "_", "\u03a6", "\u0393",
  "\u039b", "\u03a9", "\u03a0", "\u03a8", "\u03a3", "\u0398", "\u039e", "\u00c6", "\u00e6",
  "\u00df", "\u00c9", " ", "!", "\"", "#", "\u00a4", "%", "&", "'", "(", ")", "*", "+",
  ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<",
  "=", ">", "?", "\u00a1", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
  "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "\u00c4", "\u00d6",
  "\u00d1", "\u00dc", "\u00a7", "\u00bf", "a", "b", "c", "d", "e", "f", "g", "h", "i",
  "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
  "\u00e4", "\u00f6", "\u00f1", "\u00fc", "\u00e0",
]);

/** GSM 03.38 extension table: each of these costs one escape plus itself. */
const GSM_EXTENSION = new Set([
  "\u000c", "^", "{", "}", "\\", "[", "~", "]", "|", "\u20ac",
]);

/** Hard part cap, mirroring the device-side divideMessage 1..6 gate. */
export const MAX_PARTS = 6;

export interface SegmentEstimate {
  /** "gsm" (7-bit, escapes doubled) or "ucs2" (16-bit code units). */
  encoding: "gsm" | "ucs2";
  /** Number of parts the estimate predicts: 1..6. */
  parts: number;
  /** Per-part budget: 160/70 single, 153/67 multipart. */
  perPart: number;
  /** Text length in code units (UCS-2) or septets incl. escapes (GSM). */
  length: number;
  /** True when the text is empty (still one part, like the device). */
  empty: boolean;
}

export type SegmentError =
  | "lone surrogate"
  | "control character"
  | "too long";

/** Reject characters no SMS alphabet carries: lone surrogates and most C0 controls. */
function validateCodeUnits(text: string): void {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("lone surrogate");
      i += 1; // The pair is two UCS-2 code units; both counted later.
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("lone surrogate");
    } else if (code < 0x20 && code !== 0x0a && code !== 0x0d && code !== 0x0c) {
      throw new Error("control character");
    }
  }
}

function isGsm(text: string): boolean {
  for (const ch of text) {
    if (!GSM_DEFAULT.has(ch) && !GSM_EXTENSION.has(ch)) return false;
  }
  return true;
}

function gsmSeptets(text: string): number {
  let septets = 0;
  for (const ch of text) {
    septets += GSM_EXTENSION.has(ch) ? 2 : 1;
  }
  return septets;
}

/**
 * Estimate the segment count of `text` under the spec's bounded algorithm.
 * Throws on lone surrogates, uncarriable control characters, or text that
 * would exceed MAX_PARTS. The result is a composition estimate only.
 */
export function estimateSegments(text: string): SegmentEstimate {
  if (typeof text !== "string") throw new Error("text must be a string");
  validateCodeUnits(text);
  const empty = text.length === 0;
  if (isGsm(text)) {
    const length = gsmSeptets(text);
    const single = length <= 160;
    const perPart = single ? 160 : 153;
    const parts = single ? 1 : Math.ceil(length / perPart);
    if (parts > MAX_PARTS) throw new Error("too long");
    return { encoding: "gsm", parts, perPart, length, empty };
  }
  const length = text.length; // UTF-16 code units == UCS-2 code units here.
  const single = length <= 70;
  const perPart = single ? 70 : 67;
  const parts = single ? 1 : Math.ceil(length / perPart);
  if (parts > MAX_PARTS) throw new Error("too long");
  return { encoding: "ucs2", parts, perPart, length, empty };
}
