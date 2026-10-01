// SPDX-License-Identifier: AGPL-3.0-only
/** Experimental profile-01 selected-reader seam; not a production profile-02 reader. */
import { openDraftEnvelope, parseDraftEnvelope } from '../typescript/dist/draft01.js';

const uuidBytes = value => Buffer.from(value.replaceAll('-', ''), 'hex');
const same = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);

/** load must fetch only the existing event's selected ciphertext/context from a
 * customer secret store. authorize must independently verify current manifest,
 * recipient and reader grants. Missing inputs deny; no keys enter a HTTP body. */
export function createSelectedDraftReader({ load, authorize }) {
  return async (event, signal) => {
    if (signal?.aborted || typeof load !== 'function' || typeof authorize !== 'function' ||
        await authorize(event) !== true) return { kind: 'unavailable' };
    const selected = await load(event, signal);
    if (!selected || !(selected.envelope instanceof Uint8Array) || !selected.context) return { kind: 'unavailable' };
    const envelope = Uint8Array.from(selected.envelope);
    const parsed = parseDraftEnvelope(envelope);
    if (parsed.kind !== 2 || !same(parsed.eventId, uuidBytes(event.event_id)) ||
        !same(parsed.accountId, uuidBytes(event.account_id)) || !same(parsed.deviceId, uuidBytes(event.device_id)) ||
        !same(parsed.lineId, uuidBytes(event.line_id)) ||
        parsed.observedMs !== BigInt(event.observed_at_ms)) return { kind: 'unavailable' };
    const text = await openDraftEnvelope(envelope, selected.context);
    if (signal?.aborted || await authorize(event) !== true) return { kind: 'unavailable' };
    return { kind: 'decrypted', text };
  };
}
