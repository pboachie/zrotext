// SPDX-License-Identifier: AGPL-3.0-only
// Coordination only. A pause acknowledgement is never authentication evidence.
export function createReviewFlight() {
  let inFlight = false;
  let requestedPause = null;
  const canonicalId = (id) => typeof id === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)
    && id !== '00000000-0000-0000-0000-000000000000';
  return Object.freeze({
    async run(operation) {
      if (inFlight || requestedPause !== null) throw new Error('Review operation unavailable');
      inFlight = true;
      try { return await operation(); }
      finally { inFlight = false; }
    },
    requestPause(id) {
      if (!canonicalId(id) || (requestedPause !== null && requestedPause !== id)) return false;
      requestedPause = id;
      return true;
    },
    pauseStatus(id) {
      if (!canonicalId(id) || requestedPause !== id) return null;
      return Object.freeze({ version: 1, request_id: id, state: inFlight ? 'waiting' : 'paused' });
    },
    resume(id) {
      if (!canonicalId(id) || requestedPause !== id || inFlight) return false;
      requestedPause = null;
      return true;
    },
  });
}
