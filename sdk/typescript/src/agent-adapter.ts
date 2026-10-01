/** Simulator-only agent adapter; no live transport or agent authority. */
import { parseDraftEnvelope } from './draft01.js';
import { SealedApiError, SealedMessagePlaneClient } from './msgplane-client.js';

export type SimulatedResponse = Readonly<{ status: number; body: unknown }> | 'disconnect';
export type SimulationResult = Readonly<{
  synthetic: true;
  state: 'accepted' | 'refused' | 'unknown';
  attempts: number;
  code?: string;
  messageId?: string;
  created?: boolean;
}>;

/** Readiness cannot enable a route or imply scoped authority exists. */
export function agentReadiness(): Readonly<{ synthetic: true; available: false; code: 'unavailable' }> {
  return { synthetic: true, available: false, code: 'unavailable' };
}

/** Run the existing SDK contract against explicit fixtures, never a network. */
export async function simulateSubmission(
  envelope: Uint8Array, responses: readonly SimulatedResponse[], maxAttempts = 1,
): Promise<SimulationResult> {
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3) {
    return { synthetic: true, state: 'refused', attempts: 0, code: 'invalid_request' };
  }
  // Snapshot both caller inputs before any asynchronous SDK work.
  let snapshot: Uint8Array;
  let queue: SimulatedResponse[];
  try {
    if (!(envelope instanceof Uint8Array)) throw new Error();
    snapshot = Uint8Array.from(envelope);
    if (parseDraftEnvelope(snapshot).kind !== 1) throw new Error();
    if (!Array.isArray(responses) || responses.length > 3) throw new Error();
    queue = structuredClone(responses);
  } catch {
    return { synthetic: true, state: 'refused', attempts: 0, code: 'invalid_request' };
  }
  let attempts = 0;
  const client = new SealedMessagePlaneClient({
    origin: 'https://simulator.example', bearer: 'synthetic',
    fetchImpl: async () => {
      attempts++;
      const response = queue.shift();
      if (response === 'disconnect' || response === undefined) throw new Error('unknown');
      return { status: response.status, json: async () => response.body };
    },
  });
  try {
    const accepted = await client.withRetry(bytes => client.submitOutbound(bytes), snapshot, {
      maxAttempts, sleepMs: () => 0, sleep: async () => {},
    });
    return { synthetic: true, state: 'accepted', attempts, ...accepted };
  } catch (error) {
    // Malformed success/error bodies and disconnects may follow durable acceptance.
    // Neither is permission to submit a new operation or claim radio delivery.
    if (!(error instanceof SealedApiError) || error.code === 'unexpected_response') {
      return { synthetic: true, state: 'unknown', attempts, code: 'submission_unknown' };
    }
    return { synthetic: true, state: 'refused', attempts, code: error.code };
  }
}
