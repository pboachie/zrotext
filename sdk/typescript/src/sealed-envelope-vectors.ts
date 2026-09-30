// SPDX-License-Identifier: AGPL-3.0-only
/**
 * TEST SEAM — test-only vector-reproduction entry point. NOT part of the
 * production surface.
 *
 * The only purpose of this module is to let test files reproduce cross-client
 * vectors byte-for-byte by pinning the content key, body nonce and HPKE
 * ephemeral IKMs through `composeSealedOutboundEnvelopeForVectors`. The
 * production entry point (`sealed-envelope.ts`) refuses this override, its
 * public input type cannot express it, and no production module imports this
 * file. Only `test/sealed-envelope.test.mjs` and
 * `test/support/generate-cross-client.mjs` may import it; treat any other
 * import as a bug. Production callers use `composeSealedOutboundEnvelope`
 * with fresh CSPRNG material.
 */
import {
  composeSealedEnvelopeInternal,
  type SealedDeterministicKeyMaterial,
  type SealedOutboundComposition,
  type SealedOutboundCompositionBase,
} from "./sealed-envelope-internal.js";

export type { SealedDeterministicKeyMaterial } from "./sealed-envelope-internal.js";

/** The production input shape plus the required pinned material; test files only. */
export type SealedVectorCompositionInput = SealedOutboundCompositionBase & Readonly<{
  deterministicKeyMaterial: SealedDeterministicKeyMaterial;
}>;

/**
 * Composes through the same internal core as production, with pinned key
 * material, producing reproducible unsigned bytes and digest for
 * cross-client vectors. Fresh-material callers must not use this function.
 */
export function composeSealedOutboundEnvelopeForVectors(input: SealedVectorCompositionInput): Promise<SealedOutboundComposition> {
  return composeSealedEnvelopeInternal(input);
}
