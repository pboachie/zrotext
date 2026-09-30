// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Production sealed outbound envelope composition (issue #537 slice A).
 *
 * `composeSealedOutboundEnvelope` composes one complete kind-01 profile-02
 * candidate envelope from explicit caller inputs and returns the exact bytes
 * together with the SHA-256 digest of the unsigned envelope — the Q6
 * idempotency identity a caller must reuse on retry. The wire layout, bounds
 * and rules mirror the dormant Rust parser (crates/server/src/sealed_envelope
 * and sealed_body) and the reviewed draft-02 helpers: composition is delegated
 * to `prepareOutboundEnvelope02` after this module's own fail-closed
 * validation, so the bytes are exactly the ones the cross-client lane feeds to
 * the Rust verifier and the strict server admission route. Authorization is
 * never re-implemented: the exact manifest object returned by
 * `verifyManifest02` must authorize the request.
 *
 * The content key, body nonce and every HPKE ephemeral IKM are drawn fresh
 * from `crypto.getRandomValues` on every call. The public input type has no
 * way to pin them: deterministic key material exists only on the internal
 * core (`sealed-envelope-internal.ts`) and reaches test files solely through
 * the clearly-marked test seam (`sealed-envelope-vectors.ts`). This
 * production entry point also refuses an input that carries a
 * `deterministicKeyMaterial` property at runtime - including one inherited through the
 * prototype chain - so a caller cannot reach
 * the vector override by casting. Two compositions of the same message under
 * fresh material are two different Q6 identities by design.
 *
 * This module has no network client, no send path and no server dependency;
 * the HTTP client is `sealed-client.ts` (issue #537 slice B). The server
 * route stays disabled by default, and composing an envelope is never
 * carrier submission.
 */
import {
  SealedEnvelopeError,
  composeSealedEnvelopeInternal,
  type SealedOutboundComposition,
  type SealedOutboundCompositionBase,
} from "./sealed-envelope-internal.js";

export const SEALED_CONTENT_TYPE = "application/vnd.zrotext.sealed.v1";

export type {
  SealedEnvelopeErrorCode,
  SealedOutboundRecipient,
  SealedOutboundSigner,
  SealedOutboundComposition,
} from "./sealed-envelope-internal.js";
export { SealedEnvelopeError, isSealedEnvelopeError } from "./sealed-envelope-internal.js";

/**
 * The production input: exactly the internal base shape with no field able to
 * supply key material. `Omit` keeps this type structurally unable to grow the
 * override back without editing this module.
 */
export type SealedOutboundCompositionInput = Omit<SealedOutboundCompositionBase, "deterministicKeyMaterial">;

/**
 * Snapshots every caller-held value synchronously, validates fail-closed
 * against the server parser's rules with typed errors, authorizes against
 * the exact verified manifest, and returns the envelope bytes plus the
 * unsigned SHA-256 digest composed under fresh CSPRNG key material. An input
 * that still carries the vector override is refused, never silently honored.
 */
export async function composeSealedOutboundEnvelope(input: SealedOutboundCompositionInput): Promise<SealedOutboundComposition> {
  if (input !== null && typeof input === "object" &&
      "deterministicKeyMaterial" in input) {
    throw new SealedEnvelopeError(
      "key_material",
      "deterministicKeyMaterial is not part of the production API; it exists only on the test seam (sealed-envelope-vectors.ts)",
    );
  }
  return composeSealedEnvelopeInternal(input);
}
