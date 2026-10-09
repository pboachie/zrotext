// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Implemented privately by the observation issuer, never by a decoder or caller-supplied count. */
internal sealed interface CompletePrivacyProjectionFence {
    val apiLevel: Int
    val observerEpoch: Long
    val monitorLifetime: UUID?
    val selected: SubscriptionObservationRow
    val activeRows: List<SubscriptionObservationRow>
}

/**
 * Unused, RAM-only privacy projection from an exact held local observation. The canonical bytes
 * are declarations, not a signature, OS attestation, installation permit or send capability.
 * Callback/selection/permission/registration withdrawal invalidates memory currentness at entry.
 * Raw logical identifiers stay in private RAM maps; neither map is serialized or persisted.
 */
internal class CompleteSetPrivacyProjectionV2 private constructor(
    private val issuer: CompleteSubscriptionObserver,
    private val fence: CompletePrivacyProjectionFence,
    val monitorLifetime: UUID,
    val selectedLease: UUID,
    private val cards: Map<Int, UUID>,
    private val profiles: Map<SubscriptionObservationRow, UUID>,
    private val declaration: LineActivationV2Observation,
    preimage: ByteArray
) {
    private val frozenPreimage = preimage.copyOf()
    val apiLevel get() = fence.apiLevel
    val count get() = fence.activeRows.size
    val observerEpoch get() = fence.observerEpoch

    /** These copies do not restore currentness and cannot be used to manufacture another issuer. */
    fun observation() = LineActivationV2Observation.decode(declaration.bytes())
    fun completeSetPreimage() = frozenPreimage.copyOf()
    fun isCurrent() = issuer.isPrivacyProjectionCurrent(this)
    internal fun usesFence(expected: CompleteSubscriptionObserver, actual: CompletePrivacyProjectionFence) =
        issuer === expected && fence === actual
    override fun toString() = "CompleteSetPrivacyProjectionV2(local declaration, redacted)"

    internal companion object {
        fun issue(issuer: CompleteSubscriptionObserver,
            snapshot: CompleteSelectionSnapshot): CompleteSetPrivacyProjectionV2? =
            assemble(issuer, snapshot) {}

        /** Scheduling-only test seam: supplies no rows, identities, UUIDs, counts or trusted flags. */
        internal fun issueWithAssemblyBarrierForTest(issuer: CompleteSubscriptionObserver,
            snapshot: CompleteSelectionSnapshot, barrier: () -> Unit): CompleteSetPrivacyProjectionV2? =
            assemble(issuer, snapshot, barrier)

        private fun assemble(issuer: CompleteSubscriptionObserver,
            snapshot: CompleteSelectionSnapshot, barrier: () -> Unit): CompleteSetPrivacyProjectionV2? {
            issuer.cachedPrivacyProjection(snapshot)?.let { return it }
            val fence = issuer.capturePrivacyProjection(snapshot) ?: return null
            if (fence.apiLevel !in 33..65535 || fence.activeRows.size !in 1..256) return null
            // No observer or adapter lock spans this barrier, randomness, mapping or SHA-256.
            try {
                barrier()
                val used = HashSet<UUID>()
                val lifetime = fence.monitorLifetime ?: freshId(used)
                used.add(lifetime)
                val lease = freshId(used)
                val cards = HashMap<Int, UUID>()
                val profiles = HashMap<SubscriptionObservationRow, UUID>()
                val rows = fence.activeRows.map { raw ->
                    val card = requireNotNull(raw.cardId)
                    val cardToken = cards.getOrPut(card) { freshId(used) }
                    val profileToken = freshId(used)
                    profiles[raw] = profileToken
                    LineActivationV2Row(
                        if (raw.kind == ObservedSubscriptionKind.PHYSICAL) LineActivationV2Kind.PHYSICAL
                        else LineActivationV2Kind.EMBEDDED,
                        cardToken, profileToken, requireNotNull(raw.portIndex), requireNotNull(raw.slotIndex))
                }
                val selectedIndex = fence.activeRows.indexOf(fence.selected)
                if (selectedIndex < 0) return null
                val set = LineActivationV2CompleteSet(lifetime, fence.observerEpoch, fence.apiLevel, rows)
                val declaration = set.observation(rows[selectedIndex], fence.selected.subscriptionId, lease)
                val candidate = CompleteSetPrivacyProjectionV2(issuer, fence, lifetime, lease,
                    cards.toMap(), profiles.toMap(), declaration, set.preimage())
                // An old build cannot populate a replacement epoch. Concurrent builders reuse the
                // single actually published projection, not their own discarded random candidates.
                return issuer.publishPrivacyProjection(fence, candidate)
            } catch (failure: Exception) {
                if (failure is InterruptedException) Thread.currentThread().interrupt()
                return null
            }
        }

        private fun freshId(used: MutableSet<UUID>): UUID {
            repeat(8) {
                val id = UUID.randomUUID()
                if (id != UUID(0, 0) && used.add(id)) return id
            }
            throw IllegalStateException("Local identifier construction refused")
        }
    }
}
