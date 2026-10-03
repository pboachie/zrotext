// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Process-only, independent phone approval. Neither pairing nor a server challenge approves a line. */
internal class SealedLineReviewController(
    private val identity: () -> ConversationSocketComposition.AuthenticatedIdentitySnapshot?,
    private val subscription: () -> Int?,
    private val existingSigner: () -> ByteArray,
    private val install: (SealedLineAcceptance, () -> Boolean) -> AutoCloseable?
) : AutoCloseable {
    internal class Review internal constructor(
        val account: UUID, val device: UUID, val line: UUID, val generation: Long,
        val subscription: Int, private val fingerprint: ByteArray,
        internal val scope: ConversationSocketComposition.AuthenticatedIdentitySnapshot
    ) {
        internal fun fingerprint() = fingerprint.copyOf()
        override fun toString() = "SealedLineReview(redacted)"
    }
    private var review: Review? = null
    private var acceptance: AutoCloseable? = null
    private var closed = false

    @Synchronized fun prepare(line: String, generation: String): Review? {
        if (closed) return null
        withdraw()
        return try {
            val scope = identity() ?: return null
            scope.requireCurrent()
            val lineId = UUID.fromString(line)
            require(lineId.toString() == line && lineId != UUID(0, 0))
            val revision = generation.toLong()
            require(revision > 0 && revision.toString() == generation)
            val sim = subscription()?.takeIf { it >= 0 } ?: return null
            val point = existingSigner()
            require(point.size == 65 && point[0] == 4.toByte())
            val fingerprint = SealedLineActivationTranscript.digest(point)
            scope.requireCurrent()
            require(subscription() == sim)
            Review(UUID.fromString(scope.identity.accountId), UUID.fromString(scope.identity.deviceId),
                lineId, revision, sim, fingerprint, scope).also { review = it }
        } catch (_: Exception) { null }
    }

    /** Confirm only the exact displayed request; recheck the original socket, SIM and existing key. */
    @Synchronized fun confirm(displayed: Review): Boolean {
        if (closed || review !== displayed) return false
        review = null // Single use, including failed installation.
        return try {
            displayed.scope.requireCurrent()
            require(subscription() == displayed.subscription)
            require(MessageDigest.isEqual(displayed.fingerprint(),
                SealedLineActivationTranscript.digest(existingSigner())))
            val selection = SealedLineAcceptance(displayed.account, displayed.device, displayed.line,
                displayed.generation, displayed.subscription, displayed.fingerprint())
            val candidate = install(selection) {
                runCatching { displayed.scope.requireCurrent(); true }.getOrDefault(false)
            } ?: return false
            try {
                displayed.scope.requireCurrent()
                require(subscription() == displayed.subscription)
                require(MessageDigest.isEqual(displayed.fingerprint(),
                    SealedLineActivationTranscript.digest(existingSigner())))
                acceptance = candidate
                true
            } catch (_: Exception) { candidate.close(); false }
        } catch (_: Exception) { false }
    }

    @Synchronized fun cancel() { withdraw() }
    private fun withdraw() {
        review = null
        val old = acceptance
        acceptance = null
        old?.close()
    }
    @Synchronized override fun close() { closed = true; withdraw() }
}
