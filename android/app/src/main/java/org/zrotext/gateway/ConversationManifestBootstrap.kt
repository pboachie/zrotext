// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer

/** Public predecessor imports use the already compared root and the negotiated socket clock. */
internal object ConversationManifestBootstrap {
    fun install(trust: Draft02TrustStore, chain: List<ByteArray>, parsed: ConversationActivationCodec.Parsed,
                phoneReader: ByteArray, now: () -> Long, requireCurrent: () -> Unit) {
        if (chain.isEmpty()) return
        require(chain.size in 1..ConversationEnrollmentSession.MAX_CHAIN)
        val copies = chain.map { require(it.size in 364..9751); it.copyOf() }
        try {
            val versions = copies.map {
                require(it.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 77, 65, 2)))
                require(it.copyOfRange(5, 21).contentEquals(ConversationEnrollmentSession.uuid(parsed.scope.accountId)))
                require(ByteBuffer.wrap(it, 21, 8).long == parsed.scope.trustGeneration)
                require(it.size == 215 + 149 * (it[150].toInt() and 255))
                ByteBuffer.wrap(it, 29, 8).long.also { version -> require(version > 0) }
            }
            require(versions.zipWithNext().all { (before, after) -> before < Long.MAX_VALUE && after == before + 1 })
            requireCurrent()
            val saved = trust.inspect()
            check(saved.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
            var snapshot = checkNotNull(saved.snapshot)
            val pin = snapshot.pin
            var start = 0
            var final: Draft02ManifestAuthority? = null
            var position = if (snapshot.version == 0L) Draft02ManifestAuthority.Position.genesis(ByteArray(32)) else {
                val current = trust.currentAuthority(now)
                final = current
                if (versions.first() <= current.version) {
                    // An accepted prefix contributes no new authority. Match its exact stored checkpoint
                    // before resuming; old bytes cannot lower the high-water or authorize history reads.
                    val index = versions.indexOf(current.version)
                    check(index >= 0)
                    Draft02ManifestAuthority.verify(pin, copies[index], Draft02ManifestAuthority.Trust(
                        ConversationEnrollmentSession.uuid(parsed.scope.accountId), Draft02RootComparison.fingerprint(pin),
                        parsed.scope.trustGeneration, Draft02ManifestAuthority.Position.current(current.version, current.digest)), now())
                    start = index + 1
                }
                Draft02ManifestAuthority.Position.after(current.version, current.digest)
            }
            for (bytes in copies.drop(start)) {
                requireCurrent()
                val verified = Draft02ManifestAuthority.verify(pin, bytes,
                    Draft02ManifestAuthority.Trust(ConversationEnrollmentSession.uuid(parsed.scope.accountId),
                        Draft02RootComparison.fingerprint(pin), parsed.scope.trustGeneration, position), now())
                position = Draft02ManifestAuthority.Position.after(verified.version, verified.digest)
                final = verified
            }
            val predecessor = checkNotNull(final)
            check(predecessor.version == parsed.predecessorVersion && predecessor.digest.contentEquals(parsed.predecessorDigest))
            predecessor.requireDeviceReader(ConversationEnrollmentSession.uuid(parsed.scope.accountId),
                ConversationEnrollmentSession.uuid(parsed.scope.deviceId), ConversationEnrollmentSession.uuid(parsed.scope.lineId), phoneReader, now())
            // Preflight the entire chain before its first CAS; every write independently rechecks time/lifetime.
            for (bytes in copies.drop(start)) {
                requireCurrent()
                val accepted = trust.acceptManifest(snapshot, bytes) { requireCurrent(); now() }
                check(accepted.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                snapshot = checkNotNull(accepted.snapshot)
            }
            requireCurrent()
        } finally { copies.forEach { it.fill(0) } }
    }
}
