// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Explicit first02 import under the already compared root; no conversation scope or new root.
 * A retained accepted chain can be matched exactly, never advanced/replaced by this initial flow.
 */
internal object Profile03ManifestBootstrap {
    fun install(trust: Draft02TrustStore, chain: List<ByteArray>, binding: LocalLineBinding,
        reader: DevicePayloadPublic, now: () -> Long, requireCurrent: () -> Unit): Long {
        require(chain.size in 1..ConversationEnrollmentSession.MAX_CHAIN)
        val owned = chain.map { require(it.size in 364..9751); it.copyOf() }
        try {
            requireCurrent()
            val saved = trust.inspect()
            check(saved.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
            var snapshot = checkNotNull(saved.snapshot)
            val account = ConversationEnrollmentSession.uuid(binding.accountId)
            val pin = snapshot.pin
            require(pin.copyOfRange(5, 21).contentEquals(account) && binding.protocolVersion == 2 && binding.v2Purpose == "sealed")
            val versions = owned.mapIndexed { index, bytes ->
                require(bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 77, 65, 2)) &&
                    bytes.copyOfRange(5, 21).contentEquals(account) && ByteBuffer.wrap(bytes, 21, 8).long == 1L)
                ByteBuffer.wrap(bytes, 29, 8).long.also { require(it == index + 1L) }
            }
            val fingerprint = Draft02RootComparison.fingerprint(pin)
            if (snapshot.version > 0) {
                require(snapshot.version == versions.last())
                val history = trust.currentElectionHistory(now)
                require(MessageDigest.isEqual(history.proof.signedSha256(), sha(owned.last())))
                history.requireOriginalReader(ConversationEnrollmentSession.uuid(binding.deviceId),
                    ConversationEnrollmentSession.uuid(binding.lineId), reader.keyId, reader.point)
                requireCurrent()
                return snapshot.version
            }
            var position = Draft02ManifestAuthority.Position.genesis(ByteArray(32))
            var final: Draft02ManifestAuthority? = null
            // Verify every root-signed link and selected payload reader BEFORE the first write.
            for (bytes in owned) {
                requireCurrent()
                val value = Draft02ManifestAuthority.verify(pin, bytes,
                    Draft02ManifestAuthority.Trust(account, fingerprint, 1, position), now())
                position = Draft02ManifestAuthority.Position.after(value.version, value.digest)
                final = value
            }
            checkNotNull(final).requireElectionReader(ConversationEnrollmentSession.uuid(binding.deviceId),
                ConversationEnrollmentSession.uuid(binding.lineId), reader.keyId, reader.point, now())
            requireCurrent()
            val accepted = trust.acceptInitialManifestChain(snapshot, owned, now) { value, instant ->
                value.requireElectionReader(ConversationEnrollmentSession.uuid(binding.deviceId),
                    ConversationEnrollmentSession.uuid(binding.lineId), reader.keyId, reader.point, instant)
            }
            check(accepted.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
            snapshot = checkNotNull(accepted.snapshot)
            requireCurrent()
            return snapshot.version
        } finally { owned.forEach { it.fill(0) } }
    }
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}
